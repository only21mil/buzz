//! Production admission path and fixed-frame broker transport.
//!
//! The service layer supplies authenticated request data, reviewed workflow
//! policy, and manifest bindings. This module does not derive any of those
//! values from command-line strings.

use std::io::{Read, Write};
use std::time::Duration;

use buzz_ci_broker_protocol::{
    decode_response, encode_request, AdmitAttemptRequest, BrokerResponse, FrameHeader, Request,
    TrustClass, HEADER_SIZE, RESPONSE_BODY_SIZE,
};
use buzz_core::ci::CiRequestEnvelope;
use sha2::{Digest, Sha256};

use crate::{
    authorize_request, normalize_admit_request, BrokerManifestBinding, ControlError,
    RequestAuthorizer,
};

/// The broker socket selected by the trusted service configuration.
pub const BROKER_SOCKET_PATH: &str = "/run/buzzci/execd.sock";

const RESPONSE_FRAME_SIZE: usize = HEADER_SIZE + RESPONSE_BODY_SIZE;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_ID_DOMAIN: &[u8] = b"buzz-ci-runner:admit-request-id:v1\0";

/// Reviewed workflow facts supplied by the trusted integration layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CiWorkflowPolicy {
    trust_class: Option<TrustClass>,
    external_fork: bool,
}

impl CiWorkflowPolicy {
    /// Build policy facts already established by the trusted integration layer.
    pub const fn new(trust_class: Option<TrustClass>, external_fork: bool) -> Self {
        Self {
            trust_class,
            external_fork,
        }
    }

    pub(crate) const fn accepted_trust_class(self) -> Result<TrustClass, ControlError> {
        if self.external_fork {
            return Err(ControlError::ExternalFork);
        }
        match self.trust_class {
            Some(trust_class) => Ok(trust_class),
            None => Err(ControlError::UnacceptedTrust),
        }
    }
}

/// A request envelope paired with the digest established by signature
/// verification. The integration layer, not this crate, authenticates it.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedCiRequest<'a> {
    envelope: &'a CiRequestEnvelope,
    signed_request_digest: [u8; 32],
}

impl<'a> AuthenticatedCiRequest<'a> {
    pub const fn new(envelope: &'a CiRequestEnvelope, signed_request_digest: [u8; 32]) -> Self {
        Self {
            envelope,
            signed_request_digest,
        }
    }

    pub const fn envelope(self) -> &'a CiRequestEnvelope {
        self.envelope
    }

    pub const fn signed_request_digest(self) -> [u8; 32] {
        self.signed_request_digest
    }
}

/// Typed admission input. The caller must obtain every field from trusted
/// request verification, workflow review, and materialization stages.
#[derive(Clone, Copy, Debug)]
pub struct AdmitRequestInput<'a> {
    pub request: AuthenticatedCiRequest<'a>,
    pub workflow_policy: CiWorkflowPolicy,
    pub binding: BrokerManifestBinding,
    pub now: u64,
}

/// A broker transport accepts only a canonical, fixed-width request.
pub trait BrokerTransport {
    fn exchange(&mut self, request: AdmitAttemptRequest) -> Result<BrokerResponse, ControlError>;
}

/// Authorize, reject expired input, normalize, and only then contact the broker.
pub fn admit_request(
    input: AdmitRequestInput<'_>,
    authorizer: &impl RequestAuthorizer,
    transport: &mut impl BrokerTransport,
) -> Result<BrokerResponse, ControlError> {
    let authorized = authorize_request(input.request, input.workflow_policy, authorizer)?;
    let authorized = authorized.check_expiry(input.now)?;
    let normalized = normalize_admit_request(authorized, input.binding)?;
    transport.exchange(normalized)
}

/// Production fixed-socket Unix transport.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnixBrokerTransport;

impl BrokerTransport for UnixBrokerTransport {
    fn exchange(&mut self, request: AdmitAttemptRequest) -> Result<BrokerResponse, ControlError> {
        exchange_unix(request)
    }
}

#[cfg(unix)]
fn exchange_unix(request: AdmitAttemptRequest) -> Result<BrokerResponse, ControlError> {
    use std::os::unix::net::UnixStream;

    let mut stream =
        UnixStream::connect(BROKER_SOCKET_PATH).map_err(|_| ControlError::BrokerUnavailable)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|_| ControlError::TransportFailure)?;
    exchange_stream(&mut stream, request)
}

#[cfg(not(unix))]
fn exchange_unix(_request: AdmitAttemptRequest) -> Result<BrokerResponse, ControlError> {
    Err(ControlError::BrokerUnavailable)
}

trait ControlStream: Read + Write {
    fn shutdown_write(&mut self) -> std::io::Result<()>;
}

#[cfg(unix)]
impl ControlStream for std::os::unix::net::UnixStream {
    fn shutdown_write(&mut self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

fn exchange_stream(
    stream: &mut impl ControlStream,
    request: AdmitAttemptRequest,
) -> Result<BrokerResponse, ControlError> {
    let request_id = request_id_for_admit(request.signed_request_digest);
    let request = Request::AdmitAttempt(request);
    let encoded = encode_request(request_id, request);
    stream
        .write_all(encoded.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| ControlError::TransportFailure)?;
    stream
        .shutdown_write()
        .map_err(|_| ControlError::TransportFailure)?;

    let mut response = Vec::with_capacity(RESPONSE_FRAME_SIZE);
    stream
        .take((RESPONSE_FRAME_SIZE + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|_| ControlError::TransportFailure)?;
    if response.len() != RESPONSE_FRAME_SIZE {
        return Err(ControlError::InvalidBrokerResponse);
    }
    decode_response(
        FrameHeader {
            operation: request.operation(),
            request_id,
        },
        &response,
    )
    .map_err(|_| ControlError::InvalidBrokerResponse)
}

fn request_id_for_admit(signed_request_digest: [u8; 32]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(REQUEST_ID_DOMAIN)
        .chain_update(signed_request_digest)
        .finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    request_id
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use buzz_ci_broker_protocol::{
        decode_request, encode_response, BrokerState, Conclusion, GitOid, ResponseCode,
    };
    use buzz_core::ci::{CiRequestType, CI_SCHEMA_VERSION};
    use uuid::Uuid;

    use super::*;

    struct Policy(bool);

    impl RequestAuthorizer for Policy {
        fn authorize(&self, _request: &CiRequestEnvelope) -> bool {
            self.0
        }
    }

    #[derive(Default)]
    struct SpyTransport {
        requests: Vec<AdmitAttemptRequest>,
        written: Vec<u8>,
    }

    impl BrokerTransport for SpyTransport {
        fn exchange(
            &mut self,
            request: AdmitAttemptRequest,
        ) -> Result<BrokerResponse, ControlError> {
            self.requests.push(request);
            let request_id = request_id_for_admit(request.signed_request_digest);
            self.written.extend_from_slice(
                encode_request(request_id, Request::AdmitAttempt(request)).as_bytes(),
            );
            Ok(response_for(request))
        }
    }

    fn request() -> CiRequestEnvelope {
        CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "11".repeat(32)),
            pr_root_event_id: "22".repeat(32),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/repo".to_string(),
            immutable_source_ref: "refs/nostr/source".to_string(),
            tip_oid: "33".repeat(20),
            source_branch: "feature".to_string(),
            base_ref: "refs/heads/main".to_string(),
            base_oid: "44".repeat(20),
            workflow_id: "ci".to_string(),
            workflow_digest: "55".repeat(32),
            job_ids: vec!["test".to_string()],
            run_id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "22".repeat(32),
            actor: "66".repeat(32),
            timeout_seconds: 300,
            idempotency_key: "123e4567-e89b-12d3-a456-426614174001".to_string(),
            issued_at: 10,
            expires_at: 20,
        }
    }

    const fn accepted_policy() -> CiWorkflowPolicy {
        CiWorkflowPolicy::new(Some(TrustClass::AcceptedReviewed), false)
    }

    const fn binding() -> BrokerManifestBinding {
        BrokerManifestBinding {
            signed_request_digest: [1; 32],
            audience_digest: [2; 32],
            job_manifest_digest: [3; 32],
            isolation_profile_digest: [4; 32],
        }
    }

    fn input<'a>(request: &'a CiRequestEnvelope) -> AdmitRequestInput<'a> {
        AdmitRequestInput {
            request: AuthenticatedCiRequest::new(request, [1; 32]),
            workflow_policy: accepted_policy(),
            binding: binding(),
            now: 19,
        }
    }

    fn response_for(request: AdmitAttemptRequest) -> BrokerResponse {
        BrokerResponse {
            code: ResponseCode::Ok,
            retry_after_millis: 0,
            attempt_id: [9; 16],
            run_id: request.run_id,
            accepted_request_digest: request.signed_request_digest,
            job_manifest_digest: request.job_manifest_digest,
            tip_oid: Some(request.tip_oid),
            broker_state: BrokerState::Ready,
            conclusion: Conclusion::None,
            terminal_reason: 0,
            generation: 1,
            accepted_at: request.issued_at,
            updated_at: request.issued_at,
            lease_generation: 1,
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
            attempt: request.attempt,
        }
    }

    #[test]
    fn all_policy_rejections_write_zero_broker_bytes() {
        let request = request();

        let mut unauthorized = SpyTransport::default();
        assert_eq!(
            admit_request(input(&request), &Policy(false), &mut unauthorized),
            Err(ControlError::Unauthorized)
        );
        assert!(unauthorized.written.is_empty());

        let mut unaccepted = SpyTransport::default();
        let mut unaccepted_input = input(&request);
        unaccepted_input.workflow_policy = CiWorkflowPolicy::new(None, false);
        assert_eq!(
            admit_request(unaccepted_input, &Policy(true), &mut unaccepted),
            Err(ControlError::UnacceptedTrust)
        );
        assert!(unaccepted.written.is_empty());

        let mut fork = SpyTransport::default();
        let mut fork_input = input(&request);
        fork_input.workflow_policy =
            CiWorkflowPolicy::new(Some(TrustClass::AcceptedReviewed), true);
        assert_eq!(
            admit_request(fork_input, &Policy(true), &mut fork),
            Err(ControlError::ExternalFork)
        );
        assert!(fork.written.is_empty());

        let mut expired = SpyTransport::default();
        let mut expired_input = input(&request);
        expired_input.now = request.expires_at;
        assert_eq!(
            admit_request(expired_input, &Policy(true), &mut expired),
            Err(ControlError::ExpiredRequest)
        );
        assert!(expired.written.is_empty());

        let mut invalid_binding = SpyTransport::default();
        let mut invalid_input = input(&request);
        invalid_input.binding.signed_request_digest = [9; 32];
        assert_eq!(
            admit_request(invalid_input, &Policy(true), &mut invalid_binding),
            Err(ControlError::InvalidBinding)
        );
        assert!(invalid_binding.written.is_empty());
    }

    #[test]
    fn transport_receives_canonical_normalization_byte_for_byte() {
        let request = request();
        let mut transport = SpyTransport::default();
        admit_request(input(&request), &Policy(true), &mut transport).expect("admitted");
        let [sent] = transport.requests.as_slice() else {
            panic!("expected one request")
        };

        let expected = AdmitAttemptRequest {
            signed_request_digest: [1; 32],
            actor_pubkey: [0x66; 32],
            audience_digest: [2; 32],
            idempotency_digest: Sha256::digest(
                Uuid::parse_str("123e4567-e89b-12d3-a456-426614174001")
                    .expect("UUID")
                    .as_bytes(),
            )
            .into(),
            source_pin_event_id: [0x22; 32],
            workflow_digest: [0x55; 32],
            job_manifest_digest: [3; 32],
            isolation_profile_digest: [4; 32],
            run_id: *Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")
                .expect("UUID")
                .as_bytes(),
            tip_oid: GitOid::Sha1([0x33; 20]),
            base_oid: GitOid::Sha1([0x44; 20]),
            issued_at: 10,
            expires_at: 20,
            wall_timeout_seconds: 300,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
        };
        assert_eq!(*sent, expected);

        let request_id = request_id_for_admit(expected.signed_request_digest);
        let sent_frame = encode_request(request_id, Request::AdmitAttempt(*sent));
        let golden_frame = encode_request(request_id, Request::AdmitAttempt(expected));
        assert_eq!(transport.written, sent_frame.as_bytes());
        assert_eq!(sent_frame.as_bytes(), golden_frame.as_bytes());
    }

    struct ScriptedStream {
        response: Cursor<Vec<u8>>,
        written: Vec<u8>,
        shutdown: bool,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if !self.shutdown {
                return Err(std::io::Error::other("read before write shutdown"));
            }
            self.response.read(output)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ControlStream for ScriptedStream {
        fn shutdown_write(&mut self) -> std::io::Result<()> {
            self.shutdown = true;
            Ok(())
        }
    }

    #[test]
    fn unix_exchange_writes_one_fixed_request_and_requires_exact_response() {
        let request = transport_request();
        let request_id = request_id_for_admit(request.signed_request_digest);
        let response = response_for(request);
        let encoded = encode_response(
            FrameHeader {
                operation: Request::AdmitAttempt(request).operation(),
                request_id,
            },
            response,
        );
        let mut stream = ScriptedStream {
            response: Cursor::new(encoded.as_bytes().to_vec()),
            written: Vec::new(),
            shutdown: false,
        };

        assert_eq!(exchange_stream(&mut stream, request), Ok(response));
        assert!(stream.shutdown);
        assert_eq!(
            decode_request(&stream.written).expect("fixed request").1,
            Request::AdmitAttempt(request)
        );
    }

    #[test]
    fn unix_exchange_rejects_trailing_response_bytes() {
        let request = transport_request();
        let request_id = request_id_for_admit(request.signed_request_digest);
        let response = response_for(request);
        let encoded = encode_response(
            FrameHeader {
                operation: Request::AdmitAttempt(request).operation(),
                request_id,
            },
            response,
        );
        let mut bytes = encoded.as_bytes().to_vec();
        bytes.push(0);
        let mut stream = ScriptedStream {
            response: Cursor::new(bytes),
            written: Vec::new(),
            shutdown: false,
        };
        assert_eq!(
            exchange_stream(&mut stream, request),
            Err(ControlError::InvalidBrokerResponse)
        );
    }

    fn transport_request() -> AdmitAttemptRequest {
        let request = request();
        let authorized = authorize_request(
            AuthenticatedCiRequest::new(&request, [1; 32]),
            accepted_policy(),
            &Policy(true),
        )
        .expect("authorized")
        .check_expiry(19)
        .expect("unexpired");
        normalize_admit_request(authorized, binding()).expect("normalized")
    }
}
