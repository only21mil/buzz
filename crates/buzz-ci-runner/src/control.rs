//! Broker v2 admission, completion, and Unix transport.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use buzz_ci_broker_protocol::v2;
use buzz_ci_broker_protocol::{
    BrokerState, Conclusion, GitOid, ResponseCode, HEADER_SIZE, MAX_SAFE_INTEGER,
};
use sha2::{Digest, Sha256};

use crate::ControlError;

/// The broker socket selected by the trusted service configuration.
pub const BROKER_SOCKET_PATH: &str = "/run/buzzci/execd.sock";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const V2_REQUEST_ID_DOMAIN: &[u8] = b"buzz-ci-runner:broker-request-id:v2\0";

/// Bounded terminal evidence produced by the unprivileged execution backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedExecutionEvidence {
    advisory_conclusion: Conclusion,
    evidence_set_digest: [u8; 32],
    terminal_at: u64,
}

impl BoundedExecutionEvidence {
    /// Validate a backend's terminal evidence before it can reach the broker.
    pub fn new(
        advisory_conclusion: Conclusion,
        evidence_set_digest: [u8; 32],
        terminal_at: u64,
    ) -> Result<Self, ControlError> {
        if advisory_conclusion == Conclusion::None
            || evidence_set_digest == [0; 32]
            || terminal_at == 0
            || terminal_at > MAX_SAFE_INTEGER
        {
            return Err(ControlError::InvalidExecutionEvidence);
        }
        Ok(Self {
            advisory_conclusion,
            evidence_set_digest,
            terminal_at,
        })
    }
}

/// Version 2 broker transport. The distinct trait prevents legacy requests or
/// responses from entering the activation path.
pub trait BrokerTransportV2 {
    fn exchange(&mut self, request: v2::Request) -> Result<v2::BrokerResponse, ControlError>;
}

/// Opaque runner proof of one execd-owned version 2 execution binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedLeaseV2 {
    signer_pubkey: [u8; 32],
    signed_request_digest: [u8; 32],
    job_intent_digest: [u8; 32],
    execution_binding_digest: [u8; 32],
    run_id: [u8; 16],
    attempt: u32,
    attempt_id: [u8; 16],
    lease_id: [u8; 16],
    lease_generation: u64,
    tip_oid: GitOid,
    accepted_at: u64,
}

impl AdmittedLeaseV2 {
    pub const fn execution_binding_digest(self) -> [u8; 32] {
        self.execution_binding_digest
    }
}

/// Send one already-signed JobIntentV2 and require an exact execd binding.
pub fn admit_signed_job_intent_v2(
    request: v2::AdmitAttemptRequest,
    transport: &mut impl BrokerTransportV2,
) -> Result<AdmittedLeaseV2, ControlError> {
    let response = transport.exchange(v2::Request::AdmitAttempt(request))?;
    validate_admitted_response_v2(request, response)
}

fn validate_admitted_response_v2(
    request: v2::AdmitAttemptRequest,
    response: v2::BrokerResponse,
) -> Result<AdmittedLeaseV2, ControlError> {
    if !matches!(response.code, ResponseCode::Ok | ResponseCode::Existing) {
        return Err(ControlError::BrokerRejected);
    }
    if response.retry_after_millis != 0
        || response.attempt_id == [0; 16]
        || response.run_id != request.run_id
        || response.accepted_request_digest != request.signed_request_digest
        || response.job_intent_digest != request.job_intent_digest
        || response.execution_binding_digest == [0; 32]
        || response.tip_oid != Some(request.tip_oid)
        || response.broker_state != BrokerState::Leased
        || response.conclusion != Conclusion::None
        || response.terminal_reason != 0
        || response.generation == 0
        || response.accepted_at == 0
        || response.accepted_at > MAX_SAFE_INTEGER
        || response.updated_at < response.accepted_at
        || response.updated_at > MAX_SAFE_INTEGER
        || response.lease_generation == 0
        || response.evidence_set_digest != [0; 32]
        || response.teardown_digest != [0; 32]
        || response.attempt != request.attempt
    {
        return Err(ControlError::InvalidBrokerResponse);
    }
    Ok(AdmittedLeaseV2 {
        signer_pubkey: request.actor_pubkey,
        signed_request_digest: request.signed_request_digest,
        job_intent_digest: request.job_intent_digest,
        execution_binding_digest: response.execution_binding_digest,
        run_id: request.run_id,
        attempt: request.attempt,
        attempt_id: response.attempt_id,
        lease_id: response.attempt_id,
        lease_generation: response.lease_generation,
        tip_oid: request.tip_oid,
        accepted_at: response.accepted_at,
    })
}

/// Read one version 2 attempt by its exact execd-owned binding.
pub fn get_attempt_v2(
    lease: AdmittedLeaseV2,
    transport: &mut impl BrokerTransportV2,
) -> Result<v2::BrokerResponse, ControlError> {
    let response = transport.exchange(v2::Request::GetAttempt(v2::GetAttemptRequest {
        attempt_id: lease.attempt_id,
        execution_binding_digest: lease.execution_binding_digest,
    }))?;
    validate_bound_response_v2(lease, response)
}

/// Complete one version 2 attempt by its exact execd-owned binding.
pub fn complete_attempt_v2(
    lease: AdmittedLeaseV2,
    evidence: BoundedExecutionEvidence,
    transport: &mut impl BrokerTransportV2,
) -> Result<v2::BrokerResponse, ControlError> {
    if evidence.terminal_at < lease.accepted_at {
        return Err(ControlError::InvalidExecutionEvidence);
    }
    let response =
        transport.exchange(v2::Request::CompleteAttempt(v2::CompleteAttemptRequest {
            signer_pubkey: lease.signer_pubkey,
            signed_request_digest: lease.signed_request_digest,
            run_id: lease.run_id,
            attempt: lease.attempt,
            lease_id: lease.lease_id,
            lease_generation: lease.lease_generation,
            execution_binding_digest: lease.execution_binding_digest,
            advisory_conclusion: evidence.advisory_conclusion,
            evidence_set_digest: evidence.evidence_set_digest,
            terminal_at: evidence.terminal_at,
        }))?;
    validate_bound_response_v2(lease, response)
}

fn validate_bound_response_v2(
    lease: AdmittedLeaseV2,
    response: v2::BrokerResponse,
) -> Result<v2::BrokerResponse, ControlError> {
    if !matches!(response.code, ResponseCode::Ok | ResponseCode::Existing)
        || response.retry_after_millis != 0
        || response.attempt_id != lease.attempt_id
        || response.run_id != lease.run_id
        || response.accepted_request_digest != lease.signed_request_digest
        || response.job_intent_digest != lease.job_intent_digest
        || response.execution_binding_digest != lease.execution_binding_digest
        || response.tip_oid != Some(lease.tip_oid)
        || response.generation == 0
        || response.accepted_at != lease.accepted_at
        || response.updated_at < response.accepted_at
        || response.updated_at > MAX_SAFE_INTEGER
        || response.lease_generation != lease.lease_generation
        || response.attempt != lease.attempt
    {
        return Err(ControlError::InvalidBrokerResponse);
    }
    Ok(response)
}

/// Execution backend that obtains the broker's bounded terminal evidence.
///
/// Version 1 performs one broker read. The contract does not define a runner
/// Production Unix transport for the broker v2 activation contract.
#[derive(Clone, Debug)]
pub struct UnixBrokerTransportV2 {
    socket_path: PathBuf,
    expected_uid: u32,
}

impl UnixBrokerTransportV2 {
    pub fn new(socket_path: PathBuf, expected_uid: u32) -> Self {
        Self {
            socket_path,
            expected_uid,
        }
    }
}

impl Default for UnixBrokerTransportV2 {
    fn default() -> Self {
        Self::new(PathBuf::from(BROKER_SOCKET_PATH), 0)
    }
}

impl BrokerTransportV2 for UnixBrokerTransportV2 {
    fn exchange(&mut self, request: v2::Request) -> Result<v2::BrokerResponse, ControlError> {
        exchange_unix_v2(&self.socket_path, self.expected_uid, request)
    }
}

fn authorize_broker_peer(peer_uid: u32, expected_uid: u32) -> Result<(), ControlError> {
    if peer_uid == expected_uid {
        Ok(())
    } else {
        Err(ControlError::BrokerRejected)
    }
}

#[cfg(unix)]
fn exchange_unix_v2(
    path: &Path,
    expected_uid: u32,
    request: v2::Request,
) -> Result<v2::BrokerResponse, ControlError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(path).map_err(|_| ControlError::BrokerUnavailable)?;
    mark_control_stream_close_on_exec(&stream)?;
    let credentials =
        getsockopt(&stream, PeerCredentials).map_err(|_| ControlError::TransportFailure)?;
    authorize_broker_peer(credentials.uid(), expected_uid)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|_| ControlError::TransportFailure)?;
    exchange_stream_v2(&mut stream, request)
}

#[cfg(unix)]
fn mark_control_stream_close_on_exec(
    stream: &std::os::unix::net::UnixStream,
) -> Result<(), ControlError> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};

    let current = fcntl(stream, FcntlArg::F_GETFD).map_err(|_| ControlError::TransportFailure)?;
    let mut flags = FdFlag::from_bits_truncate(current);
    flags.insert(FdFlag::FD_CLOEXEC);
    fcntl(stream, FcntlArg::F_SETFD(flags)).map_err(|_| ControlError::TransportFailure)?;
    Ok(())
}

#[cfg(not(unix))]
fn exchange_unix_v2(
    _path: &Path,
    _expected_uid: u32,
    _request: v2::Request,
) -> Result<v2::BrokerResponse, ControlError> {
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

fn exchange_stream_v2(
    stream: &mut impl ControlStream,
    request: v2::Request,
) -> Result<v2::BrokerResponse, ControlError> {
    let request_id = request_id_v2(request);
    let encoded = v2::encode_request(request_id, request);
    stream
        .write_all(encoded.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| ControlError::TransportFailure)?;
    stream
        .shutdown_write()
        .map_err(|_| ControlError::TransportFailure)?;

    let response_frame_size = HEADER_SIZE + v2::RESPONSE_BODY_SIZE;
    let mut response = Vec::with_capacity(response_frame_size);
    stream
        .take((response_frame_size + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|_| ControlError::TransportFailure)?;
    if response.len() != response_frame_size {
        return Err(ControlError::InvalidBrokerResponse);
    }
    v2::decode_response(
        v2::FrameHeader {
            operation: request.operation(),
            request_id,
        },
        &response,
    )
    .map_err(|_| ControlError::InvalidBrokerResponse)
}

fn request_id_v2(request: v2::Request) -> [u8; 16] {
    let encoded_request = v2::encode_request([1; 16], request);
    let digest = Sha256::new()
        .chain_update(V2_REQUEST_ID_DOMAIN)
        .chain_update(encoded_request.as_bytes())
        .finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    request_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_ci_broker_protocol::TrustClass;
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::os::unix::net::UnixListener;
    use std::thread;
    fn activation_request() -> v2::AdmitAttemptRequest {
        v2::AdmitAttemptRequest {
            signed_request_digest: [1; 32],
            actor_pubkey: [2; 32],
            audience_digest: [3; 32],
            idempotency_digest: [4; 32],
            source_pin_event_id: [5; 32],
            workflow_digest: [6; 32],
            job_intent_digest: [7; 32],
            isolation_profile_digest: [8; 32],
            lane_manifest_digest: [9; 32],
            admission_signature: [10; 64],
            run_id: [11; 16],
            tip_oid: GitOid::Sha256([12; 32]),
            base_oid: GitOid::Sha256([13; 32]),
            issued_at: 10,
            expires_at: 100,
            lane_epoch: 4,
            admission_key_generation: 9,
            wall_timeout_seconds: 50,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
            admission_signature_algorithm: v2::AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
        }
    }

    fn activation_response(request: v2::AdmitAttemptRequest) -> v2::BrokerResponse {
        v2::BrokerResponse {
            code: ResponseCode::Ok,
            retry_after_millis: 0,
            attempt_id: [14; 16],
            run_id: request.run_id,
            accepted_request_digest: request.signed_request_digest,
            job_intent_digest: request.job_intent_digest,
            execution_binding_digest: [15; 32],
            tip_oid: Some(request.tip_oid),
            broker_state: BrokerState::Leased,
            conclusion: Conclusion::None,
            terminal_reason: 0,
            generation: 2,
            accepted_at: 20,
            updated_at: 20,
            lease_generation: 1,
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
            attempt: request.attempt,
        }
    }

    #[derive(Default)]
    struct ActivationTransport {
        requests: Vec<v2::Request>,
        responses: VecDeque<v2::BrokerResponse>,
    }

    impl BrokerTransportV2 for ActivationTransport {
        fn exchange(&mut self, request: v2::Request) -> Result<v2::BrokerResponse, ControlError> {
            self.requests.push(request);
            self.responses
                .pop_front()
                .ok_or(ControlError::TransportFailure)
        }
    }

    #[test]
    fn version_two_happy_path_carries_the_exact_execd_binding_on_every_followup() {
        let request = activation_request();
        let admitted = activation_response(request);
        let mut terminal = admitted;
        terminal.broker_state = BrokerState::Terminal;
        terminal.conclusion = Conclusion::Success;
        terminal.updated_at = 30;
        terminal.evidence_set_digest = [16; 32];
        terminal.teardown_digest = [17; 32];
        let mut transport = ActivationTransport {
            responses: VecDeque::from([admitted, terminal]),
            ..ActivationTransport::default()
        };

        let lease = admit_signed_job_intent_v2(request, &mut transport).expect("v2 admission");
        assert_eq!(lease.execution_binding_digest(), [15; 32]);
        let evidence = BoundedExecutionEvidence::new(Conclusion::Success, [16; 32], 30)
            .expect("bounded evidence");
        let completed = complete_attempt_v2(lease, evidence, &mut transport).expect("completion");
        assert_eq!(completed.job_intent_digest, request.job_intent_digest);
        assert_eq!(completed.execution_binding_digest, [15; 32]);
        let v2::Request::CompleteAttempt(completion) = transport.requests[1] else {
            panic!("completion request");
        };
        assert_eq!(completion.execution_binding_digest, [15; 32]);
        assert_eq!(
            completion.signed_request_digest,
            request.signed_request_digest
        );

        let mut drifted = admitted;
        drifted.job_intent_digest[0] ^= 1;
        let mut hostile = ActivationTransport {
            responses: VecDeque::from([drifted]),
            ..ActivationTransport::default()
        };
        assert_eq!(
            admit_signed_job_intent_v2(request, &mut hostile),
            Err(ControlError::InvalidBrokerResponse)
        );
    }

    #[cfg(unix)]
    #[test]
    fn broker_descriptors_are_marked_close_on_exec() {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        use std::os::unix::net::UnixStream;

        let (_peer, stream) = UnixStream::pair().expect("socket pair");
        mark_control_stream_close_on_exec(&stream).expect("set close-on-exec");
        let flags = fcntl(&stream, FcntlArg::F_GETFD).expect("read descriptor flags");
        assert!(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));
    }

    #[test]
    fn configured_root_broker_uid_is_accepted_exactly() {
        assert_eq!(authorize_broker_peer(0, 0), Ok(()));
        assert_eq!(
            authorize_broker_peer(1, 0),
            Err(ControlError::BrokerRejected)
        );
        assert_eq!(
            authorize_broker_peer(0, 1),
            Err(ControlError::BrokerRejected)
        );
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
        let admit = activation_request();
        let request = v2::Request::AdmitAttempt(admit);
        let request_id = request_id_v2(request);
        let response = activation_response(admit);
        let encoded = v2::encode_response(
            v2::FrameHeader {
                operation: request.operation(),
                request_id,
            },
            response,
        );
        let mut stream = ScriptedStream {
            response: Cursor::new(encoded.as_bytes().to_vec()),
            written: Vec::new(),
            shutdown: false,
        };

        assert_eq!(exchange_stream_v2(&mut stream, request), Ok(response));
        assert!(stream.shutdown);
        assert_eq!(
            v2::decode_request(&stream.written)
                .expect("fixed request")
                .1,
            request
        );
    }

    #[test]
    fn unix_exchange_rejects_trailing_response_bytes() {
        let admit = activation_request();
        let request = v2::Request::AdmitAttempt(admit);
        let request_id = request_id_v2(request);
        let response = activation_response(admit);
        let encoded = v2::encode_response(
            v2::FrameHeader {
                operation: request.operation(),
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
            exchange_stream_v2(&mut stream, request),
            Err(ControlError::InvalidBrokerResponse)
        );
    }

    #[test]
    fn unix_broker_transport_authenticates_peer_before_protocol_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0; 1];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });
        assert_eq!(
            exchange_unix_v2(
                &path,
                u32::MAX,
                v2::Request::AdmitAttempt(activation_request()),
            ),
            Err(ControlError::BrokerRejected)
        );
        server.join().unwrap();
    }

    #[test]
    fn authenticated_broker_still_fails_closed_on_invalid_response() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });
        assert_eq!(
            exchange_unix_v2(
                &path,
                nix::unistd::Uid::effective().as_raw(),
                v2::Request::AdmitAttempt(activation_request()),
            ),
            Err(ControlError::TransportFailure)
        );
        server.join().unwrap();
    }

    #[test]
    fn version_two_transport_failure_is_returned() {
        struct Unavailable;
        impl BrokerTransportV2 for Unavailable {
            fn exchange(&mut self, _: v2::Request) -> Result<v2::BrokerResponse, ControlError> {
                Err(ControlError::BrokerUnavailable)
            }
        }
        assert_eq!(
            admit_signed_job_intent_v2(activation_request(), &mut Unavailable),
            Err(ControlError::BrokerUnavailable)
        );
    }
    #[test]
    fn bounded_evidence_rejects_missing_or_unsafe_fields() {
        assert_eq!(
            BoundedExecutionEvidence::new(Conclusion::None, [7; 32], 21),
            Err(ControlError::InvalidExecutionEvidence)
        );
        assert_eq!(
            BoundedExecutionEvidence::new(Conclusion::Success, [0; 32], 21),
            Err(ControlError::InvalidExecutionEvidence)
        );
        assert_eq!(
            BoundedExecutionEvidence::new(Conclusion::Success, [7; 32], 0),
            Err(ControlError::InvalidExecutionEvidence)
        );
        assert_eq!(
            BoundedExecutionEvidence::new(Conclusion::Success, [7; 32], MAX_SAFE_INTEGER + 1),
            Err(ControlError::InvalidExecutionEvidence)
        );

        let normalized = activation_request();
        let lease = validate_admitted_response_v2(normalized, activation_response(normalized))
            .expect("admitted lease");
        let before_admission =
            BoundedExecutionEvidence::new(Conclusion::Success, [7; 32], 9).expect("bounded");
        let mut transport = ActivationTransport::default();
        assert_eq!(
            complete_attempt_v2(lease, before_admission, &mut transport),
            Err(ControlError::InvalidExecutionEvidence)
        );
        assert!(transport.requests.is_empty());
    }
}
