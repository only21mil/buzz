//! Production admission, unprivileged execution, completion, and broker transport.
//!
//! The service layer supplies authenticated request data, reviewed workflow
//! policy, and manifest bindings. This module does not derive any of those
//! values from command-line strings.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use buzz_ci_broker_protocol::{
    decode_response, encode_request, AdmitAttemptRequest, BrokerResponse, BrokerState,
    CompleteAttemptRequest, Conclusion, FrameHeader, GetAttemptRequest, GitOid, Request,
    ResponseCode, TrustClass, HEADER_SIZE, MAX_SAFE_INTEGER, RESPONSE_BODY_SIZE,
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
const ADMIT_REQUEST_ID_DOMAIN: &[u8] = b"buzz-ci-runner:admit-request-id:v1\0";
const GET_REQUEST_ID_DOMAIN: &[u8] = b"buzz-ci-runner:get-request-id:v1\0";
const COMPLETE_REQUEST_ID_DOMAIN: &[u8] = b"buzz-ci-runner:complete-request-id:v1\0";

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

/// Raw workflow inputs already approved by the trusted integration layer.
///
/// The runner passes this value only to the unprivileged execution backend. It
/// is never reduced into, or exposed to, the broker protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedWorkflowInputs<T> {
    raw: T,
}

impl<T> AuthorizedWorkflowInputs<T> {
    /// Wrap workflow inputs after the trusted integration layer authorizes them.
    pub const fn new(raw: T) -> Self {
        Self { raw }
    }

    /// Borrow the authorized workflow inputs.
    pub const fn raw(&self) -> &T {
        &self.raw
    }

    /// Consume the wrapper and return the authorized workflow inputs.
    pub fn into_raw(self) -> T {
        self.raw
    }
}

/// Opaque proof of one broker-admitted ordinary execution lease.
///
/// Private fields prevent an execution backend from constructing or changing
/// the binding. Accessors expose only the identity needed to bind its evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedLease {
    signer_pubkey: [u8; 32],
    signed_request_digest: [u8; 32],
    run_id: [u8; 16],
    attempt: u32,
    job_manifest_digest: [u8; 32],
    tip_oid: GitOid,
    lease_id: [u8; 16],
    lease_generation: u64,
    accepted_at: u64,
}

impl AdmittedLease {
    /// Return the request run identifier bound at admission.
    pub const fn run_id(self) -> [u8; 16] {
        self.run_id
    }

    /// Return the request attempt number bound at admission.
    pub const fn attempt(self) -> u32 {
        self.attempt
    }

    /// Return the exact broker lease identifier.
    pub const fn lease_id(self) -> [u8; 16] {
        self.lease_id
    }

    /// Return the exact broker lease generation.
    pub const fn lease_generation(self) -> u64 {
        self.lease_generation
    }
}

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

/// Closed execution failures. Backend-specific details stay outside this API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionBackendError {
    /// No concrete artifact and job backend is configured.
    Unavailable,
    /// Execution failed before it produced terminal bounded evidence.
    Failed,
    /// Execution returned without a complete bounded evidence set.
    MissingEvidence,
    /// The trusted runner wall deadline elapsed before the process tree exited.
    DeadlineExceeded,
}

impl From<ExecutionBackendError> for ControlError {
    fn from(error: ExecutionBackendError) -> Self {
        match error {
            ExecutionBackendError::Unavailable => Self::ExecutionBackendUnavailable,
            ExecutionBackendError::Failed => Self::ExecutionFailed,
            ExecutionBackendError::MissingEvidence => Self::InvalidExecutionEvidence,
            ExecutionBackendError::DeadlineExceeded => Self::ExpiredRequest,
        }
    }
}

/// Unprivileged workflow execution seam.
pub trait ExecutionBackend<T> {
    /// Execute already-authorized raw inputs under one admitted lease.
    fn execute(
        &mut self,
        inputs: AuthorizedWorkflowInputs<T>,
        lease: &AdmittedLease,
    ) -> Result<BoundedExecutionEvidence, ExecutionBackendError>;
}

/// A broker transport accepts only canonical, fixed-width protocol values.
pub trait BrokerTransport {
    /// Send one normalized admission request.
    fn admit(&mut self, request: AdmitAttemptRequest) -> Result<BrokerResponse, ControlError>;

    /// Read the broker-owned state for one opaque admitted lease.
    fn get(&mut self, request: GetAttemptRequest) -> Result<BrokerResponse, ControlError>;

    /// Send one completion bound to the admitted lease.
    fn complete(&mut self, request: CompleteAttemptRequest)
        -> Result<BrokerResponse, ControlError>;
}

/// Execution backend that obtains the broker's bounded terminal evidence.
///
/// Version 1 performs one broker read. The contract does not define a runner
/// retry schedule, so callers reconcile a nonterminal response through
/// controld instead of spinning or inventing backoff rules here.
pub struct BrokerExecutionBackend<T> {
    transport: T,
}

impl<T> BrokerExecutionBackend<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T: BrokerTransport> ExecutionBackend<()> for BrokerExecutionBackend<T> {
    fn execute(
        &mut self,
        _inputs: AuthorizedWorkflowInputs<()>,
        lease: &AdmittedLease,
    ) -> Result<BoundedExecutionEvidence, ExecutionBackendError> {
        let response = self
            .transport
            .get(GetAttemptRequest {
                attempt_id: lease.lease_id,
            })
            .map_err(|_| ExecutionBackendError::Unavailable)?;
        validate_execution_response(*lease, response)
            .map_err(|_| ExecutionBackendError::MissingEvidence)
    }
}

fn validate_execution_response(
    lease: AdmittedLease,
    response: BrokerResponse,
) -> Result<BoundedExecutionEvidence, ControlError> {
    if !matches!(response.code, ResponseCode::Ok | ResponseCode::Existing)
        || response.retry_after_millis != 0
        || response.attempt_id != lease.lease_id
        || response.run_id != lease.run_id
        || response.accepted_request_digest != lease.signed_request_digest
        || response.job_manifest_digest != lease.job_manifest_digest
        || response.tip_oid != Some(lease.tip_oid)
        || !matches!(
            response.broker_state,
            BrokerState::Ready | BrokerState::Quarantined | BrokerState::Terminal
        )
        || response.conclusion == Conclusion::None
        || response.generation == 0
        || response.accepted_at != lease.accepted_at
        || response.updated_at < response.accepted_at
        || response.updated_at > MAX_SAFE_INTEGER
        || response.lease_generation != lease.lease_generation
        || response.evidence_set_digest == [0; 32]
        || response.attempt != lease.attempt
    {
        return Err(ControlError::InvalidBrokerResponse);
    }
    BoundedExecutionEvidence::new(
        response.conclusion,
        response.evidence_set_digest,
        response.updated_at,
    )
}

/// Authorize, reject expired input, normalize, and only then contact the broker.
pub fn admit_request(
    input: AdmitRequestInput<'_>,
    authorizer: &impl RequestAuthorizer,
    transport: &mut impl BrokerTransport,
) -> Result<AdmittedLease, ControlError> {
    let authorized = authorize_request(input.request, input.workflow_policy, authorizer)?;
    let authorized = authorized.check_expiry(input.now)?;
    let normalized = normalize_admit_request(authorized, input.binding)?;
    let response = transport.admit(normalized)?;
    validate_admitted_response(normalized, response)
}

/// Validate an admission response against the exact normalized request.
pub fn validate_admitted_response(
    request: AdmitAttemptRequest,
    response: BrokerResponse,
) -> Result<AdmittedLease, ControlError> {
    if !matches!(response.code, ResponseCode::Ok | ResponseCode::Existing) {
        return Err(ControlError::BrokerRejected);
    }
    if response.retry_after_millis != 0
        || response.attempt_id == [0; 16]
        || response.run_id != request.run_id
        || response.accepted_request_digest != request.signed_request_digest
        || response.job_manifest_digest != request.job_manifest_digest
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
        || response.lease_generation != response.generation
        || response.evidence_set_digest != [0; 32]
        || response.teardown_digest != [0; 32]
        || response.attempt != request.attempt
    {
        return Err(ControlError::InvalidBrokerResponse);
    }
    Ok(AdmittedLease {
        signer_pubkey: request.actor_pubkey,
        signed_request_digest: request.signed_request_digest,
        run_id: request.run_id,
        attempt: request.attempt,
        job_manifest_digest: request.job_manifest_digest,
        tip_oid: request.tip_oid,
        lease_id: response.attempt_id,
        lease_generation: response.lease_generation,
        accepted_at: response.accepted_at,
    })
}

/// Execute authorized inputs in the runner and complete the exact admitted lease.
pub fn execute_request<T>(
    input: AdmitRequestInput<'_>,
    workflow_inputs: AuthorizedWorkflowInputs<T>,
    authorizer: &impl RequestAuthorizer,
    transport: &mut impl BrokerTransport,
    backend: &mut impl ExecutionBackend<T>,
) -> Result<BrokerResponse, ControlError> {
    let lease = admit_request(input, authorizer, transport)?;
    let evidence = backend.execute(workflow_inputs, &lease)?;
    complete_attempt(lease, evidence, transport)
}

/// Build and send one completion for the exact admitted lease.
pub fn complete_attempt(
    lease: AdmittedLease,
    evidence: BoundedExecutionEvidence,
    transport: &mut impl BrokerTransport,
) -> Result<BrokerResponse, ControlError> {
    if evidence.terminal_at < lease.accepted_at {
        return Err(ControlError::InvalidExecutionEvidence);
    }
    let request = CompleteAttemptRequest {
        signer_pubkey: lease.signer_pubkey,
        signed_request_digest: lease.signed_request_digest,
        run_id: lease.run_id,
        attempt: lease.attempt,
        lease_id: lease.lease_id,
        lease_generation: lease.lease_generation,
        advisory_conclusion: evidence.advisory_conclusion,
        evidence_set_digest: evidence.evidence_set_digest,
        terminal_at: evidence.terminal_at,
    };
    let response = transport.complete(request)?;
    validate_completed_response(lease, request, response)
}

/// Reject a terminal broker response that is not bound to the completed lease.
pub fn validate_completed_response(
    lease: AdmittedLease,
    request: CompleteAttemptRequest,
    response: BrokerResponse,
) -> Result<BrokerResponse, ControlError> {
    if !matches!(response.code, ResponseCode::Ok | ResponseCode::Existing)
        || response.retry_after_millis != 0
        || response.attempt_id != request.lease_id
        || response.run_id != request.run_id
        || response.accepted_request_digest != request.signed_request_digest
        || response.job_manifest_digest != lease.job_manifest_digest
        || response.tip_oid != Some(lease.tip_oid)
        || !matches!(
            response.broker_state,
            BrokerState::Ready | BrokerState::Quarantined | BrokerState::Terminal
        )
        || response.conclusion == Conclusion::None
        || response.generation == 0
        || response.updated_at < response.accepted_at
        || response.updated_at < request.terminal_at
        || response.updated_at > MAX_SAFE_INTEGER
        || response.lease_generation != request.lease_generation
        || response.accepted_at != lease.accepted_at
        || response.attempt != request.attempt
    {
        return Err(ControlError::InvalidBrokerResponse);
    }
    Ok(response)
}

/// Production Unix transport bound to one configured socket and broker UID.
#[derive(Clone, Debug)]
pub struct UnixBrokerTransport {
    socket_path: PathBuf,
    expected_uid: u32,
}

impl UnixBrokerTransport {
    pub fn new(socket_path: PathBuf, expected_uid: u32) -> Self {
        Self {
            socket_path,
            expected_uid,
        }
    }
}

impl Default for UnixBrokerTransport {
    fn default() -> Self {
        Self::new(PathBuf::from(BROKER_SOCKET_PATH), 0)
    }
}

impl BrokerTransport for UnixBrokerTransport {
    fn admit(&mut self, request: AdmitAttemptRequest) -> Result<BrokerResponse, ControlError> {
        exchange_unix(
            &self.socket_path,
            self.expected_uid,
            Request::AdmitAttempt(request),
        )
    }

    fn get(&mut self, request: GetAttemptRequest) -> Result<BrokerResponse, ControlError> {
        exchange_unix(
            &self.socket_path,
            self.expected_uid,
            Request::GetAttempt(request),
        )
    }

    fn complete(
        &mut self,
        request: CompleteAttemptRequest,
    ) -> Result<BrokerResponse, ControlError> {
        exchange_unix(
            &self.socket_path,
            self.expected_uid,
            Request::CompleteAttempt(request),
        )
    }
}

#[cfg(unix)]
fn exchange_unix(
    path: &Path,
    expected_uid: u32,
    request: Request,
) -> Result<BrokerResponse, ControlError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(path).map_err(|_| ControlError::BrokerUnavailable)?;
    let credentials =
        getsockopt(&stream, PeerCredentials).map_err(|_| ControlError::TransportFailure)?;
    if expected_uid == 0 || credentials.uid() != expected_uid {
        return Err(ControlError::BrokerRejected);
    }
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|_| ControlError::TransportFailure)?;
    exchange_stream(&mut stream, request)
}

#[cfg(not(unix))]
fn exchange_unix(
    _path: &Path,
    _expected_uid: u32,
    _request: Request,
) -> Result<BrokerResponse, ControlError> {
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
    request: Request,
) -> Result<BrokerResponse, ControlError> {
    let request_id = request_id_for(request);
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

fn request_id_for(request: Request) -> [u8; 16] {
    let digest = match request {
        Request::AdmitAttempt(request) => Sha256::new()
            .chain_update(ADMIT_REQUEST_ID_DOMAIN)
            .chain_update(request.signed_request_digest)
            .finalize(),
        Request::GetAttempt(request) => Sha256::new()
            .chain_update(GET_REQUEST_ID_DOMAIN)
            .chain_update(request.attempt_id)
            .finalize(),
        Request::CompleteAttempt(request) => Sha256::new()
            .chain_update(COMPLETE_REQUEST_ID_DOMAIN)
            .chain_update(request.signer_pubkey)
            .chain_update(request.signed_request_digest)
            .chain_update(request.run_id)
            .chain_update(request.attempt.to_be_bytes())
            .chain_update(request.lease_id)
            .chain_update(request.lease_generation.to_be_bytes())
            .chain_update([request.advisory_conclusion as u8])
            .chain_update(request.evidence_set_digest)
            .chain_update(request.terminal_at.to_be_bytes())
            .finalize(),
        Request::Hello(_) | Request::CancelAttempt(_) | Request::AdmitQualification(_) => {
            unreachable!("runner transport exposes only admit, get, and complete")
        }
    };
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    request_id
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

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
        admissions: Vec<AdmitAttemptRequest>,
        gets: Vec<GetAttemptRequest>,
        completions: Vec<CompleteAttemptRequest>,
        frames: Vec<Vec<u8>>,
        admit_response: Option<BrokerResponse>,
        get_response: Option<BrokerResponse>,
        fail_admit: bool,
        fail_get: bool,
        fail_complete: bool,
    }

    impl BrokerTransport for SpyTransport {
        fn admit(&mut self, request: AdmitAttemptRequest) -> Result<BrokerResponse, ControlError> {
            self.admissions.push(request);
            let request = Request::AdmitAttempt(request);
            self.frames.push(
                encode_request(request_id_for(request), request)
                    .as_bytes()
                    .to_vec(),
            );
            if self.fail_admit {
                return Err(ControlError::TransportFailure);
            }
            Ok(self
                .admit_response
                .unwrap_or_else(|| response_for(self.admissions[0])))
        }

        fn get(&mut self, request: GetAttemptRequest) -> Result<BrokerResponse, ControlError> {
            self.gets.push(request);
            let request = Request::GetAttempt(request);
            self.frames.push(
                encode_request(request_id_for(request), request)
                    .as_bytes()
                    .to_vec(),
            );
            if self.fail_get {
                return Err(ControlError::TransportFailure);
            }
            self.get_response.ok_or(ControlError::InvalidBrokerResponse)
        }

        fn complete(
            &mut self,
            request: CompleteAttemptRequest,
        ) -> Result<BrokerResponse, ControlError> {
            self.completions.push(request);
            let request = Request::CompleteAttempt(request);
            self.frames.push(
                encode_request(request_id_for(request), request)
                    .as_bytes()
                    .to_vec(),
            );
            if self.fail_complete {
                return Err(ControlError::TransportFailure);
            }
            Ok(completion_response(self.completions[0]))
        }
    }

    #[derive(Default)]
    struct SpyBackend {
        calls: Vec<Vec<String>>,
        leases: Vec<AdmittedLease>,
        failure: Option<ExecutionBackendError>,
    }

    impl ExecutionBackend<Vec<String>> for SpyBackend {
        fn execute(
            &mut self,
            inputs: AuthorizedWorkflowInputs<Vec<String>>,
            lease: &AdmittedLease,
        ) -> Result<BoundedExecutionEvidence, ExecutionBackendError> {
            self.calls.push(inputs.into_raw());
            self.leases.push(*lease);
            if let Some(error) = self.failure {
                return Err(error);
            }
            BoundedExecutionEvidence::new(Conclusion::Success, [7; 32], 21)
                .map_err(|_| ExecutionBackendError::MissingEvidence)
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
            broker_state: BrokerState::Leased,
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

    fn completion_response(request: CompleteAttemptRequest) -> BrokerResponse {
        BrokerResponse {
            code: ResponseCode::Ok,
            retry_after_millis: 0,
            attempt_id: request.lease_id,
            run_id: request.run_id,
            accepted_request_digest: request.signed_request_digest,
            job_manifest_digest: [3; 32],
            tip_oid: Some(GitOid::Sha1([0x33; 20])),
            broker_state: BrokerState::Terminal,
            conclusion: request.advisory_conclusion,
            terminal_reason: 0,
            generation: request.lease_generation,
            accepted_at: 10,
            updated_at: request.terminal_at,
            lease_generation: request.lease_generation,
            evidence_set_digest: request.evidence_set_digest,
            teardown_digest: [8; 32],
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
        assert!(unauthorized.frames.is_empty());

        let mut unaccepted = SpyTransport::default();
        let mut unaccepted_input = input(&request);
        unaccepted_input.workflow_policy = CiWorkflowPolicy::new(None, false);
        assert_eq!(
            admit_request(unaccepted_input, &Policy(true), &mut unaccepted),
            Err(ControlError::UnacceptedTrust)
        );
        assert!(unaccepted.frames.is_empty());

        let mut fork = SpyTransport::default();
        let mut fork_input = input(&request);
        fork_input.workflow_policy =
            CiWorkflowPolicy::new(Some(TrustClass::AcceptedReviewed), true);
        assert_eq!(
            admit_request(fork_input, &Policy(true), &mut fork),
            Err(ControlError::ExternalFork)
        );
        assert!(fork.frames.is_empty());

        let mut expired = SpyTransport::default();
        let mut expired_input = input(&request);
        expired_input.now = request.expires_at;
        assert_eq!(
            admit_request(expired_input, &Policy(true), &mut expired),
            Err(ControlError::ExpiredRequest)
        );
        assert!(expired.frames.is_empty());

        let mut invalid_binding = SpyTransport::default();
        let mut invalid_input = input(&request);
        invalid_input.binding.signed_request_digest = [9; 32];
        assert_eq!(
            admit_request(invalid_input, &Policy(true), &mut invalid_binding),
            Err(ControlError::InvalidBinding)
        );
        assert!(invalid_binding.frames.is_empty());
    }

    #[test]
    fn transport_receives_canonical_admit_frame_byte_for_byte() {
        let request = request();
        let mut transport = SpyTransport::default();
        admit_request(input(&request), &Policy(true), &mut transport).expect("admitted");
        let [sent] = transport.admissions.as_slice() else {
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

        let expected_request = Request::AdmitAttempt(expected);
        let request_id = request_id_for(expected_request);
        let sent_frame = encode_request(request_id, Request::AdmitAttempt(*sent));
        let golden_frame = encode_request(request_id, expected_request);
        assert_eq!(transport.frames[0], sent_frame.as_bytes());
        assert_eq!(sent_frame.as_bytes(), golden_frame.as_bytes());
        assert_eq!(
            hex::encode(Sha256::digest(&transport.frames[0])),
            "d3dd76de6ad85d1d3e860af6e4339eb4450bf94b65fcbf340d1d2ec03a1c2e1c"
        );
    }

    #[test]
    fn admitted_response_returns_exact_bound_opaque_lease() {
        let normalized = transport_request();
        let response = response_for(normalized);
        let lease = validate_admitted_response(normalized, response).expect("bound lease");
        assert_eq!(lease.run_id(), normalized.run_id);
        assert_eq!(lease.attempt(), normalized.attempt);
        assert_eq!(lease.lease_id(), [9; 16]);
        assert_eq!(lease.lease_generation(), 1);

        let mut mismatch = response;
        mismatch.accepted_request_digest = [8; 32];
        assert_eq!(
            validate_admitted_response(normalized, mismatch),
            Err(ControlError::InvalidBrokerResponse)
        );
        let mut wrong_attempt = response;
        wrong_attempt.attempt = 2;
        assert_eq!(
            validate_admitted_response(normalized, wrong_attempt),
            Err(ControlError::InvalidBrokerResponse)
        );
        let mut missing_lease = response;
        missing_lease.attempt_id = [0; 16];
        assert_eq!(
            validate_admitted_response(normalized, missing_lease),
            Err(ControlError::InvalidBrokerResponse)
        );
        let mut generation_mismatch = response;
        generation_mismatch.lease_generation = 2;
        assert_eq!(
            validate_admitted_response(normalized, generation_mismatch),
            Err(ControlError::InvalidBrokerResponse)
        );
    }

    #[test]
    fn broker_execution_backend_maps_one_bound_terminal_poll() {
        let normalized = transport_request();
        let lease =
            validate_admitted_response(normalized, response_for(normalized)).expect("bound lease");
        let mut terminal = response_for(normalized);
        terminal.broker_state = BrokerState::Terminal;
        terminal.conclusion = Conclusion::Success;
        terminal.updated_at = 21;
        terminal.evidence_set_digest = [7; 32];
        terminal.teardown_digest = [8; 32];
        let transport = SpyTransport {
            get_response: Some(terminal),
            ..SpyTransport::default()
        };
        let mut backend = BrokerExecutionBackend::new(transport);

        let evidence = backend
            .execute(AuthorizedWorkflowInputs::new(()), &lease)
            .expect("bounded terminal evidence");
        assert_eq!(evidence.advisory_conclusion, Conclusion::Success);
        assert_eq!(evidence.evidence_set_digest, [7; 32]);
        assert_eq!(evidence.terminal_at, 21);
        let transport = backend.into_inner();
        assert_eq!(
            transport.gets,
            vec![GetAttemptRequest {
                attempt_id: lease.lease_id(),
            }]
        );
        assert_eq!(transport.frames.len(), 1);
    }

    #[test]
    fn runner_executes_raw_inputs_then_sends_exact_completion_frame() {
        let request = request();
        let raw_inputs = vec![
            "/unprivileged/work/repo".to_string(),
            "cargo test --workspace".to_string(),
        ];
        let mut transport = SpyTransport::default();
        let mut backend = SpyBackend::default();

        let response = execute_request(
            input(&request),
            AuthorizedWorkflowInputs::new(raw_inputs.clone()),
            &Policy(true),
            &mut transport,
            &mut backend,
        )
        .expect("completed");

        assert_eq!(backend.calls.as_slice(), std::slice::from_ref(&raw_inputs));
        assert_eq!(backend.leases.len(), 1);
        assert_eq!(transport.admissions.len(), 1);
        let [complete] = transport.completions.as_slice() else {
            panic!("expected one completion")
        };
        assert_eq!(complete.signer_pubkey, [0x66; 32]);
        assert_eq!(complete.signed_request_digest, [1; 32]);
        assert_eq!(complete.run_id, transport_request().run_id);
        assert_eq!(complete.attempt, 1);
        assert_eq!(complete.lease_id, [9; 16]);
        assert_eq!(complete.lease_generation, 1);
        assert_eq!(complete.advisory_conclusion, Conclusion::Success);
        assert_eq!(complete.evidence_set_digest, [7; 32]);
        assert_eq!(complete.terminal_at, 21);
        assert_eq!(response, completion_response(*complete));

        let admitted = backend.leases[0];
        let mut switched_manifest = response;
        switched_manifest.job_manifest_digest = [99; 32];
        assert_eq!(
            validate_completed_response(admitted, *complete, switched_manifest),
            Err(ControlError::InvalidBrokerResponse)
        );
        let mut switched_tip = response;
        switched_tip.tip_oid = Some(GitOid::Sha1([0x44; 20]));
        assert_eq!(
            validate_completed_response(admitted, *complete, switched_tip),
            Err(ControlError::InvalidBrokerResponse)
        );
        let mut switched_acceptance = response;
        switched_acceptance.accepted_at += 1;
        assert_eq!(
            validate_completed_response(admitted, *complete, switched_acceptance),
            Err(ControlError::InvalidBrokerResponse)
        );

        let request = Request::CompleteAttempt(*complete);
        let golden = encode_request(request_id_for(request), request);
        assert_eq!(transport.frames[1], golden.as_bytes());
        assert_eq!(
            hex::encode(Sha256::digest(&transport.frames[1])),
            "d929daa3a6b651a6efe88237754f360e02e8d68631407e9de8cbdfefc3ce928a"
        );
        for frame in &transport.frames {
            for raw in &raw_inputs {
                assert!(!frame
                    .windows(raw.len())
                    .any(|window| window == raw.as_bytes()));
            }
        }
    }

    #[test]
    fn binding_mismatch_stops_before_execution_and_completion() {
        let request = request();
        let normalized = transport_request();
        let mut mismatch = response_for(normalized);
        mismatch.job_manifest_digest = [99; 32];
        let mut transport = SpyTransport {
            admit_response: Some(mismatch),
            ..SpyTransport::default()
        };
        let mut backend = SpyBackend::default();

        assert_eq!(
            execute_request(
                input(&request),
                AuthorizedWorkflowInputs::new(vec!["raw".to_string()]),
                &Policy(true),
                &mut transport,
                &mut backend,
            ),
            Err(ControlError::InvalidBrokerResponse)
        );
        assert!(backend.calls.is_empty());
        assert!(transport.completions.is_empty());
        assert_eq!(transport.frames.len(), 1);
    }

    #[test]
    fn missing_evidence_and_transport_failures_never_forge_later_phases() {
        let request = request();

        let mut admission_failure = SpyTransport {
            fail_admit: true,
            ..SpyTransport::default()
        };
        let mut backend = SpyBackend::default();
        assert_eq!(
            execute_request(
                input(&request),
                AuthorizedWorkflowInputs::new(vec!["raw".to_string()]),
                &Policy(true),
                &mut admission_failure,
                &mut backend,
            ),
            Err(ControlError::TransportFailure)
        );
        assert!(backend.calls.is_empty());
        assert!(admission_failure.completions.is_empty());

        let mut missing = SpyBackend {
            failure: Some(ExecutionBackendError::MissingEvidence),
            ..SpyBackend::default()
        };
        let mut transport = SpyTransport::default();
        assert_eq!(
            execute_request(
                input(&request),
                AuthorizedWorkflowInputs::new(vec!["raw".to_string()]),
                &Policy(true),
                &mut transport,
                &mut missing,
            ),
            Err(ControlError::InvalidExecutionEvidence)
        );
        assert!(transport.completions.is_empty());
        assert_eq!(transport.frames.len(), 1);

        let mut completion_failure = SpyTransport {
            fail_complete: true,
            ..SpyTransport::default()
        };
        let mut backend = SpyBackend::default();
        assert_eq!(
            execute_request(
                input(&request),
                AuthorizedWorkflowInputs::new(vec!["raw".to_string()]),
                &Policy(true),
                &mut completion_failure,
                &mut backend,
            ),
            Err(ControlError::TransportFailure)
        );
        assert_eq!(backend.calls.len(), 1);
        assert_eq!(completion_failure.completions.len(), 1);
        assert_eq!(completion_failure.frames.len(), 2);
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

        let normalized = transport_request();
        let lease = validate_admitted_response(normalized, response_for(normalized))
            .expect("admitted lease");
        let before_admission =
            BoundedExecutionEvidence::new(Conclusion::Success, [7; 32], 9).expect("bounded");
        let mut transport = SpyTransport::default();
        assert_eq!(
            complete_attempt(lease, before_admission, &mut transport),
            Err(ControlError::InvalidExecutionEvidence)
        );
        assert!(transport.frames.is_empty());
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
        let admit = transport_request();
        let request = Request::AdmitAttempt(admit);
        let request_id = request_id_for(request);
        let response = response_for(admit);
        let encoded = encode_response(
            FrameHeader {
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

        assert_eq!(exchange_stream(&mut stream, request), Ok(response));
        assert!(stream.shutdown);
        assert_eq!(
            decode_request(&stream.written).expect("fixed request").1,
            request
        );
    }

    #[test]
    fn unix_exchange_rejects_trailing_response_bytes() {
        let admit = transport_request();
        let request = Request::AdmitAttempt(admit);
        let request_id = request_id_for(request);
        let response = response_for(admit);
        let encoded = encode_response(
            FrameHeader {
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
            exchange_stream(&mut stream, request),
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
            exchange_unix(
                &path,
                u32::MAX,
                Request::GetAttempt(GetAttemptRequest {
                    attempt_id: [7; 16]
                }),
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
            exchange_unix(
                &path,
                nix::unistd::Uid::effective().as_raw(),
                Request::GetAttempt(GetAttemptRequest {
                    attempt_id: [7; 16]
                }),
            ),
            Err(ControlError::TransportFailure)
        );
        server.join().unwrap();
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
