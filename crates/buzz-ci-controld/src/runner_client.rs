//! Fail-closed client for the frozen runner socket protocol.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use buzz_core::ci::{
    CiJobState, CiRequestEnvelope, CiTeardownAttestationEnvelope, CI_MAX_SAFE_INTEGER,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::manifest::CompiledJobManifest;

/// Frozen socket transport schema.
pub const RUNNER_TRANSPORT_SCHEMA_VERSION: u32 = 1;
/// Maximum accepted JSON body size.
pub const MAX_RUNNER_FRAME_BODY_BYTES: usize = 1024 * 1024;
/// Domain used by the runner to bind every non-terminal receipt frame.
pub const RECEIPT_SET_DIGEST_DOMAIN: &[u8] = b"buzz-ci-runner:receipt-set:v1\0";
const MAX_COMPLETED_CACHE_ENTRIES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum RunnerRequestWire {
    #[serde(rename = "execute_attempt")]
    ExecuteAttempt {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        request_event: CiRequestEnvelope,
        signed_request_digest: String,
        assigned_at: u64,
        deadline_at: u64,
        jobs: Vec<ExecuteJobWire>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecuteJobWire {
    job_id: String,
    attempt: u32,
    parent_attempt: u32,
    workflow_path: String,
    job_manifest: String,
    job_manifest_digest: String,
    audience_digest: String,
    isolation_profile_digest: String,
}

/// Immutable byte-identical request used for every transport retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRunnerRequest {
    dispatch_id: String,
    request_event_id: String,
    request: CiRequestEnvelope,
    assigned_at: u64,
    deadline_at: u64,
    jobs: BTreeMap<String, u32>,
    frame: Vec<u8>,
    frame_digest: String,
}

impl PreparedRunnerRequest {
    /// Return the stable dispatch UUID reused for every transport retry.
    pub fn dispatch_id(&self) -> &str {
        &self.dispatch_id
    }
    /// Return the exact framed bytes sent on every connection.
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }
    /// Return SHA-256 of the exact framed request.
    pub fn frame_digest(&self) -> &str {
        &self.frame_digest
    }

    pub(crate) fn matches_request(
        &self,
        request_event_id: &str,
        request: &CiRequestEnvelope,
    ) -> bool {
        self.request_event_id == request_event_id && self.request == *request
    }

    pub(crate) fn job_ids(&self) -> impl Iterator<Item = &str> {
        self.jobs.keys().map(String::as_str)
    }
}

/// Errors produced before any runner connection is opened.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RunnerRequestError {
    #[error("dispatch or signed request identity is invalid")]
    InvalidIdentity,
    #[error("accepted request is invalid")]
    InvalidRequest,
    #[error("assignment deadline is invalid")]
    InvalidDeadline,
    #[error("compiled jobs do not exactly match the accepted request")]
    JobMismatch,
    #[error("runner request frame exceeds the frozen bound")]
    Oversized,
    #[error("runner request serialization failed")]
    Serialization,
}

/// Build the exact version-1 `RunnerRequest` frame.
pub fn prepare_runner_request(
    dispatch_id: String,
    request_event_id: String,
    request: CiRequestEnvelope,
    signed_request_digest: String,
    assigned_at: u64,
    deadline_at: u64,
    manifests: Vec<CompiledJobManifest>,
) -> Result<PreparedRunnerRequest, RunnerRequestError> {
    if Uuid::parse_str(&dispatch_id).is_err()
        || !is_lower_hex(&request_event_id, 64)
        || !is_lower_hex(&signed_request_digest, 64)
    {
        return Err(RunnerRequestError::InvalidIdentity);
    }
    request
        .validate()
        .map_err(|_| RunnerRequestError::InvalidRequest)?;
    if assigned_at == 0
        || assigned_at > CI_MAX_SAFE_INTEGER
        || deadline_at <= assigned_at
        || deadline_at > CI_MAX_SAFE_INTEGER
        || deadline_at > request.expires_at
        || deadline_at.saturating_sub(assigned_at) > request.timeout_seconds
    {
        return Err(RunnerRequestError::InvalidDeadline);
    }
    let expected_parent = request.parent_attempt.unwrap_or(0);
    let mut wire_jobs_by_id = BTreeMap::new();
    for manifest in manifests {
        if manifest.attempt() != request.attempt
            || manifest.parent_attempt() != expected_parent
            || !request
                .job_ids
                .iter()
                .any(|job_id| job_id == manifest.job_id())
        {
            return Err(RunnerRequestError::JobMismatch);
        }
        let job_id = manifest.job_id().to_owned();
        let wire = ExecuteJobWire {
            job_id: manifest.job_id().to_owned(),
            attempt: manifest.attempt(),
            parent_attempt: manifest.parent_attempt(),
            workflow_path: manifest.workflow_path().to_owned(),
            job_manifest: manifest.job_manifest().to_owned(),
            job_manifest_digest: manifest.job_manifest_digest().to_owned(),
            audience_digest: manifest.audience_digest().to_owned(),
            isolation_profile_digest: manifest.isolation_profile_digest().to_owned(),
        };
        if wire_jobs_by_id.insert(job_id, wire).is_some() {
            return Err(RunnerRequestError::JobMismatch);
        }
    }
    let requested: BTreeSet<_> = request.job_ids.iter().cloned().collect();
    if wire_jobs_by_id.is_empty()
        || requested.len() != request.job_ids.len()
        || wire_jobs_by_id.keys().cloned().collect::<BTreeSet<_>>() != requested
    {
        return Err(RunnerRequestError::JobMismatch);
    }
    let jobs = wire_jobs_by_id
        .iter()
        .map(|(job_id, wire)| (job_id.clone(), wire.attempt))
        .collect();
    let wire_jobs = request
        .job_ids
        .iter()
        .map(|job_id| {
            wire_jobs_by_id
                .remove(job_id)
                .ok_or(RunnerRequestError::JobMismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let wire = RunnerRequestWire::ExecuteAttempt {
        schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
        dispatch_id: dispatch_id.clone(),
        request_event_id: request_event_id.clone(),
        request_event: request.clone(),
        signed_request_digest,
        assigned_at,
        deadline_at,
        jobs: wire_jobs,
    };
    let frame = encode_frame(&wire)?;
    let frame_digest = hex::encode(Sha256::digest(&frame));
    Ok(PreparedRunnerRequest {
        dispatch_id,
        request_event_id,
        request,
        assigned_at,
        deadline_at,
        jobs,
        frame,
        frame_digest,
    })
}

fn encode_frame(value: &impl Serialize) -> Result<Vec<u8>, RunnerRequestError> {
    let body = serde_json::to_vec(value).map_err(|_| RunnerRequestError::Serialization)?;
    if body.len() > MAX_RUNNER_FRAME_BODY_BYTES {
        return Err(RunnerRequestError::Oversized);
    }
    let length = u32::try_from(body.len()).map_err(|_| RunnerRequestError::Oversized)?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Runner refusal reason frozen by transport version 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// Request shape or binding was invalid.
    InvalidRequest,
    /// The accepted request signer lacked runner authority.
    Unauthorized,
    /// The accepted request expired before admission.
    Expired,
    /// A signed job manifest failed verification.
    InvalidManifest,
    /// The dispatch deadline passed before admission.
    DeadlineExceeded,
    /// The unprivileged execution backend was unavailable.
    BackendUnavailable,
    /// The privileged broker refused admission.
    BrokerRefused,
    /// Durable runner reconciliation failed closed.
    ReconciliationFailed,
}

/// Closed outcome of a runner attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    /// Every selected job and teardown proof completed.
    Completed,
    /// The attempt ended without a complete teardown-backed result.
    InfrastructureFailure,
}

/// Closed infrastructure reason reported by the runner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptFailureReason {
    /// The execution backend was unavailable.
    BackendUnavailable,
    /// The fixed executor failed to run a selected job.
    ExecutionFailed,
    /// Output or broker evidence failed validation.
    EvidenceInvalid,
    /// The attempt exceeded its bound deadline.
    DeadlineExceeded,
    /// The runner could not prove every selected lease empty.
    TeardownUnproven,
    /// Durable reconciliation failed closed.
    ReconciliationFailed,
}

/// Validated log descriptor from one job receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogEvidence {
    /// Runner-root-relative log path.
    pub relative_path: String,
    /// SHA-256 of the complete log bytes.
    pub sha256: String,
    /// Complete log byte length.
    pub byte_length: u64,
    /// Configured hard log cap.
    pub cap_bytes: u64,
    /// Whether the runner truncated the log. Validated results require false.
    pub truncated: bool,
}

/// Validated artifact descriptor from one job receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEvidence {
    /// Runner-root-relative artifact path.
    pub relative_path: String,
    /// SHA-256 of the complete artifact bytes.
    pub sha256: String,
    /// Complete artifact byte length.
    pub byte_length: u64,
    /// Declared artifact media type.
    pub media_type: String,
    /// Stable artifact name within the job.
    pub logical_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SelectedJobAttempt {
    job_id: String,
    attempt: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum RunnerReceipt {
    #[serde(rename = "accepted")]
    Accepted {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        run_id: String,
        attempt: u32,
        receipt_sequence: u64,
        accepted_at: u64,
    },
    #[serde(rename = "refused")]
    Refused {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        run_id: String,
        attempt: u32,
        receipt_sequence: u64,
        reason: RefusalReason,
    },
    #[serde(rename = "job_started")]
    JobStarted {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        run_id: String,
        attempt: u32,
        receipt_sequence: u64,
        job_id: String,
        job_attempt: u32,
        started_at: u64,
    },
    #[serde(rename = "job_finished")]
    JobFinished {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        run_id: String,
        attempt: u32,
        receipt_sequence: u64,
        job_id: String,
        job_attempt: u32,
        state: CiJobState,
        reason: Option<String>,
        started_at: u64,
        finished_at: u64,
        log: LogEvidence,
        artifacts: Vec<ArtifactEvidence>,
    },
    #[serde(rename = "attempt_finished")]
    AttemptFinished {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        run_id: String,
        attempt: u32,
        receipt_sequence: u64,
        outcome: AttemptOutcome,
        reason: Option<AttemptFailureReason>,
        finished_at: u64,
        selected_job_attempts: Vec<SelectedJobAttempt>,
        teardown_attestation: Option<CiTeardownAttestationEnvelope>,
        receipt_set_digest: String,
    },
}

impl RunnerReceipt {
    fn common(&self) -> (u32, &str, &str, &str, u32, u64) {
        match self {
            Self::Accepted {
                schema_version,
                dispatch_id,
                request_event_id,
                run_id,
                attempt,
                receipt_sequence,
                ..
            }
            | Self::Refused {
                schema_version,
                dispatch_id,
                request_event_id,
                run_id,
                attempt,
                receipt_sequence,
                ..
            }
            | Self::JobStarted {
                schema_version,
                dispatch_id,
                request_event_id,
                run_id,
                attempt,
                receipt_sequence,
                ..
            }
            | Self::JobFinished {
                schema_version,
                dispatch_id,
                request_event_id,
                run_id,
                attempt,
                receipt_sequence,
                ..
            }
            | Self::AttemptFinished {
                schema_version,
                dispatch_id,
                request_event_id,
                run_id,
                attempt,
                receipt_sequence,
                ..
            } => (
                *schema_version,
                dispatch_id,
                request_event_id,
                run_id,
                *attempt,
                *receipt_sequence,
            ),
        }
    }
}

/// One fully validated terminal job receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedJobReceipt {
    /// Static job identifier.
    pub job_id: String,
    /// Selected one-based job attempt.
    pub attempt: u32,
    /// Terminal job state.
    pub state: CiJobState,
    /// Closed executor reason when the job failed.
    pub reason: Option<String>,
    /// Runner-observed start time.
    pub started_at: u64,
    /// Runner-observed finish time.
    pub finished_at: u64,
    /// Complete, non-truncated log descriptor.
    pub log: LogEvidence,
    /// Complete artifact descriptors.
    pub artifacts: Vec<ArtifactEvidence>,
}

/// Terminal result after framing, identity, ordering, and digest validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatedRunnerResult {
    /// The runner refused the request before acceptance.
    Refused {
        /// Closed refusal reason.
        reason: RefusalReason,
    },
    /// The runner accepted and durably terminated the dispatch.
    Finished(Box<ValidatedAttemptReceipt>),
}

/// Complete validated terminal attempt receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAttemptReceipt {
    /// Closed terminal outcome.
    pub outcome: AttemptOutcome,
    /// Infrastructure reason, present only for infrastructure failure.
    pub reason: Option<AttemptFailureReason>,
    /// Runner-observed attempt finish time.
    pub finished_at: u64,
    /// Validated terminal job receipts in canonical job-ID order.
    pub jobs: Vec<ValidatedJobReceipt>,
    /// Teardown proof, present only for a completed attempt.
    pub teardown_attestation: Option<CiTeardownAttestationEnvelope>,
    /// SHA-256 binding the exact non-terminal receipt frames.
    pub receipt_set_digest: String,
}

/// Recovery action allowed for a runner client failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    /// Reconnect and resend the exact same dispatch frame.
    RetrySameDispatch,
    /// Stop. A new attempt requires an explicit control-plane decision.
    PermanentProtocolFailure,
}

/// Fail-closed runner client error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RunnerClientError {
    #[error("runner transport failed")]
    Transport,
    #[error("runner frame was truncated")]
    Truncated,
    #[error("runner frame is oversized or empty")]
    InvalidFrameLength,
    #[error("runner frame is not valid UTF-8 JSON")]
    InvalidJson,
    #[error("runner frame has duplicate or unknown fields")]
    NonCanonicalJson,
    #[error("runner receipt schema, identity, sequence, or state is invalid")]
    ReceiptMismatch,
    #[error("runner receipt-set digest is invalid")]
    ReceiptDigestMismatch,
    #[error("runner output descriptor is invalid or truncated")]
    InvalidDescriptor,
    #[error("runner replay diverged from prior bytes for the same dispatch")]
    ReplayMismatch,
    #[error("runner transport retry limit was exhausted")]
    RetryExhausted,
}

impl RunnerClientError {
    /// Return the only safe retry action for this failure.
    pub const fn failure_class(self) -> FailureClass {
        match self {
            Self::Transport | Self::Truncated | Self::RetryExhausted => {
                FailureClass::RetrySameDispatch
            }
            _ => FailureClass::PermanentProtocolFailure,
        }
    }
}

/// Factory for fresh byte streams. Each retry receives the identical request.
pub trait RunnerConnector {
    /// Fresh readable and writable connection type.
    type Connection: Read + Write;
    /// Connector-specific transport error.
    type Error;
    /// Open one fresh connection to the configured runner endpoint.
    fn connect(&mut self) -> Result<Self::Connection, Self::Error>;
}

/// Exact local runner-control endpoint binding used by the production daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixRunnerConnectorConfig {
    pub socket_path: PathBuf,
    pub runner_uid: u32,
    pub runner_gid: u32,
    pub connect_timeout_millis: u64,
    pub io_timeout_millis: u64,
}

impl UnixRunnerConnectorConfig {
    /// Reject incomplete identities, unbounded waits, and non-canonical paths.
    pub fn validate(&self) -> Result<(), UnixRunnerConnectorError> {
        if self.runner_uid == 0
            || self.runner_gid == 0
            || self.connect_timeout_millis == 0
            || self.connect_timeout_millis > 5_000
            || self.io_timeout_millis == 0
            || self.io_timeout_millis > 30_000
            || !self.socket_path.is_absolute()
            || self.socket_path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir
                        | std::path::Component::ParentDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(UnixRunnerConnectorError::InvalidConfig);
        }
        Ok(())
    }
}

/// Sanitized production runner transport failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum UnixRunnerConnectorError {
    #[error("runner connector configuration is invalid")]
    InvalidConfig,
    #[error("runner control socket is unavailable")]
    Unavailable,
    #[error("runner control socket metadata is invalid")]
    WrongSocket,
    #[error("runner service identity is invalid")]
    WrongPeer,
    #[error("runner connection timed out")]
    Timeout,
    #[error("runner returned an invalid response frame")]
    InvalidResponse,
}

/// Per-attempt connection factory for the dedicated runner-control socket.
#[derive(Clone, Debug)]
pub struct UnixRunnerConnector {
    config: UnixRunnerConnectorConfig,
}

impl UnixRunnerConnector {
    pub fn new(config: UnixRunnerConnectorConfig) -> Result<Self, UnixRunnerConnectorError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Send one immutable v2 frame, close the write half, and read one exact
    /// operation-specific response. Every retry reuses the same bytes.
    #[cfg(target_os = "linux")]
    pub fn exchange_v2_frame(
        &mut self,
        frame: &[u8],
        response_length: usize,
        transport_attempts: u32,
    ) -> Result<Vec<u8>, UnixRunnerConnectorError> {
        use std::net::Shutdown;

        if frame.is_empty()
            || frame.len() > buzz_ci_broker_protocol::v2::MAX_FRAME_SIZE
            || response_length == 0
            || response_length > buzz_ci_broker_protocol::v2::MAX_FRAME_SIZE
            || !(1..=8).contains(&transport_attempts)
        {
            return Err(UnixRunnerConnectorError::InvalidConfig);
        }
        for attempt in 1..=transport_attempts {
            let result = (|| {
                let mut stream = self.connect()?;
                stream
                    .write_all(frame)
                    .and_then(|()| stream.flush())
                    .and_then(|()| stream.shutdown(Shutdown::Write))
                    .map_err(|error| {
                        if error.kind() == io::ErrorKind::TimedOut {
                            UnixRunnerConnectorError::Timeout
                        } else {
                            UnixRunnerConnectorError::Unavailable
                        }
                    })?;
                let mut response = Vec::with_capacity(response_length);
                stream
                    .take(response_length as u64 + 1)
                    .read_to_end(&mut response)
                    .map_err(|error| {
                        if error.kind() == io::ErrorKind::TimedOut {
                            UnixRunnerConnectorError::Timeout
                        } else {
                            UnixRunnerConnectorError::Unavailable
                        }
                    })?;
                if response.len() != response_length {
                    return Err(UnixRunnerConnectorError::InvalidResponse);
                }
                Ok(response)
            })();
            match result {
                Err(UnixRunnerConnectorError::Unavailable | UnixRunnerConnectorError::Timeout)
                    if attempt < transport_attempts => {}
                other => return other,
            }
        }
        Err(UnixRunnerConnectorError::Unavailable)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn exchange_v2_frame(
        &mut self,
        _frame: &[u8],
        _response_length: usize,
        _transport_attempts: u32,
    ) -> Result<Vec<u8>, UnixRunnerConnectorError> {
        Err(UnixRunnerConnectorError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
impl RunnerConnector for UnixRunnerConnector {
    type Connection = UnixStream;
    type Error = UnixRunnerConnectorError;

    fn connect(&mut self) -> Result<Self::Connection, Self::Error> {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        use nix::unistd::getegid;

        let metadata = std::fs::symlink_metadata(&self.config.socket_path)
            .map_err(|_| UnixRunnerConnectorError::Unavailable)?;
        if !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o7777 != 0o620
            || metadata.uid() != self.config.runner_uid
            || metadata.gid() != getegid().as_raw()
        {
            return Err(UnixRunnerConnectorError::WrongSocket);
        }
        let stream = connect_unix_with_timeout(
            &self.config.socket_path,
            Duration::from_millis(self.config.connect_timeout_millis),
        )?;
        let peer = getsockopt(&stream, PeerCredentials)
            .map_err(|_| UnixRunnerConnectorError::WrongPeer)?;
        if peer.uid() != self.config.runner_uid || peer.gid() != self.config.runner_gid {
            return Err(UnixRunnerConnectorError::WrongPeer);
        }
        let timeout = Duration::from_millis(self.config.io_timeout_millis);
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|_| UnixRunnerConnectorError::Unavailable)?;
        Ok(stream)
    }
}

#[cfg(not(target_os = "linux"))]
impl RunnerConnector for UnixRunnerConnector {
    type Connection = std::io::Cursor<Vec<u8>>;
    type Error = UnixRunnerConnectorError;

    fn connect(&mut self) -> Result<Self::Connection, Self::Error> {
        Err(UnixRunnerConnectorError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn connect_unix_with_timeout(
    path: &std::path::Path,
    timeout: Duration,
) -> Result<UnixStream, UnixRunnerConnectorError> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use nix::sys::socket::{
        connect, getsockopt, socket, sockopt::SocketError, AddressFamily, SockFlag, SockType,
        UnixAddr,
    };
    use std::os::fd::{AsFd, AsRawFd};

    let descriptor = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|_| UnixRunnerConnectorError::Unavailable)?;
    let address = UnixAddr::new(path).map_err(|_| UnixRunnerConnectorError::InvalidConfig)?;
    match connect(descriptor.as_raw_fd(), &address) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINPROGRESS) => {
            let mut poll_descriptors = [PollFd::new(descriptor.as_fd(), PollFlags::POLLOUT)];
            let timeout = PollTimeout::try_from(timeout)
                .map_err(|_| UnixRunnerConnectorError::InvalidConfig)?;
            if poll(&mut poll_descriptors, timeout)
                .map_err(|_| UnixRunnerConnectorError::Unavailable)?
                == 0
            {
                return Err(UnixRunnerConnectorError::Timeout);
            }
            let socket_error = getsockopt(&descriptor, SocketError)
                .map_err(|_| UnixRunnerConnectorError::Unavailable)?;
            if socket_error != 0 {
                return Err(UnixRunnerConnectorError::Unavailable);
            }
        }
        Err(_) => return Err(UnixRunnerConnectorError::Unavailable),
    }
    let current =
        fcntl(&descriptor, FcntlArg::F_GETFL).map_err(|_| UnixRunnerConnectorError::Unavailable)?;
    let mut flags = OFlag::from_bits_truncate(current);
    flags.remove(OFlag::O_NONBLOCK);
    fcntl(&descriptor, FcntlArg::F_SETFL(flags))
        .map_err(|_| UnixRunnerConnectorError::Unavailable)?;
    Ok(UnixStream::from(descriptor))
}

#[derive(Clone)]
struct CachedTerminal {
    request_digest: String,
    result: ValidatedRunnerResult,
}

/// Idempotent runner client with bounded same-dispatch transport retries.
pub struct RunnerClient<C> {
    connector: C,
    max_transport_attempts: u32,
    completed: BTreeMap<String, CachedTerminal>,
    completed_order: VecDeque<String>,
}

impl<C: RunnerConnector> RunnerClient<C> {
    /// Create a client. At least one transport attempt is required.
    pub fn new(connector: C, max_transport_attempts: u32) -> Result<Self, RunnerClientError> {
        if max_transport_attempts == 0 {
            return Err(RunnerClientError::RetryExhausted);
        }
        Ok(Self {
            connector,
            max_transport_attempts,
            completed: BTreeMap::new(),
            completed_order: VecDeque::new(),
        })
    }

    /// Dispatch once, retrying only the byte-identical frame and rejecting divergent replay.
    pub fn execute(
        &mut self,
        request: &PreparedRunnerRequest,
    ) -> Result<ValidatedRunnerResult, RunnerClientError> {
        if let Some(cached) = self.completed.get(request.dispatch_id()) {
            if cached.request_digest != request.frame_digest() {
                return Err(RunnerClientError::ReplayMismatch);
            }
            return Ok(cached.result.clone());
        }

        let mut longest_observed = Vec::new();
        for _ in 0..self.max_transport_attempts {
            let mut connection = match self.connector.connect() {
                Ok(connection) => connection,
                Err(_) => continue,
            };
            if connection.write_all(request.frame()).is_err() || connection.flush().is_err() {
                continue;
            }
            let mut recorder = RecordingReader::new(&mut connection);
            let result = read_validated_result(&mut recorder, request);
            let observed = recorder.into_bytes();
            if !common_prefix_matches(&longest_observed, &observed) {
                return Err(RunnerClientError::ReplayMismatch);
            }
            if observed.len() > longest_observed.len() {
                longest_observed = observed;
            }
            match result {
                Ok(result) => {
                    self.cache_terminal(
                        request.dispatch_id().to_owned(),
                        request.frame_digest().to_owned(),
                        result.clone(),
                    );
                    return Ok(result);
                }
                Err(error) if error.failure_class() == FailureClass::RetrySameDispatch => {}
                Err(error) => return Err(error),
            }
        }
        Err(RunnerClientError::RetryExhausted)
    }

    /// Return the connector after tests or host composition finish.
    pub fn into_connector(self) -> C {
        self.connector
    }

    fn cache_terminal(
        &mut self,
        dispatch_id: String,
        request_digest: String,
        result: ValidatedRunnerResult,
    ) {
        if self.completed.len() == MAX_COMPLETED_CACHE_ENTRIES {
            if let Some(oldest) = self.completed_order.pop_front() {
                self.completed.remove(&oldest);
            }
        }
        self.completed_order.push_back(dispatch_id.clone());
        self.completed.insert(
            dispatch_id,
            CachedTerminal {
                request_digest,
                result,
            },
        );
    }
}

struct RecordingReader<'a, R> {
    inner: &'a mut R,
    bytes: Vec<u8>,
}

impl<'a, R> RecordingReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            bytes: Vec::new(),
        }
    }
    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl<R: Read> Read for RecordingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.bytes.extend_from_slice(&buffer[..read]);
        Ok(read)
    }
}

fn common_prefix_matches(left: &[u8], right: &[u8]) -> bool {
    let shared = left.len().min(right.len());
    left[..shared] == right[..shared]
}

struct ReceiptState {
    next_sequence: u64,
    accepted: bool,
    last_finished_at: u64,
    started: BTreeMap<String, u64>,
    finished: BTreeMap<String, ValidatedJobReceipt>,
    receipt_set_hasher: Sha256,
}

fn read_validated_result(
    reader: &mut impl Read,
    request: &PreparedRunnerRequest,
) -> Result<ValidatedRunnerResult, RunnerClientError> {
    let mut state = ReceiptState {
        next_sequence: 1,
        accepted: false,
        last_finished_at: request.assigned_at,
        started: BTreeMap::new(),
        finished: BTreeMap::new(),
        receipt_set_hasher: Sha256::new(),
    };
    state.receipt_set_hasher.update(RECEIPT_SET_DIGEST_DOMAIN);
    let maximum_frames = 2 + request.jobs.len().saturating_mul(2);
    for _ in 0..maximum_frames {
        let (frame, body) = read_raw_frame(reader)?;
        reject_duplicate_keys(&body)?;
        reject_unknown_receipt_fields(&body)?;
        let receipt: RunnerReceipt =
            serde_json::from_slice(&body).map_err(|_| RunnerClientError::InvalidJson)?;
        validate_common(&receipt, request, state.next_sequence)?;

        match receipt {
            RunnerReceipt::Accepted { accepted_at, .. } => {
                if state.next_sequence != 1 || accepted_at != request.assigned_at {
                    return Err(RunnerClientError::ReceiptMismatch);
                }
                state.accepted = true;
                state.receipt_set_hasher.update(&frame);
            }
            RunnerReceipt::Refused { reason, .. } => {
                if state.next_sequence != 1 {
                    return Err(RunnerClientError::ReceiptMismatch);
                }
                require_eof(reader)?;
                return Ok(ValidatedRunnerResult::Refused { reason });
            }
            RunnerReceipt::JobStarted {
                job_id,
                job_attempt,
                started_at,
                ..
            } => {
                if !state.accepted
                    || request.jobs.get(&job_id) != Some(&job_attempt)
                    || started_at < state.last_finished_at
                    || started_at > request.deadline_at
                    || state.started.insert(job_id, started_at).is_some()
                {
                    return Err(RunnerClientError::ReceiptMismatch);
                }
                state.receipt_set_hasher.update(&frame);
            }
            RunnerReceipt::JobFinished {
                job_id,
                job_attempt,
                state: job_state,
                reason,
                started_at,
                finished_at,
                log,
                artifacts,
                ..
            } => {
                if !state.accepted
                    || !job_state.is_terminal()
                    || request.jobs.get(&job_id) != Some(&job_attempt)
                    || state.started.get(&job_id) != Some(&started_at)
                    || finished_at < started_at
                    || finished_at > request.deadline_at
                    || reason.as_ref().is_some_and(|value| !safe_reason(value))
                    || (job_state == CiJobState::Success) != reason.is_none()
                {
                    return Err(RunnerClientError::ReceiptMismatch);
                }
                validate_descriptors(&log, &artifacts)?;
                let receipt = ValidatedJobReceipt {
                    job_id: job_id.clone(),
                    attempt: job_attempt,
                    state: job_state,
                    reason,
                    started_at,
                    finished_at,
                    log,
                    artifacts,
                };
                if state.finished.insert(job_id, receipt).is_some() {
                    return Err(RunnerClientError::ReceiptMismatch);
                }
                state.last_finished_at = finished_at;
                state.receipt_set_hasher.update(&frame);
            }
            RunnerReceipt::AttemptFinished {
                outcome,
                reason,
                finished_at,
                selected_job_attempts,
                teardown_attestation,
                receipt_set_digest,
                ..
            } => {
                if !state.accepted
                    || finished_at < state.last_finished_at
                    || finished_at > request.deadline_at
                    || !is_lower_hex(&receipt_set_digest, 64)
                    || receipt_set_digest != hex::encode(state.receipt_set_hasher.finalize())
                {
                    return Err(RunnerClientError::ReceiptDigestMismatch);
                }
                let selected = validate_selected(&selected_job_attempts, &state.finished)?;
                match outcome {
                    AttemptOutcome::Completed => {
                        if reason.is_some()
                            || selected.len() != request.jobs.len()
                            || selected != request.jobs
                        {
                            return Err(RunnerClientError::ReceiptMismatch);
                        }
                        let teardown = teardown_attestation
                            .as_ref()
                            .ok_or(RunnerClientError::ReceiptMismatch)?;
                        let selected_pairs: Vec<_> = selected.into_iter().collect();
                        teardown
                            .validate_context(
                                &request.request_event_id,
                                &request.request,
                                &selected_pairs,
                            )
                            .map_err(|_| RunnerClientError::ReceiptMismatch)?;
                    }
                    AttemptOutcome::InfrastructureFailure => {
                        if reason.is_none() || teardown_attestation.is_some() {
                            return Err(RunnerClientError::ReceiptMismatch);
                        }
                    }
                }
                let jobs = state.finished.into_values().collect();
                require_eof(reader)?;
                return Ok(ValidatedRunnerResult::Finished(Box::new(
                    ValidatedAttemptReceipt {
                        outcome,
                        reason,
                        finished_at,
                        jobs,
                        teardown_attestation,
                        receipt_set_digest,
                    },
                )));
            }
        }
        state.next_sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or(RunnerClientError::ReceiptMismatch)?;
    }
    Err(RunnerClientError::ReceiptMismatch)
}

fn validate_common(
    receipt: &RunnerReceipt,
    request: &PreparedRunnerRequest,
    expected_sequence: u64,
) -> Result<(), RunnerClientError> {
    let (schema, dispatch_id, request_event_id, run_id, attempt, sequence) = receipt.common();
    if schema != RUNNER_TRANSPORT_SCHEMA_VERSION
        || dispatch_id != request.dispatch_id
        || request_event_id != request.request_event_id
        || run_id != request.request.run_id
        || attempt != request.request.attempt
        || sequence != expected_sequence
    {
        return Err(RunnerClientError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_selected(
    selected: &[SelectedJobAttempt],
    finished: &BTreeMap<String, ValidatedJobReceipt>,
) -> Result<BTreeMap<String, u32>, RunnerClientError> {
    let mut result = BTreeMap::new();
    for item in selected {
        if item.attempt == 0
            || finished.get(&item.job_id).map(|job| job.attempt) != Some(item.attempt)
            || result.insert(item.job_id.clone(), item.attempt).is_some()
        {
            return Err(RunnerClientError::ReceiptMismatch);
        }
    }
    if result.len() != finished.len() {
        return Err(RunnerClientError::ReceiptMismatch);
    }
    Ok(result)
}

fn validate_descriptors(
    log: &LogEvidence,
    artifacts: &[ArtifactEvidence],
) -> Result<(), RunnerClientError> {
    if !safe_relative_path(&log.relative_path)
        || !is_lower_hex(&log.sha256, 64)
        || log.cap_bytes == 0
        || log.cap_bytes > CI_MAX_SAFE_INTEGER
        || log.byte_length > log.cap_bytes
        || log.truncated
    {
        return Err(RunnerClientError::InvalidDescriptor);
    }
    let mut paths = HashSet::from([log.relative_path.as_str()]);
    let mut logical_names = HashSet::new();
    for artifact in artifacts {
        if !safe_relative_path(&artifact.relative_path)
            || !is_lower_hex(&artifact.sha256, 64)
            || artifact.byte_length > CI_MAX_SAFE_INTEGER
            || artifact.media_type.is_empty()
            || artifact.media_type.len() > 255
            || artifact.logical_name.is_empty()
            || artifact.logical_name.len() > 255
            || artifact.media_type.contains(['\0', '\r', '\n'])
            || artifact.logical_name.contains(['\0', '\r', '\n'])
            || !paths.insert(&artifact.relative_path)
            || !logical_names.insert(&artifact.logical_name)
        {
            return Err(RunnerClientError::InvalidDescriptor);
        }
    }
    Ok(())
}

fn safe_reason(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn safe_relative_path(value: &str) -> bool {
    let mut components = value.split('/');
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains(['\0', '\r', '\n', '\\'])
        && components.all(|part| !part.is_empty() && part != "." && part != "..")
}

fn read_raw_frame(reader: &mut impl Read) -> Result<(Vec<u8>, Vec<u8>), RunnerClientError> {
    let mut prefix = [0_u8; 4];
    read_exact(reader, &mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_RUNNER_FRAME_BODY_BYTES {
        return Err(RunnerClientError::InvalidFrameLength);
    }
    let mut body = vec![0_u8; length];
    read_exact(reader, &mut body)?;
    std::str::from_utf8(&body).map_err(|_| RunnerClientError::InvalidJson)?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(&body);
    Ok((frame, body))
}

fn read_exact(reader: &mut impl Read, buffer: &mut [u8]) -> Result<(), RunnerClientError> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            RunnerClientError::Truncated
        } else {
            RunnerClientError::Transport
        }
    })
}

fn require_eof(reader: &mut impl Read) -> Result<(), RunnerClientError> {
    let mut byte = [0_u8; 1];
    match reader.read(&mut byte) {
        Ok(0) => Ok(()),
        Ok(_) => Err(RunnerClientError::ReceiptMismatch),
        Err(_) => Err(RunnerClientError::Transport),
    }
}

fn reject_unknown_receipt_fields(body: &[u8]) -> Result<(), RunnerClientError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| RunnerClientError::InvalidJson)?;
    let object = value
        .as_object()
        .ok_or(RunnerClientError::NonCanonicalJson)?;
    let kind = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or(RunnerClientError::NonCanonicalJson)?;
    match kind {
        "accepted" => exact_keys(
            object,
            &[
                "type",
                "schema_version",
                "dispatch_id",
                "request_event_id",
                "run_id",
                "attempt",
                "receipt_sequence",
                "accepted_at",
            ],
        ),
        "refused" => exact_keys(
            object,
            &[
                "type",
                "schema_version",
                "dispatch_id",
                "request_event_id",
                "run_id",
                "attempt",
                "receipt_sequence",
                "reason",
            ],
        ),
        "job_started" => exact_keys(
            object,
            &[
                "type",
                "schema_version",
                "dispatch_id",
                "request_event_id",
                "run_id",
                "attempt",
                "receipt_sequence",
                "job_id",
                "job_attempt",
                "started_at",
            ],
        ),
        "job_finished" => {
            allowed_keys(
                object,
                &[
                    "type",
                    "schema_version",
                    "dispatch_id",
                    "request_event_id",
                    "run_id",
                    "attempt",
                    "receipt_sequence",
                    "job_id",
                    "job_attempt",
                    "state",
                    "started_at",
                    "finished_at",
                    "log",
                    "artifacts",
                ],
                &[
                    "type",
                    "schema_version",
                    "dispatch_id",
                    "request_event_id",
                    "run_id",
                    "attempt",
                    "receipt_sequence",
                    "job_id",
                    "job_attempt",
                    "state",
                    "reason",
                    "started_at",
                    "finished_at",
                    "log",
                    "artifacts",
                ],
            )?;
            if object.get("reason").is_some_and(serde_json::Value::is_null) {
                return Err(RunnerClientError::NonCanonicalJson);
            }
            exact_nested_keys(
                object.get("log"),
                &[
                    "relative_path",
                    "sha256",
                    "byte_length",
                    "cap_bytes",
                    "truncated",
                ],
            )?;
            exact_array_keys(
                object.get("artifacts"),
                &[
                    "relative_path",
                    "sha256",
                    "byte_length",
                    "media_type",
                    "logical_name",
                ],
            )
        }
        "attempt_finished" => {
            allowed_keys(
                object,
                &[
                    "type",
                    "schema_version",
                    "dispatch_id",
                    "request_event_id",
                    "run_id",
                    "attempt",
                    "receipt_sequence",
                    "outcome",
                    "finished_at",
                    "selected_job_attempts",
                    "receipt_set_digest",
                ],
                &[
                    "type",
                    "schema_version",
                    "dispatch_id",
                    "request_event_id",
                    "run_id",
                    "attempt",
                    "receipt_sequence",
                    "outcome",
                    "reason",
                    "finished_at",
                    "selected_job_attempts",
                    "teardown_attestation",
                    "receipt_set_digest",
                ],
            )?;
            match object.get("outcome").and_then(serde_json::Value::as_str) {
                Some("completed")
                    if !object.contains_key("reason")
                        && object
                            .get("teardown_attestation")
                            .is_some_and(|value| !value.is_null()) => {}
                Some("infrastructure_failure")
                    if object.get("reason").is_some_and(|value| !value.is_null())
                        && !object.contains_key("teardown_attestation") => {}
                _ => return Err(RunnerClientError::NonCanonicalJson),
            }
            exact_array_keys(object.get("selected_job_attempts"), &["job_id", "attempt"])?;
            if let Some(teardown) = object
                .get("teardown_attestation")
                .filter(|value| !value.is_null())
            {
                let teardown = teardown
                    .as_object()
                    .ok_or(RunnerClientError::NonCanonicalJson)?;
                exact_keys(
                    teardown,
                    &[
                        "schema_version",
                        "request_event_id",
                        "run_id",
                        "workflow_id",
                        "target_repo_a",
                        "tip_oid",
                        "base_oid",
                        "workflow_digest",
                        "attempt",
                        "leases",
                        "lease_empty",
                        "teardown_at",
                        "relay_signer",
                    ],
                )?;
                exact_array_keys(teardown.get("leases"), &["job_id", "attempt", "lease_id"])?;
            }
            Ok(())
        }
        _ => Err(RunnerClientError::NonCanonicalJson),
    }
}

fn exact_nested_keys(
    value: Option<&serde_json::Value>,
    keys: &[&str],
) -> Result<(), RunnerClientError> {
    exact_keys(
        value
            .and_then(serde_json::Value::as_object)
            .ok_or(RunnerClientError::NonCanonicalJson)?,
        keys,
    )
}

fn exact_array_keys(
    value: Option<&serde_json::Value>,
    keys: &[&str],
) -> Result<(), RunnerClientError> {
    let values = value
        .and_then(serde_json::Value::as_array)
        .ok_or(RunnerClientError::NonCanonicalJson)?;
    for value in values {
        exact_nested_keys(Some(value), keys)?;
    }
    Ok(())
}

fn exact_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Result<(), RunnerClientError> {
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(RunnerClientError::NonCanonicalJson);
    }
    Ok(())
}

fn allowed_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    required: &[&str],
    allowed: &[&str],
) -> Result<(), RunnerClientError> {
    if required.iter().any(|key| !object.contains_key(*key))
        || object.keys().any(|key| !allowed.contains(&key.as_str()))
    {
        return Err(RunnerClientError::NonCanonicalJson);
    }
    Ok(())
}

fn reject_duplicate_keys(body: &[u8]) -> Result<(), RunnerClientError> {
    serde_json::from_slice::<UniqueJsonValue>(body)
        .map(|_| ())
        .map_err(|_| RunnerClientError::NonCanonicalJson)
}

struct UniqueJsonValue;

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }
    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }
    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        UniqueJsonValue::deserialize(deserializer)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        while sequence.next_element::<UniqueJsonValue>()?.is_some() {}
        Ok(UniqueJsonValue)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            map.next_value::<UniqueJsonValue>()?;
        }
        Ok(UniqueJsonValue)
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    struct NeverConnect;

    impl RunnerConnector for NeverConnect {
        type Connection = Cursor<Vec<u8>>;
        type Error = ();

        fn connect(&mut self) -> Result<Self::Connection, Self::Error> {
            Err(())
        }
    }

    #[test]
    fn completed_cache_is_fixed_capacity_fifo() {
        let mut client = RunnerClient::new(NeverConnect, 1).expect("client");
        for index in 0..=MAX_COMPLETED_CACHE_ENTRIES {
            client.cache_terminal(
                format!("dispatch-{index}"),
                format!("digest-{index}"),
                ValidatedRunnerResult::Refused {
                    reason: RefusalReason::InvalidRequest,
                },
            );
        }

        assert_eq!(client.completed.len(), MAX_COMPLETED_CACHE_ENTRIES);
        assert_eq!(client.completed_order.len(), MAX_COMPLETED_CACHE_ENTRIES);
        assert!(!client.completed.contains_key("dispatch-0"));
        assert_eq!(
            client.completed_order.front().map(String::as_str),
            Some("dispatch-1")
        );
        assert!(client
            .completed
            .contains_key(&format!("dispatch-{MAX_COMPLETED_CACHE_ENTRIES}")));
    }
}
