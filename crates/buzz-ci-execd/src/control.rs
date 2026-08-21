//! Linux Unix-socket control transport for the privileged broker.
//!
//! The transport accepts one systemd-owned listener and one fixed-width frame
//! per connection. It verifies the peer UID before reading any request bytes.

use std::{
    env,
    fs::File,
    io::{self, Read},
    os::fd::AsRawFd,
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use buzz_ci_broker_protocol::{
    decode_request, decode_request_header, encode_response, AdmitAttemptRequest, BrokerResponse,
    BrokerState, Conclusion, FrameHeader, QualificationRequest, Request, ResponseCode, HEADER_SIZE,
    MAX_BODY_SIZE,
};
use nix::{
    sys::socket::{
        getsockname, getsockopt, sockopt::AcceptConn, sockopt::PeerCredentials, sockopt::SockType,
        SockType as NixSockType, UnixAddr,
    },
    unistd::write,
};
use thiserror::Error;

use crate::activation::{
    ActivationController, AdmissionError, LeaseToken, OrdinaryAdmission, QualificationLease,
    VerifiedSigner,
};
use crate::qualification_host::{
    QualificationHostExecution, QualificationHostOutcome, QualificationHostPlan,
};

const CONTROL_ACCOUNT: &str = "buzzci-ctl";
const CONTROL_ACCOUNT_UID: u32 = 961;
const CONTROL_ACCOUNT_HOME: &str = "/var/lib/buzzci/principals/ctl";
const CONTROL_ACCOUNT_SHELL: &str = "/usr/sbin/nologin";
const SYSTEMD_FD_NAME: &str = "buzz-ci-execd";
pub const EXECD_SOCKET_PATH: &str = "/run/buzzci/execd.sock";
const PASSWD_PATH: &str = "/etc/passwd";
const MAX_PASSWD_BYTES: u64 = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// A refused or failed control connection.
#[derive(Debug, Error)]
pub enum ControlError {
    /// Socket activation did not supply the exact listener contract.
    #[error("invalid systemd socket activation: {0}")]
    Activation(&'static str),
    /// The dedicated control account is absent or unsafe.
    #[error("invalid control account: {0}")]
    Account(&'static str),
    /// The connected process does not own the dedicated control UID.
    #[error("peer UID refused")]
    UnauthorizedPeer,
    /// The peer did not send exactly one canonical fixed-width frame.
    #[error("request frame refused: {0}")]
    Frame(&'static str),
    /// The inherited listener failed while accepting a connection.
    #[error("control accept failed: {0}")]
    Accept(#[source] io::Error),
    /// Local Unix-socket I/O failed or timed out.
    #[error("control I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Result of the service-owned signature and activation-coordinate boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionBoundaryError {
    /// The request does not carry a verified accepted signer.
    Unauthorized,
    /// The request cannot be bound to exact activation coordinates.
    InvalidCoordinates,
    /// Durable activation state or another required service fact is unavailable.
    Unavailable,
}

/// Trusted adapter required before a wire admission may reach activation state.
///
/// Implementations must verify the signed request and load exact durable host,
/// nonce, and lease facts. A decoded `actor_pubkey` alone is not a
/// [`crate::activation::VerifiedSigner`].
pub trait OrdinaryAdmissionBoundary {
    /// Convert one decoded wire request into verified activation input.
    fn authorize(
        &mut self,
        header: FrameHeader,
        request: AdmitAttemptRequest,
    ) -> Result<OrdinaryAdmission, AdmissionBoundaryError>;

    /// Encode the service-owned durable identity of an admitted lease.
    ///
    /// `LeaseToken` is opaque so this adapter cannot bypass the controller.
    fn admitted_response(
        &mut self,
        header: FrameHeader,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        now: u64,
    ) -> BrokerResponse;
}

/// Service-owned authentication and execution boundary for qualification.
///
/// The wire signer is only a claim. Implementations authenticate the dedicated
/// control principal and load the exact root permit before returning a signer.
pub trait QualificationAdmissionBoundary {
    /// Authenticate the fixed qualification control path independently of the
    /// claimed signer carried in `request`.
    fn authenticate(
        &mut self,
        header: FrameHeader,
        request: QualificationRequest,
    ) -> Result<VerifiedSigner, AdmissionBoundaryError>;

    /// Execute the admitted qualification lease and encode its bounded result.
    /// A teardown-failure directive must yield infrastructure failure and must
    /// never authorize publication.
    fn admitted_response(
        &mut self,
        header: FrameHeader,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> BrokerResponse;

    /// Execute only the closed teardown-failure plan inside root execd.
    /// Every production boundary must provide this path explicitly.
    fn execute_teardown_failure(
        &mut self,
        plan: QualificationHostPlan,
    ) -> QualificationHostExecution;
}

/// Dispatches one already authenticated and decoded control request.
///
/// The qualification lane extends this seam with its dedicated fixed frame.
pub trait ControlDispatch {
    /// Return exactly one bounded protocol response.
    fn dispatch(&mut self, header: FrameHeader, request: Request, now: u64) -> BrokerResponse;
}

/// Ordinary admission dispatcher backed by the activation state machine.
pub struct ActivationDispatch<A, Q> {
    controller: ActivationController,
    ordinary_boundary: A,
    qualification_boundary: Q,
}

impl<A, Q> ActivationDispatch<A, Q> {
    /// Install service-restored activation state and its verification boundary.
    pub fn new(
        controller: ActivationController,
        ordinary_boundary: A,
        qualification_boundary: Q,
    ) -> Self {
        Self {
            controller,
            ordinary_boundary,
            qualification_boundary,
        }
    }
}

impl<A: OrdinaryAdmissionBoundary, Q: QualificationAdmissionBoundary> ControlDispatch
    for ActivationDispatch<A, Q>
{
    fn dispatch(&mut self, header: FrameHeader, request: Request, now: u64) -> BrokerResponse {
        match request {
            Request::AdmitAttempt(request) => {
                let admission = match self.ordinary_boundary.authorize(header, request) {
                    Ok(admission) => admission,
                    Err(AdmissionBoundaryError::Unavailable) => {
                        return response(ResponseCode::NotProvisioned, now)
                    }
                    Err(
                        AdmissionBoundaryError::Unauthorized
                        | AdmissionBoundaryError::InvalidCoordinates,
                    ) => return response(ResponseCode::PolicyDenied, now),
                };
                match self.controller.admit_ordinary(admission, now) {
                    Ok(lease) => self
                        .ordinary_boundary
                        .admitted_response(header, request, admission, lease, now),
                    Err(error) => response(admission_error_code(error), now),
                }
            }
            Request::AdmitQualification(request) => {
                let signer = match self.qualification_boundary.authenticate(header, request) {
                    Ok(signer) => signer,
                    Err(AdmissionBoundaryError::Unavailable) => {
                        return response(ResponseCode::NotProvisioned, now)
                    }
                    Err(
                        AdmissionBoundaryError::Unauthorized
                        | AdmissionBoundaryError::InvalidCoordinates,
                    ) => return response(ResponseCode::PolicyDenied, now),
                };
                match self
                    .controller
                    .admit_qualification_request(request, signer, now)
                {
                    Ok(lease) => match lease.directive() {
                        None => self
                            .qualification_boundary
                            .admitted_response(header, request, lease, now),
                        Some(buzz_ci_broker_protocol::QualificationDirective::TeardownFailure) => {
                            let plan = QualificationHostPlan::from_admitted(request, lease).ok();
                            let outcome = plan.map(|plan| {
                                QualificationHostOutcome::evaluate(
                                    plan,
                                    self.qualification_boundary.execute_teardown_failure(plan),
                                )
                            });
                            let cleanup_state =
                                self.controller.finish_qualification_teardown_failure(lease);
                            qualification_teardown_response(
                                request,
                                lease,
                                outcome.filter(|_| cleanup_state.is_ok()),
                                now,
                            )
                        }
                    },
                    Err(error) => response(admission_error_code(error), now),
                }
            }
            Request::Hello(_) => response(ResponseCode::NotProvisioned, now),
            Request::CancelAttempt(_) | Request::GetAttempt(_) => {
                response(ResponseCode::NotFound, now)
            }
        }
    }
}

/// Runtime dispatcher used until the durable activation adapter is installed.
pub struct ClosedDispatch;

impl ClosedDispatch {
    /// Construct the zero-capacity runtime dispatcher.
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ClosedDispatch {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlDispatch for ClosedDispatch {
    fn dispatch(&mut self, _header: FrameHeader, request: Request, now: u64) -> BrokerResponse {
        match request {
            Request::CancelAttempt(_) | Request::GetAttempt(_) => {
                response(ResponseCode::NotFound, now)
            }
            Request::Hello(_) | Request::AdmitAttempt(_) | Request::AdmitQualification(_) => {
                response(ResponseCode::NotProvisioned, now)
            }
        }
    }
}

/// Single-threaded control server over one inherited listener.
pub struct ControlServer<D> {
    listener: UnixListener,
    expected_peer_uid: u32,
    dispatch: D,
    io_timeout: Duration,
}

impl<D: ControlDispatch> ControlServer<D> {
    /// Construct a server over a previously validated listener.
    pub fn new(listener: UnixListener, expected_peer_uid: u32, dispatch: D) -> Self {
        Self {
            listener,
            expected_peer_uid,
            dispatch,
            io_timeout: IO_TIMEOUT,
        }
    }

    /// Accept and process one connection. The caller owns loop policy.
    pub fn serve_once(&mut self) -> Result<(), ControlError> {
        let (stream, _) = self.listener.accept().map_err(ControlError::Accept)?;
        serve_stream(
            stream,
            self.expected_peer_uid,
            self.io_timeout,
            &mut self.dispatch,
        )
    }
}

/// Validate systemd's process-local environment before fd 3 is adopted.
pub fn validate_systemd_environment() -> Result<(), ControlError> {
    let listen_pid = parse_env_u32("LISTEN_PID")?;
    if listen_pid != process::id() {
        return Err(ControlError::Activation(
            "LISTEN_PID does not match this process",
        ));
    }
    if parse_env_u32("LISTEN_FDS")? != 1 {
        return Err(ControlError::Activation("LISTEN_FDS must equal one"));
    }
    if env::var("LISTEN_FDNAMES").as_deref() != Ok(SYSTEMD_FD_NAME) {
        return Err(ControlError::Activation(
            "LISTEN_FDNAMES does not identify buzz-ci-execd",
        ));
    }
    Ok(())
}

/// Validate the sole listener after the binary adopts systemd fd 3.
pub fn validate_systemd_listener(listener: UnixListener) -> Result<UnixListener, ControlError> {
    if getsockopt(&listener, SockType).map_err(nix_io)? != NixSockType::Stream {
        return Err(ControlError::Activation("fd 3 is not a stream socket"));
    }
    if !getsockopt(&listener, AcceptConn).map_err(nix_io)? {
        return Err(ControlError::Activation("fd 3 is not listening"));
    }
    let address = getsockname::<UnixAddr>(listener.as_raw_fd())
        .map_err(nix_io)
        .map_err(ControlError::Io)?;
    if address.path() != Some(Path::new(EXECD_SOCKET_PATH)) {
        return Err(ControlError::Activation(
            "fd 3 is not the fixed execd socket",
        ));
    }

    Ok(listener)
}

/// Resolve the fixed service account used for control-plane peer checks.
pub fn control_account_uid() -> Result<u32, ControlError> {
    let file = File::open(PASSWD_PATH)
        .map_err(|_| ControlError::Account("local account database is unavailable"))?;
    let mut bytes = Vec::new();
    file.take(MAX_PASSWD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ControlError::Account("local account database read failed"))?;
    if bytes.len() as u64 > MAX_PASSWD_BYTES {
        return Err(ControlError::Account("local account database is oversized"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ControlError::Account("local account database is not UTF-8"))?;
    parse_control_account(text)
}

fn parse_control_account(text: &str) -> Result<u32, ControlError> {
    let mut matches = text
        .lines()
        .filter(|line| line.split(':').next() == Some(CONTROL_ACCOUNT));
    let line = matches
        .next()
        .ok_or(ControlError::Account("buzzci-ctl account is absent"))?;
    if matches.next().is_some() {
        return Err(ControlError::Account("buzzci-ctl account is duplicated"));
    }
    let fields: Vec<_> = line.split(':').collect();
    if fields.len() != 7 {
        return Err(ControlError::Account("buzzci-ctl account shape is invalid"));
    }
    let uid =
        parse_canonical_u32(fields[2]).ok_or(ControlError::Account("buzzci-ctl UID is invalid"))?;
    let gid =
        parse_canonical_u32(fields[3]).ok_or(ControlError::Account("buzzci-ctl GID is invalid"))?;
    if uid != CONTROL_ACCOUNT_UID || gid != CONTROL_ACCOUNT_UID {
        return Err(ControlError::Account(
            "buzzci-ctl identity does not match the deployment contract",
        ));
    }
    if fields[5] != CONTROL_ACCOUNT_HOME || fields[6] != CONTROL_ACCOUNT_SHELL {
        return Err(ControlError::Account("buzzci-ctl login posture is invalid"));
    }
    Ok(uid)
}

fn serve_stream<D: ControlDispatch>(
    stream: UnixStream,
    expected_peer_uid: u32,
    timeout: Duration,
    dispatch: &mut D,
) -> Result<(), ControlError> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let peer_uid = getsockopt(&stream, PeerCredentials).map_err(nix_io)?.uid();
    authorize_peer_uid(peer_uid, expected_peer_uid)?;
    serve_verified_stream(stream, dispatch)
}

fn serve_verified_stream<D: ControlDispatch>(
    stream: UnixStream,
    dispatch: &mut D,
) -> Result<(), ControlError> {
    serve_verified_stream_mode(stream, dispatch, true)
}

fn serve_verified_stream_mode<D: ControlDispatch>(
    mut stream: UnixStream,
    dispatch: &mut D,
    require_write_shutdown: bool,
) -> Result<(), ControlError> {
    let mut frame = [0_u8; HEADER_SIZE + MAX_BODY_SIZE];
    read_exact_frame_part(&mut stream, &mut frame[..HEADER_SIZE], "short header")?;
    let (header, body_size) = decode_request_header(&frame[..HEADER_SIZE])
        .map_err(|_| ControlError::Frame("malformed header"))?;
    let frame_size = HEADER_SIZE + body_size;
    read_exact_frame_part(
        &mut stream,
        &mut frame[HEADER_SIZE..frame_size],
        "short body",
    )?;
    if require_write_shutdown {
        let mut trailing = [0_u8; 1];
        match stream.read(&mut trailing) {
            Ok(0) => {}
            Ok(_) => return Err(ControlError::Frame("trailing bytes")),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ControlError::Frame("missing write shutdown"))
            }
            Err(error) => return Err(ControlError::Io(error)),
        }
    }
    let (decoded_header, request) =
        decode_request(&frame[..frame_size]).map_err(|_| ControlError::Frame("malformed body"))?;
    debug_assert_eq!(decoded_header, header);
    let response = dispatch.dispatch(header, request, unix_now()?);
    write_all_fd(&stream, encode_response(header, response).as_bytes())?;
    Ok(())
}

fn authorize_peer_uid(peer_uid: u32, expected_peer_uid: u32) -> Result<(), ControlError> {
    if peer_uid == expected_peer_uid {
        Ok(())
    } else {
        Err(ControlError::UnauthorizedPeer)
    }
}

fn write_all_fd(fd: &impl std::os::fd::AsFd, mut input: &[u8]) -> Result<(), ControlError> {
    while !input.is_empty() {
        match write(fd, input) {
            Ok(0) => return Err(ControlError::Io(io::ErrorKind::WriteZero.into())),
            Ok(count) => input = &input[count..],
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(ControlError::Io(nix_io(error))),
        }
    }
    Ok(())
}

fn read_exact_frame_part(
    stream: &mut UnixStream,
    output: &mut [u8],
    short_reason: &'static str,
) -> Result<(), ControlError> {
    let mut read = 0;
    while read < output.len() {
        match stream.read(&mut output[read..]) {
            Ok(0) => return Err(ControlError::Frame(short_reason)),
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(ControlError::Io(error)),
        }
    }
    Ok(())
}

fn parse_env_u32(key: &'static str) -> Result<u32, ControlError> {
    let value = env::var(key)
        .map_err(|_| ControlError::Activation("required variable is absent or non-Unicode"))?;
    parse_canonical_u32(&value).ok_or(ControlError::Activation(
        "required variable is not a canonical integer",
    ))
}

fn parse_canonical_u32(value: &str) -> Option<u32> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}

fn unix_now() -> Result<u64, ControlError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ControlError::Frame("system clock predates Unix epoch"))
}

fn nix_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn admission_error_code(error: AdmissionError) -> ResponseCode {
    match error {
        AdmissionError::Replay => ResponseCode::ReplayConflict,
        AdmissionError::RateLimit | AdmissionError::ConcurrencyLimit => ResponseCode::NoCapacity,
        AdmissionError::QualificationOnly | AdmissionError::NotReady => {
            ResponseCode::NotProvisioned
        }
        AdmissionError::ExpiredNonce
        | AdmissionError::UnauthorizedSigner
        | AdmissionError::UnacceptedTrustClass
        | AdmissionError::CoordinateMismatch
        | AdmissionError::InvalidNonce => ResponseCode::PolicyDenied,
        AdmissionError::GenerationExhausted => ResponseCode::InternalFailure,
    }
}

fn response(code: ResponseCode, now: u64) -> BrokerResponse {
    BrokerResponse {
        code,
        retry_after_millis: 0,
        attempt_id: [0; 16],
        run_id: [0; 16],
        accepted_request_digest: [0; 32],
        job_manifest_digest: [0; 32],
        tip_oid: None,
        broker_state: BrokerState::Reconciling,
        conclusion: Conclusion::None,
        terminal_reason: 0,
        generation: 0,
        accepted_at: 0,
        updated_at: now,
        lease_generation: 0,
        evidence_set_digest: [0; 32],
        teardown_digest: [0; 32],
        attempt: 0,
    }
}

fn qualification_teardown_response(
    request: QualificationRequest,
    lease: QualificationLease,
    outcome: Option<QualificationHostOutcome>,
    now: u64,
) -> BrokerResponse {
    let complete = outcome.is_some_and(QualificationHostOutcome::is_complete);
    BrokerResponse {
        code: if complete {
            ResponseCode::Ok
        } else {
            ResponseCode::InternalFailure
        },
        retry_after_millis: 0,
        attempt_id: lease.lease_id(),
        run_id: [0; 16],
        accepted_request_digest: request.request_digest,
        job_manifest_digest: request.manifest_digest,
        tip_oid: Some(request.integrated_candidate_sha),
        broker_state: BrokerState::Quarantined,
        conclusion: Conclusion::InfrastructureFailure,
        terminal_reason: 1,
        generation: lease.generation(),
        accepted_at: now,
        updated_at: now,
        lease_generation: lease.generation(),
        evidence_set_digest: outcome.map_or([0; 32], QualificationHostOutcome::no_publish_digest),
        teardown_digest: outcome.map_or([0; 32], QualificationHostOutcome::teardown_digest),
        attempt: 1,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use crate::activation::{
        FixtureJobCoordinates, HostActivationCoordinates, QualificationPermit,
    };
    use crate::qualification_host::{QualificationHostReceipt, QUALIFICATION_TERMINAL_ORDER};
    use buzz_ci_broker_protocol::{
        decode_response, encode_request, AdmitAttemptRequest, GitOid, HelloRequest,
        QualificationDirective, QualificationRequest, Request, ResponseCode, TrustClass,
        MAX_FRAME_SIZE,
    };

    struct RefusingOrdinaryBoundary;

    impl OrdinaryAdmissionBoundary for RefusingOrdinaryBoundary {
        fn authorize(
            &mut self,
            _header: FrameHeader,
            _request: AdmitAttemptRequest,
        ) -> Result<OrdinaryAdmission, AdmissionBoundaryError> {
            Err(AdmissionBoundaryError::Unavailable)
        }

        fn admitted_response(
            &mut self,
            _header: FrameHeader,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
            _now: u64,
        ) -> BrokerResponse {
            unreachable!("refusing boundary cannot admit")
        }
    }

    struct FixedQualificationBoundary(VerifiedSigner);

    impl QualificationAdmissionBoundary for FixedQualificationBoundary {
        fn authenticate(
            &mut self,
            _header: FrameHeader,
            _request: QualificationRequest,
        ) -> Result<VerifiedSigner, AdmissionBoundaryError> {
            Ok(self.0)
        }

        fn admitted_response(
            &mut self,
            _header: FrameHeader,
            request: QualificationRequest,
            _lease: QualificationLease,
            now: u64,
        ) -> BrokerResponse {
            let mut accepted = response(ResponseCode::Ok, now);
            accepted
                .attempt_id
                .copy_from_slice(&request.fixture_identity[..16]);
            accepted.accepted_request_digest = request.request_digest;
            accepted.job_manifest_digest = request.manifest_digest;
            accepted
        }

        fn execute_teardown_failure(
            &mut self,
            _plan: QualificationHostPlan,
        ) -> QualificationHostExecution {
            QualificationHostExecution::Missing
        }
    }

    #[derive(Clone, Copy)]
    enum TeardownEvidence {
        Complete,
        Missing,
        Ambiguous,
    }

    struct TeardownQualificationBoundary {
        signer: VerifiedSigner,
        evidence: TeardownEvidence,
    }

    impl QualificationAdmissionBoundary for TeardownQualificationBoundary {
        fn authenticate(
            &mut self,
            _header: FrameHeader,
            _request: QualificationRequest,
        ) -> Result<VerifiedSigner, AdmissionBoundaryError> {
            Ok(self.signer)
        }

        fn admitted_response(
            &mut self,
            _header: FrameHeader,
            _request: QualificationRequest,
            _lease: QualificationLease,
            _now: u64,
        ) -> BrokerResponse {
            panic!("teardown qualification reached ordinary response path")
        }

        fn execute_teardown_failure(
            &mut self,
            plan: QualificationHostPlan,
        ) -> QualificationHostExecution {
            match self.evidence {
                TeardownEvidence::Complete => QualificationHostExecution::Complete(
                    QualificationHostReceipt::new(
                        plan,
                        QUALIFICATION_TERMINAL_ORDER,
                        [21; 32],
                        [22; 32],
                        [23; 32],
                    )
                    .unwrap(),
                ),
                TeardownEvidence::Missing => QualificationHostExecution::Missing,
                TeardownEvidence::Ambiguous => QualificationHostExecution::Ambiguous,
            }
        }
    }

    fn qualification(
        directive: Option<QualificationDirective>,
    ) -> (ActivationController, QualificationRequest) {
        let root = VerifiedSigner([1; 32]);
        let signer = VerifiedSigner([2; 32]);
        let host = HostActivationCoordinates {
            integrated_candidate_sha: GitOid::Sha256([3; 32]),
            broker_build_identity: [4; 32],
            host_profile_digest: [5; 32],
            suite_identity: [6; 32],
        };
        let fixture_job = FixtureJobCoordinates {
            request_digest: [7; 32],
            manifest_digest: [8; 32],
            isolation_profile_digest: [9; 32],
            source_oid: GitOid::Sha256([10; 32]),
            base_oid: GitOid::Sha256([11; 32]),
            test_identity: [12; 32],
        };
        let permit = QualificationPermit {
            authorized_by: root,
            host,
            fixture_job,
            fixture_identity: [13; 32],
            fixture_signer: signer,
            nonce: [14; 32],
            not_before: 10,
            expires_at: 30,
            directive,
        };
        let mut controller = ActivationController::new(root);
        controller.start_qualification(permit).unwrap();
        (
            controller,
            QualificationRequest {
                integrated_candidate_sha: host.integrated_candidate_sha,
                broker_build_identity: host.broker_build_identity,
                host_profile_digest: host.host_profile_digest,
                suite_identity: host.suite_identity,
                fixture_signer: signer.0,
                request_digest: fixture_job.request_digest,
                manifest_digest: fixture_job.manifest_digest,
                isolation_profile_digest: fixture_job.isolation_profile_digest,
                source_oid: fixture_job.source_oid,
                base_oid: fixture_job.base_oid,
                job_identity: fixture_job.test_identity,
                fixture_identity: permit.fixture_identity,
                nonce: permit.nonce,
                not_before: permit.not_before,
                expires_at: permit.expires_at,
                directive,
            },
        )
    }

    fn round_trip(bytes: &[u8]) -> Result<Vec<u8>, ControlError> {
        let (mut client, server) = UnixStream::pair().expect("socketpair");
        write_all_fd(&client, bytes).expect("write request");
        // This sandbox denies `shutdown(Write)` on socketpairs. Production
        // always calls `serve_verified_stream`, which requires EOF; this
        // parser/dispatch test bypasses only that kernel operation.
        let result = serve_verified_stream_mode(server, &mut ClosedDispatch::new(), false);
        result?;
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");
        Ok(response)
    }

    fn rejected(bytes: &[u8]) -> ControlError {
        let (client, server) = UnixStream::pair().expect("socketpair");
        write_all_fd(&client, bytes).expect("write request");
        drop(client);
        serve_verified_stream(server, &mut ClosedDispatch::new()).unwrap_err()
    }

    fn hello() -> buzz_ci_broker_protocol::EncodedFrame {
        encode_request(
            [3; 16],
            Request::Hello(HelloRequest {
                controller_instance: [1; 32],
                nonce: [2; 32],
            }),
        )
    }

    fn admit() -> buzz_ci_broker_protocol::EncodedFrame {
        encode_request(
            [4; 16],
            Request::AdmitAttempt(AdmitAttemptRequest {
                signed_request_digest: [1; 32],
                actor_pubkey: [2; 32],
                audience_digest: [3; 32],
                idempotency_digest: [4; 32],
                source_pin_event_id: [5; 32],
                workflow_digest: [6; 32],
                job_manifest_digest: [7; 32],
                isolation_profile_digest: [8; 32],
                run_id: [9; 16],
                tip_oid: GitOid::Sha256([10; 32]),
                base_oid: GitOid::Sha256([11; 32]),
                issued_at: 10,
                expires_at: 20,
                wall_timeout_seconds: 5,
                attempt: 1,
                parent_attempt: 0,
                trust_class: TrustClass::AcceptedReviewed,
            }),
        )
    }

    #[test]
    fn socketpair_accepts_one_exact_frame_and_denies_capacity() {
        let encoded = hello();
        let response = round_trip(encoded.as_bytes()).unwrap();
        let (header, _) = decode_request(encoded.as_bytes()).unwrap();
        let decoded = decode_response(header, &response).unwrap();
        assert_eq!(decoded.code, ResponseCode::NotProvisioned);
    }

    #[test]
    fn peer_uid_is_checked_before_request_bytes() {
        let error = authorize_peer_uid(1_000, 1_001).unwrap_err();
        assert!(matches!(error, ControlError::UnauthorizedPeer));

        let (_client, server) = UnixStream::pair().expect("socketpair");
        match getsockopt(&server, PeerCredentials) {
            Ok(credentials) => {
                let refused_uid = credentials.uid() ^ 1;
                let error = authorize_peer_uid(credentials.uid(), refused_uid).unwrap_err();
                assert!(matches!(error, ControlError::UnauthorizedPeer));
            }
            Err(nix::errno::Errno::EPERM) => {
                // Some test sandboxes deny SO_PEERCRED. Production treats this
                // exact failure as an I/O refusal before reading any bytes.
                assert!(matches!(
                    serve_stream(
                        server,
                        1_001,
                        Duration::from_secs(1),
                        &mut ClosedDispatch::new()
                    ),
                    Err(ControlError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
                ));
            }
            Err(error) => panic!("unexpected SO_PEERCRED failure: {error}"),
        }
    }

    #[test]
    fn activation_numbers_are_canonical() {
        assert_eq!(parse_canonical_u32("0"), Some(0));
        assert_eq!(parse_canonical_u32("4294967295"), Some(u32::MAX));
        for invalid in ["", "00", "01", "+1", "-1", " 1", "1 ", "4294967296"] {
            assert_eq!(parse_canonical_u32(invalid), None);
        }
    }

    #[test]
    fn control_account_must_match_the_exact_nologin_principal() {
        let exact = "root:x:0:0:root:/root:/bin/bash\nbuzzci-ctl:x:961:961::/var/lib/buzzci/principals/ctl:/usr/sbin/nologin\n";
        assert_eq!(parse_control_account(exact).unwrap(), 961);
        for drift in [
            exact.replace(":961:961:", ":962:961:"),
            exact.replace(":961:961:", ":961:962:"),
            exact.replace("/usr/sbin/nologin", "/bin/bash"),
            format!(
                "{exact}buzzci-ctl:x:961:961::/var/lib/buzzci/principals/ctl:/usr/sbin/nologin\n"
            ),
        ] {
            assert!(parse_control_account(&drift).is_err());
        }
    }

    #[test]
    fn short_and_malformed_frames_are_rejected() {
        let short = rejected(b"BZCI");
        assert!(matches!(short, ControlError::Frame("short header")));

        let mut malformed = hello().as_bytes().to_vec();
        malformed[0] = b'X';
        let error = rejected(&malformed);
        assert!(matches!(error, ControlError::Frame("malformed header")));
    }

    #[test]
    fn trailing_bytes_are_rejected_without_dispatch() {
        let mut bytes = hello().as_bytes().to_vec();
        bytes.push(1);
        let error = rejected(&bytes);
        assert!(matches!(error, ControlError::Frame("trailing bytes")));
    }

    #[test]
    fn default_runtime_never_writes_a_successful_admission() {
        let encoded = admit();
        assert!(encoded.as_bytes().len() <= MAX_FRAME_SIZE);
        let response = round_trip(encoded.as_bytes()).unwrap();
        let (header, _) = decode_request(encoded.as_bytes()).unwrap();
        let decoded = decode_response(header, &response).unwrap();
        assert_eq!(decoded.code, ResponseCode::NotProvisioned);
        assert_ne!(decoded.code, ResponseCode::Ok);
        assert_eq!(decoded.attempt_id, [0; 16]);
    }

    #[test]
    fn qualification_dispatch_uses_only_the_service_authenticated_signer() {
        let header = FrameHeader {
            operation: buzz_ci_broker_protocol::Operation::AdmitQualification,
            request_id: [15; 16],
        };
        let (controller, request) = qualification(None);
        let mut wrong = ActivationDispatch::new(
            controller,
            RefusingOrdinaryBoundary,
            FixedQualificationBoundary(VerifiedSigner([99; 32])),
        );
        assert_eq!(
            wrong
                .dispatch(header, Request::AdmitQualification(request), 10)
                .code,
            ResponseCode::PolicyDenied
        );

        let (controller, request) = qualification(None);
        let mut exact = ActivationDispatch::new(
            controller,
            RefusingOrdinaryBoundary,
            FixedQualificationBoundary(VerifiedSigner([2; 32])),
        );
        let accepted = exact.dispatch(header, Request::AdmitQualification(request), 10);
        assert_eq!(accepted.code, ResponseCode::Ok);
        assert_eq!(accepted.attempt_id, [13; 16]);
        assert_eq!(accepted.accepted_request_digest, [7; 32]);
    }

    #[test]
    fn teardown_qualification_can_only_fail_quarantine_and_suppress_publication() {
        let header = FrameHeader {
            operation: buzz_ci_broker_protocol::Operation::AdmitQualification,
            request_id: [15; 16],
        };
        for evidence in [
            TeardownEvidence::Complete,
            TeardownEvidence::Missing,
            TeardownEvidence::Ambiguous,
        ] {
            let (controller, request) =
                qualification(Some(QualificationDirective::TeardownFailure));
            let mut dispatch = ActivationDispatch::new(
                controller,
                RefusingOrdinaryBoundary,
                TeardownQualificationBoundary {
                    signer: VerifiedSigner([2; 32]),
                    evidence,
                },
            );
            let result = dispatch.dispatch(header, Request::AdmitQualification(request), 10);
            assert_eq!(result.broker_state, BrokerState::Quarantined);
            assert_eq!(result.conclusion, Conclusion::InfrastructureFailure);
            assert_eq!(result.attempt_id, [13; 16]);
            assert_eq!(result.lease_generation, 1);
            assert_eq!(result.accepted_request_digest, [7; 32]);
            assert_eq!(result.job_manifest_digest, [8; 32]);
            match evidence {
                TeardownEvidence::Complete => {
                    assert_eq!(result.code, ResponseCode::Ok);
                    assert_eq!(result.evidence_set_digest, [22; 32]);
                    assert_eq!(result.teardown_digest, [21; 32]);
                }
                TeardownEvidence::Missing | TeardownEvidence::Ambiguous => {
                    assert_eq!(result.code, ResponseCode::InternalFailure);
                    assert_eq!(result.evidence_set_digest, [0; 32]);
                    assert_eq!(result.teardown_digest, [0; 32]);
                }
            }
        }
    }
}
