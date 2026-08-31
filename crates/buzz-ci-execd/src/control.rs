//! Linux Unix-socket control transport for the privileged broker.
//!
//! The transport accepts one systemd-owned listener and one fixed-width frame
//! per connection. It verifies the peer UID before reading any request bytes.

use std::{
    env,
    io::{self, Read},
    os::fd::AsRawFd,
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use buzz_ci_broker_protocol::v2;
use buzz_ci_broker_protocol::{
    decode_request, decode_request_header, encode_response, AdmitAttemptRequest, BrokerResponse,
    BrokerState, Conclusion, FrameHeader, Operation, QualificationRequest, Request, ResponseCode,
    HEADER_SIZE, PROTOCOL_VERSION,
};
use nix::{
    sys::socket::{
        getsockname, getsockopt, sockopt::AcceptConn, sockopt::PeerCredentials, sockopt::SockType,
        SockType as NixSockType, UnixAddr,
    },
    unistd::write,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::activation::{
    ActivationController, AdmissionError, LeaseToken, OrdinaryAdmission, QualificationLease,
    VerifiedSigner,
};
use crate::qualification_host::{
    QualificationHostExecution, QualificationHostOutcome, QualificationHostPlan,
};

const SYSTEMD_FD_NAME: &str = "buzz-ci-execd";
pub const EXECD_SOCKET_PATH: &str = "/run/buzzci/execd.sock";
const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn sha256_v2_admission(request: v2::AdmitAttemptRequest) -> [u8; 32] {
    Sha256::digest(v2::admission_signature_message(&request)).into()
}

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
    /// The authenticated peer is not authorized for the requested operation.
    #[error("operation refused for peer UID")]
    UnauthorizedOperation,
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

/// Exact service identities allowed to use the broker control socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerUidPolicy {
    control_uid: u32,
    control_gid: u32,
    runner_uid: u32,
    runner_gid: u32,
}

impl PeerUidPolicy {
    /// Bind the qualification and ordinary operation families to distinct non-root peers.
    pub fn new(control_uid: u32, runner_uid: u32) -> Result<Self, ControlError> {
        Self::new_with_gids(control_uid, control_uid, runner_uid, runner_uid)
    }

    /// Bind both roles to exact SO_PEERCRED UID and primary GID pairs.
    pub fn new_with_gids(
        control_uid: u32,
        control_gid: u32,
        runner_uid: u32,
        runner_gid: u32,
    ) -> Result<Self, ControlError> {
        if control_uid == 0
            || control_gid == 0
            || runner_uid == 0
            || runner_gid == 0
            || control_uid == runner_uid
        {
            return Err(ControlError::Account(
                "control and runner UIDs must be distinct and nonzero",
            ));
        }
        Ok(Self {
            control_uid,
            control_gid,
            runner_uid,
            runner_gid,
        })
    }

    fn role_for_credentials(self, peer_uid: u32, peer_gid: u32) -> Result<PeerRole, ControlError> {
        if peer_uid == self.control_uid && peer_gid == self.control_gid {
            Ok(PeerRole::Control)
        } else if peer_uid == self.runner_uid && peer_gid == self.runner_gid {
            Ok(PeerRole::Runner)
        } else {
            Err(ControlError::UnauthorizedPeer)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerRole {
    Control,
    Runner,
}

impl PeerRole {
    const fn permits(self, operation: Operation) -> bool {
        match self {
            Self::Control => matches!(operation, Operation::AdmitQualification),
            Self::Runner => matches!(
                operation,
                Operation::Hello
                    | Operation::AdmitAttempt
                    | Operation::CancelAttempt
                    | Operation::GetAttempt
                    | Operation::CompleteAttempt
                    | Operation::DescribeAttemptEvidence
                    | Operation::ReadAttemptEvidence
                    | Operation::RegisterJobIntent
            ),
        }
    }
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

    /// Consume the frozen version 2 request contract. Existing dispatchers stay
    /// fail-closed until they explicitly bind the v2 admission controller.
    fn dispatch_v2(
        &mut self,
        _header: v2::FrameHeader,
        _request: v2::Request,
        now: u64,
    ) -> v2::BrokerResponse {
        crate::production_binding::empty_response(ResponseCode::NotProvisioned, now)
    }

    /// Encode an operation-specific v2 response. Evidence export overrides
    /// this seam; existing operations retain their frozen broker response.
    fn dispatch_v2_encoded(
        &mut self,
        header: v2::FrameHeader,
        request: v2::Request,
        now: u64,
    ) -> v2::EncodedFrame {
        match request {
            v2::Request::DescribeAttemptEvidence(value) => {
                v2::encode_evidence_description_response(
                    header,
                    v2::EvidenceDescriptionResponse {
                        code: ResponseCode::NotProvisioned,
                        execution_binding_digest: value.coordinates.execution_binding_digest,
                        generation: value.coordinates.expected_generation,
                        request_frame_digest: value.request_frame_digest,
                        descriptor_set_digest: [0; 32],
                        item_count: 0,
                        items: [None; v2::MAX_EVIDENCE_ITEMS],
                        request_event_id: value.coordinates.request_event_id,
                        run_id: value.coordinates.run_id,
                        workflow_id: value.coordinates.workflow_id,
                        workflow_digest: value.coordinates.workflow_digest,
                        job_id: value.coordinates.job_id,
                        attempt: value.coordinates.attempt,
                    },
                )
            }
            v2::Request::ReadAttemptEvidence(value) => v2::encode_evidence_chunk_response(
                header,
                &v2::EvidenceChunkResponse {
                    code: ResponseCode::NotProvisioned,
                    execution_binding_digest: value.coordinates.execution_binding_digest,
                    generation: value.coordinates.expected_generation,
                    request_frame_digest: value.request_frame_digest,
                    kind: value.kind,
                    item_index: value.item_index,
                    descriptor_digest: value.descriptor_digest,
                    offset: value.offset,
                    total_length: 0,
                    bytes: Vec::new(),
                    request_event_id: value.coordinates.request_event_id,
                    run_id: value.coordinates.run_id,
                    workflow_id: value.coordinates.workflow_id,
                    workflow_digest: value.coordinates.workflow_digest,
                    job_id: value.coordinates.job_id,
                    attempt: value.coordinates.attempt,
                },
            ),
            v2::Request::RegisterJobIntent(value) => {
                let admission = value.admission;
                v2::encode_intent_registration_response(
                    header,
                    v2::IntentRegistrationResponse {
                        code: ResponseCode::NotProvisioned,
                        retry_after_millis: 0,
                        signed_request_digest: admission.signed_request_digest,
                        job_intent_digest: admission.job_intent_digest,
                        request_frame_digest: value.request_frame_digest,
                        admission_message_digest: sha256_v2_admission(admission),
                        registration_key_digest: v2::intent_registration_key_digest(&value),
                        lane_manifest_digest: admission.lane_manifest_digest,
                        run_id: admission.run_id,
                        lane_epoch: admission.lane_epoch,
                        admission_key_generation: admission.admission_key_generation,
                        issued_at: admission.issued_at,
                        expires_at: admission.expires_at,
                        attempt: admission.attempt,
                    },
                )
            }
            _ => {
                let response = self.dispatch_v2(header, request, now);
                v2::encode_response(header, response)
            }
        }
    }

    /// Run traffic-independent lease maintenance at one trusted clock reading.
    fn maintenance(&mut self, _now: u64) {}
}

impl<T: ControlDispatch + ?Sized> ControlDispatch for Box<T> {
    fn dispatch(&mut self, header: FrameHeader, request: Request, now: u64) -> BrokerResponse {
        (**self).dispatch(header, request, now)
    }

    fn dispatch_v2(
        &mut self,
        header: v2::FrameHeader,
        request: v2::Request,
        now: u64,
    ) -> v2::BrokerResponse {
        (**self).dispatch_v2(header, request, now)
    }

    fn dispatch_v2_encoded(
        &mut self,
        header: v2::FrameHeader,
        request: v2::Request,
        now: u64,
    ) -> v2::EncodedFrame {
        (**self).dispatch_v2_encoded(header, request, now)
    }

    fn maintenance(&mut self, now: u64) {
        (**self).maintenance(now);
    }
}

/// Encode the operation-specific capacity-zero response without constructing a
/// legacy dispatcher.
pub fn encode_not_provisioned_v2(
    header: v2::FrameHeader,
    request: v2::Request,
    now: u64,
) -> v2::EncodedFrame {
    match request {
        v2::Request::DescribeAttemptEvidence(value) => v2::encode_evidence_description_response(
            header,
            v2::EvidenceDescriptionResponse {
                code: ResponseCode::NotProvisioned,
                execution_binding_digest: value.coordinates.execution_binding_digest,
                generation: value.coordinates.expected_generation,
                request_frame_digest: value.request_frame_digest,
                descriptor_set_digest: [0; 32],
                item_count: 0,
                items: [None; v2::MAX_EVIDENCE_ITEMS],
                request_event_id: value.coordinates.request_event_id,
                run_id: value.coordinates.run_id,
                workflow_id: value.coordinates.workflow_id,
                workflow_digest: value.coordinates.workflow_digest,
                job_id: value.coordinates.job_id,
                attempt: value.coordinates.attempt,
            },
        ),
        v2::Request::ReadAttemptEvidence(value) => v2::encode_evidence_chunk_response(
            header,
            &v2::EvidenceChunkResponse {
                code: ResponseCode::NotProvisioned,
                execution_binding_digest: value.coordinates.execution_binding_digest,
                generation: value.coordinates.expected_generation,
                request_frame_digest: value.request_frame_digest,
                kind: value.kind,
                item_index: value.item_index,
                descriptor_digest: value.descriptor_digest,
                offset: value.offset,
                total_length: 0,
                bytes: Vec::new(),
                request_event_id: value.coordinates.request_event_id,
                run_id: value.coordinates.run_id,
                workflow_id: value.coordinates.workflow_id,
                workflow_digest: value.coordinates.workflow_digest,
                job_id: value.coordinates.job_id,
                attempt: value.coordinates.attempt,
            },
        ),
        v2::Request::RegisterJobIntent(value) => {
            let admission = value.admission;
            v2::encode_intent_registration_response(
                header,
                v2::IntentRegistrationResponse {
                    code: ResponseCode::NotProvisioned,
                    retry_after_millis: 0,
                    signed_request_digest: admission.signed_request_digest,
                    job_intent_digest: admission.job_intent_digest,
                    request_frame_digest: value.request_frame_digest,
                    admission_message_digest: sha256_v2_admission(admission),
                    registration_key_digest: v2::intent_registration_key_digest(&value),
                    lane_manifest_digest: admission.lane_manifest_digest,
                    run_id: admission.run_id,
                    lane_epoch: admission.lane_epoch,
                    admission_key_generation: admission.admission_key_generation,
                    issued_at: admission.issued_at,
                    expires_at: admission.expires_at,
                    attempt: admission.attempt,
                },
            )
        }
        _ => v2::encode_response(
            header,
            crate::production_binding::empty_response(ResponseCode::NotProvisioned, now),
        ),
    }
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
            Request::CancelAttempt(_) | Request::GetAttempt(_) | Request::CompleteAttempt(_) => {
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
            Request::CancelAttempt(_) | Request::GetAttempt(_) | Request::CompleteAttempt(_) => {
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
    peer_policy: PeerUidPolicy,
    dispatch: D,
    io_timeout: Duration,
    allow_v1: bool,
}

impl<D: ControlDispatch> ControlServer<D> {
    /// Construct a server over a previously validated listener.
    pub fn new(listener: UnixListener, peer_policy: PeerUidPolicy, dispatch: D) -> Self {
        Self {
            listener,
            peer_policy,
            dispatch,
            io_timeout: IO_TIMEOUT,
            allow_v1: true,
        }
    }

    /// Construct the production polling server used for timer maintenance.
    pub fn new_polling(
        listener: UnixListener,
        peer_policy: PeerUidPolicy,
        dispatch: D,
    ) -> Result<Self, ControlError> {
        listener.set_nonblocking(true).map_err(ControlError::Io)?;
        let mut server = Self::new(listener, peer_policy, dispatch);
        server.allow_v1 = false;
        Ok(server)
    }

    /// Accept and process one connection. The caller owns loop policy.
    pub fn serve_once(&mut self) -> Result<(), ControlError> {
        let (stream, _) = self.listener.accept().map_err(ControlError::Accept)?;
        serve_stream_mode(
            stream,
            self.peer_policy,
            self.io_timeout,
            &mut self.dispatch,
            self.allow_v1,
        )
    }

    /// Run maintenance and serve at most one ready connection without blocking.
    pub fn serve_tick(&mut self, now: u64) -> Result<(), ControlError> {
        self.dispatch.maintenance(now);
        let (stream, _) = match self.listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(ControlError::Accept(error)),
        };
        serve_stream_mode(
            stream,
            self.peer_policy,
            self.io_timeout,
            &mut self.dispatch,
            self.allow_v1,
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

#[cfg(test)]
fn serve_stream<D: ControlDispatch>(
    stream: UnixStream,
    peer_policy: PeerUidPolicy,
    timeout: Duration,
    dispatch: &mut D,
) -> Result<(), ControlError> {
    serve_stream_mode(stream, peer_policy, timeout, dispatch, true)
}

fn serve_stream_mode<D: ControlDispatch>(
    stream: UnixStream,
    peer_policy: PeerUidPolicy,
    timeout: Duration,
    dispatch: &mut D,
    allow_v1: bool,
) -> Result<(), ControlError> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let credentials = getsockopt(&stream, PeerCredentials).map_err(nix_io)?;
    let role = peer_policy.role_for_credentials(credentials.uid(), credentials.gid())?;
    serve_verified_stream_protocol_mode(stream, role, dispatch, allow_v1)
}

fn serve_verified_stream<D: ControlDispatch>(
    stream: UnixStream,
    role: PeerRole,
    dispatch: &mut D,
) -> Result<(), ControlError> {
    serve_verified_stream_mode(stream, role, dispatch, true)
}

fn serve_verified_stream_protocol_mode<D: ControlDispatch>(
    stream: UnixStream,
    role: PeerRole,
    dispatch: &mut D,
    allow_v1: bool,
) -> Result<(), ControlError> {
    if allow_v1 {
        serve_verified_stream(stream, role, dispatch)
    } else {
        serve_verified_stream_mode_with_protocol(stream, role, dispatch, true, false)
    }
}

fn serve_verified_stream_mode<D: ControlDispatch>(
    stream: UnixStream,
    role: PeerRole,
    dispatch: &mut D,
    require_write_shutdown: bool,
) -> Result<(), ControlError> {
    serve_verified_stream_mode_with_protocol(stream, role, dispatch, require_write_shutdown, true)
}

fn serve_verified_stream_mode_with_protocol<D: ControlDispatch>(
    mut stream: UnixStream,
    role: PeerRole,
    dispatch: &mut D,
    require_write_shutdown: bool,
    allow_v1: bool,
) -> Result<(), ControlError> {
    let mut frame = [0_u8; HEADER_SIZE + v2::MAX_BODY_SIZE];
    read_exact_frame_part(&mut stream, &mut frame[..HEADER_SIZE], "short header")?;
    let version = u16::from_be_bytes([frame[4], frame[5]]);
    match version {
        PROTOCOL_VERSION if allow_v1 => {
            let (header, body_size) = decode_request_header(&frame[..HEADER_SIZE])
                .map_err(|_| ControlError::Frame("malformed header"))?;
            authorize_and_read_body(
                &mut stream,
                role,
                header.operation,
                &mut frame,
                body_size,
                require_write_shutdown,
            )?;
            let frame_size = HEADER_SIZE + body_size;
            let (decoded_header, request) = decode_request(&frame[..frame_size])
                .map_err(|_| ControlError::Frame("malformed body"))?;
            debug_assert_eq!(decoded_header, header);
            let response = dispatch.dispatch(header, request, unix_now()?);
            write_all_fd(&stream, encode_response(header, response).as_bytes())
        }
        v2::PROTOCOL_VERSION => {
            let (header, body_size) = v2::decode_request_header(&frame[..HEADER_SIZE])
                .map_err(|_| ControlError::Frame("malformed header"))?;
            authorize_and_read_body(
                &mut stream,
                role,
                header.operation,
                &mut frame,
                body_size,
                require_write_shutdown,
            )?;
            let frame_size = HEADER_SIZE + body_size;
            let (decoded_header, request) = v2::decode_request(&frame[..frame_size])
                .map_err(|_| ControlError::Frame("malformed body"))?;
            debug_assert_eq!(decoded_header, header);
            let response = dispatch.dispatch_v2_encoded(header, request, unix_now()?);
            write_all_fd(&stream, response.as_bytes())
        }
        PROTOCOL_VERSION => Err(ControlError::Frame("version 1 is disabled")),
        _ => Err(ControlError::Frame("malformed header")),
    }
}

fn authorize_and_read_body(
    stream: &mut UnixStream,
    role: PeerRole,
    operation: Operation,
    frame: &mut [u8],
    body_size: usize,
    require_write_shutdown: bool,
) -> Result<(), ControlError> {
    if !role.permits(operation) {
        return Err(ControlError::UnauthorizedOperation);
    }
    let frame_size = HEADER_SIZE + body_size;
    read_exact_frame_part(stream, &mut frame[HEADER_SIZE..frame_size], "short body")?;
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
                return Err(ControlError::Frame("missing write shutdown"));
            }
            Err(error) => return Err(ControlError::Io(error)),
        }
    }
    Ok(())
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
    use std::{cell::Cell, io::Read, rc::Rc};

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

    struct MaintenanceCounter(Rc<Cell<u64>>);

    impl ControlDispatch for MaintenanceCounter {
        fn dispatch(
            &mut self,
            _header: FrameHeader,
            _request: Request,
            _now: u64,
        ) -> BrokerResponse {
            unreachable!("maintenance test has no control traffic")
        }

        fn maintenance(&mut self, now: u64) {
            self.0.set(now);
        }
    }

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
        let result =
            serve_verified_stream_mode(server, PeerRole::Runner, &mut ClosedDispatch::new(), false);
        result?;
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");
        Ok(response)
    }

    fn rejected(bytes: &[u8]) -> ControlError {
        let (client, server) = UnixStream::pair().expect("socketpair");
        write_all_fd(&client, bytes).expect("write request");
        drop(client);
        serve_verified_stream(server, PeerRole::Runner, &mut ClosedDispatch::new()).unwrap_err()
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
    fn socketpair_consumes_version_two_without_reinterpreting_it_as_version_one() {
        let encoded = v2::encode_request(
            [31; 16],
            v2::Request::Hello(HelloRequest {
                controller_instance: [32; 32],
                nonce: [33; 32],
            }),
        );
        let response = round_trip(encoded.as_bytes()).unwrap();
        let (header, _) = v2::decode_request(encoded.as_bytes()).unwrap();
        let decoded = v2::decode_response(header, &response).unwrap();
        assert_eq!(decoded.code, ResponseCode::NotProvisioned);
        assert_eq!(decoded.execution_binding_digest, [0; 32]);
    }

    #[test]
    fn polling_tick_runs_maintenance_without_control_traffic() {
        let temporary = tempfile::tempdir().unwrap();
        let listener = match UnixListener::bind(temporary.path().join("execd.sock")) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("unexpected listener bind failure: {error}"),
        };
        let observed = Rc::new(Cell::new(0));
        let mut server = ControlServer::new_polling(
            listener,
            PeerUidPolicy::new(961, 962).unwrap(),
            MaintenanceCounter(Rc::clone(&observed)),
        )
        .unwrap();

        server.serve_tick(42).unwrap();

        assert_eq!(observed.get(), 42);
    }

    #[test]
    fn peer_uid_is_checked_before_request_bytes() {
        let (_client, server) = UnixStream::pair().expect("socketpair");
        match getsockopt(&server, PeerCredentials) {
            Ok(credentials) => {
                let peer_uid = credentials.uid();
                let control_uid = if peer_uid == 1 { 2 } else { 1 };
                let runner_uid = if peer_uid == 2 { 3 } else { 2 };
                let policy = PeerUidPolicy::new(control_uid, runner_uid).unwrap();
                assert!(matches!(
                    serve_stream(
                        server,
                        policy,
                        Duration::from_secs(1),
                        &mut ClosedDispatch::new()
                    ),
                    Err(ControlError::UnauthorizedPeer)
                ));
            }
            Err(nix::errno::Errno::EPERM) => {
                // Some test sandboxes deny SO_PEERCRED. Production treats this
                // exact failure as an I/O refusal before reading any bytes.
                let policy = PeerUidPolicy::new(1_001, 1_002).unwrap();
                assert!(matches!(
                    serve_stream(
                        server,
                        policy,
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
    fn peer_policy_requires_distinct_nonroot_uids() {
        assert!(PeerUidPolicy::new(961, 962).is_ok());
        for invalid in [(0, 962), (961, 0), (961, 961)] {
            assert!(matches!(
                PeerUidPolicy::new(invalid.0, invalid.1),
                Err(ControlError::Account(_))
            ));
        }
    }

    #[test]
    fn peer_policy_requires_exact_primary_gid_as_well_as_uid() {
        let policy = PeerUidPolicy::new_with_gids(961, 971, 962, 972).unwrap();
        assert_eq!(
            policy.role_for_credentials(961, 971).unwrap(),
            PeerRole::Control
        );
        assert_eq!(
            policy.role_for_credentials(962, 972).unwrap(),
            PeerRole::Runner
        );
        for credentials in [(961, 972), (962, 971), (961, 0), (962, 0)] {
            assert!(matches!(
                policy.role_for_credentials(credentials.0, credentials.1),
                Err(ControlError::UnauthorizedPeer)
            ));
        }
    }

    #[test]
    fn peer_roles_are_bound_to_disjoint_operation_families() {
        for operation in [
            Operation::Hello,
            Operation::AdmitAttempt,
            Operation::CancelAttempt,
            Operation::GetAttempt,
            Operation::CompleteAttempt,
            Operation::DescribeAttemptEvidence,
            Operation::ReadAttemptEvidence,
            Operation::RegisterJobIntent,
        ] {
            assert!(PeerRole::Runner.permits(operation));
            assert!(!PeerRole::Control.permits(operation));
        }
        assert!(PeerRole::Control.permits(Operation::AdmitQualification));
        assert!(!PeerRole::Runner.permits(Operation::AdmitQualification));
    }

    #[test]
    fn unauthorized_operation_is_refused_after_header_before_body() {
        let encoded = admit();
        let (client, server) = UnixStream::pair().expect("socketpair");
        write_all_fd(&client, &encoded.as_bytes()[..HEADER_SIZE]).expect("write header");
        let error = serve_verified_stream_mode(
            server,
            PeerRole::Control,
            &mut ClosedDispatch::new(),
            false,
        )
        .unwrap_err();
        assert!(matches!(error, ControlError::UnauthorizedOperation));
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
    fn production_protocol_mode_rejects_every_v1_frame() {
        let encoded = hello();
        let (client, server) = UnixStream::pair().expect("socketpair");
        write_all_fd(&client, &encoded.as_bytes()[..HEADER_SIZE]).expect("write header");
        let error = serve_verified_stream_mode_with_protocol(
            server,
            PeerRole::Runner,
            &mut ClosedDispatch::new(),
            false,
            false,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ControlError::Frame("version 1 is disabled")
        ));
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
