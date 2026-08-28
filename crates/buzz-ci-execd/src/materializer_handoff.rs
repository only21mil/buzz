//! Authenticated descriptor handoff for the confined materializer principal.
//!
//! The root broker connects only after systemd has started this process inside
//! the materializer unit. One bounded typed frame carries the lease capability
//! tuple and exactly one `SCM_RIGHTS` workspace directory. The shim validates
//! the peer, tuple, descriptor, and frozen Git command before executing it.

use std::fs::{File, Permissions};
use std::io::{self, IoSlice, IoSliceMut, Read};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use buzz_ci_materializer::{
    CommandSpec, ConfinedGitProcessResult, MaterializeError, ProcessGitBackend,
};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::geteuid;
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::dns_exec::MaterializerCommandPlan;

const FRAME_MAGIC: &[u8; 4] = b"BZMH";
const FRAME_VERSION: u16 = 1;
const REQUEST_KIND: u16 = 1;
const RESPONSE_KIND: u16 = 2;
const FRAME_HEADER_BYTES: usize = 12;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 48 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 256;
const MAX_STDERR_BYTES: u64 = 64 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_COMMAND_DEADLINE_MILLIS: u64 = 15 * 60 * 1_000;
const RESPONSE_PROTOCOL_MARGIN_MILLIS: u64 = 5_000;
const MAX_RESPONSE_WAIT_MILLIS: u64 =
    MAX_COMMAND_DEADLINE_MILLIS.saturating_add(RESPONSE_PROTOCOL_MARGIN_MILLIS);
#[cfg(not(test))]
const FRAME_IO_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const FRAME_IO_TIMEOUT: Duration = Duration::from_millis(50);
const ROOT_BROKER_UID: u32 = 0;

/// Run the fixed materializer shim until its listener fails.
pub fn run_materializer_handoff_service(socket_path: &Path) -> Result<(), MaterializerShimError> {
    validate_socket_path(socket_path)?;
    let listener = UnixListener::bind(socket_path).map_err(MaterializerShimError::Io)?;
    std::fs::set_permissions(socket_path, Permissions::from_mode(0o600))
        .map_err(MaterializerShimError::Io)?;
    let mut service = MaterializerService::new(ROOT_BROKER_UID, geteuid().as_raw())?;
    for connection in listener.incoming() {
        let mut stream = connection.map_err(MaterializerShimError::Io)?;
        if let Err(error) = service.serve_stream(&mut stream, &ProcessExecutor) {
            let _ = write_response(
                &mut stream,
                &HandoffResponse::refused(error.public_reason()),
            );
        }
    }
    Err(MaterializerShimError::ListenerStopped)
}

/// Send one validated command and workspace descriptor to the confined shim.
pub fn execute_materializer_handoff(
    plan: &MaterializerCommandPlan,
    workspace_directory: &File,
) -> Result<ConfinedGitProcessResult, MaterializerShimError> {
    execute_materializer_handoff_with_connector(plan, workspace_directory, |path| {
        UnixStream::connect(path)
    })
}

fn execute_materializer_handoff_with_connector<F>(
    plan: &MaterializerCommandPlan,
    workspace_directory: &File,
    connect: F,
) -> Result<ConfinedGitProcessResult, MaterializerShimError>
where
    F: FnOnce(&Path) -> io::Result<UnixStream>,
{
    validate_command_bounds(plan.command())?;
    let response_timeout = response_read_timeout(plan.command().deadline_millis);
    if workspace_directory.as_raw_fd() != plan.workspace_fd() {
        return Err(MaterializerShimError::WrongDescriptor);
    }
    let mut stream = connect(plan.socket_path()).map_err(MaterializerShimError::Io)?;
    configure_stream(&stream)?;
    let peer = peer_uid(&stream)?;
    if peer != plan.command().required_uid {
        return Err(MaterializerShimError::UnauthorizedPeer);
    }
    let request = HandoffRequest::new(plan.command().clone(), workspace_directory)?;
    send_request(&mut stream, &request, workspace_directory)?;
    let response: HandoffResponse = read_json_frame(
        &mut stream,
        RESPONSE_KIND,
        MAX_RESPONSE_BYTES,
        response_timeout,
    )?;
    if response.schema_version != FRAME_VERSION {
        return Err(MaterializerShimError::MalformedFrame);
    }
    match (response.status.as_str(), response.result, response.reason) {
        ("ok", Some(result), None) => Ok(result.into()),
        ("refused", None, Some(reason)) | ("execution_failed", None, Some(reason)) => {
            Err(MaterializerShimError::RemoteRefusal(reason))
        }
        _ => Err(MaterializerShimError::MalformedFrame),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HandoffRequest {
    schema_version: u16,
    materializer_uid: u32,
    lease_id: String,
    cgroup_token: String,
    netns_token: String,
    sender_workspace_fd: i32,
    workspace_device: u64,
    workspace_inode: u64,
    command: CommandSpec,
}

impl HandoffRequest {
    fn new(command: CommandSpec, workspace: &File) -> Result<Self, MaterializerShimError> {
        let metadata = workspace.metadata().map_err(MaterializerShimError::Io)?;
        Ok(Self {
            schema_version: FRAME_VERSION,
            materializer_uid: command.required_uid,
            lease_id: command.lease_id.clone(),
            cgroup_token: command.cgroup_token.clone(),
            netns_token: command.netns_token.clone(),
            sender_workspace_fd: workspace.as_raw_fd(),
            workspace_device: metadata.dev(),
            workspace_inode: metadata.ino(),
            command,
        })
    }

    fn capability(&self) -> Result<MaterializerCapability, MaterializerShimError> {
        let capability = MaterializerCapability {
            materializer_uid: self.materializer_uid,
            lease_id: self.lease_id.clone(),
            cgroup_token: self.cgroup_token.clone(),
            netns_token: self.netns_token.clone(),
        };
        capability.validate()?;
        Ok(capability)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HandoffResponse {
    schema_version: u16,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<WireProcessResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl HandoffResponse {
    fn ok(result: ConfinedGitProcessResult) -> Self {
        Self {
            schema_version: FRAME_VERSION,
            status: "ok".to_owned(),
            result: Some(result.into()),
            reason: None,
        }
    }

    fn refused(reason: &'static str) -> Self {
        Self {
            schema_version: FRAME_VERSION,
            status: "refused".to_owned(),
            result: None,
            reason: Some(reason.to_owned()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireProcessResult {
    exit_code: Option<i32>,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_observed_bytes: u64,
    stderr_observed_bytes: u64,
    stdout_truncated: bool,
    stderr_truncated: bool,
    elapsed_millis: u64,
    process_group_empty: bool,
}

impl From<ConfinedGitProcessResult> for WireProcessResult {
    fn from(result: ConfinedGitProcessResult) -> Self {
        Self {
            exit_code: result.exit_code,
            timed_out: result.timed_out,
            stdout: result.stdout,
            stderr: result.stderr,
            stdout_observed_bytes: result.stdout_observed_bytes,
            stderr_observed_bytes: result.stderr_observed_bytes,
            stdout_truncated: result.stdout_truncated,
            stderr_truncated: result.stderr_truncated,
            elapsed_millis: result.elapsed_millis,
            process_group_empty: result.process_group_empty,
        }
    }
}

impl From<WireProcessResult> for ConfinedGitProcessResult {
    fn from(result: WireProcessResult) -> Self {
        Self {
            exit_code: result.exit_code,
            timed_out: result.timed_out,
            stdout: result.stdout,
            stderr: result.stderr,
            stdout_observed_bytes: result.stdout_observed_bytes,
            stderr_observed_bytes: result.stderr_observed_bytes,
            stdout_truncated: result.stdout_truncated,
            stderr_truncated: result.stderr_truncated,
            elapsed_millis: result.elapsed_millis,
            process_group_empty: result.process_group_empty,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MaterializerCapability {
    materializer_uid: u32,
    lease_id: String,
    cgroup_token: String,
    netns_token: String,
}

impl MaterializerCapability {
    fn validate(&self) -> Result<(), MaterializerShimError> {
        if self.materializer_uid == 0
            || !valid_token(&self.lease_id)
            || !valid_token(&self.cgroup_token)
            || !valid_token(&self.netns_token)
        {
            return Err(MaterializerShimError::CapabilityMismatch);
        }
        Ok(())
    }
}

struct MaterializerService {
    authorized_peer_uid: u32,
    effective_uid: u32,
    capability: Option<MaterializerCapability>,
}

impl MaterializerService {
    fn new(authorized_peer_uid: u32, effective_uid: u32) -> Result<Self, MaterializerShimError> {
        if effective_uid == 0 {
            return Err(MaterializerShimError::WrongEffectiveUid);
        }
        Ok(Self {
            authorized_peer_uid,
            effective_uid,
            capability: None,
        })
    }

    fn serve_stream<E: ShimExecutor>(
        &mut self,
        stream: &mut UnixStream,
        executor: &E,
    ) -> Result<(), MaterializerShimError> {
        configure_stream(stream)?;
        let actual_peer_uid = peer_uid(stream)?;
        self.serve_authenticated_stream(stream, actual_peer_uid, executor)
    }

    fn serve_authenticated_stream<E: ShimExecutor>(
        &mut self,
        stream: &mut UnixStream,
        actual_peer_uid: u32,
        executor: &E,
    ) -> Result<(), MaterializerShimError> {
        configure_stream(stream)?;
        if actual_peer_uid != self.authorized_peer_uid {
            return Err(MaterializerShimError::UnauthorizedPeer);
        }
        let (mut request, descriptor) = receive_request(stream)?;
        let capability = request.capability()?;
        if capability.materializer_uid != self.effective_uid
            || request.command.required_uid != self.effective_uid
            || request.command.lease_id != capability.lease_id
            || request.command.cgroup_token != capability.cgroup_token
            || request.command.netns_token != capability.netns_token
        {
            return Err(MaterializerShimError::CapabilityMismatch);
        }
        if self
            .capability
            .as_ref()
            .is_some_and(|bound| bound != &capability)
        {
            return Err(MaterializerShimError::CapabilityMismatch);
        }
        let workspace = File::from(descriptor);
        validate_workspace(&request, &workspace, self.effective_uid)?;
        request.command.current_dir =
            PathBuf::from(format!("/proc/self/fd/{}", workspace.as_raw_fd()));
        validate_command_bounds(&request.command)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MaterializerShimError::InvalidCommand("system clock".to_owned()))?
            .as_secs();
        if now >= request.command.lease_expires_at_unix_seconds {
            return Err(MaterializerShimError::InvalidCommand(
                "command lease expired before exec".to_owned(),
            ));
        }
        let validator = ProcessGitBackend::new(
            PathBuf::from("/usr/bin/git"),
            self.effective_uid,
            capability.lease_id.clone(),
            capability.cgroup_token.clone(),
            capability.netns_token.clone(),
            (),
        )
        .map_err(MaterializerShimError::Materializer)?;
        let result = executor.execute(&validator, &request.command, &workspace)?;
        self.capability.get_or_insert(capability);
        write_response(stream, &HandoffResponse::ok(result))
    }
}

trait ShimExecutor {
    fn execute(
        &self,
        validator: &ProcessGitBackend<()>,
        command: &CommandSpec,
        workspace: &File,
    ) -> Result<ConfinedGitProcessResult, MaterializerShimError>;
}

struct ProcessExecutor;

impl ShimExecutor for ProcessExecutor {
    fn execute(
        &self,
        validator: &ProcessGitBackend<()>,
        command: &CommandSpec,
        workspace: &File,
    ) -> Result<ConfinedGitProcessResult, MaterializerShimError> {
        validator
            .run_confined_command(command, workspace)
            .map_err(MaterializerShimError::InvalidCommand)
    }
}

fn validate_command_bounds(command: &CommandSpec) -> Result<(), MaterializerShimError> {
    if command.maximum_stdout_bytes == 0
        || command.maximum_stdout_bytes > MAX_COMMAND_OUTPUT_BYTES
        || command.maximum_stderr_bytes == 0
        || command.maximum_stderr_bytes > MAX_STDERR_BYTES
        || command.deadline_millis == 0
        || command.deadline_millis > MAX_COMMAND_DEADLINE_MILLIS
        || command.maximum_processes == 0
    {
        return Err(MaterializerShimError::InvalidCommand(
            "command bounds exceed the shim protocol".to_owned(),
        ));
    }
    Ok(())
}

fn response_read_timeout(command_deadline_millis: u64) -> Duration {
    Duration::from_millis(
        command_deadline_millis
            .saturating_add(RESPONSE_PROTOCOL_MARGIN_MILLIS)
            .min(MAX_RESPONSE_WAIT_MILLIS),
    )
}

fn validate_workspace(
    request: &HandoffRequest,
    workspace: &File,
    effective_uid: u32,
) -> Result<(), MaterializerShimError> {
    let expected_current_dir = format!("/proc/self/fd/{}", request.sender_workspace_fd);
    if request.sender_workspace_fd < 0
        || request.command.current_dir.to_str() != Some(expected_current_dir.as_str())
    {
        return Err(MaterializerShimError::WrongDescriptor);
    }
    let metadata = workspace.metadata().map_err(MaterializerShimError::Io)?;
    if !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.dev() != request.workspace_device
        || metadata.ino() != request.workspace_inode
    {
        return Err(MaterializerShimError::WrongDescriptor);
    }
    Ok(())
}

fn receive_request(
    stream: &mut UnixStream,
) -> Result<(HandoffRequest, OwnedFd), MaterializerShimError> {
    let mut bytes = vec![0_u8; FRAME_HEADER_BYTES + MAX_REQUEST_BYTES];
    let mut iov = [IoSliceMut::new(&mut bytes)];
    let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut ancillary_space);
    let deadline = Instant::now() + FRAME_IO_TIMEOUT;
    let message = loop {
        match recvmsg(
            stream.as_fd(),
            &mut iov,
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        ) {
            Ok(message) => break message,
            Err(error) => {
                let error: io::Error = error.into();
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                return Err(map_io_error(error));
            }
        }
    };
    let received = message.bytes;
    if message.flags.contains(ReturnFlags::CTRUNC) {
        return Err(MaterializerShimError::WrongDescriptor);
    }
    let mut descriptors = Vec::new();
    for control in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(rights) = control {
            descriptors.extend(rights);
        }
    }
    if received == 0 {
        return Err(MaterializerShimError::Disconnected);
    }
    if descriptors.len() != 1 {
        return Err(MaterializerShimError::WrongDescriptor);
    }
    let payload = complete_frame(
        stream,
        &mut bytes,
        received,
        REQUEST_KIND,
        MAX_REQUEST_BYTES,
    )?;
    let request: HandoffRequest =
        serde_json::from_slice(payload).map_err(|_| MaterializerShimError::MalformedFrame)?;
    if request.schema_version != FRAME_VERSION {
        return Err(MaterializerShimError::MalformedFrame);
    }
    Ok((request, descriptors.remove(0)))
}

fn send_request(
    stream: &mut UnixStream,
    request: &HandoffRequest,
    descriptor: &File,
) -> Result<(), MaterializerShimError> {
    let frame = encode_json_frame(REQUEST_KIND, request, MAX_REQUEST_BYTES)?;
    let descriptor = [descriptor.as_fd()];
    let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut ancillary_space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptor)) {
        return Err(MaterializerShimError::WrongDescriptor);
    }
    let sent = sendmsg(
        stream.as_fd(),
        &[IoSlice::new(&frame)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(|error| map_io_error(error.into()))?;
    if sent == 0 {
        return Err(MaterializerShimError::Disconnected);
    }
    send_bytes(stream, &frame[sent..])
}

fn write_response(
    stream: &mut UnixStream,
    response: &HandoffResponse,
) -> Result<(), MaterializerShimError> {
    let frame = encode_json_frame(RESPONSE_KIND, response, MAX_RESPONSE_BYTES)?;
    send_bytes(stream, &frame)
}

fn read_json_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
    expected_kind: u16,
    max_payload: usize,
    timeout: Duration,
) -> Result<T, MaterializerShimError> {
    let mut clock = SystemElapsedClock::new();
    read_json_frame_with_clock(stream, expected_kind, max_payload, timeout, &mut clock)
}

fn read_json_frame_with_clock<T: for<'de> Deserialize<'de>, R: Read, C: ElapsedClock>(
    reader: &mut R,
    expected_kind: u16,
    max_payload: usize,
    timeout: Duration,
    clock: &mut C,
) -> Result<T, MaterializerShimError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    read_exact_with_clock(reader, &mut header, timeout, clock)?;
    let length = decode_header(&header, expected_kind, max_payload)?;
    let mut payload = vec![0_u8; length];
    read_exact_with_clock(reader, &mut payload, timeout, clock)?;
    serde_json::from_slice(&payload).map_err(|_| MaterializerShimError::MalformedFrame)
}

fn complete_frame<'a>(
    stream: &mut UnixStream,
    bytes: &'a mut [u8],
    mut received: usize,
    expected_kind: u16,
    max_payload: usize,
) -> Result<&'a [u8], MaterializerShimError> {
    if received < FRAME_HEADER_BYTES {
        read_exact_bounded(stream, &mut bytes[received..FRAME_HEADER_BYTES])?;
        received = FRAME_HEADER_BYTES;
    }
    let length = decode_header(&bytes[..FRAME_HEADER_BYTES], expected_kind, max_payload)?;
    let frame_length = FRAME_HEADER_BYTES + length;
    if received > frame_length {
        return Err(MaterializerShimError::MalformedFrame);
    }
    if received < frame_length {
        read_exact_bounded(stream, &mut bytes[received..frame_length])?;
    }
    Ok(&bytes[FRAME_HEADER_BYTES..frame_length])
}

fn encode_json_frame<T: Serialize>(
    kind: u16,
    value: &T,
    max_payload: usize,
) -> Result<Vec<u8>, MaterializerShimError> {
    let payload = serde_json::to_vec(value).map_err(|_| MaterializerShimError::MalformedFrame)?;
    if payload.len() > max_payload || payload.len() > u32::MAX as usize {
        return Err(MaterializerShimError::OversizedFrame);
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(FRAME_MAGIC);
    frame.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&kind.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_header(
    header: &[u8],
    expected_kind: u16,
    max_payload: usize,
) -> Result<usize, MaterializerShimError> {
    if header.len() != FRAME_HEADER_BYTES
        || &header[..4] != FRAME_MAGIC
        || u16::from_be_bytes([header[4], header[5]]) != FRAME_VERSION
        || u16::from_be_bytes([header[6], header[7]]) != expected_kind
    {
        return Err(MaterializerShimError::MalformedFrame);
    }
    let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if length == 0 {
        return Err(MaterializerShimError::MalformedFrame);
    }
    if length > max_payload {
        return Err(MaterializerShimError::OversizedFrame);
    }
    Ok(length)
}

fn configure_stream(stream: &UnixStream) -> Result<(), MaterializerShimError> {
    stream
        .set_nonblocking(true)
        .map_err(MaterializerShimError::Io)
}

fn read_exact_bounded(
    stream: &mut UnixStream,
    destination: &mut [u8],
) -> Result<(), MaterializerShimError> {
    let mut clock = SystemElapsedClock::new();
    read_exact_with_clock(stream, destination, FRAME_IO_TIMEOUT, &mut clock)
}

trait ElapsedClock {
    fn elapsed(&self) -> Duration;
    fn wait(&mut self);
}

struct SystemElapsedClock {
    start: Instant,
}

impl SystemElapsedClock {
    fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl ElapsedClock for SystemElapsedClock {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn wait(&mut self) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn read_exact_with_clock<R: Read, C: ElapsedClock>(
    reader: &mut R,
    mut destination: &mut [u8],
    timeout: Duration,
    clock: &mut C,
) -> Result<(), MaterializerShimError> {
    while !destination.is_empty() {
        match reader.read(destination) {
            Ok(0) => return Err(MaterializerShimError::Disconnected),
            Ok(read) => destination = &mut destination[read..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if clock.elapsed() >= timeout {
                    return Err(MaterializerShimError::TimedOut);
                }
                clock.wait();
            }
            Err(error) => return Err(map_io_error(error)),
        }
    }
    Ok(())
}

fn send_bytes(stream: &UnixStream, mut bytes: &[u8]) -> Result<(), MaterializerShimError> {
    let deadline = Instant::now() + FRAME_IO_TIMEOUT;
    while !bytes.is_empty() {
        let mut ancillary = SendAncillaryBuffer::default();
        match sendmsg(
            stream.as_fd(),
            &[IoSlice::new(bytes)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        ) {
            Ok(0) => return Err(MaterializerShimError::Disconnected),
            Ok(sent) => bytes = &bytes[sent..],
            Err(error) => {
                let error: io::Error = error.into();
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                } else {
                    return Err(map_io_error(error));
                }
            }
        }
    }
    Ok(())
}

fn peer_uid(stream: &UnixStream) -> Result<u32, MaterializerShimError> {
    getsockopt(stream, PeerCredentials)
        .map(|credential| credential.uid())
        .map_err(|error| MaterializerShimError::PeerCredential(error.to_string()))
}

fn validate_socket_path(path: &Path) -> Result<(), MaterializerShimError> {
    let parent = path
        .parent()
        .ok_or(MaterializerShimError::InvalidSocketPath)?;
    let runtime = parent
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| valid_runtime_name(name))
        .ok_or(MaterializerShimError::InvalidSocketPath)?;
    if parent.parent() != Some(Path::new("/run"))
        || path.file_name().and_then(|name| name.to_str()) != Some("materializer.sock")
        || runtime.is_empty()
    {
        return Err(MaterializerShimError::InvalidSocketPath);
    }
    Ok(())
}

fn valid_runtime_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn map_io_error(error: io::Error) -> MaterializerShimError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => MaterializerShimError::TimedOut,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset => MaterializerShimError::Disconnected,
        _ => MaterializerShimError::Io(error),
    }
}

/// Fail-closed materializer shim refusal.
#[derive(Debug, Error)]
pub enum MaterializerShimError {
    #[error("materializer handoff frame is malformed")]
    MalformedFrame,
    #[error("materializer handoff frame exceeds its byte ceiling")]
    OversizedFrame,
    #[error("materializer handoff peer is unauthorized")]
    UnauthorizedPeer,
    #[error("materializer handoff capability tuple does not match")]
    CapabilityMismatch,
    #[error("materializer handoff descriptor is missing or wrong")]
    WrongDescriptor,
    #[error("materializer shim must run under a non-root principal UID")]
    WrongEffectiveUid,
    #[error("materializer command refused: {0}")]
    InvalidCommand(String),
    #[error("materializer handoff timed out")]
    TimedOut,
    #[error("materializer handoff peer disconnected")]
    Disconnected,
    #[error("materializer handoff socket path is outside the fixed runtime directory")]
    InvalidSocketPath,
    #[error("materializer handoff peer credential failed: {0}")]
    PeerCredential(String),
    #[error("materializer shim listener stopped")]
    ListenerStopped,
    #[error("materializer shim remote refusal: {0}")]
    RemoteRefusal(String),
    #[error("materializer command binding failed: {0}")]
    Materializer(#[from] MaterializeError),
    #[error("materializer shim I/O failed: {0}")]
    Io(io::Error),
}

impl MaterializerShimError {
    fn public_reason(&self) -> &'static str {
        match self {
            Self::MalformedFrame | Self::OversizedFrame => "bad_frame",
            Self::UnauthorizedPeer | Self::PeerCredential(_) => "unauthorized_peer",
            Self::CapabilityMismatch => "capability_mismatch",
            Self::WrongDescriptor => "wrong_descriptor",
            Self::InvalidCommand(_) | Self::Materializer(_) => "invalid_command",
            Self::TimedOut => "timeout",
            Self::Disconnected => "disconnect",
            Self::WrongEffectiveUid
            | Self::InvalidSocketPath
            | Self::ListenerStopped
            | Self::RemoteRefusal(_)
            | Self::Io(_) => "service_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::fs::OpenOptions;
    use std::io::Cursor;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use buzz_ci_materializer::{GitOperation, NetworkScope};
    use tempfile::tempdir;

    use super::*;

    struct FakeExecutor {
        calls: AtomicUsize,
    }

    impl FakeExecutor {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl ShimExecutor for FakeExecutor {
        fn execute(
            &self,
            validator: &ProcessGitBackend<()>,
            command: &CommandSpec,
            workspace: &File,
        ) -> Result<ConfinedGitProcessResult, MaterializerShimError> {
            validator
                .validate_command(command, workspace)
                .map_err(MaterializerShimError::InvalidCommand)?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(success_result())
        }
    }

    struct FakeElapsedClock {
        elapsed: Rc<Cell<Duration>>,
    }

    impl ElapsedClock for FakeElapsedClock {
        fn elapsed(&self) -> Duration {
            self.elapsed.get()
        }

        fn wait(&mut self) {}
    }

    struct DelayedReader {
        bytes: Cursor<Vec<u8>>,
        elapsed: Rc<Cell<Duration>>,
        delayed: bool,
    }

    impl Read for DelayedReader {
        fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
            if !self.delayed {
                self.delayed = true;
                self.elapsed.set(Duration::from_secs(11));
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.bytes.read(destination)
        }
    }

    fn success_result() -> ConfinedGitProcessResult {
        ConfinedGitProcessResult {
            exit_code: Some(0),
            timed_out: false,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            stdout_observed_bytes: 2,
            stderr_observed_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            elapsed_millis: 1,
            process_group_empty: true,
        }
    }

    fn environment() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("GIT_EXEC_PATH".to_owned(), "/usr/lib/git-core".to_owned()),
            ("HOME".to_owned(), "/proc/self/cwd/home".to_owned()),
            ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
            ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
            ("GIT_CONFIG_GLOBAL".to_owned(), "/dev/null".to_owned()),
            ("GIT_CONFIG_COUNT".to_owned(), "2".to_owned()),
            (
                "GIT_CONFIG_KEY_0".to_owned(),
                "credential.helper".to_owned(),
            ),
            ("GIT_CONFIG_VALUE_0".to_owned(), String::new()),
            ("GIT_CONFIG_KEY_1".to_owned(), "core.hooksPath".to_owned()),
            ("GIT_CONFIG_VALUE_1".to_owned(), "/dev/null".to_owned()),
            ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
            ("GIT_ASKPASS".to_owned(), "/bin/false".to_owned()),
            ("SSH_ASKPASS".to_owned(), "/bin/false".to_owned()),
            ("GIT_LFS_SKIP_SMUDGE".to_owned(), "1".to_owned()),
        ])
    }

    fn request(workspace: &File, uid: u32) -> HandoffRequest {
        let command = CommandSpec {
            operation: GitOperation::Init,
            program: PathBuf::from("/usr/bin/git"),
            arguments: vec![
                "--git-dir=objects.git".to_owned(),
                "init".to_owned(),
                "--bare".to_owned(),
            ],
            current_dir: PathBuf::from(format!("/proc/self/fd/{}", workspace.as_raw_fd())),
            clear_environment: true,
            environment: environment(),
            required_uid: uid,
            lease_id: "lease-capability".to_owned(),
            cgroup_token: "cgroup-capability".to_owned(),
            netns_token: "netns-capability".to_owned(),
            lease_expires_at_unix_seconds: u64::MAX,
            maximum_stdout_bytes: 4_096,
            maximum_stderr_bytes: 4_096,
            deadline_millis: 1_000,
            network: NetworkScope::None,
            maximum_network_bytes: 0,
            maximum_processes: 32,
        };
        HandoffRequest::new(command, workspace).unwrap()
    }

    fn send_raw(stream: &mut UnixStream, bytes: &[u8], descriptor: Option<&File>) {
        if let Some(descriptor) = descriptor {
            let descriptors = [descriptor.as_fd()];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
            let sent = sendmsg(
                stream.as_fd(),
                &[IoSlice::new(bytes)],
                &mut ancillary,
                SendFlags::NOSIGNAL,
            )
            .unwrap();
            send_bytes(stream, &bytes[sent..]).unwrap();
        } else {
            send_bytes(stream, bytes).unwrap();
        }
    }

    fn serve(
        service: &mut MaterializerService,
        request: &HandoffRequest,
        descriptor: Option<&File>,
        executor: &FakeExecutor,
    ) -> Result<(), MaterializerShimError> {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let frame = encode_json_frame(REQUEST_KIND, request, MAX_REQUEST_BYTES).unwrap();
        send_raw(&mut client, &frame, descriptor);
        service.serve_authenticated_stream(&mut server, 0, executor)
    }

    #[test]
    fn authenticated_descriptor_executes_after_all_validation() {
        let temporary = tempdir().unwrap();
        let workspace = File::open(temporary.path()).unwrap();
        let uid = geteuid().as_raw();
        assert_ne!(uid, 0, "test requires an unprivileged account");
        let mut service = MaterializerService::new(0, uid).unwrap();
        let executor = FakeExecutor::new();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        send_request(&mut client, &request(&workspace, uid), &workspace).unwrap();
        service
            .serve_authenticated_stream(&mut server, 0, &executor)
            .unwrap();
        let response: HandoffResponse = read_json_frame(
            &mut client,
            RESPONSE_KIND,
            MAX_RESPONSE_BYTES,
            FRAME_IO_TIMEOUT,
        )
        .unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.result.unwrap().stdout, b"ok");
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn response_read_accepts_arrival_after_former_ten_second_limit() {
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let frame = encode_json_frame(
            RESPONSE_KIND,
            &HandoffResponse::ok(success_result()),
            MAX_RESPONSE_BYTES,
        )
        .unwrap();
        let mut reader = DelayedReader {
            bytes: Cursor::new(frame),
            elapsed: Rc::clone(&elapsed),
            delayed: false,
        };
        let mut clock = FakeElapsedClock { elapsed };
        let timeout = response_read_timeout(10_001);

        let response: HandoffResponse = read_json_frame_with_clock(
            &mut reader,
            RESPONSE_KIND,
            MAX_RESPONSE_BYTES,
            timeout,
            &mut clock,
        )
        .unwrap();

        assert_eq!(timeout, Duration::from_millis(15_001));
        assert_eq!(response.status, "ok");
    }

    #[test]
    fn response_deadline_margin_is_overflow_safe_and_protocol_bounded() {
        let maximum = Duration::from_millis(MAX_RESPONSE_WAIT_MILLIS);
        assert_eq!(response_read_timeout(MAX_COMMAND_DEADLINE_MILLIS), maximum);
        assert_eq!(response_read_timeout(u64::MAX), maximum);
    }

    #[test]
    fn invalid_command_deadlines_refuse_before_connector_io() {
        let temporary = tempdir().unwrap();
        let workspace = File::open(temporary.path()).unwrap();

        for deadline_millis in [0, MAX_COMMAND_DEADLINE_MILLIS + 1] {
            let mut command = request(&workspace, geteuid().as_raw()).command;
            command.deadline_millis = deadline_millis;
            let plan = MaterializerCommandPlan::test_new(
                PathBuf::from("/run/buzzci-lease01-mat/materializer.sock"),
                workspace.as_raw_fd(),
                command,
            );
            let connector_calls = Cell::new(0);

            let result = execute_materializer_handoff_with_connector(&plan, &workspace, |_| {
                connector_calls.set(connector_calls.get() + 1);
                Err(io::Error::other("connector must not run"))
            });

            assert!(matches!(
                result,
                Err(MaterializerShimError::InvalidCommand(_))
            ));
            assert_eq!(connector_calls.get(), 0);
        }
    }

    #[test]
    fn malformed_and_oversized_frames_are_refused() {
        let temporary = tempdir().unwrap();
        let workspace = File::open(temporary.path()).unwrap();
        let uid = geteuid().as_raw();
        let executor = FakeExecutor::new();
        for frame in [vec![0_u8; FRAME_HEADER_BYTES], {
            let mut header = Vec::from(*FRAME_MAGIC);
            header.extend_from_slice(&FRAME_VERSION.to_be_bytes());
            header.extend_from_slice(&REQUEST_KIND.to_be_bytes());
            header.extend_from_slice(&((MAX_REQUEST_BYTES + 1) as u32).to_be_bytes());
            header
        }] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            send_raw(&mut client, &frame, Some(&workspace));
            let mut service = MaterializerService::new(0, uid).unwrap();
            assert!(matches!(
                service.serve_authenticated_stream(&mut server, 0, &executor),
                Err(MaterializerShimError::MalformedFrame | MaterializerShimError::OversizedFrame)
            ));
        }
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn wrong_peer_uid_or_capability_tuple_is_refused() {
        let temporary = tempdir().unwrap();
        let workspace = File::open(temporary.path()).unwrap();
        let uid = geteuid().as_raw();
        let executor = FakeExecutor::new();
        let mut service = MaterializerService::new(0, uid).unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        send_request(&mut client, &request(&workspace, uid), &workspace).unwrap();
        assert!(matches!(
            service.serve_authenticated_stream(&mut server, 1, &executor),
            Err(MaterializerShimError::UnauthorizedPeer)
        ));

        let mut wrong_uid = request(&workspace, uid);
        wrong_uid.materializer_uid = uid + 1;
        wrong_uid.command.required_uid = uid + 1;
        let mut unbound_service = MaterializerService::new(0, uid).unwrap();
        assert!(matches!(
            serve(
                &mut unbound_service,
                &wrong_uid,
                Some(&workspace),
                &executor
            ),
            Err(MaterializerShimError::CapabilityMismatch)
        ));

        serve(
            &mut service,
            &request(&workspace, uid),
            Some(&workspace),
            &executor,
        )
        .unwrap();
        let mut drift = request(&workspace, uid);
        drift.cgroup_token.push_str("-wrong");
        drift.command.cgroup_token = drift.cgroup_token.clone();
        assert!(matches!(
            serve(&mut service, &drift, Some(&workspace), &executor),
            Err(MaterializerShimError::CapabilityMismatch)
        ));
    }

    #[test]
    fn missing_or_wrong_descriptor_is_refused() {
        let temporary = tempdir().unwrap();
        let workspace = File::open(temporary.path()).unwrap();
        let regular_path = temporary.path().join("file");
        let regular = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(regular_path)
            .unwrap();
        let uid = geteuid().as_raw();
        let executor = FakeExecutor::new();
        let request = request(&workspace, uid);

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let frame = encode_json_frame(REQUEST_KIND, &request, MAX_REQUEST_BYTES).unwrap();
        send_raw(&mut client, &frame, None);
        let mut service = MaterializerService::new(0, uid).unwrap();
        assert!(matches!(
            service.serve_authenticated_stream(&mut server, 0, &executor),
            Err(MaterializerShimError::WrongDescriptor)
        ));

        let mut service = MaterializerService::new(0, uid).unwrap();
        assert!(matches!(
            serve(&mut service, &request, Some(&regular), &executor),
            Err(MaterializerShimError::WrongDescriptor)
        ));
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn nonfixed_program_argv_and_environment_are_refused() {
        type RequestMutation = Box<dyn Fn(&mut HandoffRequest)>;

        let temporary = tempdir().unwrap();
        let workspace = File::open(temporary.path()).unwrap();
        let uid = geteuid().as_raw();
        let executor = FakeExecutor::new();
        let mut mutations: Vec<RequestMutation> = vec![
            Box::new(|request| request.command.program = PathBuf::from("/tmp/git")),
            Box::new(|request| {
                request
                    .command
                    .arguments
                    .push("--upload-pack=/tmp/x".to_owned())
            }),
            Box::new(|request| {
                request
                    .command
                    .environment
                    .insert("LD_PRELOAD".to_owned(), "/tmp/x".to_owned());
            }),
        ];
        for mutation in mutations.drain(..) {
            let mut hostile = request(&workspace, uid);
            mutation(&mut hostile);
            let mut service = MaterializerService::new(0, uid).unwrap();
            assert!(matches!(
                serve(&mut service, &hostile, Some(&workspace), &executor),
                Err(MaterializerShimError::InvalidCommand(_))
            ));
        }
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn disconnect_and_timeout_are_refused() {
        let uid = geteuid().as_raw();
        let executor = FakeExecutor::new();
        let (client, mut server) = UnixStream::pair().unwrap();
        drop(client);
        let mut service = MaterializerService::new(0, uid).unwrap();
        assert!(matches!(
            service.serve_authenticated_stream(&mut server, 0, &executor),
            Err(MaterializerShimError::Disconnected)
        ));

        let temporary = tempdir().unwrap();
        let workspace = File::open(temporary.path()).unwrap();
        let frame =
            encode_json_frame(REQUEST_KIND, &request(&workspace, uid), MAX_REQUEST_BYTES).unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        send_raw(
            &mut client,
            &frame[..FRAME_HEADER_BYTES + 8],
            Some(&workspace),
        );
        drop(client);
        let mut service = MaterializerService::new(0, uid).unwrap();
        assert!(matches!(
            service.serve_authenticated_stream(&mut server, 0, &executor),
            Err(MaterializerShimError::Disconnected)
        ));

        let (_client, mut server) = UnixStream::pair().unwrap();
        let mut service = MaterializerService::new(0, uid).unwrap();
        assert!(matches!(
            service.serve_authenticated_stream(&mut server, 0, &executor),
            Err(MaterializerShimError::TimedOut)
        ));
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn service_socket_grammar_is_fixed() {
        assert!(
            validate_socket_path(Path::new("/run/buzzci-lease01-mat/materializer.sock")).is_ok()
        );
        for path in [
            "/tmp/materializer.sock",
            "/run/a/b/materializer.sock",
            "/run/../materializer.sock",
            "/run/lease/other.sock",
        ] {
            assert!(matches!(
                validate_socket_path(Path::new(path)),
                Err(MaterializerShimError::InvalidSocketPath)
            ));
        }
    }
}
