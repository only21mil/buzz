use std::fs::Permissions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;
use nix::errno::Errno;
use nix::sys::signal::{kill, killpg, Signal};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{geteuid, Pid};
use serde::{Deserialize, Serialize};

use crate::host_composition::HostCompositionContract;
use crate::normal_engine::ActLaunchPlan;

use super::handoff_descriptor::{
    configure_stream, decode_header, read_frame, write_frame, Clock, ControllerLeaseIdentity,
    DescriptorReplayGuard, HandoffDescriptor, HandoffIdentity, HandoffOperation, HandoffRole,
    Sequencer, SystemClock, FRAME_HEADER_BYTES, MAX_FRAME_BYTES,
};
use super::{verify_act_binary, ActChild, ActProcessSpawner, ActProxyLaunchError};

const EXECUTOR_REQUEST_KIND: u16 = 10;
const EXECUTOR_RESPONSE_KIND: u16 = 11;
const EXECUTOR_CANCEL_KIND: u16 = 12;
const STOP_DEADLINE: Duration = Duration::from_secs(5);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);
const TERM_GRACE: Duration = Duration::from_secs(2);
const KILL_GRACE: Duration = Duration::from_secs(5);
const ROOT_BROKER_UID: u32 = 0;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutorRequest {
    descriptor: HandoffDescriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan: Option<ActLaunchPlan>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutorResponse {
    schema_version: u16,
    status: String,
    request_id: [u8; 32],
    identity_digest: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_wait_status: Option<i32>,
}

impl ExecutorResponse {
    fn ready(descriptor: &HandoffDescriptor) -> Result<Self, ()> {
        Ok(Self {
            schema_version: 1,
            status: "ready".into(),
            request_id: descriptor.request_id,
            identity_digest: descriptor.identity_digest()?,
            raw_wait_status: None,
        })
    }

    fn started(descriptor: &HandoffDescriptor) -> Result<Self, ()> {
        Ok(Self {
            schema_version: 1,
            status: "started".into(),
            request_id: descriptor.request_id,
            identity_digest: descriptor.identity_digest()?,
            raw_wait_status: None,
        })
    }

    fn exited(descriptor: &HandoffDescriptor, status: ExitStatus) -> Result<Self, ()> {
        Ok(Self {
            schema_version: 1,
            status: "exited".into(),
            request_id: descriptor.request_id,
            identity_digest: descriptor.identity_digest()?,
            raw_wait_status: Some(status.into_raw()),
        })
    }

    fn validate(
        &self,
        expected_status: &str,
        descriptor: &HandoffDescriptor,
    ) -> Result<(), ActProxyLaunchError> {
        if self.schema_version != 1
            || self.status != expected_status
            || self.request_id != descriptor.request_id
            || self.identity_digest
                != descriptor
                    .identity_digest()
                    .map_err(|_| ActProxyLaunchError::Unavailable)?
        {
            return Err(ActProxyLaunchError::Unavailable);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CancelRequest {
    request_id: [u8; 32],
    identity_digest: [u8; 32],
}

pub(super) struct ConnectedStream {
    stream: UnixStream,
    peer_uid: u32,
}

pub(super) trait ExecutorConnector: Send + Sync {
    fn connect(&self, path: &Path) -> io::Result<ConnectedStream>;
}

#[derive(Default)]
struct UnixExecutorConnector;

impl ExecutorConnector for UnixExecutorConnector {
    fn connect(&self, path: &Path) -> io::Result<ConnectedStream> {
        let stream = UnixStream::connect(path)?;
        let peer_uid = getsockopt(&stream, PeerCredentials)
            .map(|credentials| credentials.uid())
            .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        Ok(ConnectedStream { stream, peer_uid })
    }
}

struct PreflightState {
    identity: HandoffIdentity,
}

/// Authenticated handoff into the executor service already created by DNS.
pub struct ExecutorUnitHandoff {
    contract: HostCompositionContract,
    connector: Arc<dyn ExecutorConnector>,
    clock: Arc<dyn Clock>,
    sequence: Sequencer,
    preflight: Mutex<Option<PreflightState>>,
}

impl ExecutorUnitHandoff {
    /// Bind the handoff to the validated root-owned host declaration.
    pub fn new(contract: HostCompositionContract) -> Result<Self, ActProxyLaunchError> {
        contract
            .validate()
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        Ok(Self {
            contract,
            connector: Arc::new(UnixExecutorConnector),
            clock: Arc::new(SystemClock),
            sequence: Sequencer::new(),
            preflight: Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub(super) fn test_with(
        contract: HostCompositionContract,
        connector: Arc<dyn ExecutorConnector>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            contract,
            connector,
            clock,
            sequence: Sequencer::new(),
            preflight: Mutex::new(None),
        }
    }

    fn request(
        &self,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
        operation: HandoffOperation,
        lease: Option<crate::activation::LeaseToken>,
    ) -> Result<ExecutorRequest, ActProxyLaunchError> {
        let identity = HandoffIdentity::from_validated(plan, binding, &self.contract)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let now = self
            .clock
            .now()
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let controller_lease = lease.map(ControllerLeaseIdentity::from_lease);
        if let Some(controller) = &controller_lease {
            controller
                .validate_for(
                    lease.ok_or(ActProxyLaunchError::Unavailable)?,
                    &identity,
                    now,
                )
                .map_err(|_| ActProxyLaunchError::Unavailable)?;
        }
        let descriptor = HandoffDescriptor::issue(
            identity,
            HandoffRole::Executor,
            operation,
            self.sequence
                .next()
                .map_err(|_| ActProxyLaunchError::Unavailable)?,
            now,
            controller_lease,
        )
        .map_err(|_| ActProxyLaunchError::Unavailable)?;
        Ok(ExecutorRequest {
            descriptor,
            plan: (operation == HandoffOperation::Launch).then(|| plan.clone()),
        })
    }

    fn connect(&self, identity: &HandoffIdentity) -> Result<UnixStream, ActProxyLaunchError> {
        let connected = self
            .connector
            .connect(identity.socket(HandoffRole::Executor))
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        if connected.peer_uid != identity.expected_uid(HandoffRole::Executor) {
            return Err(ActProxyLaunchError::Unavailable);
        }
        configure_stream(&connected.stream).map_err(|_| ActProxyLaunchError::Unavailable)?;
        Ok(connected.stream)
    }
}

impl ActProcessSpawner for ExecutorUnitHandoff {
    type Child = ExecutorUnitHandoffChild;

    fn preflight(
        &self,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ActProxyLaunchError> {
        let request = self.request(plan, binding, HandoffOperation::Probe, None)?;
        let mut stream = self.connect(&request.descriptor.identity)?;
        write_frame(&mut stream, EXECUTOR_REQUEST_KIND, &request)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let response: ExecutorResponse = read_frame(&mut stream, EXECUTOR_RESPONSE_KIND)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        response.validate("ready", &request.descriptor)?;
        *self
            .preflight
            .lock()
            .map_err(|_| ActProxyLaunchError::Unavailable)? = Some(PreflightState {
            identity: request.descriptor.identity,
        });
        Ok(())
    }

    fn spawn(
        &mut self,
        lease: crate::activation::LeaseToken,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<Self::Child, ActProxyLaunchError> {
        verify_act_binary(plan)?;
        let request = self.request(plan, binding, HandoffOperation::Launch, Some(lease))?;
        let preflight = self
            .preflight
            .lock()
            .map_err(|_| ActProxyLaunchError::Unavailable)?
            .take()
            .ok_or(ActProxyLaunchError::Unavailable)?;
        if preflight.identity != request.descriptor.identity {
            return Err(ActProxyLaunchError::Unavailable);
        }
        let mut stream = self.connect(&request.descriptor.identity)?;
        write_frame(&mut stream, EXECUTOR_REQUEST_KIND, &request)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let response: ExecutorResponse = read_frame(&mut stream, EXECUTOR_RESPONSE_KIND)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        response.validate("started", &request.descriptor)?;
        stream
            .set_nonblocking(true)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        Ok(ExecutorUnitHandoffChild {
            stream,
            descriptor: request.descriptor,
            reader: ResponseReader::default(),
            terminal: None,
        })
    }
}

/// Broker-side supervision handle for one process inside the executor unit.
pub struct ExecutorUnitHandoffChild {
    stream: UnixStream,
    descriptor: HandoffDescriptor,
    reader: ResponseReader,
    terminal: Option<ExitStatus>,
}

impl ActChild for ExecutorUnitHandoffChild {
    fn try_wait(&mut self) -> Result<Option<ExitStatus>, ActProxyLaunchError> {
        if let Some(status) = self.terminal {
            return Ok(Some(status));
        }
        let Some(response) = self.reader.try_read(&mut self.stream)? else {
            return Ok(None);
        };
        response.validate("exited", &self.descriptor)?;
        let raw = response
            .raw_wait_status
            .ok_or(ActProxyLaunchError::Unavailable)?;
        let status = ExitStatus::from_raw(raw);
        self.terminal = Some(status);
        Ok(Some(status))
    }

    fn stop_and_reap(&mut self) -> Result<(), ActProxyLaunchError> {
        if self.terminal.is_some() {
            return Ok(());
        }
        self.stream
            .set_nonblocking(false)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        configure_stream(&self.stream).map_err(|_| ActProxyLaunchError::Unavailable)?;
        let cancel = CancelRequest {
            request_id: self.descriptor.request_id,
            identity_digest: self
                .descriptor
                .identity_digest()
                .map_err(|_| ActProxyLaunchError::Unavailable)?,
        };
        write_frame(&mut self.stream, EXECUTOR_CANCEL_KIND, &cancel)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        self.stream
            .set_nonblocking(true)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let deadline = Instant::now() + STOP_DEADLINE;
        while Instant::now() < deadline {
            if self.try_wait()?.is_some() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(5));
        }
        Err(ActProxyLaunchError::Unavailable)
    }
}

#[derive(Default)]
struct ResponseReader {
    bytes: Vec<u8>,
    disconnected: bool,
}

impl ResponseReader {
    fn try_read(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<Option<ExecutorResponse>, ActProxyLaunchError> {
        let mut buffer = [0_u8; 4_096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    self.disconnected = true;
                    break;
                }
                Ok(count) => self.bytes.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(ActProxyLaunchError::Unavailable),
            }
        }
        if self.bytes.len() < FRAME_HEADER_BYTES {
            return if self.disconnected {
                Err(ActProxyLaunchError::Unavailable)
            } else {
                Ok(None)
            };
        }
        let length = decode_header(&self.bytes[..FRAME_HEADER_BYTES], EXECUTOR_RESPONSE_KIND)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let frame_length = FRAME_HEADER_BYTES + length;
        if frame_length > FRAME_HEADER_BYTES + MAX_FRAME_BYTES {
            return Err(ActProxyLaunchError::Unavailable);
        }
        if self.bytes.len() < frame_length {
            return if self.disconnected {
                Err(ActProxyLaunchError::Unavailable)
            } else {
                Ok(None)
            };
        }
        if self.bytes.len() != frame_length {
            return Err(ActProxyLaunchError::Unavailable);
        }
        let response = serde_json::from_slice(&self.bytes[FRAME_HEADER_BYTES..frame_length])
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        self.bytes.clear();
        Ok(Some(response))
    }
}

/// Run the fixed executor shim inside a DNS-owned executor service.
pub fn run_executor_handoff_service(socket_path: &Path) -> Result<(), ActProxyLaunchError> {
    validate_socket_path(socket_path, "executor.sock", "-exec")?;
    let effective_uid = geteuid().as_raw();
    if effective_uid == 0 {
        return Err(ActProxyLaunchError::Unavailable);
    }
    validate_runtime_directory(socket_path, effective_uid)?;
    let listener = UnixListener::bind(socket_path).map_err(|_| ActProxyLaunchError::Unavailable)?;
    std::fs::set_permissions(socket_path, Permissions::from_mode(0o600))
        .map_err(|_| ActProxyLaunchError::Unavailable)?;
    let mut replay = DescriptorReplayGuard::default();
    for connection in listener.incoming() {
        let mut stream = connection.map_err(|_| ActProxyLaunchError::Unavailable)?;
        configure_stream(&stream).map_err(|_| ActProxyLaunchError::Unavailable)?;
        let peer =
            getsockopt(&stream, PeerCredentials).map_err(|_| ActProxyLaunchError::Unavailable)?;
        if peer.uid() != ROOT_BROKER_UID {
            continue;
        }
        match serve_request(&mut stream, socket_path, effective_uid, &mut replay) {
            Ok(()) | Err(ServiceRequestError::Rejected) => continue,
            Err(ServiceRequestError::CleanupUnproven) => {
                return Err(ActProxyLaunchError::Unavailable)
            }
        }
    }
    Err(ActProxyLaunchError::Unavailable)
}

fn serve_request(
    stream: &mut UnixStream,
    socket_path: &Path,
    effective_uid: u32,
    replay: &mut DescriptorReplayGuard,
) -> Result<(), ServiceRequestError> {
    let request: ExecutorRequest =
        read_frame(stream, EXECUTOR_REQUEST_KIND).map_err(|_| ServiceRequestError::Rejected)?;
    let now = super::handoff_descriptor::SystemClock
        .now()
        .map_err(|_| ServiceRequestError::Rejected)?;
    request
        .descriptor
        .validate_at(now)
        .map_err(|_| ServiceRequestError::Rejected)?;
    if request.descriptor.role != HandoffRole::Executor
        || request
            .descriptor
            .identity
            .expected_uid(HandoffRole::Executor)
            != effective_uid
    {
        return Err(ServiceRequestError::Rejected);
    }
    request
        .descriptor
        .identity
        .validate_live_service(HandoffRole::Executor, socket_path, effective_uid)
        .map_err(|_| ServiceRequestError::Rejected)?;
    replay
        .accept(&request.descriptor, now)
        .map_err(|_| ServiceRequestError::Rejected)?;
    match (request.descriptor.operation, request.plan) {
        (HandoffOperation::Probe, None) => {
            let response = ExecutorResponse::ready(&request.descriptor)
                .map_err(|_| ServiceRequestError::Rejected)?;
            write_frame(stream, EXECUTOR_RESPONSE_KIND, &response)
                .map_err(|_| ServiceRequestError::Rejected)
        }
        (HandoffOperation::Launch, Some(plan)) => {
            request
                .descriptor
                .identity
                .validate_plan(&plan, effective_uid)
                .map_err(|_| ServiceRequestError::Rejected)?;
            verify_act_binary(&plan).map_err(|_| ServiceRequestError::Rejected)?;
            let argv = plan.argv().map_err(|_| ServiceRequestError::Rejected)?;
            let environment = plan
                .environment()
                .map_err(|_| ServiceRequestError::Rejected)?;
            let controller = request
                .descriptor
                .controller_lease
                .as_ref()
                .ok_or(ServiceRequestError::Rejected)?;
            let budget = controller
                .monotonic_budget(&request.descriptor.identity, now)
                .map_err(|_| ServiceRequestError::Rejected)?;
            let lease_deadline = Instant::now()
                .checked_add(budget)
                .ok_or(ServiceRequestError::Rejected)?;
            let mut command = Command::new(&plan.binary);
            command
                .args(argv)
                .current_dir(&plan.working_directory)
                .env_clear()
                .envs(environment)
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut child = command.spawn().map_err(|_| ServiceRequestError::Rejected)?;
            supervise_launched_child(
                stream,
                &request.descriptor,
                &mut child,
                &mut SystemProcessGroup,
                lease_deadline,
                CleanupPolicy::production(),
            )
        }
        _ => Err(ServiceRequestError::Rejected),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceRequestError {
    Rejected,
    CleanupUnproven,
}

trait ManagedChild {
    fn process_id(&self) -> u32;
    fn try_wait_managed(&mut self) -> io::Result<Option<ExitStatus>>;
}

impl ManagedChild for std::process::Child {
    fn process_id(&self) -> u32 {
        self.id()
    }

    fn try_wait_managed(&mut self) -> io::Result<Option<ExitStatus>> {
        self.try_wait()
    }
}

trait ProcessGroupControl {
    fn probe(&mut self, process_group: Pid) -> Result<(), Errno>;
    fn signal(&mut self, process_group: Pid, signal: Signal) -> Result<(), Errno>;
}

struct SystemProcessGroup;

impl ProcessGroupControl for SystemProcessGroup {
    fn probe(&mut self, process_group: Pid) -> Result<(), Errno> {
        kill(Pid::from_raw(-process_group.as_raw()), None)
    }

    fn signal(&mut self, process_group: Pid, signal: Signal) -> Result<(), Errno> {
        killpg(process_group, signal)
    }
}

#[derive(Clone, Copy)]
struct CleanupPolicy {
    term_grace: Duration,
    kill_grace: Duration,
    poll_interval: Duration,
}

impl CleanupPolicy {
    const fn production() -> Self {
        Self {
            term_grace: TERM_GRACE,
            kill_grace: KILL_GRACE,
            poll_interval: CHILD_POLL_INTERVAL,
        }
    }
}

fn supervise_launched_child<C: ManagedChild, G: ProcessGroupControl>(
    stream: &mut UnixStream,
    descriptor: &HandoffDescriptor,
    child: &mut C,
    process_group: &mut G,
    lease_deadline: Instant,
    cleanup_policy: CleanupPolicy,
) -> Result<(), ServiceRequestError> {
    let started = ExecutorResponse::started(descriptor)
        .map_err(|_| cleanup_after_failure(child, process_group, cleanup_policy))?;
    if write_frame(stream, EXECUTOR_RESPONSE_KIND, &started).is_err() {
        return Err(cleanup_after_failure(child, process_group, cleanup_policy));
    }
    if stream.set_nonblocking(true).is_err() {
        return Err(cleanup_after_failure(child, process_group, cleanup_policy));
    }
    let mut cancel_reader = CancelReader::default();
    let status = loop {
        match child.try_wait_managed() {
            Ok(Some(status)) => {
                break cleanup_process_group(child, process_group, Some(status), cleanup_policy)
                    .map_err(|_| ServiceRequestError::CleanupUnproven)?;
            }
            Ok(None) => {}
            Err(_) => {
                return Err(cleanup_after_failure(child, process_group, cleanup_policy));
            }
        }
        if Instant::now() >= lease_deadline {
            break cleanup_process_group(child, process_group, None, cleanup_policy)
                .map_err(|_| ServiceRequestError::CleanupUnproven)?;
        }
        match cancel_reader.try_read(stream) {
            Ok(Some(cancel)) => {
                let valid = descriptor.identity_digest().is_ok_and(|digest| {
                    cancel.request_id == descriptor.request_id && cancel.identity_digest == digest
                });
                if !valid {
                    return Err(cleanup_after_failure(child, process_group, cleanup_policy));
                }
                break cleanup_process_group(child, process_group, None, cleanup_policy)
                    .map_err(|_| ServiceRequestError::CleanupUnproven)?;
            }
            Ok(None) => {}
            Err(_) => {
                return Err(cleanup_after_failure(child, process_group, cleanup_policy));
            }
        }
        thread::sleep(CHILD_POLL_INTERVAL);
    };
    if stream.set_nonblocking(false).is_err() {
        return Err(ServiceRequestError::Rejected);
    }
    let exited =
        ExecutorResponse::exited(descriptor, status).map_err(|_| ServiceRequestError::Rejected)?;
    write_frame(stream, EXECUTOR_RESPONSE_KIND, &exited).map_err(|_| ServiceRequestError::Rejected)
}

fn cleanup_after_failure<C: ManagedChild, G: ProcessGroupControl>(
    child: &mut C,
    process_group: &mut G,
    policy: CleanupPolicy,
) -> ServiceRequestError {
    match cleanup_process_group(child, process_group, None, policy) {
        Ok(_) => ServiceRequestError::Rejected,
        Err(()) => ServiceRequestError::CleanupUnproven,
    }
}

fn cleanup_process_group<C: ManagedChild, G: ProcessGroupControl>(
    child: &mut C,
    process_group: &mut G,
    mut terminal: Option<ExitStatus>,
    policy: CleanupPolicy,
) -> Result<ExitStatus, ()> {
    let raw_pid = i32::try_from(child.process_id()).map_err(|_| ())?;
    if raw_pid <= 0 {
        return Err(());
    }
    let process_group_id = Pid::from_raw(raw_pid);
    if let Ok(Some(status)) = observe_cleanup(child, process_group, process_group_id, &mut terminal)
    {
        return Ok(status);
    }

    let _ = process_group.signal(process_group_id, Signal::SIGTERM);
    if let Ok(Some(status)) = wait_for_cleanup(
        child,
        process_group,
        process_group_id,
        &mut terminal,
        policy.term_grace,
        policy.poll_interval,
    ) {
        return Ok(status);
    }

    let _ = process_group.signal(process_group_id, Signal::SIGKILL);
    wait_for_cleanup(
        child,
        process_group,
        process_group_id,
        &mut terminal,
        policy.kill_grace,
        policy.poll_interval,
    )?
    .ok_or(())
}

fn wait_for_cleanup<C: ManagedChild, G: ProcessGroupControl>(
    child: &mut C,
    process_group: &mut G,
    process_group_id: Pid,
    terminal: &mut Option<ExitStatus>,
    grace: Duration,
    poll_interval: Duration,
) -> Result<Option<ExitStatus>, ()> {
    let deadline = Instant::now().checked_add(grace).ok_or(())?;
    loop {
        if let Some(status) = observe_cleanup(child, process_group, process_group_id, terminal)? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(poll_interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn observe_cleanup<C: ManagedChild, G: ProcessGroupControl>(
    child: &mut C,
    process_group: &mut G,
    process_group_id: Pid,
    terminal: &mut Option<ExitStatus>,
) -> Result<Option<ExitStatus>, ()> {
    if terminal.is_none() {
        *terminal = child.try_wait_managed().map_err(|_| ())?;
    }
    let group_absent = match process_group.probe(process_group_id) {
        Err(Errno::ESRCH) => true,
        Ok(()) => false,
        Err(_) => return Err(()),
    };
    Ok(if group_absent { *terminal } else { None })
}

#[derive(Default)]
struct CancelReader {
    bytes: Vec<u8>,
}

impl CancelReader {
    fn try_read(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<Option<CancelRequest>, ActProxyLaunchError> {
        let mut buffer = [0_u8; 4_096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => return Err(ActProxyLaunchError::Unavailable),
                Ok(count) => self.bytes.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(ActProxyLaunchError::Unavailable),
            }
        }
        if self.bytes.len() < FRAME_HEADER_BYTES {
            return Ok(None);
        }
        let length = decode_header(&self.bytes[..FRAME_HEADER_BYTES], EXECUTOR_CANCEL_KIND)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let frame_length = FRAME_HEADER_BYTES + length;
        if self.bytes.len() < frame_length {
            return Ok(None);
        }
        if self.bytes.len() != frame_length {
            return Err(ActProxyLaunchError::Unavailable);
        }
        let cancel = serde_json::from_slice(&self.bytes[FRAME_HEADER_BYTES..frame_length])
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        self.bytes.clear();
        Ok(Some(cancel))
    }
}

fn validate_socket_path(
    path: &Path,
    filename: &str,
    suffix: &str,
) -> Result<(), ActProxyLaunchError> {
    let runtime = path
        .parent()
        .filter(|parent| parent.parent() == Some(Path::new("/run")))
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .filter(|name| name.ends_with(suffix))
        .filter(|name| {
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        });
    if runtime.is_none() || path.file_name().and_then(|name| name.to_str()) != Some(filename) {
        return Err(ActProxyLaunchError::Unavailable);
    }
    Ok(())
}

fn validate_runtime_directory(path: &Path, effective_uid: u32) -> Result<(), ActProxyLaunchError> {
    let metadata =
        std::fs::symlink_metadata(path.parent().ok_or(ActProxyLaunchError::Unavailable)?)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(ActProxyLaunchError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use crate::host_composition::HostCompositionContract;
    use crate::normal_engine::tests::ordinary_fixture;

    use super::super::handoff_descriptor::FixedClock;
    use super::*;

    #[derive(Default)]
    struct FakeProcessState {
        exited: bool,
        reaped: bool,
        group_alive: bool,
        fail_signals: bool,
        signals: Vec<Signal>,
    }

    struct FakeChild {
        pid: u32,
        state: Arc<Mutex<FakeProcessState>>,
    }

    impl ManagedChild for FakeChild {
        fn process_id(&self) -> u32 {
            self.pid
        }

        fn try_wait_managed(&mut self) -> io::Result<Option<ExitStatus>> {
            let mut state = self.state.lock().unwrap();
            if state.exited {
                state.reaped = true;
                Ok(Some(ExitStatus::from_raw(9)))
            } else {
                Ok(None)
            }
        }
    }

    struct FakeProcessGroup {
        state: Arc<Mutex<FakeProcessState>>,
    }

    impl ProcessGroupControl for FakeProcessGroup {
        fn probe(&mut self, _process_group: Pid) -> Result<(), Errno> {
            if self.state.lock().unwrap().group_alive {
                Ok(())
            } else {
                Err(Errno::ESRCH)
            }
        }

        fn signal(&mut self, _process_group: Pid, signal: Signal) -> Result<(), Errno> {
            let mut state = self.state.lock().unwrap();
            state.signals.push(signal);
            if state.fail_signals {
                return Err(Errno::EPERM);
            }
            if signal == Signal::SIGKILL {
                state.group_alive = false;
                state.exited = true;
            }
            Ok(())
        }
    }

    fn fake_process(
        fail_signals: bool,
    ) -> (FakeChild, FakeProcessGroup, Arc<Mutex<FakeProcessState>>) {
        let state = Arc::new(Mutex::new(FakeProcessState {
            group_alive: true,
            fail_signals,
            ..FakeProcessState::default()
        }));
        (
            FakeChild {
                pid: 42,
                state: Arc::clone(&state),
            },
            FakeProcessGroup {
                state: Arc::clone(&state),
            },
            state,
        )
    }

    fn immediate_cleanup() -> CleanupPolicy {
        CleanupPolicy {
            term_grace: Duration::ZERO,
            kill_grace: Duration::ZERO,
            poll_interval: Duration::ZERO,
        }
    }

    struct QueueConnector {
        streams: Mutex<VecDeque<ConnectedStream>>,
    }

    impl QueueConnector {
        fn one(stream: UnixStream, peer_uid: u32) -> Self {
            Self {
                streams: Mutex::new(VecDeque::from([ConnectedStream { stream, peer_uid }])),
            }
        }

        fn empty() -> Self {
            Self {
                streams: Mutex::new(VecDeque::new()),
            }
        }
    }

    impl ExecutorConnector for QueueConnector {
        fn connect(&self, _path: &Path) -> io::Result<ConnectedStream> {
            self.streams
                .lock()
                .map_err(|_| io::Error::other("poisoned connector"))?
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing socket"))
        }
    }

    fn contract(binding: &ValidatedAttemptLeaseBinding) -> HostCompositionContract {
        let binding = binding.as_binding();
        HostCompositionContract {
            schema_version: 1,
            revision: 1,
            executor_uid: binding.principals.executor,
            runtime_uid: binding.principals.runtime,
            executor_socket_template: "/run/buzzci-{lease_id}-exec/executor.sock".into(),
            runtime_socket_template: "/run/buzzci-{lease_id}-runtime/runtime.sock".into(),
            materialization_authority_root: "/var/lib/buzz-ci/materialization".into(),
            proxy_authority_root: "/var/lib/buzz-ci/proxy".into(),
            terminal_evidence_root: "/var/lib/buzz-ci/terminal".into(),
            teardown_authority_root: "/var/lib/buzz-ci/teardown".into(),
            qualification_lease_root: "/var/lib/buzz-ci/qualification-leases".into(),
            qualification_binding_root: "/var/lib/buzz-ci/qualification-bindings".into(),
            qualification_handoff_root: "/var/lib/buzz-ci/qualification-handoffs".into(),
            qualification_readback_root: "/var/lib/buzz-ci/qualification-readbacks".into(),
            proved_invariants: crate::host_composition::REQUIRED_HOST_INVARIANTS
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }

    fn launch_descriptor(
        fixture: &crate::normal_engine::tests::OrdinaryFixture,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> HandoffDescriptor {
        let identity =
            HandoffIdentity::from_validated(&fixture.plan.act, binding, &contract(binding))
                .unwrap();
        HandoffDescriptor::issue(
            identity,
            HandoffRole::Executor,
            HandoffOperation::Launch,
            1,
            20,
            Some(ControllerLeaseIdentity::from_lease(fixture.lease)),
        )
        .unwrap()
    }

    fn assert_cleanup_proved(state: &Arc<Mutex<FakeProcessState>>) {
        let state = state.lock().unwrap();
        assert!(state.reaped);
        assert!(!state.group_alive);
        assert_eq!(state.signals, [Signal::SIGTERM, Signal::SIGKILL]);
    }

    #[test]
    fn authenticated_probe_binds_the_dns_owned_executor_unit() {
        let fixture = ordinary_fixture();
        let binding = fixture
            .plan
            .binding
            .clone()
            .validate_phase1(&fixture.plan.validation.context())
            .unwrap();
        let expected_uid = binding.as_binding().principals.executor;
        let (client, mut server) = UnixStream::pair().unwrap();
        let service = thread::spawn(move || {
            let request: ExecutorRequest = read_frame(&mut server, EXECUTOR_REQUEST_KIND).unwrap();
            assert_eq!(request.descriptor.operation, HandoffOperation::Probe);
            assert!(request.plan.is_none());
            let response = ExecutorResponse::ready(&request.descriptor).unwrap();
            write_frame(&mut server, EXECUTOR_RESPONSE_KIND, &response).unwrap();
        });
        let handoff = ExecutorUnitHandoff::test_with(
            contract(&binding),
            Arc::new(QueueConnector::one(client, expected_uid)),
            Arc::new(FixedClock(20)),
        );

        handoff.preflight(&fixture.plan.act, &binding).unwrap();
        service.join().unwrap();
    }

    #[test]
    fn missing_socket_and_wrong_peer_fail_before_handoff() {
        let fixture = ordinary_fixture();
        let binding = fixture
            .plan
            .binding
            .clone()
            .validate_phase1(&fixture.plan.validation.context())
            .unwrap();
        let missing = ExecutorUnitHandoff::test_with(
            contract(&binding),
            Arc::new(QueueConnector::empty()),
            Arc::new(FixedClock(20)),
        );
        assert_eq!(
            missing.preflight(&fixture.plan.act, &binding),
            Err(ActProxyLaunchError::Unavailable)
        );

        let (client, _server) = UnixStream::pair().unwrap();
        let wrong_peer = ExecutorUnitHandoff::test_with(
            contract(&binding),
            Arc::new(QueueConnector::one(client, u32::MAX)),
            Arc::new(FixedClock(20)),
        );
        assert_eq!(
            wrong_peer.preflight(&fixture.plan.act, &binding),
            Err(ActProxyLaunchError::Unavailable)
        );
    }

    #[test]
    fn initial_response_write_failure_unconditionally_kills_and_reaps() {
        let fixture = ordinary_fixture();
        let binding = fixture
            .plan
            .binding
            .clone()
            .validate_phase1(&fixture.plan.validation.context())
            .unwrap();
        let descriptor = launch_descriptor(&fixture, &binding);
        let (mut service, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let (mut child, mut group, state) = fake_process(false);

        assert_eq!(
            supervise_launched_child(
                &mut service,
                &descriptor,
                &mut child,
                &mut group,
                Instant::now() + Duration::from_secs(1),
                immediate_cleanup(),
            ),
            Err(ServiceRequestError::Rejected)
        );
        assert_cleanup_proved(&state);
    }

    #[test]
    fn disconnect_and_malformed_cancel_cannot_orphan_the_process_group() {
        for malformed in [false, true] {
            let fixture = ordinary_fixture();
            let binding = fixture
                .plan
                .binding
                .clone()
                .validate_phase1(&fixture.plan.validation.context())
                .unwrap();
            let descriptor = launch_descriptor(&fixture, &binding);
            let (mut service, mut peer) = UnixStream::pair().unwrap();
            let (mut child, mut group, state) = fake_process(false);
            let descriptor_for_service = descriptor.clone();
            let worker = thread::spawn(move || {
                supervise_launched_child(
                    &mut service,
                    &descriptor_for_service,
                    &mut child,
                    &mut group,
                    Instant::now() + Duration::from_secs(1),
                    immediate_cleanup(),
                )
            });
            let _: ExecutorResponse = read_frame(&mut peer, EXECUTOR_RESPONSE_KIND).unwrap();
            let result = if malformed {
                write_frame(&mut peer, EXECUTOR_CANCEL_KIND, &"malformed").unwrap();
                worker.join().unwrap()
            } else {
                drop(peer);
                worker.join().unwrap()
            };

            assert_eq!(result, Err(ServiceRequestError::Rejected));
            assert_cleanup_proved(&state);
        }
    }

    #[test]
    fn valid_cancel_and_monotonic_deadline_both_kill_and_reap() {
        for deadline_expired in [false, true] {
            let fixture = ordinary_fixture();
            let binding = fixture
                .plan
                .binding
                .clone()
                .validate_phase1(&fixture.plan.validation.context())
                .unwrap();
            let descriptor = launch_descriptor(&fixture, &binding);
            let (mut service, mut peer) = UnixStream::pair().unwrap();
            let (mut child, mut group, state) = fake_process(false);
            let descriptor_for_service = descriptor.clone();
            let worker = thread::spawn(move || {
                supervise_launched_child(
                    &mut service,
                    &descriptor_for_service,
                    &mut child,
                    &mut group,
                    if deadline_expired {
                        Instant::now()
                    } else {
                        Instant::now() + Duration::from_secs(1)
                    },
                    immediate_cleanup(),
                )
            });
            let _: ExecutorResponse = read_frame(&mut peer, EXECUTOR_RESPONSE_KIND).unwrap();
            if !deadline_expired {
                let cancel = CancelRequest {
                    request_id: descriptor.request_id,
                    identity_digest: descriptor.identity_digest().unwrap(),
                };
                write_frame(&mut peer, EXECUTOR_CANCEL_KIND, &cancel).unwrap();
            }
            let exited: ExecutorResponse = read_frame(&mut peer, EXECUTOR_RESPONSE_KIND).unwrap();
            assert_eq!(exited.status, "exited");

            assert_eq!(worker.join().unwrap(), Ok(()));
            assert_cleanup_proved(&state);
        }
    }

    #[test]
    fn unprovable_kill_fails_the_service_closed() {
        let fixture = ordinary_fixture();
        let binding = fixture
            .plan
            .binding
            .clone()
            .validate_phase1(&fixture.plan.validation.context())
            .unwrap();
        let descriptor = launch_descriptor(&fixture, &binding);
        let (mut service, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let (mut child, mut group, state) = fake_process(true);

        assert_eq!(
            supervise_launched_child(
                &mut service,
                &descriptor,
                &mut child,
                &mut group,
                Instant::now() + Duration::from_secs(1),
                immediate_cleanup(),
            ),
            Err(ServiceRequestError::CleanupUnproven)
        );
        let state = state.lock().unwrap();
        assert!(!state.reaped);
        assert!(state.group_alive);
        assert_eq!(state.signals, [Signal::SIGTERM, Signal::SIGKILL]);
    }
}
