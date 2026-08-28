use std::fs::Permissions;
use std::io::{self, IoSlice, IoSliceMut, Read};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::geteuid;
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use serde::{Deserialize, Serialize};

use crate::activation::LeaseToken;
use crate::host_composition::HostCompositionContract;
use crate::normal_engine::ActLaunchPlan;

use super::handoff_descriptor::{
    configure_stream, decode_header, encode_frame, read_frame, write_frame, Clock,
    ControllerLeaseIdentity, DescriptorReplayGuard, HandoffDescriptor, HandoffIdentity,
    HandoffOperation, HandoffRole, Sequencer, SystemClock, FRAME_HEADER_BYTES, MAX_FRAME_BYTES,
};
use super::{ActProxyLaunchError, ActRuntimeDescriptorSource};

const RUNTIME_REQUEST_KIND: u16 = 20;
const RUNTIME_RESPONSE_KIND: u16 = 21;
const ROOT_BROKER_UID: u32 = 0;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRequest {
    descriptor: HandoffDescriptor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeResponse {
    schema_version: u16,
    status: String,
    request_id: [u8; 32],
    identity_digest: [u8; 32],
    descriptor_count: u8,
}

impl RuntimeResponse {
    fn ready(descriptor: &HandoffDescriptor) -> Result<Self, ()> {
        Ok(Self {
            schema_version: 1,
            status: "ready".into(),
            request_id: descriptor.request_id,
            identity_digest: descriptor.identity_digest()?,
            descriptor_count: 0,
        })
    }

    fn descriptor(descriptor: &HandoffDescriptor) -> Result<Self, ()> {
        Ok(Self {
            schema_version: 1,
            status: "descriptor".into(),
            request_id: descriptor.request_id,
            identity_digest: descriptor.identity_digest()?,
            descriptor_count: 1,
        })
    }

    fn validate(
        &self,
        status: &str,
        count: u8,
        descriptor: &HandoffDescriptor,
    ) -> Result<(), ActProxyLaunchError> {
        if self.schema_version != 1
            || self.status != status
            || self.descriptor_count != count
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

pub(super) struct ConnectedStream {
    stream: UnixStream,
    peer_uid: u32,
}

pub(super) trait RuntimeConnector: Send + Sync {
    fn connect(&self, path: &Path) -> io::Result<ConnectedStream>;
}

#[derive(Default)]
struct UnixRuntimeConnector;

impl RuntimeConnector for UnixRuntimeConnector {
    fn connect(&self, path: &Path) -> io::Result<ConnectedStream> {
        let stream = UnixStream::connect(path)?;
        let peer_uid = getsockopt(&stream, PeerCredentials)
            .map(|credentials| credentials.uid())
            .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        Ok(ConnectedStream { stream, peer_uid })
    }
}

struct RuntimeState {
    identity: HandoffIdentity,
}

/// Fresh one-shot Podman descriptor provider for the DNS-owned runtime unit.
pub struct RuntimeDescriptorProvider {
    contract: HostCompositionContract,
    connector: Arc<dyn RuntimeConnector>,
    clock: Arc<dyn Clock>,
    sequence: Sequencer,
    state: Mutex<Option<RuntimeState>>,
}

impl RuntimeDescriptorProvider {
    /// Bind the provider to the validated root-owned host declaration.
    pub fn new(contract: HostCompositionContract) -> Result<Self, ActProxyLaunchError> {
        contract
            .validate()
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        Ok(Self {
            contract,
            connector: Arc::new(UnixRuntimeConnector),
            clock: Arc::new(SystemClock),
            sequence: Sequencer::new(),
            state: Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub(super) fn test_with(
        contract: HostCompositionContract,
        connector: Arc<dyn RuntimeConnector>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            contract,
            connector,
            clock,
            sequence: Sequencer::new(),
            state: Mutex::new(None),
        }
    }

    fn connect(&self, identity: &HandoffIdentity) -> Result<UnixStream, ActProxyLaunchError> {
        let connected = self
            .connector
            .connect(identity.socket(HandoffRole::Runtime))
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        if connected.peer_uid != identity.expected_uid(HandoffRole::Runtime) {
            return Err(ActProxyLaunchError::Unavailable);
        }
        configure_stream(&connected.stream).map_err(|_| ActProxyLaunchError::Unavailable)?;
        Ok(connected.stream)
    }

    fn descriptor(
        &self,
        identity: HandoffIdentity,
        operation: HandoffOperation,
        controller_lease: Option<ControllerLeaseIdentity>,
    ) -> Result<HandoffDescriptor, ActProxyLaunchError> {
        let now = self
            .clock
            .now()
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        HandoffDescriptor::issue(
            identity,
            HandoffRole::Runtime,
            operation,
            self.sequence
                .next()
                .map_err(|_| ActProxyLaunchError::Unavailable)?,
            now,
            controller_lease,
        )
        .map_err(|_| ActProxyLaunchError::Unavailable)
    }
}

impl ActRuntimeDescriptorSource for RuntimeDescriptorProvider {
    fn preflight(
        &self,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ActProxyLaunchError> {
        let identity = HandoffIdentity::from_validated(plan, binding, &self.contract)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let descriptor = self.descriptor(identity.clone(), HandoffOperation::Probe, None)?;
        let request = RuntimeRequest { descriptor };
        let mut stream = self.connect(&identity)?;
        write_frame(&mut stream, RUNTIME_REQUEST_KIND, &request)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let response: RuntimeResponse = read_frame(&mut stream, RUNTIME_RESPONSE_KIND)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        response.validate("ready", 0, &request.descriptor)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        if state
            .as_ref()
            .is_some_and(|bound| bound.identity != identity)
        {
            return Err(ActProxyLaunchError::Unavailable);
        }
        *state = Some(RuntimeState { identity });
        Ok(())
    }

    fn next_upstream(
        &mut self,
        lease: LeaseToken,
        deadline: Instant,
    ) -> Result<UnixStream, ActProxyLaunchError> {
        if Instant::now() >= deadline {
            return Err(ActProxyLaunchError::Unavailable);
        }
        let now = self
            .clock
            .now()
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let identity = {
            let state = self
                .state
                .lock()
                .map_err(|_| ActProxyLaunchError::Unavailable)?;
            let state = state.as_ref().ok_or(ActProxyLaunchError::Unavailable)?;
            state.identity.clone()
        };
        let controller = ControllerLeaseIdentity::from_lease(lease);
        controller
            .validate_for(lease, &identity, now)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let descriptor = self.descriptor(
            identity.clone(),
            HandoffOperation::AcquireRuntime,
            Some(controller),
        )?;
        let request = RuntimeRequest { descriptor };
        let mut stream = self.connect(&identity)?;
        write_frame(&mut stream, RUNTIME_REQUEST_KIND, &request)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let (response, descriptors) = receive_response_with_descriptors(&mut stream)?;
        response.validate("descriptor", 1, &request.descriptor)?;
        if descriptors.len() != 1 {
            return Err(ActProxyLaunchError::Unavailable);
        }
        let upstream = UnixStream::from(
            descriptors
                .into_iter()
                .next()
                .ok_or(ActProxyLaunchError::Unavailable)?,
        );
        let peer =
            getsockopt(&upstream, PeerCredentials).map_err(|_| ActProxyLaunchError::Unavailable)?;
        if peer.uid() != identity.expected_uid(HandoffRole::Runtime) {
            return Err(ActProxyLaunchError::Unavailable);
        }
        Ok(upstream)
    }
}

/// Supplies a fresh already-connected rootless runtime descriptor.
pub trait RuntimeDescriptorOpener {
    fn open(&mut self) -> io::Result<UnixStream>;
}

/// Run the fixed descriptor broker inside a DNS-owned runtime service.
pub fn run_runtime_descriptor_service<O: RuntimeDescriptorOpener>(
    socket_path: &Path,
    opener: &mut O,
) -> Result<(), ActProxyLaunchError> {
    validate_socket_path(socket_path)?;
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
        if serve_request(&mut stream, socket_path, effective_uid, &mut replay, opener).is_err() {
            continue;
        }
    }
    Err(ActProxyLaunchError::Unavailable)
}

fn serve_request<O: RuntimeDescriptorOpener>(
    stream: &mut UnixStream,
    socket_path: &Path,
    effective_uid: u32,
    replay: &mut DescriptorReplayGuard,
    opener: &mut O,
) -> Result<(), ActProxyLaunchError> {
    let request: RuntimeRequest =
        read_frame(stream, RUNTIME_REQUEST_KIND).map_err(|_| ActProxyLaunchError::Unavailable)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ActProxyLaunchError::Unavailable)?
        .as_secs();
    if request.descriptor.role != HandoffRole::Runtime
        || request
            .descriptor
            .identity
            .expected_uid(HandoffRole::Runtime)
            != effective_uid
    {
        return Err(ActProxyLaunchError::Unavailable);
    }
    request
        .descriptor
        .identity
        .validate_live_service(HandoffRole::Runtime, socket_path, effective_uid)
        .map_err(|_| ActProxyLaunchError::Unavailable)?;
    replay
        .accept(&request.descriptor, now)
        .map_err(|_| ActProxyLaunchError::Unavailable)?;
    match request.descriptor.operation {
        HandoffOperation::Probe if request.descriptor.controller_lease.is_none() => {
            let response = RuntimeResponse::ready(&request.descriptor)
                .map_err(|_| ActProxyLaunchError::Unavailable)?;
            write_frame(stream, RUNTIME_RESPONSE_KIND, &response)
                .map_err(|_| ActProxyLaunchError::Unavailable)
        }
        HandoffOperation::AcquireRuntime if request.descriptor.controller_lease.is_some() => {
            let upstream = opener
                .open()
                .map_err(|_| ActProxyLaunchError::Unavailable)?;
            let peer = getsockopt(&upstream, PeerCredentials)
                .map_err(|_| ActProxyLaunchError::Unavailable)?;
            if peer.uid() != effective_uid {
                return Err(ActProxyLaunchError::Unavailable);
            }
            let response = RuntimeResponse::descriptor(&request.descriptor)
                .map_err(|_| ActProxyLaunchError::Unavailable)?;
            send_response_with_descriptor(stream, &response, &upstream)
        }
        _ => Err(ActProxyLaunchError::Unavailable),
    }
}

fn receive_response_with_descriptors(
    stream: &mut UnixStream,
) -> Result<(RuntimeResponse, Vec<OwnedFd>), ActProxyLaunchError> {
    let mut bytes = vec![0_u8; FRAME_HEADER_BYTES + MAX_FRAME_BYTES];
    let mut iov = [IoSliceMut::new(&mut bytes)];
    let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut ancillary_space);
    let message = recvmsg(
        stream.as_fd(),
        &mut iov,
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| ActProxyLaunchError::Unavailable)?;
    if message.bytes == 0 || message.flags.contains(ReturnFlags::CTRUNC) {
        return Err(ActProxyLaunchError::Unavailable);
    }
    let received = message.bytes;
    let mut descriptors = Vec::new();
    for control in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(rights) = control {
            descriptors.extend(rights);
        }
    }
    if received < FRAME_HEADER_BYTES {
        stream
            .read_exact(&mut bytes[received..FRAME_HEADER_BYTES])
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
    }
    let length = decode_header(&bytes[..FRAME_HEADER_BYTES], RUNTIME_RESPONSE_KIND)
        .map_err(|_| ActProxyLaunchError::Unavailable)?;
    let frame_length = FRAME_HEADER_BYTES + length;
    if received > frame_length {
        return Err(ActProxyLaunchError::Unavailable);
    }
    if received < frame_length {
        stream
            .read_exact(&mut bytes[received..frame_length])
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
    }
    let response = serde_json::from_slice(&bytes[FRAME_HEADER_BYTES..frame_length])
        .map_err(|_| ActProxyLaunchError::Unavailable)?;
    Ok((response, descriptors))
}

fn send_response_with_descriptor(
    stream: &mut UnixStream,
    response: &RuntimeResponse,
    descriptor: &UnixStream,
) -> Result<(), ActProxyLaunchError> {
    let frame = encode_frame(RUNTIME_RESPONSE_KIND, response)
        .map_err(|_| ActProxyLaunchError::Unavailable)?;
    let descriptors = [descriptor.as_fd()];
    let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut ancillary_space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(ActProxyLaunchError::Unavailable);
    }
    let sent = sendmsg(
        stream.as_fd(),
        &[IoSlice::new(&frame)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(|_| ActProxyLaunchError::Unavailable)?;
    if sent != frame.len() {
        return Err(ActProxyLaunchError::Unavailable);
    }
    Ok(())
}

fn validate_socket_path(path: &Path) -> Result<(), ActProxyLaunchError> {
    let runtime = path
        .parent()
        .filter(|parent| parent.parent() == Some(Path::new("/run")))
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .filter(|name| name.ends_with("-runtime"))
        .filter(|name| {
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        });
    if runtime.is_none() || path.file_name().and_then(|name| name.to_str()) != Some("runtime.sock")
    {
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
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    use crate::host_composition::HostCompositionContract;
    use crate::normal_engine::tests::ordinary_fixture;

    use super::super::handoff_descriptor::FixedClock;
    use super::*;

    struct QueueConnector {
        streams: Mutex<VecDeque<ConnectedStream>>,
    }

    impl QueueConnector {
        fn new(streams: impl IntoIterator<Item = (UnixStream, u32)>) -> Self {
            Self {
                streams: Mutex::new(
                    streams
                        .into_iter()
                        .map(|(stream, peer_uid)| ConnectedStream { stream, peer_uid })
                        .collect(),
                ),
            }
        }
    }

    impl RuntimeConnector for QueueConnector {
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

    fn fixture_binding() -> (
        crate::normal_engine::tests::OrdinaryFixture,
        ValidatedAttemptLeaseBinding,
    ) {
        let fixture = ordinary_fixture();
        let binding = fixture
            .plan
            .binding
            .clone()
            .validate_phase1(&fixture.plan.validation.context())
            .unwrap();
        (fixture, binding)
    }

    #[test]
    fn runtime_provider_returns_one_authenticated_fresh_descriptor() {
        let (fixture, binding) = fixture_binding();
        let runtime_uid = binding.as_binding().principals.runtime;
        let (probe_client, mut probe_server) = UnixStream::pair().unwrap();
        let probe = thread::spawn(move || {
            let request: RuntimeRequest =
                read_frame(&mut probe_server, RUNTIME_REQUEST_KIND).unwrap();
            let response = RuntimeResponse::ready(&request.descriptor).unwrap();
            write_frame(&mut probe_server, RUNTIME_RESPONSE_KIND, &response).unwrap();
        });
        let (acquire_client, mut acquire_server) = UnixStream::pair().unwrap();
        let acquire = thread::spawn(move || {
            let request: RuntimeRequest =
                read_frame(&mut acquire_server, RUNTIME_REQUEST_KIND).unwrap();
            assert_eq!(
                request.descriptor.operation,
                HandoffOperation::AcquireRuntime
            );
            assert!(request.descriptor.controller_lease.is_some());
            let response = RuntimeResponse::descriptor(&request.descriptor).unwrap();
            let (upstream, _peer) = UnixStream::pair().unwrap();
            send_response_with_descriptor(&mut acquire_server, &response, &upstream).unwrap();
        });
        let connector = Arc::new(QueueConnector::new([
            (probe_client, runtime_uid),
            (acquire_client, runtime_uid),
        ]));
        let mut provider = RuntimeDescriptorProvider::test_with(
            contract(&binding),
            connector,
            Arc::new(FixedClock(20)),
        );

        provider.preflight(&fixture.plan.act, &binding).unwrap();
        let upstream = provider
            .next_upstream(fixture.lease, Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            getsockopt(&upstream, PeerCredentials).unwrap().uid(),
            runtime_uid
        );
        probe.join().unwrap();
        acquire.join().unwrap();
    }

    #[test]
    fn missing_or_mismatched_runtime_descriptor_fails_closed() {
        let (fixture, binding) = fixture_binding();
        let runtime_uid = binding.as_binding().principals.runtime;
        let (probe_client, mut probe_server) = UnixStream::pair().unwrap();
        let probe = thread::spawn(move || {
            let request: RuntimeRequest =
                read_frame(&mut probe_server, RUNTIME_REQUEST_KIND).unwrap();
            let response = RuntimeResponse::ready(&request.descriptor).unwrap();
            write_frame(&mut probe_server, RUNTIME_RESPONSE_KIND, &response).unwrap();
        });
        let (acquire_client, mut acquire_server) = UnixStream::pair().unwrap();
        let acquire = thread::spawn(move || {
            let request: RuntimeRequest =
                read_frame(&mut acquire_server, RUNTIME_REQUEST_KIND).unwrap();
            let response = RuntimeResponse::descriptor(&request.descriptor).unwrap();
            write_frame(&mut acquire_server, RUNTIME_RESPONSE_KIND, &response).unwrap();
        });
        let mut provider = RuntimeDescriptorProvider::test_with(
            contract(&binding),
            Arc::new(QueueConnector::new([
                (probe_client, runtime_uid),
                (acquire_client, runtime_uid),
            ])),
            Arc::new(FixedClock(20)),
        );

        provider.preflight(&fixture.plan.act, &binding).unwrap();
        assert!(provider
            .next_upstream(fixture.lease, Instant::now() + Duration::from_secs(1))
            .is_err());
        probe.join().unwrap();
        acquire.join().unwrap();

        let (wrong_client, _wrong_server) = UnixStream::pair().unwrap();
        let wrong_peer = RuntimeDescriptorProvider::test_with(
            contract(&binding),
            Arc::new(QueueConnector::new([(wrong_client, u32::MAX)])),
            Arc::new(FixedClock(20)),
        );
        assert!(wrong_peer.preflight(&fixture.plan.act, &binding).is_err());
    }
}
