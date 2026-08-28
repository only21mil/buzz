use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buzz_ci_isolation_contract::{RuntimeEndpointIdentity, ValidatedAttemptLeaseBinding};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::activation::LeaseToken;
use crate::host_composition::HostCompositionContract;
use crate::normal_engine::ActLaunchPlan;

pub(super) const FRAME_MAGIC: &[u8; 4] = b"BZHD";
pub(super) const FRAME_VERSION: u16 = 1;
pub(super) const FRAME_HEADER_BYTES: usize = 12;
pub(super) const MAX_FRAME_BYTES: usize = 128 * 1024;
pub(super) const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DESCRIPTOR_AGE_SECONDS: u64 = 30;
const MAX_REPLAY_ENTRIES: usize = 8_192;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HandoffRole {
    Executor,
    Runtime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HandoffOperation {
    Probe,
    Launch,
    AcquireRuntime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkspaceIdentity {
    path: String,
    device: u64,
    inode: u64,
    owner_uid: u32,
    object_token_sha256: [u8; 32],
    quota_token_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlatformIdentity {
    source_sha: String,
    base_oid: String,
    workflow_id: String,
    workflow_digest: String,
    image_digest: String,
    engine_version: String,
    architecture: String,
    act_binary_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnitIdentity {
    host_contract_revision: u64,
    executor_uid: u32,
    runtime_uid: u32,
    executor_unit: String,
    runtime_unit: String,
    lease_slice: String,
    executor_socket: PathBuf,
    runtime_socket: PathBuf,
    cgroup_device: u64,
    cgroup_inode: u64,
    netns_device: u64,
    netns_inode: u64,
    netns_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HandoffIdentity {
    schema_version: u16,
    run_id: String,
    job_id: String,
    attempt: u32,
    lease_id: String,
    lease_expires_at_unix_seconds: u64,
    workspace: WorkspaceIdentity,
    platform: PlatformIdentity,
    units: UnitIdentity,
    runtime_endpoint_token_sha256: [u8; 32],
    runtime_endpoint_device: Option<u64>,
    runtime_endpoint_inode: Option<u64>,
    cgroup_token_sha256: [u8; 32],
    netns_token_sha256: [u8; 32],
}

impl HandoffIdentity {
    pub(super) fn from_validated(
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
        contract: &HostCompositionContract,
    ) -> Result<Self, ()> {
        contract.validate().map_err(|_| ())?;
        plan.argv().map_err(|_| ())?;
        plan.environment().map_err(|_| ())?;
        let binding = binding.as_binding();
        if contract.executor_uid != binding.principals.executor
            || contract.runtime_uid != binding.principals.runtime
            || plan.job_id != binding.job_id
            || plan.image != binding.isolation_profile.image_digest
        {
            return Err(());
        }
        let executor_socket = render_socket(&contract.executor_socket_template, &binding.lease_id)?;
        let runtime_socket = render_socket(&contract.runtime_socket_template, &binding.lease_id)?;
        let (runtime_endpoint_device, runtime_endpoint_inode, runtime_token) =
            match &binding.runtime_endpoint {
                RuntimeEndpointIdentity::UnixSocket {
                    token,
                    device,
                    inode,
                    ..
                } => (Some(*device), Some(*inode), token.as_str()),
                RuntimeEndpointIdentity::InheritedFd { token, .. } => (None, None, token.as_str()),
            };
        Ok(Self {
            schema_version: FRAME_VERSION,
            run_id: binding.run_id.clone(),
            job_id: binding.job_id.clone(),
            attempt: binding.attempt,
            lease_id: binding.lease_id.clone(),
            lease_expires_at_unix_seconds: binding.expires_at_unix_seconds,
            workspace: WorkspaceIdentity {
                path: binding.workspace.path.clone(),
                device: binding.workspace.object.device,
                inode: binding.workspace.object.inode,
                owner_uid: binding.workspace.owner_uid,
                object_token_sha256: digest(binding.workspace.object.token.as_bytes()),
                quota_token_sha256: digest(binding.workspace.quota_token.as_bytes()),
            },
            platform: PlatformIdentity {
                source_sha: binding.source_sha.clone(),
                base_oid: binding.base_oid.clone(),
                workflow_id: binding.workflow_id.clone(),
                workflow_digest: binding.workflow_digest.clone(),
                image_digest: binding.isolation_profile.image_digest.clone(),
                engine_version: binding.isolation_profile.engine_version.clone(),
                architecture: binding.isolation_profile.arch.clone(),
                act_binary_sha256: plan.binary_sha256,
            },
            units: UnitIdentity {
                host_contract_revision: contract.revision,
                executor_uid: contract.executor_uid,
                runtime_uid: contract.runtime_uid,
                executor_unit: plan.executor_unit.clone(),
                runtime_unit: plan.runtime_unit.clone(),
                lease_slice: plan.lease_slice.clone(),
                executor_socket,
                runtime_socket,
                cgroup_device: binding.cgroup.object.device,
                cgroup_inode: binding.cgroup.object.inode,
                netns_device: binding.netns.object.device,
                netns_inode: binding.netns.object.inode,
                netns_name: binding.netns.name.clone(),
            },
            runtime_endpoint_token_sha256: digest(runtime_token.as_bytes()),
            runtime_endpoint_device,
            runtime_endpoint_inode,
            cgroup_token_sha256: digest(binding.cgroup.object.token.as_bytes()),
            netns_token_sha256: digest(binding.netns.object.token.as_bytes()),
        })
    }

    pub(super) fn digest(&self) -> Result<[u8; 32], ()> {
        serde_json::to_vec(self)
            .map(|bytes| digest(&bytes))
            .map_err(|_| ())
    }

    pub(super) fn socket(&self, role: HandoffRole) -> &Path {
        match role {
            HandoffRole::Executor => &self.units.executor_socket,
            HandoffRole::Runtime => &self.units.runtime_socket,
        }
    }

    pub(super) fn expected_uid(&self, role: HandoffRole) -> u32 {
        match role {
            HandoffRole::Executor => self.units.executor_uid,
            HandoffRole::Runtime => self.units.runtime_uid,
        }
    }

    pub(super) fn lease_expiry(&self) -> u64 {
        self.lease_expires_at_unix_seconds
    }

    pub(super) fn validate_plan(&self, plan: &ActLaunchPlan, effective_uid: u32) -> Result<(), ()> {
        if self.schema_version != FRAME_VERSION
            || effective_uid != self.units.executor_uid
            || plan.executor_unit != self.units.executor_unit
            || plan.runtime_unit != self.units.runtime_unit
            || plan.lease_slice != self.units.lease_slice
            || plan.job_id != self.job_id
            || plan.image != self.platform.image_digest
            || plan.binary_sha256 != self.platform.act_binary_sha256
            || plan.argv().is_err()
            || plan.environment().is_err()
        {
            return Err(());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn mutate_run_id(&mut self) {
        self.run_id.push('x');
    }

    #[cfg(test)]
    pub(super) fn contains_secret_fields(&self) -> bool {
        serde_json::to_string(self).is_ok_and(|json| {
            [
                "secrets_path",
                "vars_path",
                "env_path",
                "inputs_path",
                "BUZZ_PRIVATE_KEY",
                "GITHUB_TOKEN",
            ]
            .iter()
            .any(|value| json.contains(value))
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControllerLeaseIdentity {
    controller_lease_id: [u8; 16],
    generation: u64,
    run_id: [u8; 16],
    attempt: u32,
    deadline_at: u64,
    nonce_sha256: [u8; 32],
}

impl ControllerLeaseIdentity {
    pub(super) fn from_lease(lease: LeaseToken) -> Self {
        Self {
            controller_lease_id: lease.lease_id(),
            generation: lease.generation(),
            run_id: lease.run_id(),
            attempt: lease.attempt(),
            deadline_at: lease.deadline_at(),
            nonce_sha256: digest(&lease.nonce()),
        }
    }

    pub(super) fn validate_for(
        &self,
        lease: LeaseToken,
        identity: &HandoffIdentity,
        now: u64,
    ) -> Result<(), ()> {
        let run_id = uuid::Uuid::parse_str(&identity.run_id).map_err(|_| ())?;
        if self != &Self::from_lease(lease)
            || run_id.as_bytes() != &self.run_id
            || identity.attempt != self.attempt
            || self.validate_live(now).is_err()
            || identity.lease_expires_at_unix_seconds <= now
        {
            return Err(());
        }
        Ok(())
    }

    fn validate_live(&self, now: u64) -> Result<(), ()> {
        if self.controller_lease_id == [0; 16]
            || self.generation == 0
            || self.run_id == [0; 16]
            || self.attempt == 0
            || self.deadline_at <= now
            || self.nonce_sha256 == [0; 32]
        {
            return Err(());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HandoffDescriptor {
    pub(super) schema_version: u16,
    pub(super) role: HandoffRole,
    pub(super) operation: HandoffOperation,
    pub(super) sequence: u64,
    pub(super) issued_at_unix_seconds: u64,
    pub(super) valid_until_unix_seconds: u64,
    pub(super) identity: HandoffIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) controller_lease: Option<ControllerLeaseIdentity>,
    pub(super) request_id: [u8; 32],
}

impl HandoffDescriptor {
    pub(super) fn issue(
        identity: HandoffIdentity,
        role: HandoffRole,
        operation: HandoffOperation,
        sequence: u64,
        now: u64,
        controller_lease: Option<ControllerLeaseIdentity>,
    ) -> Result<Self, ()> {
        let valid_until_unix_seconds = now
            .checked_add(MAX_DESCRIPTOR_AGE_SECONDS)
            .map(|deadline| deadline.min(identity.lease_expiry()))
            .filter(|deadline| *deadline > now)
            .ok_or(())?;
        let mut descriptor = Self {
            schema_version: FRAME_VERSION,
            role,
            operation,
            sequence,
            issued_at_unix_seconds: now,
            valid_until_unix_seconds,
            identity,
            controller_lease,
            request_id: [0; 32],
        };
        descriptor.request_id = descriptor.compute_request_id()?;
        descriptor.validate_at(now)?;
        Ok(descriptor)
    }

    pub(super) fn validate_at(&self, now: u64) -> Result<(), ()> {
        let operation_shape = match (self.role, self.operation, &self.controller_lease) {
            (HandoffRole::Executor | HandoffRole::Runtime, HandoffOperation::Probe, None) => true,
            (HandoffRole::Executor, HandoffOperation::Launch, Some(controller))
            | (HandoffRole::Runtime, HandoffOperation::AcquireRuntime, Some(controller)) => {
                controller.validate_live(now).is_ok()
            }
            _ => false,
        };
        if self.schema_version != FRAME_VERSION
            || !operation_shape
            || self.sequence == 0
            || self.issued_at_unix_seconds > now
            || self.valid_until_unix_seconds <= now
            || self.valid_until_unix_seconds > self.identity.lease_expiry()
            || self
                .valid_until_unix_seconds
                .saturating_sub(self.issued_at_unix_seconds)
                > MAX_DESCRIPTOR_AGE_SECONDS
            || self.request_id == [0; 32]
            || self.request_id != self.compute_request_id()?
        {
            return Err(());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn validate_expected(
        &self,
        expected: &HandoffIdentity,
        role: HandoffRole,
        operation: HandoffOperation,
        now: u64,
    ) -> Result<(), ()> {
        self.validate_at(now)?;
        if self.role != role || self.operation != operation || &self.identity != expected {
            return Err(());
        }
        Ok(())
    }

    pub(super) fn identity_digest(&self) -> Result<[u8; 32], ()> {
        self.identity.digest()
    }

    fn compute_request_id(&self) -> Result<[u8; 32], ()> {
        let mut unsigned = self.clone();
        unsigned.request_id = [0; 32];
        serde_json::to_vec(&unsigned)
            .map(|bytes| digest(&bytes))
            .map_err(|_| ())
    }
}

#[derive(Default)]
pub(super) struct DescriptorReplayGuard {
    identity_digest: Option<[u8; 32]>,
    highest_sequence: u64,
    seen: BTreeSet<[u8; 32]>,
    probed: bool,
}

impl DescriptorReplayGuard {
    pub(super) fn accept(&mut self, descriptor: &HandoffDescriptor, now: u64) -> Result<(), ()> {
        descriptor.validate_at(now)?;
        let identity_digest = descriptor.identity_digest()?;
        if (!self.probed && descriptor.operation != HandoffOperation::Probe)
            || self
                .identity_digest
                .is_some_and(|expected| expected != identity_digest)
            || descriptor.sequence <= self.highest_sequence
            || self.seen.contains(&descriptor.request_id)
            || self.seen.len() >= MAX_REPLAY_ENTRIES
        {
            return Err(());
        }
        self.identity_digest.get_or_insert(identity_digest);
        self.highest_sequence = descriptor.sequence;
        self.seen.insert(descriptor.request_id);
        self.probed |= descriptor.operation == HandoffOperation::Probe;
        Ok(())
    }
}

pub(super) trait Clock: Send + Sync {
    fn now(&self) -> Result<u64, ()>;
}

#[derive(Default)]
pub(super) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64, ()> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| ())
    }
}

#[cfg(test)]
pub(super) struct FixedClock(pub(super) u64);

#[cfg(test)]
impl Clock for FixedClock {
    fn now(&self) -> Result<u64, ()> {
        Ok(self.0)
    }
}

pub(super) struct Sequencer(Mutex<u64>);

impl Sequencer {
    pub(super) fn new() -> Self {
        Self(Mutex::new(0))
    }

    pub(super) fn next(&self) -> Result<u64, ()> {
        let mut sequence = self.0.lock().map_err(|_| ())?;
        *sequence = sequence.checked_add(1).ok_or(())?;
        Ok(*sequence)
    }
}

pub(super) fn configure_stream(stream: &UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(FRAME_TIMEOUT))?;
    stream.set_write_timeout(Some(FRAME_TIMEOUT))
}

pub(super) fn write_frame<T: Serialize>(
    stream: &mut UnixStream,
    kind: u16,
    value: &T,
) -> Result<(), ()> {
    let frame = encode_frame(kind, value)?;
    stream.write_all(&frame).map_err(|_| ())
}

pub(super) fn read_frame<T: DeserializeOwned>(
    stream: &mut UnixStream,
    expected_kind: u16,
) -> Result<T, ()> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    stream.read_exact(&mut header).map_err(|_| ())?;
    let length = decode_header(&header, expected_kind)?;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).map_err(|_| ())?;
    serde_json::from_slice(&payload).map_err(|_| ())
}

pub(super) fn encode_frame<T: Serialize>(kind: u16, value: &T) -> Result<Vec<u8>, ()> {
    let payload = serde_json::to_vec(value).map_err(|_| ())?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES || payload.len() > u32::MAX as usize {
        return Err(());
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(FRAME_MAGIC);
    frame.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&kind.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub(super) fn decode_header(header: &[u8], expected_kind: u16) -> Result<usize, ()> {
    if header.len() != FRAME_HEADER_BYTES
        || &header[..4] != FRAME_MAGIC
        || u16::from_be_bytes([header[4], header[5]]) != FRAME_VERSION
        || u16::from_be_bytes([header[6], header[7]]) != expected_kind
    {
        return Err(());
    }
    let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(());
    }
    Ok(length)
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn render_socket(template: &Path, lease_id: &str) -> Result<PathBuf, ()> {
    let template = template.to_str().ok_or(())?;
    if template.matches("{lease_id}").count() != 1 {
        return Err(());
    }
    let rendered = PathBuf::from(template.replace("{lease_id}", lease_id));
    if !rendered.is_absolute()
        || rendered
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(());
    }
    Ok(rendered)
}
