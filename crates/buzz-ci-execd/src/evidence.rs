//! Broker-owned, per-lease evidence publication.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ROOT_ONLY_DIRECTORY_MODE: u32 = 0o700;
pub const ROOT_READ_ONLY_FILE_MODE: u32 = 0o400;
pub const SECCOMP_PROFILE_PATH: &str = "/var/lib/buzzci/seccomp/v1/sha256/2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4.json";
pub const SECCOMP_PROFILE_SHA256: &str =
    "2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4";
const MAX_JSONL_BYTES: u64 = 16 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum PublicationError {
    #[error("unsafe lease identifier")]
    UnsafeLeaseId,
    #[error("lease evidence path is a symbolic link")]
    SymbolicLink,
    #[error("lease record does not match the store or required seccomp seed")]
    RecordMismatch,
    #[error("evidence log exceeds its broker-side size bound")]
    LogTooLarge,
    #[error("evidence record sequence is not contiguous")]
    SequenceViolation,
    #[error("evidence serialization failed")]
    Serialize(#[from] serde_json::Error),
    #[error("evidence filesystem operation failed")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeasePaths {
    pub root: PathBuf,
    pub lease: PathBuf,
    pub materializer_receipt: PathBuf,
    pub materializer_commands: PathBuf,
    pub proxy_decisions: PathBuf,
    pub proxy_objects: PathBuf,
    pub ordering: PathBuf,
    pub teardown: PathBuf,
    pub reconcile: PathBuf,
}

impl LeasePaths {
    pub fn new(state_root: &Path, lease_id: &str) -> Result<Self, PublicationError> {
        validate_lease_id(lease_id)?;
        let root = state_root.join(lease_id);
        Ok(Self {
            lease: root.join("lease.json"),
            materializer_receipt: root.join("materializer/receipt.json"),
            materializer_commands: root.join("materializer/commands.jsonl"),
            proxy_decisions: root.join("proxy/decisions.jsonl"),
            proxy_objects: root.join("proxy/objects"),
            ordering: root.join("ordering.jsonl"),
            teardown: root.join("teardown.json"),
            reconcile: root.join("reconcile.json"),
            root,
        })
    }

    pub fn proxy_object(&self, sequence: u64) -> Result<PathBuf, PublicationError> {
        if sequence == 0 {
            return Err(PublicationError::RecordMismatch);
        }
        Ok(self.proxy_objects.join(format!("{sequence}.json")))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourcePropertyReadback {
    pub cpu_quota_per_sec_usec: u64,
    pub memory_max_bytes: u64,
    pub tasks_max: u64,
    pub runtime_max_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseRecord {
    pub schema_version: u16,
    pub lease_id: String,
    pub lease_unit: String,
    pub cgroup_path: PathBuf,
    pub workspace_dir: PathBuf,
    pub limits: LeaseLimits,
    pub resource_readback: ResourcePropertyReadback,
    pub dns_readback: DnsReadback,
    pub seccomp_profile: SeccompEvidence,
    pub sanitized_artifact_store_path: PathBuf,
    pub sanitized_log_store_path: PathBuf,
    pub created_at_unix_ns: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseLimits {
    pub wall_deadline: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsReadback {
    pub files_lookup_ok: bool,
    pub arbitrary_getent_refused: bool,
    pub resolved_varlink_inaccessible: bool,
    pub direct_53_refused: bool,
    pub allowed_tuples_only: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SeccompEvidence {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaterializerReceipt {
    pub lease_id: String,
    pub requested_commit_oid: GitObjectId,
    pub exact_commit_oid: GitObjectId,
    pub exact_tree_oid: GitObjectId,
    pub exact_workflow_blob_oid: GitObjectId,
    pub workflow_sha256: Digest32,
    pub manifest_sha256: Digest32,
    pub input_digests: Vec<MaterializedInputDigest>,
    pub completed_at_unix_ns: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "algorithm", content = "bytes")]
pub enum GitObjectId {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Digest32(pub [u8; 32]);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaterializedInputDigest {
    pub kind: MaterializedInputKind,
    pub name_sha256: Digest32,
    pub value_sha256: Digest32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializedInputKind {
    WorkflowFile,
    JobDefinition,
    ActionDefinition,
    ContainerImage,
    RuntimeFixture,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializerOperation {
    Init,
    FetchExactObject,
    ReadCommit,
    ReadTree,
    ReadWorkflow,
    Checkout,
    InvokeAct,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaterializerCommandRecord {
    pub lease_id: String,
    pub sequence: u64,
    pub operation: MaterializerOperation,
    /// Canonical argv after credential-bearing transport inputs have been
    /// reduced to broker-approved local coordinates.
    pub argv: Vec<String>,
    pub environment: HardenedEnvironment,
    pub ceilings: CommandCeilings,
    pub result: CommandResult,
    pub started_at_unix_ns: u64,
    pub finished_at_unix_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HardenedEnvironment {
    pub clear_environment: bool,
    pub home: PathBuf,
    pub locale: String,
    pub git_config_nosystem: bool,
    pub git_terminal_prompt: bool,
    pub git_askpass_disabled: bool,
    pub credential_helper_disabled: bool,
    pub hooks_path_dev_null: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandCeilings {
    pub wall_seconds: u32,
    pub output_bytes: u64,
    pub process_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandResult {
    pub exit_code: i32,
    pub timed_out: bool,
    pub stdout_sha256: Digest32,
    pub stderr_sha256: Digest32,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyVerdict {
    Allowed,
    Refused,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyRoute {
    Ping,
    Version,
    Info,
    ContainerList,
    ImageInspect,
    VolumeList,
    ContainerCreate,
    ContainerInspect,
    ContainerAttach,
    ContainerStart,
    ContainerWait,
    ContainerLogs,
    ContainerDelete,
    ExecCreate,
    ExecStart,
    ExecInspect,
    Archive,
    ImagePull,
    Build,
    ForbiddenFamily,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyDecisionReason {
    PolicyAllowed,
    UnsafeRouteClass,
    UnknownRoute,
    MethodNotAllowed,
    RequestMalformed,
    LeaseNotReady,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProxyDecisionRecord {
    pub schema_version: u16,
    pub lease_id: String,
    pub sequence: u64,
    pub route: ProxyRoute,
    pub verdict: ProxyVerdict,
    pub reason: ProxyDecisionReason,
    pub request_hash: String,
    pub method: DockerMethod,
    pub target: String,
    pub decided_at_unix_ns: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DockerMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "HEAD")]
    Head,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "DELETE")]
    Delete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProxyObjectRecord {
    pub lease_id: String,
    pub sequence: u64,
    pub object_id: String,
    pub rebuilt_create_request: CanonicalCreateRequest,
    pub rebuilt_exec_request: CanonicalExecRequest,
    #[serde(rename = "env")]
    pub environment: BTreeMap<String, String>,
    pub effective_spec: EffectiveContainerSpec,
    pub proof: EffectiveSpecProof,
    pub image_digest: String,
    pub recorded_at_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalCreateRequest {
    pub container_id: String,
    pub bundle: PathBuf,
    pub pid_file: PathBuf,
    pub rootfs_read_only: bool,
    pub no_new_privileges: bool,
    pub network_disabled: bool,
    pub seccomp_profile_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalExecRequest {
    pub container_id: String,
    pub argv: Vec<String>,
    pub clear_environment: bool,
    pub working_directory: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EffectiveSpecProof {
    pub source_request_sha256: Digest32,
    pub rebuilt_create_sha256: Digest32,
    pub rebuilt_exec_sha256: Digest32,
    pub effective_spec_sha256: Digest32,
    pub seccomp_profile_sha256: Digest32,
    pub recorded_before_unit_start: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EffectiveContainerSpec {
    pub user: String,
    pub userns_mode: String,
    pub cap_drop: Vec<String>,
    pub security_opt: Vec<String>,
    pub network_mode: String,
    pub image: String,
    pub binds: Vec<PathBuf>,
    pub log_driver: String,
    pub artifact_server_enabled: bool,
    pub persistent_logs: bool,
    pub nano_cpus: u64,
    pub memory: u64,
    pub pids_limit: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingEvent {
    Materialized,
    ProxyObjectRecorded,
    Start,
    Stop,
    FinalizeRawStream,
    Extract,
    Scrub,
    Scan,
    Hash,
    Upload,
    TeardownProof,
    Publish,
    Reconcile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderingRecord {
    pub lease_id: String,
    pub sequence: u64,
    pub event_binding: CiEventBinding,
    pub event: OrderingEvent,
    pub object_id: Option<String>,
    pub timestamp_unix_ns: u64,
    pub status_event_id: Option<String>,
    pub verdict_event_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TeardownRecord {
    pub lease_id: String,
    pub event_binding: CiEventBinding,
    pub lease_unit: String,
    pub cgroup_path: PathBuf,
    pub unit_inactive: bool,
    pub cgroup_procs_empty: bool,
    pub mounts_removed: bool,
    pub dirs_removed: bool,
    pub teardown_sha256: Digest32,
    pub completed_at_unix_ns: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CiEventBinding {
    pub request_event_id_46105: [u8; 32],
    pub teardown_event_id_46106: [u8; 32],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileState {
    Clean,
    Quarantined,
    Blocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciledResource {
    LeaseUnit,
    Cgroup,
    Workspace,
    NetworkNamespace,
    RuntimeSocket,
    ProxyObjectState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReconcileRecord {
    pub lease_id: String,
    pub lease_unit: String,
    pub cgroup_path: PathBuf,
    pub state: ReconcileState,
    pub emptied: bool,
    pub quarantined: bool,
    pub before_reuse: bool,
    pub emptied_resources: Vec<ReconciledResource>,
    pub quarantined_resources: Vec<ReconciledResource>,
    pub reuse_allowed: bool,
    pub observed_at_unix_ns: u64,
}

pub struct EvidenceStore {
    state_root: PathBuf,
}

impl EvidenceStore {
    pub fn new(state_root: PathBuf) -> Result<Self, PublicationError> {
        if !safe_absolute_path(&state_root) {
            return Err(PublicationError::RecordMismatch);
        }
        Ok(Self { state_root })
    }

    pub fn paths(&self, lease_id: &str) -> Result<LeasePaths, PublicationError> {
        LeasePaths::new(&self.state_root, lease_id)
    }

    pub fn initialize_lease(&self, record: &LeaseRecord) -> Result<LeasePaths, PublicationError> {
        validate_lease_record(record)?;
        let paths = self.paths(&record.lease_id)?;
        create_owned_dir(&self.state_root)?;
        create_owned_dir(&paths.root)?;
        create_owned_dir(&paths.root.join("materializer"))?;
        create_owned_dir(&paths.root.join("proxy"))?;
        create_owned_dir(&paths.proxy_objects)?;
        publish_json(&paths.lease, record)?;
        for log in [
            &paths.materializer_commands,
            &paths.proxy_decisions,
            &paths.ordering,
        ] {
            atomic_publish(log, b"", ROOT_READ_ONLY_FILE_MODE)?;
        }
        Ok(paths)
    }

    pub fn publish_materializer_receipt(
        &self,
        value: &MaterializerReceipt,
    ) -> Result<(), PublicationError> {
        self.require_record_lease(&value.lease_id)?;
        validate_materializer_receipt(value)?;
        publish_json(&self.paths(&value.lease_id)?.materializer_receipt, value)
    }

    pub fn append_materializer_command(
        &self,
        value: &MaterializerCommandRecord,
    ) -> Result<(), PublicationError> {
        self.require_record_lease(&value.lease_id)?;
        validate_materializer_command(value)?;
        append_ordered_jsonl(
            &self.paths(&value.lease_id)?.materializer_commands,
            value.sequence,
            value,
        )
    }

    pub fn append_proxy_decision(
        &self,
        value: &ProxyDecisionRecord,
    ) -> Result<(), PublicationError> {
        self.require_record_lease(&value.lease_id)?;
        if !valid_proxy_decision(value) {
            return Err(PublicationError::RecordMismatch);
        }
        append_ordered_jsonl(
            &self.paths(&value.lease_id)?.proxy_decisions,
            value.sequence,
            value,
        )
    }

    pub fn publish_proxy_object(&self, value: &ProxyObjectRecord) -> Result<(), PublicationError> {
        self.require_record_lease(&value.lease_id)?;
        validate_proxy_object(value)?;
        let paths = self.paths(&value.lease_id)?;
        if value.sequence > 1 && !paths.proxy_object(value.sequence - 1)?.is_file() {
            return Err(PublicationError::SequenceViolation);
        }
        let destination = paths.proxy_object(value.sequence)?;
        if destination.exists() {
            return Err(PublicationError::SequenceViolation);
        }
        publish_json(&destination, value)
    }

    pub fn append_ordering(&self, value: &OrderingRecord) -> Result<(), PublicationError> {
        self.require_record_lease(&value.lease_id)?;
        validate_event_binding(value.event_binding)?;
        if value.sequence == 0
            || value.timestamp_unix_ns == 0
            || value
                .object_id
                .as_deref()
                .is_some_and(|object_id| !safe_identifier(object_id))
            || (value.event == OrderingEvent::Start && value.object_id.is_none())
        {
            return Err(PublicationError::RecordMismatch);
        }
        let path = self.paths(&value.lease_id)?.ordering;
        validate_ordering_transition(&path, value)?;
        append_ordered_jsonl(&path, value.sequence, value)
    }

    pub fn publish_teardown(&self, value: &TeardownRecord) -> Result<(), PublicationError> {
        self.require_record_lease(&value.lease_id)?;
        validate_event_binding(value.event_binding)?;
        if !safe_cgroup_path(&value.cgroup_path)
            || is_zero_digest(value.teardown_sha256)
            || !value.unit_inactive
            || !value.cgroup_procs_empty
            || !value.mounts_removed
            || !value.dirs_removed
        {
            return Err(PublicationError::RecordMismatch);
        }
        publish_json(&self.paths(&value.lease_id)?.teardown, value)
    }

    pub fn publish_reconcile(&self, value: &ReconcileRecord) -> Result<(), PublicationError> {
        self.require_record_lease(&value.lease_id)?;
        validate_reconcile(value)?;
        publish_json(&self.paths(&value.lease_id)?.reconcile, value)
    }

    fn require_record_lease(&self, lease_id: &str) -> Result<(), PublicationError> {
        let paths = self.paths(lease_id)?;
        if !paths.lease.is_file() {
            return Err(PublicationError::RecordMismatch);
        }
        Ok(())
    }
}

fn validate_ordering_transition(
    path: &Path,
    value: &OrderingRecord,
) -> Result<(), PublicationError> {
    let status_valid = value
        .status_event_id
        .as_deref()
        .is_some_and(valid_external_event_id);
    let verdict_valid = value
        .verdict_event_id
        .as_deref()
        .is_some_and(valid_external_event_id);
    if value.event == OrderingEvent::Publish {
        if !status_valid || !verdict_valid {
            return Err(PublicationError::RecordMismatch);
        }
    } else if value.status_event_id.is_some() && !status_valid
        || value.verdict_event_id.is_some() && !verdict_valid
    {
        return Err(PublicationError::RecordMismatch);
    }

    let existing = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let records = existing
        .lines()
        .map(serde_json::from_str::<OrderingRecord>)
        .collect::<Result<Vec<_>, _>>()?;
    if records
        .last()
        .is_some_and(|previous| value.timestamp_unix_ns <= previous.timestamp_unix_ns)
    {
        return Err(PublicationError::SequenceViolation);
    }
    let last_terminal = records
        .iter()
        .filter_map(|record| terminal_order(record.event))
        .next_back();
    match terminal_order(value.event) {
        Some(0) if last_terminal.is_some() => Err(PublicationError::SequenceViolation),
        Some(0) => Ok(()),
        Some(current) if last_terminal == Some(current - 1) => Ok(()),
        Some(_) => Err(PublicationError::SequenceViolation),
        None if last_terminal.is_none() => Ok(()),
        None if value.event == OrderingEvent::Reconcile && last_terminal == Some(8) => Ok(()),
        None => Err(PublicationError::SequenceViolation),
    }
}

fn terminal_order(event: OrderingEvent) -> Option<u8> {
    match event {
        OrderingEvent::Stop => Some(0),
        OrderingEvent::FinalizeRawStream => Some(1),
        OrderingEvent::Extract => Some(2),
        OrderingEvent::Scrub => Some(3),
        OrderingEvent::Scan => Some(4),
        OrderingEvent::Hash => Some(5),
        OrderingEvent::Upload => Some(6),
        OrderingEvent::TeardownProof => Some(7),
        OrderingEvent::Publish => Some(8),
        _ => None,
    }
}

fn valid_external_event_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value
            .bytes()
            .any(|byte| byte <= b' ' || byte == b'=' || byte == 0x7f)
}

fn validate_lease_record(record: &LeaseRecord) -> Result<(), PublicationError> {
    validate_lease_id(&record.lease_id)?;
    let safe_unit = !record.lease_unit.is_empty()
        && (record.lease_unit.ends_with(".service")
            || record.lease_unit.ends_with(".scope")
            || record.lease_unit.ends_with(".slice"))
        && record
            .lease_unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'));
    let seccomp = &record.seccomp_profile;
    if record.schema_version != 1
        || !safe_unit
        || !safe_cgroup_path(&record.cgroup_path)
        || record.cgroup_path.parent() != Some(Path::new("/buzzci.slice"))
        || record
            .cgroup_path
            .file_name()
            .and_then(|name| name.to_str())
            != Some(record.lease_unit.as_str())
        || !safe_absolute_path(&record.workspace_dir)
        || !safe_absolute_path(&record.sanitized_artifact_store_path)
        || !safe_absolute_path(&record.sanitized_log_store_path)
        || record.limits.wall_deadline <= record.created_at_unix_ns
        || !dns_readback_complete(record.dns_readback)
        || seccomp.path != Path::new(SECCOMP_PROFILE_PATH)
        || seccomp.sha256 != SECCOMP_PROFILE_SHA256
    {
        return Err(PublicationError::RecordMismatch);
    }
    Ok(())
}

fn validate_materializer_receipt(value: &MaterializerReceipt) -> Result<(), PublicationError> {
    if value.requested_commit_oid != value.exact_commit_oid
        || is_zero_oid(value.exact_commit_oid)
        || is_zero_oid(value.exact_tree_oid)
        || is_zero_oid(value.exact_workflow_blob_oid)
        || is_zero_digest(value.workflow_sha256)
        || is_zero_digest(value.manifest_sha256)
        || value.input_digests.len() > 128
        || value
            .input_digests
            .iter()
            .any(|input| is_zero_digest(input.name_sha256) || is_zero_digest(input.value_sha256))
    {
        return Err(PublicationError::RecordMismatch);
    }
    Ok(())
}

fn validate_materializer_command(
    value: &MaterializerCommandRecord,
) -> Result<(), PublicationError> {
    let env = &value.environment;
    let limits = value.ceilings;
    if value.sequence == 0
        || value.started_at_unix_ns > value.finished_at_unix_ns
        || value.argv.is_empty()
        || value.argv.len() > 64
        || !materializer_program_matches(value)
        || value
            .argv
            .iter()
            .any(|argument| !credential_free_arg(argument))
        || !env.clear_environment
        || !safe_absolute_path(&env.home)
        || env.locale != "C.UTF-8"
        || !env.git_config_nosystem
        || env.git_terminal_prompt
        || !env.git_askpass_disabled
        || !env.credential_helper_disabled
        || !env.hooks_path_dev_null
        || limits.wall_seconds == 0
        || limits.output_bytes == 0
        || limits.process_count == 0
        || value.result.stdout_bytes > limits.output_bytes
        || value.result.stderr_bytes > limits.output_bytes
        || is_zero_digest(value.result.stdout_sha256)
        || is_zero_digest(value.result.stderr_sha256)
    {
        return Err(PublicationError::RecordMismatch);
    }
    Ok(())
}

fn validate_proxy_object(value: &ProxyObjectRecord) -> Result<(), PublicationError> {
    let create = &value.rebuilt_create_request;
    let execute = &value.rebuilt_exec_request;
    let spec = &value.effective_spec;
    let proof = value.proof;
    if value.sequence == 0
        || value.recorded_at_ns == 0
        || value.object_id != create.container_id
        || create.container_id != execute.container_id
        || !safe_identifier(&create.container_id)
        || !safe_absolute_path(&create.bundle)
        || !safe_absolute_path(&create.pid_file)
        || !safe_absolute_path(&execute.working_directory)
        || create.seccomp_profile_path != Path::new(SECCOMP_PROFILE_PATH)
        || !create.rootfs_read_only
        || !create.no_new_privileges
        || !create.network_disabled
        || !execute.clear_environment
        || !valid_proxy_environment(&value.environment)
        || execute.argv.is_empty()
        || execute.argv.len() > 64
        || execute
            .argv
            .iter()
            .any(|argument| !credential_free_arg(argument))
        || !value.image_digest.starts_with("sha256:")
        || value.image_digest.len() != 71
        || !value.image_digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || spec.image != value.image_digest
        || !effective_spec_is_constrained(spec)
        || is_zero_digest(proof.source_request_sha256)
        || is_zero_digest(proof.rebuilt_create_sha256)
        || is_zero_digest(proof.rebuilt_exec_sha256)
        || is_zero_digest(proof.effective_spec_sha256)
        || digest_hex(proof.seccomp_profile_sha256) != SECCOMP_PROFILE_SHA256
        || !proof.recorded_before_unit_start
    {
        return Err(PublicationError::RecordMismatch);
    }
    Ok(())
}

fn effective_spec_is_constrained(spec: &EffectiveContainerSpec) -> bool {
    let Some((uid, gid)) = spec.user.split_once(':') else {
        return false;
    };
    uid.parse::<u32>().is_ok_and(|value| value > 0)
        && gid.parse::<u32>().is_ok_and(|value| value > 0)
        && !spec.userns_mode.is_empty()
        && spec.userns_mode != "host"
        && spec.cap_drop.iter().any(|capability| capability == "ALL")
        && spec
            .security_opt
            .iter()
            .filter(|option| option.to_ascii_lowercase().starts_with("seccomp="))
            .eq([format!("seccomp={SECCOMP_PROFILE_PATH}")].iter())
        && spec.security_opt.iter().any(|option| {
            let lower = option.to_ascii_lowercase();
            lower.contains("label") || lower.contains("selinux")
        })
        && spec.network_mode == "none"
        && spec.binds.len() <= 32
        && spec.binds.iter().all(|path| {
            safe_absolute_path(path)
                && !path.to_string_lossy().contains("docker.sock")
                && !path.to_string_lossy().contains("podman.sock")
                && !path.to_string_lossy().contains("proxy.sock")
        })
        && spec.log_driver == "none"
        && !spec.artifact_server_enabled
        && !spec.persistent_logs
        && spec.nano_cpus > 0
        && spec.memory > 0
        && spec.pids_limit > 0
}

fn materializer_program_matches(value: &MaterializerCommandRecord) -> bool {
    match value.operation {
        MaterializerOperation::InvokeAct => {
            value.argv.first().is_some_and(|program| program == "act")
                && value
                    .argv
                    .iter()
                    .any(|argument| argument == "--concurrent-jobs=1")
        }
        _ => value.argv.first().is_some_and(|program| program == "git"),
    }
}

fn valid_proxy_environment(environment: &BTreeMap<String, String>) -> bool {
    const REQUIRED: [&str; 3] = ["BUZZ_CI_ATTEMPT", "BUZZ_CI_RUN_ID", "BUZZ_CI_SHA"];
    environment.len() == REQUIRED.len()
        && REQUIRED.iter().all(|key| {
            environment.get(*key).is_some_and(|value| {
                !value.is_empty()
                    && value.trim() == value
                    && value.len() <= 256
                    && !value.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
            })
        })
}

fn dns_readback_complete(readback: DnsReadback) -> bool {
    readback.files_lookup_ok
        && readback.arbitrary_getent_refused
        && readback.resolved_varlink_inaccessible
        && readback.direct_53_refused
        && readback.allowed_tuples_only
}

fn valid_proxy_decision(value: &ProxyDecisionRecord) -> bool {
    let unsafe_route = matches!(
        value.route,
        ProxyRoute::ContainerAttach
            | ProxyRoute::ContainerLogs
            | ProxyRoute::ExecStart
            | ProxyRoute::Archive
            | ProxyRoute::ImagePull
            | ProxyRoute::Build
            | ProxyRoute::ForbiddenFamily
            | ProxyRoute::Unknown
    );
    let refusal_matches = value.verdict == ProxyVerdict::Refused
        && match value.route {
            ProxyRoute::Unknown => value.reason == ProxyDecisionReason::UnknownRoute,
            _ if unsafe_route => value.reason == ProxyDecisionReason::UnsafeRouteClass,
            _ => true,
        };
    value.schema_version == 1
        && value.sequence > 0
        && value.request_hash.len() == 64
        && value
            .request_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && value.target.starts_with('/')
        && value.target.len() <= 4096
        && !value.target.bytes().any(|byte| byte < b' ' || byte == 0x7f)
        && (!unsafe_route || refusal_matches)
        && (value.verdict != ProxyVerdict::Allowed
            || value.reason == ProxyDecisionReason::PolicyAllowed)
}

fn validate_event_binding(binding: CiEventBinding) -> Result<(), PublicationError> {
    if binding.request_event_id_46105 == [0; 32]
        || binding.teardown_event_id_46106 == [0; 32]
        || binding.request_event_id_46105 == binding.teardown_event_id_46106
    {
        return Err(PublicationError::RecordMismatch);
    }
    Ok(())
}

fn validate_reconcile(value: &ReconcileRecord) -> Result<(), PublicationError> {
    if !safe_cgroup_path(&value.cgroup_path)
        || !value.before_reuse
        || value.emptied == value.quarantined
        || value.emptied_resources.len() > 16
        || value.quarantined_resources.len() > 16
        || (value.emptied && value.emptied_resources.is_empty())
        || (value.quarantined && value.quarantined_resources.is_empty())
        || (value.reuse_allowed
            && (value.state != ReconcileState::Clean
                || !value.emptied
                || value.quarantined
                || !value.quarantined_resources.is_empty()))
        || (!value.reuse_allowed && value.state == ReconcileState::Clean)
        || (value.state == ReconcileState::Quarantined && !value.quarantined)
    {
        return Err(PublicationError::RecordMismatch);
    }
    Ok(())
}

fn is_zero_oid(value: GitObjectId) -> bool {
    match value {
        GitObjectId::Sha1(bytes) => bytes == [0; 20],
        GitObjectId::Sha256(bytes) => bytes == [0; 32],
    }
}

fn is_zero_digest(value: Digest32) -> bool {
    value.0 == [0; 32]
}

fn digest_hex(value: Digest32) -> String {
    value.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn credential_free_arg(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.bytes().any(|byte| byte < b' ' || byte == 0x7f)
    {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower == "credential.helper=" {
        return true;
    }
    let forbidden_marker = [
        "authorization",
        "credential",
        "password",
        "private_key",
        "secret",
        "token=",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let credentialed_url = lower.contains("://")
        && lower.split("://").nth(1).is_some_and(|tail| {
            tail.split('/')
                .next()
                .is_some_and(|authority| authority.contains('@'))
        });
    !forbidden_marker && !credentialed_url
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        && path
            .to_str()
            .is_some_and(|value| !value.bytes().any(|byte| byte < b' ' || byte == b'='))
}

fn safe_cgroup_path(path: &Path) -> bool {
    safe_absolute_path(path) && path.starts_with("/buzzci.slice/")
}

fn validate_lease_id(value: &str) -> Result<(), PublicationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || value == "."
        || value == ".."
    {
        return Err(PublicationError::UnsafeLeaseId);
    }
    Ok(())
}

fn create_owned_dir(path: &Path) -> Result<(), PublicationError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(PublicationError::SymbolicLink);
        }
    }
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(ROOT_ONLY_DIRECTORY_MODE))?;
    sync_parent(path)?;
    Ok(())
}

fn publish_json<T: Serialize>(destination: &Path, value: &T) -> Result<(), PublicationError> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    atomic_publish(destination, &bytes, ROOT_READ_ONLY_FILE_MODE)
}

fn append_ordered_jsonl<T: Serialize>(
    destination: &Path,
    sequence: u64,
    value: &T,
) -> Result<(), PublicationError> {
    reject_symlink(destination)?;
    let mut bytes = Vec::new();
    match File::open(destination) {
        Ok(mut file) => {
            if file.metadata()?.len() > MAX_JSONL_BYTES {
                return Err(PublicationError::LogTooLarge);
            }
            file.read_to_end(&mut bytes)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let expected = match bytes
        .split(|byte| *byte == b'\n')
        .rfind(|line| !line.is_empty())
    {
        Some(line) => serde_json::from_slice::<serde_json::Value>(line)?
            .get("sequence")
            .and_then(serde_json::Value::as_u64)
            .and_then(|previous| previous.checked_add(1))
            .ok_or(PublicationError::SequenceViolation)?,
        None => 1,
    };
    if sequence != expected {
        return Err(PublicationError::SequenceViolation);
    }
    serde_json::to_writer(&mut bytes, value)?;
    bytes.push(b'\n');
    atomic_publish(destination, &bytes, ROOT_READ_ONLY_FILE_MODE)
}

pub(crate) fn atomic_publish(
    destination: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), PublicationError> {
    let parent = destination
        .parent()
        .ok_or(PublicationError::RecordMismatch)?;
    reject_symlink(parent)?;
    reject_symlink(destination)?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(PublicationError::RecordMismatch)?,
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        fs::rename(&temporary, destination)?;
        sync_parent(destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn reject_symlink(path: &Path) -> Result<(), PublicationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(PublicationError::SymbolicLink),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sync_parent(path: &Path) -> Result<(), PublicationError> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub(crate) fn temp_root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "buzz-ci-execd-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn seccomp() -> SeccompEvidence {
        SeccompEvidence {
            path: PathBuf::from(SECCOMP_PROFILE_PATH),
            sha256: SECCOMP_PROFILE_SHA256.to_owned(),
        }
    }

    fn lease(lease_id: &str) -> LeaseRecord {
        LeaseRecord {
            schema_version: 1,
            lease_id: lease_id.to_owned(),
            lease_unit: "buzzci-lease-17.scope".to_owned(),
            cgroup_path: PathBuf::from("/buzzci.slice/buzzci-lease-17.scope"),
            workspace_dir: PathBuf::from(format!("/var/lib/buzzci/workspaces/{lease_id}")),
            limits: LeaseLimits { wall_deadline: 610 },
            resource_readback: ResourcePropertyReadback {
                cpu_quota_per_sec_usec: 100_000,
                memory_max_bytes: 1_073_741_824,
                tasks_max: 128,
                runtime_max_seconds: 600,
            },
            dns_readback: DnsReadback {
                files_lookup_ok: true,
                arbitrary_getent_refused: true,
                resolved_varlink_inaccessible: true,
                direct_53_refused: true,
                allowed_tuples_only: true,
            },
            seccomp_profile: seccomp(),
            sanitized_artifact_store_path: PathBuf::from(format!(
                "/var/lib/buzzci/published/{lease_id}/artifacts"
            )),
            sanitized_log_store_path: PathBuf::from(format!(
                "/var/lib/buzzci/published/{lease_id}/logs"
            )),
            created_at_unix_ns: 10,
        }
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32([byte; 32])
    }

    fn seccomp_digest() -> Digest32 {
        let mut bytes = [0_u8; 32];
        for (index, chunk) in SECCOMP_PROFILE_SHA256
            .as_bytes()
            .chunks_exact(2)
            .enumerate()
        {
            bytes[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        Digest32(bytes)
    }

    fn binding() -> CiEventBinding {
        CiEventBinding {
            request_event_id_46105: [0x46; 32],
            teardown_event_id_46106: [0x47; 32],
        }
    }

    fn command(lease_id: &str, sequence: u64) -> MaterializerCommandRecord {
        MaterializerCommandRecord {
            lease_id: lease_id.to_owned(),
            sequence,
            operation: MaterializerOperation::FetchExactObject,
            argv: vec![
                "git".to_owned(),
                "-c".to_owned(),
                "credential.helper=".to_owned(),
                "fetch".to_owned(),
                "origin".to_owned(),
                "11".repeat(20),
            ],
            environment: HardenedEnvironment {
                clear_environment: true,
                home: PathBuf::from("/var/empty/buzzci"),
                locale: "C.UTF-8".to_owned(),
                git_config_nosystem: true,
                git_terminal_prompt: false,
                git_askpass_disabled: true,
                credential_helper_disabled: true,
                hooks_path_dev_null: true,
            },
            ceilings: CommandCeilings {
                wall_seconds: 30,
                output_bytes: 1_048_576,
                process_count: 8,
            },
            result: CommandResult {
                exit_code: 0,
                timed_out: false,
                stdout_sha256: digest(0x91),
                stderr_sha256: digest(0x92),
                stdout_bytes: 12,
                stderr_bytes: 0,
            },
            started_at_unix_ns: 11,
            finished_at_unix_ns: 12,
        }
    }

    fn ordering(
        lease_id: &str,
        sequence: u64,
        event: OrderingEvent,
        timestamp_unix_ns: u64,
    ) -> OrderingRecord {
        let publish = event == OrderingEvent::Publish;
        OrderingRecord {
            lease_id: lease_id.to_owned(),
            sequence,
            event_binding: binding(),
            event,
            object_id: None,
            timestamp_unix_ns,
            status_event_id: publish.then(|| "status-event".to_owned()),
            verdict_event_id: publish.then(|| "verdict-event".to_owned()),
        }
    }

    #[test]
    fn exact_lease_paths_and_permissions_are_published() {
        let root = temp_root("paths");
        let store = EvidenceStore::new(root.join("leases")).unwrap();
        let paths = store.initialize_lease(&lease("lease_1")).unwrap();
        assert_eq!(
            paths.materializer_receipt,
            paths.root.join("materializer/receipt.json")
        );
        assert_eq!(
            paths.materializer_commands,
            paths.root.join("materializer/commands.jsonl")
        );
        assert_eq!(
            paths.proxy_decisions,
            paths.root.join("proxy/decisions.jsonl")
        );
        assert_eq!(
            paths.proxy_object(7).unwrap(),
            paths.root.join("proxy/objects/7.json")
        );
        assert_eq!(paths.ordering, paths.root.join("ordering.jsonl"));
        assert_eq!(paths.teardown, paths.root.join("teardown.json"));
        assert_eq!(paths.reconcile, paths.root.join("reconcile.json"));
        assert_eq!(paths.lease, paths.root.join("lease.json"));
        assert_eq!(
            fs::metadata(&paths.root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&paths.lease).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }

    #[test]
    fn typed_records_round_trip_through_atomic_publication() {
        let root = temp_root("records");
        let store = EvidenceStore::new(root.join("leases")).unwrap();
        store.initialize_lease(&lease("lease-2")).unwrap();
        let first_command = command("lease-2", 1);
        store.append_materializer_command(&first_command).unwrap();
        store
            .append_materializer_command(&MaterializerCommandRecord {
                sequence: 2,
                ..first_command.clone()
            })
            .unwrap();
        assert!(matches!(
            store.append_materializer_command(&MaterializerCommandRecord {
                sequence: 4,
                ..first_command.clone()
            }),
            Err(PublicationError::SequenceViolation)
        ));
        let mut credential_bearing = first_command.clone();
        credential_bearing.sequence = 3;
        credential_bearing
            .argv
            .push("token=do-not-store".to_owned());
        assert!(matches!(
            store.append_materializer_command(&credential_bearing),
            Err(PublicationError::RecordMismatch)
        ));
        let mut act = command("lease-2", 3);
        act.operation = MaterializerOperation::InvokeAct;
        act.argv = vec!["act".to_owned(), "--concurrent-jobs=1".to_owned()];
        store.append_materializer_command(&act).unwrap();
        let paths = store.paths("lease-2").unwrap();
        let lines = fs::read_to_string(paths.materializer_commands).unwrap();
        assert_eq!(lines.lines().count(), 3);
        assert_eq!(
            serde_json::from_str::<MaterializerCommandRecord>(lines.lines().next().unwrap())
                .unwrap(),
            first_command
        );
        assert!(!fs::read_dir(paths.root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")));
    }

    #[test]
    fn terminal_order_and_publish_event_ids_are_exact() {
        let root = temp_root("terminal-order");
        let store = EvidenceStore::new(root.join("leases")).unwrap();
        store.initialize_lease(&lease("ordered")).unwrap();
        let events = [
            OrderingEvent::Stop,
            OrderingEvent::FinalizeRawStream,
            OrderingEvent::Extract,
            OrderingEvent::Scrub,
            OrderingEvent::Scan,
            OrderingEvent::Hash,
            OrderingEvent::Upload,
            OrderingEvent::TeardownProof,
            OrderingEvent::Publish,
        ];
        for (index, event) in events.into_iter().enumerate() {
            let sequence = u64::try_from(index + 1).unwrap();
            let mut record = ordering("ordered", sequence, event, 100 + sequence);
            if event == OrderingEvent::Publish {
                record.status_event_id = Some(String::new());
                assert!(matches!(
                    store.append_ordering(&record),
                    Err(PublicationError::RecordMismatch)
                ));
                record.status_event_id = Some("status-event".to_owned());
            }
            store.append_ordering(&record).unwrap();
        }
        let paths = store.paths("ordered").unwrap();
        let rows = fs::read_to_string(paths.ordering).unwrap();
        let parsed = rows
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(parsed
            .iter()
            .all(|row| row.get("timestamp_unix_ns").is_some() && row.get("unix_ns").is_none()));
        assert_eq!(parsed.last().unwrap()["status_event_id"], "status-event");
        assert_eq!(parsed.last().unwrap()["verdict_event_id"], "verdict-event");

        store.initialize_lease(&lease("out-of-order")).unwrap();
        assert!(matches!(
            store.append_ordering(&ordering(
                "out-of-order",
                1,
                OrderingEvent::FinalizeRawStream,
                200,
            )),
            Err(PublicationError::SequenceViolation)
        ));
        store
            .append_ordering(&ordering("out-of-order", 1, OrderingEvent::Stop, 200))
            .unwrap();
        assert!(matches!(
            store.append_ordering(&ordering(
                "out-of-order",
                2,
                OrderingEvent::FinalizeRawStream,
                200,
            )),
            Err(PublicationError::SequenceViolation)
        ));
    }

    #[test]
    fn fixed_paths_and_tm05_tm11_shapes_are_enforced() {
        let root = temp_root("all-records");
        let store = EvidenceStore::new(root.join("leases")).unwrap();
        let lease = lease("lease-4");
        let paths = store.initialize_lease(&lease).unwrap();
        store
            .publish_materializer_receipt(&MaterializerReceipt {
                lease_id: lease.lease_id.clone(),
                requested_commit_oid: GitObjectId::Sha1([0x11; 20]),
                exact_commit_oid: GitObjectId::Sha1([0x11; 20]),
                exact_tree_oid: GitObjectId::Sha1([0x22; 20]),
                exact_workflow_blob_oid: GitObjectId::Sha1([0x33; 20]),
                workflow_sha256: digest(0x43),
                manifest_sha256: digest(0x44),
                input_digests: vec![MaterializedInputDigest {
                    kind: MaterializedInputKind::WorkflowFile,
                    name_sha256: digest(0x45),
                    value_sha256: digest(0x46),
                }],
                completed_at_unix_ns: 20,
            })
            .unwrap();
        store
            .append_proxy_decision(&ProxyDecisionRecord {
                schema_version: 1,
                lease_id: lease.lease_id.clone(),
                sequence: 1,
                route: ProxyRoute::Info,
                verdict: ProxyVerdict::Allowed,
                reason: ProxyDecisionReason::PolicyAllowed,
                request_hash: "55".repeat(32),
                method: DockerMethod::Get,
                target: "/info".to_owned(),
                decided_at_unix_ns: 21,
            })
            .unwrap();
        store
            .append_proxy_decision(&ProxyDecisionRecord {
                schema_version: 1,
                lease_id: lease.lease_id.clone(),
                sequence: 2,
                route: ProxyRoute::Unknown,
                verdict: ProxyVerdict::Refused,
                reason: ProxyDecisionReason::UnknownRoute,
                request_hash: "56".repeat(32),
                method: DockerMethod::Post,
                target: "/not-in-the-census".to_owned(),
                decided_at_unix_ns: 22,
            })
            .unwrap();
        store
            .publish_proxy_object(&ProxyObjectRecord {
                lease_id: lease.lease_id.clone(),
                sequence: 1,
                object_id: "lease-4".to_owned(),
                rebuilt_create_request: CanonicalCreateRequest {
                    container_id: "lease-4".to_owned(),
                    bundle: PathBuf::from("/run/buzzci/lease-4/bundle"),
                    pid_file: PathBuf::from("/run/buzzci/lease-4/pid"),
                    rootfs_read_only: true,
                    no_new_privileges: true,
                    network_disabled: true,
                    seccomp_profile_path: PathBuf::from(SECCOMP_PROFILE_PATH),
                },
                rebuilt_exec_request: CanonicalExecRequest {
                    container_id: "lease-4".to_owned(),
                    argv: vec!["act".to_owned(), "--concurrent-jobs=1".to_owned()],
                    clear_environment: true,
                    working_directory: PathBuf::from("/workspace"),
                    uid: 65534,
                    gid: 65534,
                },
                environment: BTreeMap::from([
                    ("BUZZ_CI_RUN_ID".to_owned(), "run-1".to_owned()),
                    ("BUZZ_CI_SHA".to_owned(), "11".repeat(20)),
                    ("BUZZ_CI_ATTEMPT".to_owned(), "1".to_owned()),
                ]),
                effective_spec: EffectiveContainerSpec {
                    user: "65534:65534".to_owned(),
                    userns_mode: "private".to_owned(),
                    cap_drop: vec!["ALL".to_owned()],
                    security_opt: vec![
                        format!("seccomp={SECCOMP_PROFILE_PATH}"),
                        "label=type:buzzci_job_t".to_owned(),
                    ],
                    network_mode: "none".to_owned(),
                    image: format!("sha256:{}", "77".repeat(32)),
                    binds: vec![PathBuf::from("/run/buzzci/lease-4/input")],
                    log_driver: "none".to_owned(),
                    artifact_server_enabled: false,
                    persistent_logs: false,
                    nano_cpus: 1_000_000_000,
                    memory: 1_073_741_824,
                    pids_limit: 128,
                },
                proof: EffectiveSpecProof {
                    source_request_sha256: digest(0x61),
                    rebuilt_create_sha256: digest(0x62),
                    rebuilt_exec_sha256: digest(0x63),
                    effective_spec_sha256: digest(0x66),
                    seccomp_profile_sha256: seccomp_digest(),
                    recorded_before_unit_start: true,
                },
                image_digest: format!("sha256:{}", "77".repeat(32)),
                recorded_at_ns: 22,
            })
            .unwrap();
        store
            .append_ordering(&OrderingRecord {
                lease_id: lease.lease_id.clone(),
                sequence: 1,
                event_binding: binding(),
                event: OrderingEvent::ProxyObjectRecorded,
                object_id: Some("lease-4".to_owned()),
                timestamp_unix_ns: 22,
                status_event_id: None,
                verdict_event_id: None,
            })
            .unwrap();
        store
            .publish_teardown(&TeardownRecord {
                lease_id: lease.lease_id.clone(),
                event_binding: binding(),
                lease_unit: lease.lease_unit.clone(),
                cgroup_path: lease.cgroup_path.clone(),
                unit_inactive: true,
                cgroup_procs_empty: true,
                mounts_removed: true,
                dirs_removed: true,
                teardown_sha256: digest(0x88),
                completed_at_unix_ns: 23,
            })
            .unwrap();
        store
            .publish_reconcile(&ReconcileRecord {
                lease_id: lease.lease_id.clone(),
                lease_unit: lease.lease_unit.clone(),
                cgroup_path: lease.cgroup_path.clone(),
                state: ReconcileState::Clean,
                emptied: true,
                quarantined: false,
                before_reuse: true,
                emptied_resources: vec![
                    ReconciledResource::LeaseUnit,
                    ReconciledResource::Cgroup,
                    ReconciledResource::Workspace,
                ],
                quarantined_resources: vec![],
                reuse_allowed: true,
                observed_at_unix_ns: 24,
            })
            .unwrap();

        let proxy_object = paths.proxy_object(1).unwrap();
        let proxy_json: serde_json::Value =
            serde_json::from_slice(&fs::read(&proxy_object).unwrap()).unwrap();
        assert_eq!(proxy_json["object_id"], "lease-4");
        assert_eq!(proxy_json["recorded_at_ns"], 22);
        assert_eq!(proxy_json["effective_spec"]["network_mode"], "none");
        assert_eq!(
            proxy_json["effective_spec"]["cap_drop"],
            serde_json::json!(["ALL"])
        );
        assert!(proxy_json.get("environment").is_none());
        assert_eq!(proxy_json["env"].as_object().unwrap().len(), 3);
        for key in ["BUZZ_CI_RUN_ID", "BUZZ_CI_SHA", "BUZZ_CI_ATTEMPT"] {
            assert!(!proxy_json["env"][key].as_str().unwrap().is_empty());
        }
        let mut unconfined: ProxyObjectRecord =
            serde_json::from_slice(&fs::read(&proxy_object).unwrap()).unwrap();
        unconfined.sequence = 2;
        unconfined.effective_spec.security_opt = vec![
            "seccomp=unconfined".to_owned(),
            "label=type:buzzci_job_t".to_owned(),
        ];
        assert!(matches!(
            store.publish_proxy_object(&unconfined),
            Err(PublicationError::RecordMismatch)
        ));
        let mut secret_environment: ProxyObjectRecord =
            serde_json::from_slice(&fs::read(&proxy_object).unwrap()).unwrap();
        secret_environment.sequence = 2;
        secret_environment
            .environment
            .insert("GITHUB_TOKEN".to_owned(), "must-not-persist".to_owned());
        assert!(matches!(
            store.publish_proxy_object(&secret_environment),
            Err(PublicationError::RecordMismatch)
        ));
        let mut empty_environment: ProxyObjectRecord =
            serde_json::from_slice(&fs::read(&proxy_object).unwrap()).unwrap();
        empty_environment.sequence = 2;
        empty_environment
            .environment
            .insert("BUZZ_CI_ATTEMPT".to_owned(), String::new());
        assert!(matches!(
            store.publish_proxy_object(&empty_environment),
            Err(PublicationError::RecordMismatch)
        ));
        unconfined.effective_spec.security_opt = vec![
            format!("seccomp={SECCOMP_PROFILE_PATH}"),
            "label=type:buzzci_job_t".to_owned(),
        ];
        unconfined.environment.remove("BUZZ_CI_ATTEMPT");
        assert!(matches!(
            store.publish_proxy_object(&unconfined),
            Err(PublicationError::RecordMismatch)
        ));
        let decisions = fs::read_to_string(&paths.proxy_decisions).unwrap();
        let decision_rows = decisions
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            decision_rows
                .iter()
                .map(|row| row["sequence"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(decision_rows.iter().all(|row| {
            row["schema_version"].is_number()
                && row["route"].is_string()
                && row["verdict"].is_string()
                && row["reason"].is_string()
                && row["request_hash"].is_string()
                && row["method"].is_string()
                && row["target"].is_string()
        }));
        assert!(decision_rows
            .iter()
            .any(|row| { row["route"] == "unknown" && row["verdict"] == "refused" }));
        let mut incomplete_teardown: TeardownRecord =
            serde_json::from_slice(&fs::read(&paths.teardown).unwrap()).unwrap();
        let teardown_json: serde_json::Value =
            serde_json::from_slice(&fs::read(&paths.teardown).unwrap()).unwrap();
        for key in ["cgroup_procs_empty", "mounts_removed", "dirs_removed"] {
            assert_eq!(teardown_json[key], true);
        }
        incomplete_teardown.cgroup_procs_empty = false;
        assert!(matches!(
            store.publish_teardown(&incomplete_teardown),
            Err(PublicationError::RecordMismatch)
        ));
        incomplete_teardown.cgroup_procs_empty = true;
        incomplete_teardown.unit_inactive = false;
        assert!(matches!(
            store.publish_teardown(&incomplete_teardown),
            Err(PublicationError::RecordMismatch)
        ));
        incomplete_teardown.unit_inactive = true;
        incomplete_teardown.mounts_removed = false;
        assert!(matches!(
            store.publish_teardown(&incomplete_teardown),
            Err(PublicationError::RecordMismatch)
        ));
        incomplete_teardown.mounts_removed = true;
        incomplete_teardown.dirs_removed = false;
        assert!(matches!(
            store.publish_teardown(&incomplete_teardown),
            Err(PublicationError::RecordMismatch)
        ));
        for path in [
            &paths.materializer_receipt,
            &paths.proxy_decisions,
            &proxy_object,
            &paths.ordering,
            &paths.teardown,
            &paths.reconcile,
        ] {
            assert!(path.is_file(), "missing {}", path.display());
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        let lease_bytes = fs::read(&paths.lease).unwrap();
        let persisted: LeaseRecord = serde_json::from_slice(&lease_bytes).unwrap();
        let lease_json: serde_json::Value = serde_json::from_slice(&lease_bytes).unwrap();
        assert_eq!(persisted.lease_unit, lease.lease_unit);
        assert_eq!(persisted.cgroup_path, lease.cgroup_path);
        assert_eq!(persisted.resource_readback, lease.resource_readback);
        assert_eq!(persisted.workspace_dir, lease.workspace_dir);
        assert_eq!(persisted.limits.wall_deadline, 610);
        assert!(dns_readback_complete(persisted.dns_readback));
        assert!(persisted.sanitized_artifact_store_path.is_absolute());
        assert!(persisted.sanitized_log_store_path.is_absolute());
        assert_eq!(lease_json["limits"]["wall_deadline"], 610);
        assert_eq!(lease_json["dns_readback"].as_object().unwrap().len(), 5);
        assert!(lease_json["dns_readback"]
            .as_object()
            .unwrap()
            .values()
            .all(|value| value == true));
        for key in [
            "workspace_dir",
            "sanitized_artifact_store_path",
            "sanitized_log_store_path",
        ] {
            assert!(lease_json[key].as_str().unwrap().starts_with('/'));
        }
        assert_eq!(
            persisted.seccomp_profile.path,
            Path::new(SECCOMP_PROFILE_PATH)
        );
        assert_eq!(persisted.seccomp_profile.sha256, SECCOMP_PROFILE_SHA256);

        let mut invalid_reconcile: ReconcileRecord =
            serde_json::from_slice(&fs::read(paths.reconcile).unwrap()).unwrap();
        let reconcile_json = serde_json::to_value(&invalid_reconcile).unwrap();
        assert_eq!(reconcile_json["emptied"], true);
        assert_eq!(reconcile_json["quarantined"], false);
        assert_eq!(reconcile_json["before_reuse"], true);
        assert!(reconcile_json["emptied_resources"].is_array());
        assert!(reconcile_json["quarantined_resources"].is_array());
        invalid_reconcile.before_reuse = false;
        assert!(matches!(
            store.publish_reconcile(&invalid_reconcile),
            Err(PublicationError::RecordMismatch)
        ));
    }

    #[test]
    fn seccomp_drift_and_unsafe_lease_ids_block_initialization() {
        let root = temp_root("refuse");
        let store = EvidenceStore::new(root.join("leases")).unwrap();
        let mut drifted = lease("lease-3");
        drifted.seccomp_profile.sha256 = "00".repeat(32);
        assert!(matches!(
            store.initialize_lease(&drifted),
            Err(PublicationError::RecordMismatch)
        ));
        assert!(matches!(
            store.paths("../escape"),
            Err(PublicationError::UnsafeLeaseId)
        ));
        assert!(matches!(
            EvidenceStore::new(root.join("state/../escape")),
            Err(PublicationError::RecordMismatch)
        ));
        let mut outside_cgroup = lease("lease-5");
        outside_cgroup.cgroup_path = PathBuf::from("/other.slice/lease.scope");
        assert!(matches!(
            store.initialize_lease(&outside_cgroup),
            Err(PublicationError::RecordMismatch)
        ));
        let mut incomplete_dns = lease("lease-6");
        incomplete_dns.dns_readback.direct_53_refused = false;
        assert!(matches!(
            store.initialize_lease(&incomplete_dns),
            Err(PublicationError::RecordMismatch)
        ));
        let mut expired = lease("lease-7");
        expired.limits.wall_deadline = expired.created_at_unix_ns;
        assert!(matches!(
            store.initialize_lease(&expired),
            Err(PublicationError::RecordMismatch)
        ));
        let mut unsafe_store = lease("lease-8");
        unsafe_store.sanitized_log_store_path =
            PathBuf::from("/var/lib/buzzci/published/../escape");
        assert!(matches!(
            store.initialize_lease(&unsafe_store),
            Err(PublicationError::RecordMismatch)
        ));
    }

    #[test]
    fn per_lease_slice_must_match_its_cgroup_path_exactly() {
        let root = temp_root("slice-unit");
        let store = EvidenceStore::new(root.join("leases")).unwrap();
        let mut slice = lease("slice-lease");
        slice.lease_unit = "buzzci-slice-lease.slice".to_owned();
        slice.cgroup_path = PathBuf::from("/buzzci.slice/buzzci-slice-lease.slice");
        store.initialize_lease(&slice).unwrap();

        let mut mismatched = lease("mismatched-slice");
        mismatched.lease_unit = "buzzci-mismatched-slice.slice".to_owned();
        mismatched.cgroup_path = PathBuf::from("/buzzci.slice/buzzci-other.slice");
        assert!(matches!(
            store.initialize_lease(&mismatched),
            Err(PublicationError::RecordMismatch)
        ));

        let mut unsafe_name = lease("unsafe-slice");
        unsafe_name.lease_unit = "buzzci-unsafe!.slice".to_owned();
        unsafe_name.cgroup_path = PathBuf::from("/buzzci.slice/buzzci-unsafe!.slice");
        assert!(matches!(
            store.initialize_lease(&unsafe_name),
            Err(PublicationError::RecordMismatch)
        ));
    }
}
