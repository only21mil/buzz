//! Capacity-one production composition for broker protocol v2.
//!
//! All authority is root-authored and static. The runner transports requests;
//! it never supplies a command, path, environment, or local execution fallback.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use buzz_ci_broker_protocol::{
    v2::{
        decode_production_qualification_response, decode_request,
        encode_production_qualification_response, encode_request,
        intent_registration_key_digest_for_admission, intent_registration_request_frame_digest,
        production_qualification_executor_provenance_digest, production_qualification_key_digest,
        production_qualification_principal_digest, production_qualification_receipt_digest,
        production_qualification_request_frame_digest, AdmissionSignatureAlgorithm,
        EvidenceDescriptor, EvidenceKind, FrameHeader, ProductionQualificationRequest,
        ProductionQualificationResponse, RegisterJobIntentRequest, Request, WireText64,
    },
    Conclusion, GitOid, ResponseCode, MAX_SAFE_INTEGER,
};
use buzz_ci_isolation_contract::{PHASE1_SECCOMP_PROFILE_DIGEST, PHASE1_SECCOMP_PROFILE_PATH};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::{
    sys::signal::{killpg, Signal},
    sys::stat::{mkdirat, Mode},
    unistd::{fchown, Gid, Pid, Uid},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    control::{ControlDispatch, PeerUidPolicy},
    production_binding::{
        ArtifactDeclarationV1, BindingError, BindingPhase, ExecutionBindingJournal,
        ExecutionBindingRecord, ExecutionBindingV1, HostEvidenceItem, HostIdentity,
        HostRecoveryReceipt, HostStepReceipt, HostStopReason, HostTerminalReceipt,
        IntentRegistrationWrite, JobIntentSource, JobIntentV2, JournalWrite,
        LaneActivationManifestV1, PrivilegedHostSystem, ProductionBindingController,
        RegisteredJobIntent, StaticLaneManifest, EXECUTION_BINDING_SCHEMA_V1,
    },
    seccomp_activation::{SeccompActivationAdapter, SeccompStartupProof},
};

pub const CONFIG_PATH: &str = "/etc/buzzci/execd-v2.json";
pub const INTENT_ROOT: &str = "/var/lib/buzzci/execd-v2/intents";
pub const BINDING_ROOT: &str = "/var/lib/buzzci/execd-v2/bindings";
pub const EVIDENCE_ROOT: &str = "/var/lib/buzzci/execd-v2/evidence";
pub const TEARDOWN_ROOT: &str = "/var/lib/buzzci/execd-v2/teardown";
pub const ATTEMPT_ROOT: &str = "/var/lib/buzzci/execd-v2/attempts";
pub const QUALIFICATION_ROOT: &str = "/var/lib/buzzci/execd-v2/qualification";
const SHARED_STATE_ROOT: &str = "/var/lib/buzzci";
const EXECD_STATE_ROOT: &str = "/var/lib/buzzci/execd-v2";
pub const EXECUTOR_SOCKET: &str = "/run/buzzci/executor.sock";
pub const EXECUTOR_PROGRAM: &str = "/usr/libexec/buzz-ci-executor";
pub const ACCESS_GROUP: &str = "buzzci-execd";
pub const CONTROL_UID: u32 = 961;
pub const CONTROL_GID: u32 = 961;
pub const CONTROL_USER: &str = "buzzci-ctl";
pub const CONTROL_GROUP: &str = "buzzci-ctl";
pub const CONTROL_HOME: &str = "/var/lib/buzzci/principals/ctl";
pub const JOB_USER: &str = "buzzci-job";
pub const FIXTURE_MANIFEST_SOURCE: &str =
    "/usr/share/buzzci/execd-v2/fixture/fixture-manifest.json";
pub const FIXTURE_INPUT_SOURCE: &str = "/usr/share/buzzci/execd-v2/fixture/input.txt";
pub const FIXTURE_SCRIPT_SOURCE: &str = "/usr/libexec/buzz-ci-capacity-one-fixture";
const MATERIALIZED_SOURCE_ROOT: &str = "source";
const MATERIALIZED_ARTIFACT_ROOT: &str = "artifacts";
const FIXTURE_TREE: [&str; 4] = ["deploy", "native-ci", "acceptance", "fixtures"];
const FIXTURE_MANIFEST_NAME: &str = "fixture-manifest.json";
const FIXTURE_INPUT_NAME: &str = "input.txt";
const FIXTURE_SCRIPT_NAME: &str = "run-fixture.sh";
const FIXTURE_MANIFEST_SHA256: &str =
    "f204b8fba64e972408f5a0ea1c0bb3140cfa696289903d96a8cb07d602af6b23";
const FIXTURE_INPUT_SHA256: &str =
    "967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6";
const FIXTURE_SCRIPT_SHA256: &str =
    "f0f4fa8b4f47a2edf4d3a080b2f3e818c69647441376b927265572191655c9d6";
const CONFIG_SCHEMA: u16 = 2;
const RPC_SCHEMA: u16 = 1;
const MAX_CONFIG: u64 = 64 * 1024;
const MAX_INTENT: u64 = 32 * 1024;
const MAX_RECORD: u64 = 32 * 1024;
const MAX_EVIDENCE_DOCUMENT: u64 = 256 * 1024;
const MAX_ARTIFACT_RECEIPT: u64 = 96 * 1024;
const MAX_RPC: usize = 64 * 1024;
const MAX_RAW_OUTPUT: usize = 32 * 1024;
const MAX_QUALIFICATION_RECEIPTS: usize = 16;
const STATIC_EXECUTION_SCHEMA: u16 = 1;
const STATIC_EXECUTION_DIGEST_DOMAIN: &[u8] = b"buzz-ci-execd:static-execution:v1\0";
const EXECUTOR_RECEIPT_DOMAIN: &[u8] = b"buzz-ci-executor:receipt:v2\0";
const FIXED_MAX_STDOUT_BYTES: u32 = 32 * 1024;
const FIXED_MAX_STDERR_BYTES: u32 = 32 * 1024;
const FIXED_MAX_MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const FIXED_MAX_PROCESSES: u32 = 16;
const FIXED_MAX_WALL_SECONDS: u32 = 120;

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeccompRuntimeBinding {
    profile_path: String,
    profile_digest: String,
    install_receipt_digest: String,
}

impl SeccompRuntimeBinding {
    fn from_proof(proof: SeccompStartupProof) -> Result<Self, ProductionV2Error> {
        let evidence = proof.seccomp_evidence();
        let capability = proof.install_capability();
        let binding = Self {
            profile_path: evidence.path().into(),
            profile_digest: evidence.digest().into(),
            install_receipt_digest: capability.receipt_digest(),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), ProductionV2Error> {
        if self.profile_path != PHASE1_SECCOMP_PROFILE_PATH
            || self.profile_digest != PHASE1_SECCOMP_PROFILE_DIGEST
            || self.install_receipt_digest.len() != 64
            || !lower_hex(&self.install_receipt_digest)
            || self.install_receipt_digest.bytes().all(|byte| byte == b'0')
        {
            return Err(ProductionV2Error::Closed);
        }
        Ok(())
    }

    #[cfg(test)]
    fn fixture() -> Self {
        Self {
            profile_path: PHASE1_SECCOMP_PROFILE_PATH.into(),
            profile_digest: PHASE1_SECCOMP_PROFILE_DIGEST.into(),
            install_receipt_digest: "11".repeat(32),
        }
    }
}

#[derive(Debug)]
pub enum ProductionV2Error {
    Closed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProductionConfig {
    schema_version: u16,
    enabled_protocol: u16,
    capacity: u8,
    identities: IdentityConfig,
    paths: PathConfig,
    lane_manifest: ManifestDocument,
    lane_manifest_digest: String,
    executor: ProgramProvenance,
    execution: StaticExecutionConfig,
    qualification: QualificationConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityConfig {
    execd_uid: u32,
    execd_gid: u32,
    runner_uid: u32,
    runner_gid: u32,
    control_uid: u32,
    control_gid: u32,
    job_uid: u32,
    job_gid: u32,
    access_group: String,
    access_group_gid: u32,
    access_group_members: Vec<String>,
    control_user: String,
    control_group: String,
    control_home: String,
    control_shell: String,
    control_supplementary_groups: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PathConfig {
    intent_root: String,
    binding_root: String,
    evidence_root: String,
    teardown_root: String,
    executor_socket: String,
    attempt_root: String,
    qualification_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProgramProvenance {
    path: String,
    sha256: String,
    source_commit: String,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationConfig {
    integrated_candidate_sha: String,
    activation_package_digest: String,
    fixture_digest: String,
    controller_generation: u64,
    runner_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticExecutionConfig {
    schema_version: u16,
    declaration_digest: String,
    workflow_id: String,
    workflow_digest: String,
    job_id: String,
    artifact: ArtifactDocument,
    fixture_manifest_sha256: String,
    fixture_input_sha256: String,
    fixture_script_sha256: String,
    max_stdout_bytes: u32,
    max_stderr_bytes: u32,
    max_memory_bytes: u64,
    max_processes: u32,
    max_wall_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationReceiptDocument {
    schema_version: u16,
    qualification_key_digest: String,
    request_frame_hex: String,
    response_frame_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestDocument {
    schema_version: u16,
    lane_id: String,
    lane_epoch: u64,
    admission_verifying_key: String,
    admission_key_generation: u64,
    broker_build_identity: String,
    host_profile_digest: String,
    suite_identity: String,
    isolation_profile_digest: String,
    not_before: u64,
    expires_at: u64,
    max_wall_timeout_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RegisteredIntentDocument {
    schema_version: u16,
    registration_key_digest: String,
    request_frame_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactDocument {
    artifact_id: String,
    name: String,
    media_type: String,
    relative_name: String,
    max_bytes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OidDocument {
    algorithm: String,
    hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BindingDocument {
    schema_version: u16,
    lane_manifest_digest: String,
    lane_epoch: u64,
    job_intent_digest: String,
    admission_message_digest: String,
    signed_request_digest: String,
    actor_pubkey: String,
    idempotency_digest: String,
    run_id: String,
    attempt: u32,
    attempt_id: String,
    lease_id: String,
    lease_generation: u64,
    tip_oid: OidDocument,
    base_oid: OidDocument,
    admitted_at: u64,
    deadline_at: u64,
    execution_binding_digest: String,
    phase: String,
    generation: u64,
    updated_at: u64,
    conclusion: String,
    host_receipt_digest: String,
    evidence_set_digest: String,
    teardown_digest: String,
    request_event_id: String,
    workflow_digest: String,
    workflow_id: String,
    job_id: String,
    artifacts: Vec<ArtifactDocument>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutorRequest {
    schema_version: u16,
    operation: String,
    execution_binding_digest: String,
    attempt_id: String,
    job_intent_digest: Option<String>,
    static_execution_digest: String,
    fixture_manifest_sha256: String,
    fixture_input_sha256: String,
    fixture_script_sha256: String,
    deadline_at: u64,
    max_stdout_bytes: u32,
    max_stderr_bytes: u32,
    max_memory_bytes: u64,
    max_processes: u32,
    claimed_evidence_digest: Option<String>,
    phase: Option<String>,
    stop_reason: Option<String>,
    executor_program_sha256: String,
    seccomp_profile_path: String,
    seccomp_profile_sha256: String,
    seccomp_install_receipt_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutorResponse {
    schema_version: u16,
    operation: String,
    execution_binding_digest: String,
    receipt_digest: String,
    conclusion: Option<String>,
    evidence_set_digest: Option<String>,
    teardown_digest: Option<String>,
    raw_stdout: Option<String>,
    raw_stderr: Option<String>,
    exit_code: Option<i32>,
    running: Option<bool>,
    capacity_returned: Option<bool>,
    quarantine: Option<bool>,
}

#[derive(Clone)]
struct RuntimePaths {
    prefix: PathBuf,
}

impl RuntimePaths {
    fn canonical() -> Self {
        Self { prefix: "/".into() }
    }

    fn resolve(&self, absolute: &str) -> Result<PathBuf, ProductionV2Error> {
        let path = Path::new(absolute);
        if !safe_absolute(path) {
            return Err(ProductionV2Error::Closed);
        }
        if self.prefix == Path::new("/") {
            Ok(path.to_owned())
        } else {
            Ok(self.prefix.join(
                path.strip_prefix("/")
                    .map_err(|_| ProductionV2Error::Closed)?,
            ))
        }
    }
}

struct SafeDirectory {
    directory: File,
    owner: u32,
}

impl SafeDirectory {
    fn open(path: PathBuf, owner: u32, mode: u32) -> Result<Self, ProductionV2Error> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| ProductionV2Error::Closed)?;
        let metadata = directory
            .metadata()
            .map_err(|_| ProductionV2Error::Closed)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != owner
            || metadata.permissions().mode() & 0o7777 != mode
        {
            return Err(ProductionV2Error::Closed);
        }
        Ok(Self { directory, owner })
    }

    fn descriptor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    fn names(&self, maximum: usize) -> Result<Vec<String>, ProductionV2Error> {
        let mut names = fs::read_dir(self.descriptor_path())
            .map_err(|_| ProductionV2Error::Closed)?
            .map(|entry| {
                entry
                    .map_err(|_| ProductionV2Error::Closed)?
                    .file_name()
                    .into_string()
                    .map_err(|_| ProductionV2Error::Closed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if names.len() > maximum || names.iter().any(|name| !safe_name(name)) {
            return Err(ProductionV2Error::Closed);
        }
        names.sort_unstable();
        Ok(names)
    }

    fn open_child(&self, name: &str, owner: u32, mode: u32) -> Result<Self, ProductionV2Error> {
        if !safe_name(name) {
            return Err(ProductionV2Error::Closed);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(self.descriptor_path().join(name))
            .map_err(|_| ProductionV2Error::Closed)?;
        let metadata = directory
            .metadata()
            .map_err(|_| ProductionV2Error::Closed)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != owner
            || metadata.permissions().mode() & 0o7777 != mode
        {
            return Err(ProductionV2Error::Closed);
        }
        Ok(Self { directory, owner })
    }

    fn create_child(
        &self,
        name: &str,
        owner: u32,
        group: u32,
        mode: u32,
    ) -> Result<Self, ProductionV2Error> {
        if !safe_name(name)
            || mkdirat(&self.directory, name, Mode::from_bits_truncate(0o700)).is_err()
        {
            return Err(ProductionV2Error::Closed);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(self.descriptor_path().join(name))
            .map_err(|_| ProductionV2Error::Closed)?;
        fchown(
            &directory,
            Some(Uid::from_raw(owner)),
            Some(Gid::from_raw(group)),
        )
        .map_err(|_| ProductionV2Error::Closed)?;
        directory
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| ProductionV2Error::Closed)?;
        directory
            .sync_all()
            .map_err(|_| ProductionV2Error::Closed)?;
        self.directory
            .sync_all()
            .map_err(|_| ProductionV2Error::Closed)?;
        let child = Self { directory, owner };
        child.open_file(".", owner, mode, 0, true)?;
        Ok(child)
    }

    fn open_file(
        &self,
        name: &str,
        owner: u32,
        mode: u32,
        maximum: u64,
        directory: bool,
    ) -> Result<File, ProductionV2Error> {
        if name != "." && !safe_name(name) {
            return Err(ProductionV2Error::Closed);
        }
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            nix::libc::O_NOFOLLOW
                | nix::libc::O_CLOEXEC
                | if directory { nix::libc::O_DIRECTORY } else { 0 },
        );
        let file = options
            .open(self.descriptor_path().join(name))
            .map_err(|_| ProductionV2Error::Closed)?;
        let metadata = file.metadata().map_err(|_| ProductionV2Error::Closed)?;
        let expected_owner = if directory { self.owner } else { owner };
        if (directory && !metadata.file_type().is_dir())
            || (!directory && !metadata.file_type().is_file())
            || metadata.uid() != expected_owner
            || metadata.permissions().mode() & 0o7777 != mode
            || (!directory && (metadata.nlink() != 1 || metadata.len() > maximum))
        {
            return Err(ProductionV2Error::Closed);
        }
        Ok(file)
    }

    fn read(&self, name: &str, mode: u32, maximum: u64) -> Result<Vec<u8>, ProductionV2Error> {
        let file = self.open_file(name, self.owner, mode, maximum, false)?;
        let mut bytes = Vec::new();
        file.take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ProductionV2Error::Closed)?;
        if bytes.is_empty() || bytes.len() as u64 > maximum {
            return Err(ProductionV2Error::Closed);
        }
        Ok(bytes)
    }

    fn write_once(&self, name: &str, bytes: &[u8], mode: u32) -> Result<(), ProductionV2Error> {
        self.write_once_bounded(name, bytes, mode, MAX_RECORD)
    }

    fn write_once_bounded(
        &self,
        name: &str,
        bytes: &[u8],
        mode: u32,
        maximum: u64,
    ) -> Result<(), ProductionV2Error> {
        if !safe_name(name) || bytes.is_empty() || bytes.len() as u64 > maximum {
            return Err(ProductionV2Error::Closed);
        }
        let path = self.descriptor_path().join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| ProductionV2Error::Closed)?;
        file.write_all(bytes)
            .map_err(|_| ProductionV2Error::Closed)?;
        file.sync_all().map_err(|_| ProductionV2Error::Closed)?;
        let metadata = file.metadata().map_err(|_| ProductionV2Error::Closed)?;
        if metadata.uid() != self.owner
            || metadata.permissions().mode() & 0o7777 != mode
            || metadata.nlink() != 1
        {
            let _ = fs::remove_file(path);
            return Err(ProductionV2Error::Closed);
        }
        self.directory
            .sync_all()
            .map_err(|_| ProductionV2Error::Closed)
    }

    fn write_once_owned(
        &self,
        name: &str,
        bytes: &[u8],
        owner: u32,
        group: u32,
        mode: u32,
    ) -> Result<(), ProductionV2Error> {
        if !safe_name(name) || bytes.is_empty() || bytes.len() as u64 > MAX_RECORD {
            return Err(ProductionV2Error::Closed);
        }
        let path = self.descriptor_path().join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| ProductionV2Error::Closed)?;
        fchown(
            &file,
            Some(Uid::from_raw(owner)),
            Some(Gid::from_raw(group)),
        )
        .map_err(|_| ProductionV2Error::Closed)?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| ProductionV2Error::Closed)?;
        file.write_all(bytes)
            .map_err(|_| ProductionV2Error::Closed)?;
        file.sync_all().map_err(|_| ProductionV2Error::Closed)?;
        let metadata = file.metadata().map_err(|_| ProductionV2Error::Closed)?;
        if metadata.uid() != owner
            || metadata.gid() != group
            || metadata.permissions().mode() & 0o7777 != mode
            || metadata.nlink() != 1
        {
            let _ = fs::remove_file(path);
            return Err(ProductionV2Error::Closed);
        }
        self.directory
            .sync_all()
            .map_err(|_| ProductionV2Error::Closed)
    }

    fn remove_tree_child(&self, name: &str) -> Result<(), ProductionV2Error> {
        if !safe_name(name) {
            return Err(ProductionV2Error::Closed);
        }
        let path = self.descriptor_path().join(name);
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path);
        match directory {
            Ok(directory) => {
                let group = self
                    .directory
                    .metadata()
                    .map_err(|_| ProductionV2Error::Closed)?
                    .gid();
                fchown(
                    &directory,
                    Some(Uid::from_raw(self.owner)),
                    Some(Gid::from_raw(group)),
                )
                .map_err(|_| ProductionV2Error::Closed)?;
                directory
                    .set_permissions(fs::Permissions::from_mode(0o700))
                    .map_err(|_| ProductionV2Error::Closed)?;
                let child = Self {
                    directory,
                    owner: self.owner,
                };
                for child_name in child.names(64)? {
                    child.remove_tree_child(&child_name)?;
                }
                child
                    .directory
                    .sync_all()
                    .map_err(|_| ProductionV2Error::Closed)?;
                drop(child);
                fs::remove_dir(&path).map_err(|_| ProductionV2Error::Closed)?;
            }
            Err(_) => {
                let metadata =
                    fs::symlink_metadata(&path).map_err(|_| ProductionV2Error::Closed)?;
                if metadata.file_type().is_dir() {
                    return Err(ProductionV2Error::Closed);
                }
                fs::remove_file(&path).map_err(|_| ProductionV2Error::Closed)?;
            }
        }
        self.directory
            .sync_all()
            .map_err(|_| ProductionV2Error::Closed)
    }

    fn replace(&self, name: &str, bytes: &[u8], mode: u32) -> Result<(), ProductionV2Error> {
        if !safe_name(name) || bytes.is_empty() || bytes.len() as u64 > MAX_RECORD {
            return Err(ProductionV2Error::Closed);
        }
        let temp = format!("new-{name}");
        let root = self.descriptor_path();
        let temp_path = root.join(&temp);
        let _ = fs::remove_file(&temp_path);
        self.write_once(&temp, bytes, mode)?;
        fs::rename(&temp_path, root.join(name)).map_err(|_| ProductionV2Error::Closed)?;
        self.directory
            .sync_all()
            .map_err(|_| ProductionV2Error::Closed)
    }
}

struct StaticIntentFiles {
    root: SafeDirectory,
}

impl RegisteredIntentDocument {
    fn decode(
        self,
    ) -> Result<(FrameHeader, RegisterJobIntentRequest, RegisteredJobIntent), ProductionV2Error>
    {
        if self.schema_version != 1 {
            return Err(ProductionV2Error::Closed);
        }
        let registration_key_digest = decode_hex::<32>(&self.registration_key_digest)?;
        if self.request_frame_hex.len() > MAX_INTENT as usize * 2
            || !lower_hex(&self.request_frame_hex)
        {
            return Err(ProductionV2Error::Closed);
        }
        let frame = hex::decode(&self.request_frame_hex).map_err(|_| ProductionV2Error::Closed)?;
        let (header, decoded) = decode_request(&frame).map_err(|_| ProductionV2Error::Closed)?;
        let Request::RegisterJobIntent(request) = decoded else {
            return Err(ProductionV2Error::Closed);
        };
        if intent_registration_request_frame_digest(header, &request)
            != Some(request.request_frame_digest)
            || intent_registration_key_digest_for_admission(request.admission)
                != registration_key_digest
        {
            return Err(ProductionV2Error::Closed);
        }
        let intent = JobIntentV2::from_registration(request);
        if intent.digest() != request.admission.job_intent_digest {
            return Err(ProductionV2Error::Closed);
        }
        Ok((
            header,
            request,
            RegisteredJobIntent {
                admission: request.admission,
                intent,
            },
        ))
    }
}

impl StaticIntentFiles {
    fn open(root: SafeDirectory) -> Result<Self, ProductionV2Error> {
        for entry in fs::read_dir(root.descriptor_path()).map_err(|_| ProductionV2Error::Closed)? {
            let entry = entry.map_err(|_| ProductionV2Error::Closed)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ProductionV2Error::Closed)?;
            let Some(hex_key) = name.strip_suffix(".json") else {
                return Err(ProductionV2Error::Closed);
            };
            if hex_key.len() != 64 || !lower_hex(hex_key) {
                return Err(ProductionV2Error::Closed);
            }
            let bytes = root.read(&name, 0o400, MAX_INTENT)?;
            let (_, _, registered) =
                canonical_parse::<RegisteredIntentDocument>(&bytes)?.decode()?;
            let expected = intent_registration_key_digest_for_admission(registered.admission);
            if hex::encode(expected) != hex_key {
                return Err(ProductionV2Error::Closed);
            }
        }
        Ok(Self { root })
    }
}

impl JobIntentSource for StaticIntentFiles {
    fn register(
        &mut self,
        header: FrameHeader,
        request: RegisterJobIntentRequest,
        intent: JobIntentV2,
    ) -> Result<IntentRegistrationWrite, BindingError> {
        if header.operation != Request::RegisterJobIntent(request).operation()
            || intent_registration_request_frame_digest(header, &request)
                != Some(request.request_frame_digest)
            || JobIntentV2::from_registration(request) != intent
            || intent.digest() != request.admission.job_intent_digest
        {
            return Err(BindingError::IntentRefused);
        }
        let registration_key_digest =
            intent_registration_key_digest_for_admission(request.admission);
        let name = format!("{}.json", hex::encode(registration_key_digest));
        let frame = encode_request(header.request_id, Request::RegisterJobIntent(request));
        let document = RegisteredIntentDocument {
            schema_version: 1,
            registration_key_digest: hex::encode(registration_key_digest),
            request_frame_hex: hex::encode(frame.as_bytes()),
        };
        let bytes = canonical_bytes(&document).map_err(binding_error)?;
        match self.root.write_once(&name, &bytes, 0o400) {
            Ok(()) => Ok(IntentRegistrationWrite::Written),
            Err(_) => match self.root.read(&name, 0o400, MAX_INTENT) {
                Ok(existing) if existing == bytes => Ok(IntentRegistrationWrite::Existing),
                Ok(_) => Ok(IntentRegistrationWrite::Conflict),
                Err(_) => Err(BindingError::StorageUnavailable),
            },
        }
    }

    fn load(
        &mut self,
        registration_key: [u8; 32],
        job_intent_digest: [u8; 32],
    ) -> Result<RegisteredJobIntent, BindingError> {
        let name = format!("{}.json", hex::encode(registration_key));
        let bytes = self
            .root
            .read(&name, 0o400, MAX_INTENT)
            .map_err(binding_error)?;
        let document: RegisteredIntentDocument = canonical_parse(&bytes).map_err(binding_error)?;
        let (_, _, registered) = document.decode().map_err(binding_error)?;
        (intent_registration_key_digest_for_admission(registered.admission) == registration_key
            && registered.intent.digest() == job_intent_digest)
            .then_some(registered)
            .ok_or(BindingError::IntentRefused)
    }
}

struct DurableBindingFiles {
    root: SafeDirectory,
}

impl DurableBindingFiles {
    fn name(attempt_id: [u8; 16]) -> String {
        format!("{}.json", hex::encode(attempt_id))
    }

    fn decode(bytes: &[u8]) -> Result<ExecutionBindingRecord, BindingError> {
        let document: BindingDocument = canonical_parse(bytes).map_err(binding_error)?;
        document.into_record().map_err(binding_error)
    }
}

impl ExecutionBindingJournal for DurableBindingFiles {
    fn load(
        &mut self,
        attempt_id: [u8; 16],
    ) -> Result<Option<ExecutionBindingRecord>, BindingError> {
        let name = Self::name(attempt_id);
        match self.root.read(&name, 0o600, MAX_RECORD) {
            Ok(bytes) => Self::decode(&bytes).map(Some),
            Err(_) if !self.root.descriptor_path().join(name).exists() => Ok(None),
            Err(_) => Err(BindingError::StorageUnavailable),
        }
    }

    fn list(&mut self) -> Result<Vec<ExecutionBindingRecord>, BindingError> {
        let mut records = Vec::new();
        let entries = fs::read_dir(self.root.descriptor_path())
            .map_err(|_| BindingError::StorageUnavailable)?;
        for entry in entries {
            let entry = entry.map_err(|_| BindingError::StorageUnavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| BindingError::StorageUnavailable)?;
            if !name.ends_with(".json") || name.len() != 37 || !safe_name(&name) {
                return Err(BindingError::StorageUnavailable);
            }
            records.push(Self::decode(
                &self
                    .root
                    .read(&name, 0o600, MAX_RECORD)
                    .map_err(binding_error)?,
            )?);
        }
        records.sort_by_key(|record| record.binding.attempt_id);
        Ok(records)
    }

    fn insert(&mut self, record: ExecutionBindingRecord) -> Result<JournalWrite, BindingError> {
        let name = Self::name(record.binding.attempt_id);
        if self.load(record.binding.attempt_id)?.is_some() {
            return Ok(JournalWrite::Conflict);
        }
        let bytes = canonical_bytes(&BindingDocument::from(record)).map_err(binding_error)?;
        self.root
            .write_once(&name, &bytes, 0o600)
            .map(|_| JournalWrite::Written)
            .or_else(|_| match self.load(record.binding.attempt_id)? {
                Some(_) => Ok(JournalWrite::Conflict),
                None => Err(BindingError::StorageUnavailable),
            })
    }

    fn replace(
        &mut self,
        expected_generation: u64,
        record: ExecutionBindingRecord,
    ) -> Result<JournalWrite, BindingError> {
        let Some(current) = self.load(record.binding.attempt_id)? else {
            return Ok(JournalWrite::Conflict);
        };
        if current.generation != expected_generation
            || current.binding.execution_binding_digest != record.binding.execution_binding_digest
        {
            return Ok(JournalWrite::Conflict);
        }
        let bytes = canonical_bytes(&BindingDocument::from(record)).map_err(binding_error)?;
        self.root
            .replace(&Self::name(record.binding.attempt_id), &bytes, 0o600)
            .map_err(binding_error)?;
        Ok(JournalWrite::Written)
    }
}

#[derive(Clone, Debug)]
struct StaticExecutionContract {
    declaration_digest: [u8; 32],
    candidate: GitOid,
    activation_package_digest: [u8; 32],
    lane_manifest_digest: [u8; 32],
    isolation_profile_digest: [u8; 32],
    workflow_id: WireText64,
    workflow_digest: [u8; 32],
    job_id: WireText64,
    artifact: ArtifactDeclarationV1,
    fixture_manifest: ProgramProvenance,
    fixture_input: ProgramProvenance,
    fixture_script: ProgramProvenance,
    max_stdout_bytes: u32,
    max_stderr_bytes: u32,
    max_memory_bytes: u64,
    max_processes: u32,
    max_wall_seconds: u32,
}

impl StaticExecutionContract {
    fn matches(&self, binding: ExecutionBindingV1, intent: JobIntentV2) -> bool {
        binding.job_intent_digest == intent.digest()
            && binding.tip_oid == self.candidate
            && binding.base_oid == self.candidate
            && binding.lane_manifest_digest == self.lane_manifest_digest
            && binding.workflow_digest == self.workflow_digest
            && binding.workflow_id == self.workflow_id
            && binding.job_id == self.job_id
            && binding.artifact_count == 1
            && binding.artifacts == [Some(self.artifact)]
            && intent.tip_oid == self.candidate
            && intent.base_oid == self.candidate
            && intent.lane_manifest_digest == self.lane_manifest_digest
            && intent.isolation_profile_digest == self.isolation_profile_digest
            && intent.workflow_digest == self.workflow_digest
            && intent.workflow_id == self.workflow_id
            && intent.job_id == self.job_id
            && intent.artifact_count == 1
            && intent.artifacts == [Some(self.artifact)]
            && intent.wall_timeout_seconds <= self.max_wall_seconds
            && binding.deadline_at.saturating_sub(binding.admitted_at)
                <= u64::from(self.max_wall_seconds)
            && self.activation_package_digest != [0; 32]
    }

    fn verify_sources(&self) -> Result<(), ProductionV2Error> {
        verify_program(&self.fixture_manifest)?;
        verify_program(&self.fixture_input)?;
        verify_program(&self.fixture_script)
    }
}

struct LocalHostSystem {
    identity: HostIdentity,
    socket: PathBuf,
    executor_uid: u32,
    executor_gid: u32,
    executor: ProgramProvenance,
    seccomp: SeccompRuntimeBinding,
    evidence: SafeDirectory,
    teardown: SafeDirectory,
    evidence_by_binding: BTreeMap<[u8; 32], [u8; 32]>,
    attempts: SafeDirectory,
    job_uid: u32,
    job_gid: u32,
    static_job: StaticExecutionContract,
}

impl LocalHostSystem {
    fn validate_static_job(
        &self,
        binding: ExecutionBindingV1,
        intent: JobIntentV2,
    ) -> Result<(), BindingError> {
        if !self.static_job.matches(binding, intent) {
            return Err(BindingError::HostRefused);
        }
        self.static_job.verify_sources().map_err(binding_error)
    }

    fn materialize(
        &mut self,
        binding: ExecutionBindingV1,
        intent: JobIntentV2,
    ) -> Result<[u8; 32], BindingError> {
        self.validate_static_job(binding, intent)?;
        let attempt_name = hex::encode(binding.attempt_id);
        let attempt_path = self.attempts.descriptor_path().join(&attempt_name);
        if attempt_path.exists() {
            return Err(BindingError::HostRefused);
        }
        let result = self.materialize_new_attempt(binding, &attempt_name);
        if result.is_err() {
            let _ = self.attempts.remove_tree_child(&attempt_name);
        }
        result
    }

    fn materialize_new_attempt(
        &self,
        binding: ExecutionBindingV1,
        attempt_name: &str,
    ) -> Result<[u8; 32], BindingError> {
        let attempt = self
            .attempts
            .create_child(attempt_name, self.job_uid, self.job_gid, 0o700)
            .map_err(binding_error)?;
        let source = attempt
            .create_child(MATERIALIZED_SOURCE_ROOT, self.job_uid, self.job_gid, 0o700)
            .map_err(binding_error)?;
        let mut source_tree = vec![source];
        for component in FIXTURE_TREE {
            let child = source_tree
                .last()
                .ok_or(BindingError::HostRefused)?
                .create_child(component, self.job_uid, self.job_gid, 0o700)
                .map_err(binding_error)?;
            source_tree.push(child);
        }
        let source = source_tree.last().ok_or(BindingError::HostRefused)?;
        let manifest = read_verified_program(&self.static_job.fixture_manifest)?;
        let input = read_verified_program(&self.static_job.fixture_input)?;
        let script = read_verified_program(&self.static_job.fixture_script)?;
        source
            .write_once_owned(
                FIXTURE_MANIFEST_NAME,
                &manifest,
                self.job_uid,
                self.job_gid,
                0o400,
            )
            .map_err(binding_error)?;
        source
            .write_once_owned(
                FIXTURE_INPUT_NAME,
                &input,
                self.job_uid,
                self.job_gid,
                0o400,
            )
            .map_err(binding_error)?;
        source
            .write_once_owned(
                FIXTURE_SCRIPT_NAME,
                &script,
                self.job_uid,
                self.job_gid,
                0o500,
            )
            .map_err(binding_error)?;
        attempt
            .create_child(
                MATERIALIZED_ARTIFACT_ROOT,
                self.job_uid,
                self.job_gid,
                0o700,
            )
            .map_err(binding_error)?;
        for directory in source_tree.iter().rev() {
            directory
                .directory
                .set_permissions(fs::Permissions::from_mode(0o500))
                .and_then(|_| directory.directory.sync_all())
                .map_err(|_| BindingError::HostRefused)?;
        }
        attempt
            .directory
            .set_permissions(fs::Permissions::from_mode(0o500))
            .and_then(|_| attempt.directory.sync_all())
            .map_err(|_| BindingError::HostRefused)?;
        verify_materialized_attempt(&attempt, self.job_uid, &self.static_job, false)
            .map_err(binding_error)?;
        let mut digest = Sha256::new();
        digest.update(b"buzz-ci-execd:materialization-receipt:v1\0");
        digest.update(binding.execution_binding_digest);
        digest.update(self.static_job.declaration_digest);
        digest.update(Sha256::digest(manifest));
        digest.update(Sha256::digest(input));
        digest.update(Sha256::digest(script));
        Ok(digest.finalize().into())
    }

    fn request(
        &mut self,
        operation: &str,
        binding: ExecutionBindingV1,
        intent: Option<JobIntentV2>,
        claimed: Option<[u8; 32]>,
        phase: Option<BindingPhase>,
        reason: Option<HostStopReason>,
    ) -> Result<ExecutorResponse, BindingError> {
        verify_program(&self.executor).map_err(binding_error)?;
        self.seccomp.validate().map_err(binding_error)?;
        let mut stream =
            UnixStream::connect(&self.socket).map_err(|_| BindingError::HostRefused)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| BindingError::HostRefused)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| BindingError::HostRefused)?;
        let credentials =
            getsockopt(&stream, PeerCredentials).map_err(|_| BindingError::HostRefused)?;
        if credentials.uid() != self.executor_uid || credentials.gid() != self.executor_gid {
            return Err(BindingError::HostRefused);
        }
        let request = ExecutorRequest {
            schema_version: RPC_SCHEMA,
            operation: operation.to_owned(),
            execution_binding_digest: hex::encode(binding.execution_binding_digest),
            attempt_id: hex::encode(binding.attempt_id),
            job_intent_digest: intent.map(|value| hex::encode(value.digest())),
            static_execution_digest: hex::encode(self.static_job.declaration_digest),
            fixture_manifest_sha256: self.static_job.fixture_manifest.sha256.clone(),
            fixture_input_sha256: self.static_job.fixture_input.sha256.clone(),
            fixture_script_sha256: self.static_job.fixture_script.sha256.clone(),
            deadline_at: binding.deadline_at,
            max_stdout_bytes: self.static_job.max_stdout_bytes,
            max_stderr_bytes: self.static_job.max_stderr_bytes,
            max_memory_bytes: self.static_job.max_memory_bytes,
            max_processes: self.static_job.max_processes,
            claimed_evidence_digest: claimed.map(hex::encode),
            phase: phase.map(phase_name).map(str::to_owned),
            stop_reason: reason.map(stop_name).map(str::to_owned),
            executor_program_sha256: self.executor.sha256.clone(),
            seccomp_profile_path: self.seccomp.profile_path.clone(),
            seccomp_profile_sha256: self.seccomp.profile_digest.clone(),
            seccomp_install_receipt_sha256: self.seccomp.install_receipt_digest.clone(),
        };
        let body = canonical_bytes(&request).map_err(binding_error)?;
        if body.len() > MAX_RPC {
            return Err(BindingError::HostRefused);
        }
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .and_then(|_| stream.write_all(&body))
            .map_err(|_| BindingError::HostRefused)?;
        let mut length = [0; 4];
        stream
            .read_exact(&mut length)
            .map_err(|_| BindingError::HostRefused)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_RPC {
            return Err(BindingError::HostRefused);
        }
        let mut response = vec![0; length];
        stream
            .read_exact(&mut response)
            .map_err(|_| BindingError::HostRefused)?;
        let response: ExecutorResponse = canonical_parse(&response).map_err(binding_error)?;
        if response.schema_version != RPC_SCHEMA
            || response.operation != operation
            || decode_hex::<32>(&response.execution_binding_digest).map_err(binding_error)?
                != binding.execution_binding_digest
        {
            return Err(BindingError::HostRefused);
        }
        Ok(response)
    }

    fn step(
        &mut self,
        operation: &str,
        binding: ExecutionBindingV1,
        intent: Option<JobIntentV2>,
    ) -> Result<HostStepReceipt, BindingError> {
        let response = self.request(operation, binding, intent, None, None, None)?;
        Ok(HostStepReceipt {
            execution_binding_digest: binding.execution_binding_digest,
            receipt_digest: decode_nonzero(&response.receipt_digest)?,
        })
    }

    fn write_evidence(
        &mut self,
        binding: ExecutionBindingV1,
        conclusion: Conclusion,
        raw: &str,
        claimed: Option<[u8; 32]>,
    ) -> Result<[u8; 32], BindingError> {
        let raw = raw.as_bytes();
        if raw.len() > MAX_RAW_OUTPUT {
            return Err(BindingError::HostRefused);
        }
        let scrubbed = scrub(raw)?;
        let document = EvidenceDocument {
            schema_version: 1,
            execution_binding_digest: hex::encode(binding.execution_binding_digest),
            conclusion: conclusion_name(conclusion).to_owned(),
            output_sha256: hex::encode(Sha256::digest(&scrubbed)),
            output_length: scrubbed.len() as u32,
            output: String::from_utf8(scrubbed).map_err(|_| BindingError::HostRefused)?,
        };
        let bytes = canonical_bytes(&document).map_err(binding_error)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if claimed.is_some_and(|value| value != digest) {
            return Err(BindingError::HostRefused);
        }
        let name = format!("{}.json", hex::encode(binding.attempt_id));
        match self
            .evidence
            .write_once_bounded(&name, &bytes, 0o600, MAX_EVIDENCE_DOCUMENT)
        {
            Ok(()) => {}
            Err(_) => {
                let existing = self
                    .evidence
                    .read(&name, 0o600, MAX_EVIDENCE_DOCUMENT)
                    .map_err(binding_error)?;
                if existing != bytes {
                    return Err(BindingError::HostRefused);
                }
            }
        }
        self.evidence_by_binding
            .insert(binding.execution_binding_digest, digest);
        Ok(digest)
    }

    fn existing_evidence(
        &mut self,
        binding: ExecutionBindingV1,
    ) -> Result<Option<[u8; 32]>, BindingError> {
        if let Some(digest) = self
            .evidence_by_binding
            .get(&binding.execution_binding_digest)
            .copied()
        {
            return Ok(Some(digest));
        }
        let name = format!("{}.json", hex::encode(binding.attempt_id));
        let bytes = match self.evidence.read(&name, 0o600, MAX_EVIDENCE_DOCUMENT) {
            Ok(bytes) => bytes,
            Err(_) if !self.evidence.descriptor_path().join(&name).exists() => return Ok(None),
            Err(_) => return Err(BindingError::HostRefused),
        };
        let document: EvidenceDocument = canonical_parse(&bytes).map_err(binding_error)?;
        let output = document.output.as_bytes();
        if document.schema_version != 1
            || decode_hex::<32>(&document.execution_binding_digest).map_err(binding_error)?
                != binding.execution_binding_digest
            || document.output_length as usize != output.len()
            || document.output_sha256 != hex::encode(Sha256::digest(output))
            || parse_conclusion(Some(&document.conclusion)).is_err()
        {
            return Err(BindingError::HostRefused);
        }
        let digest = Sha256::digest(&bytes).into();
        self.evidence_by_binding
            .insert(binding.execution_binding_digest, digest);
        Ok(Some(digest))
    }

    fn sealed_artifacts(
        &self,
        binding: ExecutionBindingV1,
    ) -> Result<(Vec<HostEvidenceItem>, [u8; 32]), BindingError> {
        let attempt_name = hex::encode(binding.attempt_id);
        let attempt_path = self.attempts.descriptor_path().join(&attempt_name);
        let declarations: Vec<_> = binding.artifacts.iter().flatten().copied().collect();
        let all_sealed = declarations.iter().all(|declaration| {
            declaration.artifact_id.as_str().is_ok_and(|artifact_id| {
                self.evidence
                    .descriptor_path()
                    .join(format!("{}-{}.json", attempt_name, artifact_id))
                    .exists()
            })
        });
        let attempt = match self.attempts.open_child(&attempt_name, self.job_uid, 0o500) {
            Ok(directory) => Some(directory),
            Err(_) if all_sealed => None,
            Err(_) if declarations.is_empty() && !attempt_path.exists() => None,
            Err(_) => return Err(BindingError::HostRefused),
        };
        let artifact_root = if let Some(attempt) = &attempt {
            if attempt.names(2).map_err(binding_error)?
                != [
                    MATERIALIZED_ARTIFACT_ROOT.to_owned(),
                    MATERIALIZED_SOURCE_ROOT.to_owned(),
                ]
            {
                return Err(BindingError::HostRefused);
            }
            verify_materialized_attempt(attempt, self.job_uid, &self.static_job, true)
                .map_err(binding_error)?;
            let artifact_root = attempt
                .open_child(MATERIALIZED_ARTIFACT_ROOT, self.job_uid, 0o700)
                .map_err(binding_error)?;
            let mut observed = Vec::new();
            for name in artifact_root
                .names(declarations.len())
                .map_err(binding_error)?
            {
                if !declarations
                    .iter()
                    .any(|declared| declared.relative_name.as_str().ok() == Some(name.as_str()))
                {
                    return Err(BindingError::HostRefused);
                }
                observed.push(name);
            }
            if observed.len() != declarations.len() {
                return Err(BindingError::HostRefused);
            }
            Some(artifact_root)
        } else {
            None
        };

        let mut items = Vec::new();
        let mut set_material = Vec::from(b"buzz-ci-execd:artifact-receipt-set:v1\0".as_slice());
        set_material.extend_from_slice(&binding.execution_binding_digest);
        for declaration in declarations {
            let artifact_id = declaration
                .artifact_id
                .as_str()
                .map_err(|_| BindingError::HostRefused)?;
            let receipt_name = format!("{}-{}.json", attempt_name, artifact_id);
            let bytes = match self
                .evidence
                .read(&receipt_name, 0o600, MAX_ARTIFACT_RECEIPT)
            {
                Ok(bytes) => bytes,
                Err(_) => {
                    let artifact_root = artifact_root.as_ref().ok_or(BindingError::HostRefused)?;
                    let raw = artifact_root
                        .read(
                            declaration
                                .relative_name
                                .as_str()
                                .map_err(|_| BindingError::HostRefused)?,
                            0o600,
                            u64::from(declaration.max_bytes),
                        )
                        .map_err(binding_error)?;
                    let scrubbed = scrub(&raw)?;
                    if scrubbed.len() > declaration.max_bytes as usize {
                        return Err(BindingError::HostRefused);
                    }
                    let receipt = ArtifactReceiptDocument {
                        schema_version: 1,
                        execution_binding_digest: hex::encode(binding.execution_binding_digest),
                        request_event_id: hex::encode(binding.request_event_id),
                        run_id: hex::encode(binding.run_id),
                        workflow_id: binding
                            .workflow_id
                            .as_str()
                            .map_err(|_| BindingError::HostRefused)?
                            .into(),
                        workflow_digest: hex::encode(binding.workflow_digest),
                        job_id: binding
                            .job_id
                            .as_str()
                            .map_err(|_| BindingError::HostRefused)?
                            .into(),
                        attempt: binding.attempt,
                        artifact_id: artifact_id.into(),
                        name: declaration
                            .name
                            .as_str()
                            .map_err(|_| BindingError::HostRefused)?
                            .into(),
                        media_type: declaration
                            .media_type
                            .as_str()
                            .map_err(|_| BindingError::HostRefused)?
                            .into(),
                        sha256: hex::encode(Sha256::digest(&scrubbed)),
                        byte_length: scrubbed.len() as u32,
                        content_hex: hex::encode(scrubbed),
                    };
                    let bytes = canonical_bytes(&receipt).map_err(binding_error)?;
                    match self.evidence.write_once_bounded(
                        &receipt_name,
                        &bytes,
                        0o600,
                        MAX_ARTIFACT_RECEIPT,
                    ) {
                        Ok(()) => bytes,
                        Err(_) => self
                            .evidence
                            .read(&receipt_name, 0o600, MAX_ARTIFACT_RECEIPT)
                            .map_err(binding_error)?,
                    }
                }
            };
            let receipt: ArtifactReceiptDocument =
                canonical_parse(&bytes).map_err(binding_error)?;
            let content = if receipt.content_hex.len().is_multiple_of(2)
                && receipt.content_hex.len() <= declaration.max_bytes as usize * 2
                && lower_hex(&receipt.content_hex)
            {
                hex::decode(&receipt.content_hex).map_err(|_| BindingError::HostRefused)?
            } else {
                return Err(BindingError::HostRefused);
            };
            let digest: [u8; 32] = Sha256::digest(&content).into();
            if receipt.schema_version != 1
                || receipt.execution_binding_digest != hex::encode(binding.execution_binding_digest)
                || receipt.request_event_id != hex::encode(binding.request_event_id)
                || receipt.run_id != hex::encode(binding.run_id)
                || receipt.workflow_id
                    != binding
                        .workflow_id
                        .as_str()
                        .map_err(|_| BindingError::HostRefused)?
                || receipt.workflow_digest != hex::encode(binding.workflow_digest)
                || receipt.job_id
                    != binding
                        .job_id
                        .as_str()
                        .map_err(|_| BindingError::HostRefused)?
                || receipt.attempt != binding.attempt
                || receipt.artifact_id != artifact_id
                || receipt.name
                    != declaration
                        .name
                        .as_str()
                        .map_err(|_| BindingError::HostRefused)?
                || receipt.media_type
                    != declaration
                        .media_type
                        .as_str()
                        .map_err(|_| BindingError::HostRefused)?
                || receipt.sha256 != hex::encode(digest)
                || receipt.byte_length as usize != content.len()
            {
                return Err(BindingError::HostRefused);
            }
            let receipt_digest: [u8; 32] = Sha256::digest(&bytes).into();
            set_material.extend_from_slice(&receipt_digest);
            items.push(HostEvidenceItem {
                descriptor: EvidenceDescriptor {
                    kind: EvidenceKind::Artifact,
                    digest,
                    length: content.len() as u32,
                    artifact_name_digest: Sha256::digest(receipt.name.as_bytes()).into(),
                    artifact_media_type_digest: Sha256::digest(receipt.media_type.as_bytes())
                        .into(),
                    artifact_id: declaration.artifact_id,
                    artifact_name: declaration.name,
                    artifact_media_type: declaration.media_type,
                    teardown_lease_id: [0; 16],
                    teardown_lease_generation: 0,
                    teardown_attestation_digest: [0; 32],
                },
                bytes: content,
            });
        }
        Ok((items, Sha256::digest(set_material).into()))
    }

    fn persist_teardown(
        &mut self,
        binding: ExecutionBindingV1,
        reason: HostStopReason,
        response: ExecutorResponse,
        captured_artifact_set: Option<[u8; 32]>,
    ) -> Result<HostTerminalReceipt, BindingError> {
        let conclusion = parse_conclusion(response.conclusion.as_deref())?;
        let evidence = match self.existing_evidence(binding)? {
            Some(value) => value,
            None => self.write_evidence(binding, conclusion, &terminal_output(&response), None)?,
        };
        let executor_receipt = decode_nonzero(&response.receipt_digest)?;
        let artifact_receipt_set_digest =
            captured_artifact_set.unwrap_or_else(|| empty_artifact_receipt_set_digest(binding));
        let document = TeardownDocument {
            schema_version: 1,
            execution_binding_digest: hex::encode(binding.execution_binding_digest),
            evidence_set_digest: hex::encode(evidence),
            stop_reason: stop_name(reason).to_owned(),
            executor_receipt_digest: hex::encode(executor_receipt),
            request_event_id: hex::encode(binding.request_event_id),
            run_id: hex::encode(binding.run_id),
            workflow_id: binding
                .workflow_id
                .as_str()
                .map_err(|_| BindingError::HostRefused)?
                .into(),
            workflow_digest: hex::encode(binding.workflow_digest),
            job_id: binding
                .job_id
                .as_str()
                .map_err(|_| BindingError::HostRefused)?
                .into(),
            attempt: binding.attempt,
            lease_id: hex::encode(binding.lease_id),
            lease_generation: binding.lease_generation,
            artifact_receipt_set_digest: hex::encode(artifact_receipt_set_digest),
        };
        let bytes = canonical_bytes(&document).map_err(binding_error)?;
        let teardown_digest: [u8; 32] = Sha256::digest(&bytes).into();
        let name = format!("{}.json", hex::encode(binding.attempt_id));
        match self.teardown.write_once(&name, &bytes, 0o600) {
            Ok(()) => {}
            Err(_) => {
                if self
                    .teardown
                    .read(&name, 0o600, MAX_RECORD)
                    .map_err(binding_error)?
                    != bytes
                {
                    return Err(BindingError::HostRefused);
                }
            }
        }
        self.cleanup_attempt(binding)?;
        Ok(HostTerminalReceipt {
            execution_binding_digest: binding.execution_binding_digest,
            conclusion,
            evidence_set_digest: evidence,
            teardown_digest,
        })
    }

    fn cleanup_attempt(&self, binding: ExecutionBindingV1) -> Result<(), BindingError> {
        let name = hex::encode(binding.attempt_id);
        let path = self.attempts.descriptor_path().join(&name);
        if !path.exists() {
            return Ok(());
        }
        self.attempts
            .open_child(&name, self.job_uid, 0o500)
            .map_err(binding_error)?;
        self.attempts
            .remove_tree_child(&name)
            .map_err(binding_error)?;
        if path.exists() {
            return Err(BindingError::HostRefused);
        }
        Ok(())
    }
}

fn empty_artifact_receipt_set_digest(binding: ExecutionBindingV1) -> [u8; 32] {
    let mut material = Vec::from(b"buzz-ci-execd:artifact-receipt-set:v1\0".as_slice());
    material.extend_from_slice(&binding.execution_binding_digest);
    Sha256::digest(material).into()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceDocument {
    schema_version: u16,
    execution_binding_digest: String,
    conclusion: String,
    output_sha256: String,
    output_length: u32,
    output: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReceiptDocument {
    schema_version: u16,
    execution_binding_digest: String,
    request_event_id: String,
    run_id: String,
    workflow_id: String,
    workflow_digest: String,
    job_id: String,
    attempt: u32,
    artifact_id: String,
    name: String,
    media_type: String,
    sha256: String,
    byte_length: u32,
    content_hex: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TeardownDocument {
    schema_version: u16,
    execution_binding_digest: String,
    evidence_set_digest: String,
    stop_reason: String,
    executor_receipt_digest: String,
    request_event_id: String,
    run_id: String,
    workflow_id: String,
    workflow_digest: String,
    job_id: String,
    attempt: u32,
    lease_id: String,
    lease_generation: u64,
    artifact_receipt_set_digest: String,
}

impl PrivilegedHostSystem for LocalHostSystem {
    fn identity(&mut self) -> Result<HostIdentity, BindingError> {
        verify_program(&self.executor).map_err(binding_error)?;
        Ok(self.identity)
    }

    fn executor_unit_handoff(
        &mut self,
        binding: ExecutionBindingV1,
        intent: JobIntentV2,
    ) -> Result<HostStepReceipt, BindingError> {
        self.validate_static_job(binding, intent)?;
        self.step("executor_handoff", binding, Some(intent))
    }

    fn runtime_descriptor_provider(
        &mut self,
        binding: ExecutionBindingV1,
    ) -> Result<HostStepReceipt, BindingError> {
        self.step("runtime_descriptor", binding, None)
    }

    fn materialization_input_provider(
        &mut self,
        binding: ExecutionBindingV1,
        intent: JobIntentV2,
    ) -> Result<HostStepReceipt, BindingError> {
        let materialization = self.materialize(binding, intent)?;
        let executor = self.step("materialization", binding, Some(intent))?;
        let mut digest = Sha256::new();
        digest.update(b"buzz-ci-execd:materialization-handoff:v1\0");
        digest.update(binding.execution_binding_digest);
        digest.update(materialization);
        digest.update(executor.receipt_digest);
        Ok(HostStepReceipt {
            execution_binding_digest: binding.execution_binding_digest,
            receipt_digest: digest.finalize().into(),
        })
    }

    fn proxy_input_and_lease_provider(
        &mut self,
        binding: ExecutionBindingV1,
    ) -> Result<HostStepReceipt, BindingError> {
        self.step("proxy_lease", binding, None)
    }

    fn terminal_evidence_collector(
        &mut self,
        binding: ExecutionBindingV1,
        claimed_evidence_digest: [u8; 32],
    ) -> Result<HostStepReceipt, BindingError> {
        let response = self.request(
            "terminal_evidence",
            binding,
            None,
            Some(claimed_evidence_digest),
            None,
            None,
        )?;
        if response.running == Some(true) {
            return Err(BindingError::HostRefused);
        }
        let conclusion = parse_conclusion(response.conclusion.as_deref())?;
        if conclusion != Conclusion::Success
            || response.exit_code != Some(0)
            || response
                .raw_stderr
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        {
            return Err(BindingError::HostRefused);
        }
        self.sealed_artifacts(binding)?;
        let digest = self.write_evidence(
            binding,
            conclusion,
            response
                .raw_stdout
                .as_deref()
                .ok_or(BindingError::HostRefused)?,
            Some(claimed_evidence_digest),
        )?;
        Ok(HostStepReceipt {
            execution_binding_digest: binding.execution_binding_digest,
            receipt_digest: digest,
        })
    }

    fn teardown_provider(
        &mut self,
        binding: ExecutionBindingV1,
        reason: HostStopReason,
    ) -> Result<HostTerminalReceipt, BindingError> {
        let captured = (reason == HostStopReason::Completed)
            .then(|| self.sealed_artifacts(binding))
            .transpose()?;
        let response = self.request("teardown", binding, None, None, None, Some(reason))?;
        self.persist_teardown(
            binding,
            reason,
            response,
            captured.map(|(_, digest)| digest),
        )
    }

    fn crash_recovery_coordinator(
        &mut self,
        binding: ExecutionBindingV1,
        phase: BindingPhase,
    ) -> Result<HostRecoveryReceipt, BindingError> {
        let response = self.request(
            "crash_recovery",
            binding,
            None,
            None,
            Some(phase),
            Some(HostStopReason::Recovery),
        )?;
        if response.quarantine == Some(true) || response.capacity_returned != Some(true) {
            return Ok(HostRecoveryReceipt::Quarantine);
        }
        self.persist_teardown(binding, HostStopReason::Recovery, response, None)
            .map(HostRecoveryReceipt::CapacityReturned)
            .or(Ok(HostRecoveryReceipt::Quarantine))
    }

    fn poll_terminal(
        &mut self,
        binding: ExecutionBindingV1,
    ) -> Result<Option<HostTerminalReceipt>, BindingError> {
        let response = self.request("terminal_evidence", binding, None, None, None, None)?;
        if response.running == Some(true) {
            return Ok(None);
        }
        let conclusion = parse_conclusion(response.conclusion.as_deref())?;
        if conclusion != Conclusion::Success
            || response.exit_code != Some(0)
            || response
                .raw_stderr
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        {
            let terminal = self.teardown_provider(binding, HostStopReason::Recovery)?;
            return Ok(Some(terminal));
        }
        self.sealed_artifacts(binding)?;
        let digest = self.write_evidence(
            binding,
            conclusion,
            response
                .raw_stdout
                .as_deref()
                .ok_or(BindingError::HostRefused)?,
            None,
        )?;
        if decode_nonzero(&response.receipt_digest)? != digest {
            return Err(BindingError::HostRefused);
        }
        self.teardown_provider(binding, HostStopReason::Completed)
            .map(Some)
    }

    fn sealed_attempt_evidence(
        &mut self,
        binding: ExecutionBindingV1,
    ) -> Result<Vec<HostEvidenceItem>, BindingError> {
        let name = format!("{}.json", hex::encode(binding.attempt_id));
        let evidence_bytes = self
            .evidence
            .read(&name, 0o600, MAX_EVIDENCE_DOCUMENT)
            .map_err(binding_error)?;
        let evidence: EvidenceDocument = canonical_parse(&evidence_bytes).map_err(binding_error)?;
        let output = evidence.output.as_bytes();
        let evidence_digest: [u8; 32] = Sha256::digest(&evidence_bytes).into();
        if evidence.schema_version != 1
            || decode_hex::<32>(&evidence.execution_binding_digest).map_err(binding_error)?
                != binding.execution_binding_digest
            || evidence.output_length as usize != output.len()
            || evidence.output_sha256 != hex::encode(Sha256::digest(output))
            || parse_conclusion(Some(&evidence.conclusion)).is_err()
        {
            return Err(BindingError::HostRefused);
        }

        let teardown_bytes = self
            .teardown
            .read(&name, 0o600, MAX_RECORD)
            .map_err(binding_error)?;
        let teardown: TeardownDocument = canonical_parse(&teardown_bytes).map_err(binding_error)?;
        let teardown_digest: [u8; 32] = Sha256::digest(&teardown_bytes).into();
        let (artifact_items, artifact_receipt_set_digest) = self.sealed_artifacts(binding)?;
        if teardown.schema_version != 1
            || decode_hex::<32>(&teardown.execution_binding_digest).map_err(binding_error)?
                != binding.execution_binding_digest
            || decode_hex::<32>(&teardown.evidence_set_digest).map_err(binding_error)?
                != evidence_digest
            || decode_nonzero(&teardown.executor_receipt_digest).is_err()
            || teardown.request_event_id != hex::encode(binding.request_event_id)
            || teardown.run_id != hex::encode(binding.run_id)
            || teardown.workflow_id
                != binding
                    .workflow_id
                    .as_str()
                    .map_err(|_| BindingError::HostRefused)?
            || teardown.workflow_digest != hex::encode(binding.workflow_digest)
            || teardown.job_id
                != binding
                    .job_id
                    .as_str()
                    .map_err(|_| BindingError::HostRefused)?
            || teardown.attempt != binding.attempt
            || teardown.lease_id != hex::encode(binding.lease_id)
            || teardown.lease_generation != binding.lease_generation
            || teardown.artifact_receipt_set_digest != hex::encode(artifact_receipt_set_digest)
            || !matches!(
                teardown.stop_reason.as_str(),
                "cancelled" | "completed" | "expired" | "recovery"
            )
        {
            return Err(BindingError::HostRefused);
        }

        let mut items = vec![HostEvidenceItem {
            descriptor: EvidenceDescriptor {
                kind: EvidenceKind::Stdout,
                digest: evidence_digest,
                length: evidence_bytes.len() as u32,
                artifact_name_digest: [0; 32],
                artifact_media_type_digest: [0; 32],
                artifact_id: WireText64::EMPTY,
                artifact_name: WireText64::EMPTY,
                artifact_media_type: WireText64::EMPTY,
                teardown_lease_id: [0; 16],
                teardown_lease_generation: 0,
                teardown_attestation_digest: [0; 32],
            },
            bytes: evidence_bytes,
        }];
        items.extend(artifact_items);
        items.push(HostEvidenceItem {
            descriptor: EvidenceDescriptor {
                kind: EvidenceKind::Teardown,
                digest: teardown_digest,
                length: teardown_bytes.len() as u32,
                artifact_name_digest: [0; 32],
                artifact_media_type_digest: [0; 32],
                artifact_id: WireText64::EMPTY,
                artifact_name: WireText64::EMPTY,
                artifact_media_type: WireText64::EMPTY,
                teardown_lease_id: binding.lease_id,
                teardown_lease_generation: binding.lease_generation,
                teardown_attestation_digest: teardown_digest,
            },
            bytes: teardown_bytes,
        });
        Ok(items)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProductionQualificationContract {
    integrated_candidate_sha: GitOid,
    activation_package_digest: [u8; 32],
    fixture_digest: [u8; 32],
    principal_digest: [u8; 32],
    lane_manifest_digest: [u8; 32],
    broker_build_identity: [u8; 32],
    host_profile_digest: [u8; 32],
    suite_identity: [u8; 32],
    isolation_profile_digest: [u8; 32],
    seccomp_profile_digest: [u8; 32],
    seccomp_install_receipt_digest: [u8; 32],
    executor_program_digest: [u8; 32],
    executor_provenance_digest: [u8; 32],
    controller_generation: u64,
    runner_generation: u64,
    lane_epoch: u64,
    admission_key_generation: u64,
}

impl ProductionQualificationContract {
    fn matches(self, request: ProductionQualificationRequest) -> bool {
        request.integrated_candidate_sha == self.integrated_candidate_sha
            && request.activation_package_digest == self.activation_package_digest
            && request.fixture_digest == self.fixture_digest
            && request.principal_digest == self.principal_digest
            && request.lane_manifest_digest == self.lane_manifest_digest
            && request.broker_build_identity == self.broker_build_identity
            && request.host_profile_digest == self.host_profile_digest
            && request.suite_identity == self.suite_identity
            && request.isolation_profile_digest == self.isolation_profile_digest
            && request.seccomp_profile_digest == self.seccomp_profile_digest
            && request.executor_program_digest == self.executor_program_digest
            && request.executor_provenance_digest == self.executor_provenance_digest
            && request.controller_generation == self.controller_generation
            && request.runner_generation == self.runner_generation
            && request.lane_epoch == self.lane_epoch
            && request.admission_key_generation == self.admission_key_generation
    }

    fn response(
        self,
        request: ProductionQualificationRequest,
        code: ResponseCode,
        now: u64,
    ) -> ProductionQualificationResponse {
        let qualified_at = now.clamp(request.issued_at, request.expires_at);
        let mut response = ProductionQualificationResponse {
            code,
            retry_after_millis: 0,
            request_frame_digest: request.request_frame_digest,
            qualification_receipt_digest: [0; 32],
            integrated_candidate_sha: request.integrated_candidate_sha,
            activation_package_digest: request.activation_package_digest,
            fixture_digest: request.fixture_digest,
            principal_digest: request.principal_digest,
            lane_manifest_digest: request.lane_manifest_digest,
            broker_build_identity: request.broker_build_identity,
            host_profile_digest: request.host_profile_digest,
            suite_identity: request.suite_identity,
            isolation_profile_digest: request.isolation_profile_digest,
            seccomp_profile_digest: request.seccomp_profile_digest,
            seccomp_install_receipt_digest: self.seccomp_install_receipt_digest,
            executor_program_digest: request.executor_program_digest,
            executor_provenance_digest: request.executor_provenance_digest,
            controller_generation: request.controller_generation,
            runner_generation: request.runner_generation,
            lane_epoch: request.lane_epoch,
            admission_key_generation: request.admission_key_generation,
            qualified_at,
            request_expires_at: request.expires_at,
        };
        response.qualification_receipt_digest = production_qualification_receipt_digest(&response);
        response
    }
}

struct DurableQualificationFiles {
    root: SafeDirectory,
}

impl DurableQualificationFiles {
    fn open(
        root: SafeDirectory,
        contract: ProductionQualificationContract,
    ) -> Result<Self, ProductionV2Error> {
        let mut count = 0;
        for entry in fs::read_dir(root.descriptor_path()).map_err(|_| ProductionV2Error::Closed)? {
            let entry = entry.map_err(|_| ProductionV2Error::Closed)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ProductionV2Error::Closed)?;
            if name.len() != 69 || !name.ends_with(".json") || !lower_hex(&name[..64]) {
                return Err(ProductionV2Error::Closed);
            }
            count += 1;
            if count > MAX_QUALIFICATION_RECEIPTS {
                return Err(ProductionV2Error::Closed);
            }
            let bytes = root.read(&name, 0o600, MAX_RECORD)?;
            let document: QualificationReceiptDocument = canonical_parse(&bytes)?;
            let (header, request, response) = document.decode()?;
            if hex::encode(production_qualification_key_digest(&request)) != name[..64]
                || response.code != ResponseCode::Ok
                || !contract.matches(request)
                || response.seccomp_install_receipt_digest
                    != contract.seccomp_install_receipt_digest
                || response.request_frame_digest != request.request_frame_digest
                || production_qualification_request_frame_digest(header, &request)
                    != Some(request.request_frame_digest)
                || production_qualification_receipt_digest(&response)
                    != response.qualification_receipt_digest
            {
                return Err(ProductionV2Error::Closed);
            }
        }
        Ok(Self { root })
    }

    fn qualify(
        &self,
        header: FrameHeader,
        request: ProductionQualificationRequest,
        response: ProductionQualificationResponse,
    ) -> Result<ProductionQualificationResponse, ResponseCode> {
        let key = production_qualification_key_digest(&request);
        let name = format!("{}.json", hex::encode(key));
        if !self.root.descriptor_path().join(&name).exists()
            && fs::read_dir(self.root.descriptor_path())
                .map_err(|_| ResponseCode::StorageUnavailable)?
                .take(MAX_QUALIFICATION_RECEIPTS)
                .count()
                >= MAX_QUALIFICATION_RECEIPTS
        {
            return Err(ResponseCode::StorageUnavailable);
        }
        let request_frame = encode_request(header.request_id, Request::AdmitQualification(request));
        let response_frame = encode_production_qualification_response(header, response);
        let document = QualificationReceiptDocument {
            schema_version: 1,
            qualification_key_digest: hex::encode(key),
            request_frame_hex: hex::encode(request_frame.as_bytes()),
            response_frame_hex: hex::encode(response_frame.as_bytes()),
        };
        let bytes = canonical_bytes(&document).map_err(|_| ResponseCode::StorageUnavailable)?;
        match self.root.write_once(&name, &bytes, 0o600) {
            Ok(()) => Ok(response),
            Err(_) => {
                let existing = self
                    .root
                    .read(&name, 0o600, MAX_RECORD)
                    .map_err(|_| ResponseCode::StorageUnavailable)?;
                let stored: QualificationReceiptDocument =
                    canonical_parse(&existing).map_err(|_| ResponseCode::StorageUnavailable)?;
                let (stored_header, stored_request, stored_response) = stored
                    .decode()
                    .map_err(|_| ResponseCode::StorageUnavailable)?;
                if stored_header == header && stored_request == request {
                    let mut replay = stored_response;
                    replay.code = ResponseCode::Existing;
                    Ok(replay)
                } else {
                    Err(ResponseCode::ReplayConflict)
                }
            }
        }
    }
}

impl QualificationReceiptDocument {
    fn decode(
        self,
    ) -> Result<
        (
            FrameHeader,
            ProductionQualificationRequest,
            ProductionQualificationResponse,
        ),
        ProductionV2Error,
    > {
        if self.schema_version != 1
            || self.qualification_key_digest.len() != 64
            || !lower_hex(&self.qualification_key_digest)
            || self.request_frame_hex.len() > MAX_RECORD as usize * 2
            || self.response_frame_hex.len() > MAX_RECORD as usize * 2
            || !lower_hex(&self.request_frame_hex)
            || !lower_hex(&self.response_frame_hex)
        {
            return Err(ProductionV2Error::Closed);
        }
        let request_bytes =
            hex::decode(self.request_frame_hex).map_err(|_| ProductionV2Error::Closed)?;
        let (header, decoded) =
            decode_request(&request_bytes).map_err(|_| ProductionV2Error::Closed)?;
        let Request::AdmitQualification(request) = decoded else {
            return Err(ProductionV2Error::Closed);
        };
        let response_bytes =
            hex::decode(self.response_frame_hex).map_err(|_| ProductionV2Error::Closed)?;
        let response = decode_production_qualification_response(header, &response_bytes)
            .map_err(|_| ProductionV2Error::Closed)?;
        if decode_hex::<32>(&self.qualification_key_digest)?
            != production_qualification_key_digest(&request)
        {
            return Err(ProductionV2Error::Closed);
        }
        Ok((header, request, response))
    }
}

struct ProductionV2Dispatch {
    ordinary: Option<Box<dyn ControlDispatch>>,
    qualification: DurableQualificationFiles,
    contract: ProductionQualificationContract,
}

impl ControlDispatch for ProductionV2Dispatch {
    fn dispatch(
        &mut self,
        header: buzz_ci_broker_protocol::FrameHeader,
        request: buzz_ci_broker_protocol::Request,
        now: u64,
    ) -> buzz_ci_broker_protocol::BrokerResponse {
        crate::control::ClosedDispatch::new().dispatch(header, request, now)
    }

    fn dispatch_v2_encoded(
        &mut self,
        header: FrameHeader,
        request: Request,
        now: u64,
    ) -> buzz_ci_broker_protocol::v2::EncodedFrame {
        let Request::AdmitQualification(qualification) = request else {
            return match self.ordinary.as_mut() {
                Some(dispatch) => dispatch.dispatch_v2_encoded(header, request, now),
                None => crate::control::encode_not_provisioned_v2(header, request, now),
            };
        };
        let error = if production_qualification_request_frame_digest(header, &qualification)
            != Some(qualification.request_frame_digest)
        {
            Some(ResponseCode::BadFrame)
        } else if now < qualification.issued_at
            || now >= qualification.expires_at
            || !self.contract.matches(qualification)
        {
            Some(ResponseCode::PolicyDenied)
        } else {
            let response = self.contract.response(qualification, ResponseCode::Ok, now);
            match self.qualification.qualify(header, qualification, response) {
                Ok(response) => {
                    return encode_production_qualification_response(header, response);
                }
                Err(code) => Some(code),
            }
        };
        let response = self.contract.response(
            qualification,
            error.expect("qualification error path always returns a code"),
            now,
        );
        encode_production_qualification_response(header, response)
    }

    fn maintenance(&mut self, now: u64) {
        if let Some(dispatch) = self.ordinary.as_mut() {
            dispatch.maintenance(now);
        }
    }
}

/// Fully validated production dispatch and socket peer policy.
pub struct ProductionRuntime {
    pub dispatch: Box<dyn ControlDispatch>,
    pub peer_policy: PeerUidPolicy,
}

/// Open exact production-v2 state. Any ambiguity prevents the socket from serving.
pub fn load_canonical(now: u64) -> Result<ProductionRuntime, ProductionV2Error> {
    load_from(RuntimePaths::canonical(), 0, now, true, || {
        SeccompActivationAdapter::production()
            .activate()
            .map_err(|_| ProductionV2Error::Closed)
            .and_then(SeccompRuntimeBinding::from_proof)
    })
}

fn load_from<F>(
    paths: RuntimePaths,
    owner: u32,
    now: u64,
    validate_group: bool,
    activate_seccomp: F,
) -> Result<ProductionRuntime, ProductionV2Error>
where
    F: FnOnce() -> Result<SeccompRuntimeBinding, ProductionV2Error>,
{
    let config_path = paths.resolve(CONFIG_PATH)?;
    let config = read_document::<ProductionConfig>(&config_path, owner, 0o600, MAX_CONFIG)?;
    validate_config(&config, &paths, owner, validate_group)?;
    verify_execd_state_traversal(&paths, owner, config.identities.execd_gid)?;
    let seccomp = activate_seccomp()?;
    seccomp.validate()?;
    let manifest = config.lane_manifest.clone().into_manifest()?;
    let contract = qualification_contract(&config, &manifest, &seccomp)?;
    let qualification = DurableQualificationFiles::open(
        SafeDirectory::open(paths.resolve(QUALIFICATION_ROOT)?, owner, 0o700)?,
        contract,
    )?;
    let peer_policy = PeerUidPolicy::new_with_gids(
        config.identities.control_uid,
        config.identities.control_gid,
        config.identities.runner_uid,
        config.identities.runner_gid,
    )
    .map_err(|_| ProductionV2Error::Closed)?;
    let identity = HostIdentity {
        broker_build_identity: manifest.broker_build_identity,
        host_profile_digest: manifest.host_profile_digest,
        suite_identity: manifest.suite_identity,
    };
    let ordinary: Option<Box<dyn ControlDispatch>> = if config.capacity == 1 {
        let static_job = static_execution_contract(&config, &manifest, &paths, owner)?;
        let intents = StaticIntentFiles::open(SafeDirectory::open(
            paths.resolve(INTENT_ROOT)?,
            owner,
            0o700,
        )?)?;
        let journal = DurableBindingFiles {
            root: SafeDirectory::open(paths.resolve(BINDING_ROOT)?, owner, 0o700)?,
        };
        let host = LocalHostSystem {
            identity,
            socket: paths.resolve(EXECUTOR_SOCKET)?,
            executor_uid: config.identities.job_uid,
            executor_gid: config.identities.job_gid,
            executor: mapped_program(&config.executor, &paths)?,
            seccomp,
            evidence: SafeDirectory::open(paths.resolve(EVIDENCE_ROOT)?, owner, 0o700)?,
            teardown: SafeDirectory::open(paths.resolve(TEARDOWN_ROOT)?, owner, 0o700)?,
            evidence_by_binding: BTreeMap::new(),
            attempts: SafeDirectory::open(paths.resolve(ATTEMPT_ROOT)?, owner, 0o711)?,
            job_uid: config.identities.job_uid,
            job_gid: config.identities.job_gid,
            static_job,
        };
        let mut controller = ProductionBindingController::new(
            StaticLaneManifest::new(manifest),
            intents,
            journal,
            host,
        );
        controller
            .recover_open(now)
            .map_err(|_| ProductionV2Error::Closed)?;
        Some(Box::new(controller))
    } else {
        None
    };
    Ok(ProductionRuntime {
        dispatch: Box::new(ProductionV2Dispatch {
            ordinary,
            qualification,
            contract,
        }),
        peer_policy,
    })
}

fn verify_execd_state_traversal(
    paths: &RuntimePaths,
    owner: u32,
    group: u32,
) -> Result<(), ProductionV2Error> {
    for (path, mode) in [
        (SHARED_STATE_ROOT, 0o711),
        (EXECD_STATE_ROOT, 0o711),
        (ATTEMPT_ROOT, 0o711),
    ] {
        verify_exact_directory(&paths.resolve(path)?, owner, group, mode)?;
    }
    Ok(())
}

fn verify_exact_directory(
    path: &Path,
    owner: u32,
    group: u32,
    mode: u32,
) -> Result<(), ProductionV2Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProductionV2Error::Closed)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner
        || metadata.gid() != group
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(ProductionV2Error::Closed);
    }
    Ok(())
}

fn validate_config(
    config: &ProductionConfig,
    paths: &RuntimePaths,
    owner: u32,
    validate_group: bool,
) -> Result<(), ProductionV2Error> {
    let identities = &config.identities;
    if config.schema_version != CONFIG_SCHEMA
        || config.enabled_protocol != 2
        || !matches!(config.capacity, 0 | 1)
        || identities.execd_uid != owner
        || identities.execd_uid == identities.runner_uid
        || identities.execd_uid == identities.control_uid
        || [
            identities.runner_uid,
            identities.runner_gid,
            identities.control_uid,
            identities.control_gid,
            identities.job_uid,
            identities.job_gid,
            identities.access_group_gid,
        ]
        .contains(&0)
        || identities.runner_uid == identities.control_uid
        || identities.runner_uid == identities.job_uid
        || identities.control_uid == identities.job_uid
        || identities.control_uid != CONTROL_UID
        || identities.control_gid != CONTROL_GID
        || identities.control_gid == identities.access_group_gid
        || identities.access_group != ACCESS_GROUP
        || identities.access_group_members != [CONTROL_USER, "buzzci-runner"]
        || identities.control_user != CONTROL_USER
        || identities.control_group != CONTROL_GROUP
        || identities.control_home != CONTROL_HOME
        || identities.control_shell != "/usr/sbin/nologin"
        || identities.control_supplementary_groups != [ACCESS_GROUP]
        || config.paths.intent_root != INTENT_ROOT
        || config.paths.binding_root != BINDING_ROOT
        || config.paths.evidence_root != EVIDENCE_ROOT
        || config.paths.teardown_root != TEARDOWN_ROOT
        || config.paths.attempt_root != ATTEMPT_ROOT
        || config.paths.qualification_root != QUALIFICATION_ROOT
        || config.paths.executor_socket != EXECUTOR_SOCKET
        || config.executor.path != EXECUTOR_PROGRAM
        || config.executor.source_commit.len() != 40
        || !lower_hex(&config.executor.source_commit)
        || config
            .executor
            .source_commit
            .bytes()
            .all(|byte| byte == b'0')
        || config.executor.uid != owner
        || config.executor.gid != identities.execd_gid
        || config.executor.mode != 0o755
        || config.qualification.integrated_candidate_sha != config.executor.source_commit
        || config.qualification.activation_package_digest.len() != 64
        || !lower_hex(&config.qualification.activation_package_digest)
        || config
            .qualification
            .activation_package_digest
            .bytes()
            .all(|byte| byte == b'0')
        || config.qualification.fixture_digest.len() != 64
        || !lower_hex(&config.qualification.fixture_digest)
        || config
            .qualification
            .fixture_digest
            .bytes()
            .all(|byte| byte == b'0')
        || config.qualification.controller_generation == 0
        || config.qualification.runner_generation == 0
        || config.qualification.controller_generation > MAX_SAFE_INTEGER
        || config.qualification.runner_generation > MAX_SAFE_INTEGER
        || config.execution.schema_version != STATIC_EXECUTION_SCHEMA
        || config.execution.declaration_digest.len() != 64
        || !lower_hex(&config.execution.declaration_digest)
        || config
            .execution
            .declaration_digest
            .bytes()
            .all(|byte| byte == b'0')
        || config.execution.workflow_id.is_empty()
        || wire_text(&config.execution.workflow_id).is_err()
        || config.execution.workflow_digest.len() != 64
        || !lower_hex(&config.execution.workflow_digest)
        || config
            .execution
            .workflow_digest
            .bytes()
            .all(|byte| byte == b'0')
        || config.execution.job_id != "capacity-one-fixture"
        || config.execution.artifact.artifact_id != "result"
        || config.execution.artifact.name != "result.json"
        || config.execution.artifact.media_type != "application/json"
        || config.execution.artifact.relative_name != "result.json"
        || config.execution.artifact.max_bytes != 32 * 1024
        || config.execution.fixture_manifest_sha256 != FIXTURE_MANIFEST_SHA256
        || config.execution.fixture_input_sha256 != FIXTURE_INPUT_SHA256
        || config.execution.fixture_script_sha256 != FIXTURE_SCRIPT_SHA256
        || config.execution.max_stdout_bytes != FIXED_MAX_STDOUT_BYTES
        || config.execution.max_stderr_bytes != FIXED_MAX_STDERR_BYTES
        || config.execution.max_memory_bytes != FIXED_MAX_MEMORY_BYTES
        || config.execution.max_processes != FIXED_MAX_PROCESSES
        || config.execution.max_wall_seconds != FIXED_MAX_WALL_SECONDS
    {
        return Err(ProductionV2Error::Closed);
    }
    let manifest = config.lane_manifest.clone().into_manifest()?;
    if hex::encode(manifest.digest()) != config.lane_manifest_digest {
        return Err(ProductionV2Error::Closed);
    }
    let program = mapped_program(&config.executor, paths)?;
    verify_program(&program)?;
    if validate_group {
        validate_access_group(identities, paths)?;
        validate_named_group(&identities.control_group, identities.control_gid, paths)?;
        validate_principal(
            "buzzci-runner",
            identities.runner_uid,
            identities.runner_gid,
            None,
            "/usr/sbin/nologin",
            paths,
        )?;
        validate_principal(
            &identities.control_user,
            identities.control_uid,
            identities.control_gid,
            Some(&identities.control_home),
            &identities.control_shell,
            paths,
        )?;
        validate_principal(
            JOB_USER,
            identities.job_uid,
            identities.job_gid,
            None,
            "/usr/sbin/nologin",
            paths,
        )?;
    }
    Ok(())
}

fn qualification_contract(
    config: &ProductionConfig,
    manifest: &LaneActivationManifestV1,
    seccomp: &SeccompRuntimeBinding,
) -> Result<ProductionQualificationContract, ProductionV2Error> {
    let integrated_candidate_sha = GitOid::Sha1(decode_hex::<20>(
        &config.qualification.integrated_candidate_sha,
    )?);
    let executor_program_digest = decode_hex::<32>(&config.executor.sha256)?;
    let executor_provenance_digest = production_qualification_executor_provenance_digest(
        &config.executor.path,
        executor_program_digest,
        integrated_candidate_sha,
        config.executor.uid,
        config.executor.gid,
        config.executor.mode,
    )
    .ok_or(ProductionV2Error::Closed)?;
    let principal_digest = production_qualification_principal_digest(
        &config.identities.control_user,
        &config.identities.control_group,
        config.identities.control_uid,
        config.identities.control_gid,
        &config.identities.control_home,
        &config.identities.control_shell,
        &config.identities.control_supplementary_groups,
    )
    .ok_or(ProductionV2Error::Closed)?;
    Ok(ProductionQualificationContract {
        integrated_candidate_sha,
        activation_package_digest: decode_hex(&config.qualification.activation_package_digest)?,
        fixture_digest: decode_hex(&config.qualification.fixture_digest)?,
        principal_digest,
        lane_manifest_digest: manifest.digest(),
        broker_build_identity: manifest.broker_build_identity,
        host_profile_digest: manifest.host_profile_digest,
        suite_identity: manifest.suite_identity,
        isolation_profile_digest: manifest.isolation_profile_digest,
        seccomp_profile_digest: decode_hex(&seccomp.profile_digest)?,
        seccomp_install_receipt_digest: decode_hex(&seccomp.install_receipt_digest)?,
        executor_program_digest,
        executor_provenance_digest,
        controller_generation: config.qualification.controller_generation,
        runner_generation: config.qualification.runner_generation,
        lane_epoch: manifest.lane_epoch,
        admission_key_generation: manifest.admission_key_generation,
    })
}

fn static_execution_contract(
    config: &ProductionConfig,
    manifest: &LaneActivationManifestV1,
    paths: &RuntimePaths,
    owner: u32,
) -> Result<StaticExecutionContract, ProductionV2Error> {
    let execution = &config.execution;
    let candidate = GitOid::Sha1(decode_hex(&config.qualification.integrated_candidate_sha)?);
    let artifact = ArtifactDeclarationV1 {
        artifact_id: wire_text(&execution.artifact.artifact_id)?,
        name: wire_text(&execution.artifact.name)?,
        media_type: wire_text(&execution.artifact.media_type)?,
        relative_name: wire_text(&execution.artifact.relative_name)?,
        max_bytes: execution.artifact.max_bytes,
    };
    let program =
        |path: &str, digest: &str, mode: u32| -> Result<ProgramProvenance, ProductionV2Error> {
            mapped_program(
                &ProgramProvenance {
                    path: path.into(),
                    sha256: digest.into(),
                    source_commit: config.qualification.integrated_candidate_sha.clone(),
                    uid: owner,
                    gid: config.identities.execd_gid,
                    mode,
                },
                paths,
            )
        };
    let mut contract = StaticExecutionContract {
        declaration_digest: [0; 32],
        candidate,
        activation_package_digest: decode_hex(&config.qualification.activation_package_digest)?,
        lane_manifest_digest: manifest.digest(),
        isolation_profile_digest: manifest.isolation_profile_digest,
        workflow_id: wire_text(&execution.workflow_id)?,
        workflow_digest: decode_hex(&execution.workflow_digest)?,
        job_id: wire_text(&execution.job_id)?,
        artifact,
        fixture_manifest: program(
            FIXTURE_MANIFEST_SOURCE,
            &execution.fixture_manifest_sha256,
            0o444,
        )?,
        fixture_input: program(FIXTURE_INPUT_SOURCE, &execution.fixture_input_sha256, 0o444)?,
        fixture_script: program(
            FIXTURE_SCRIPT_SOURCE,
            &execution.fixture_script_sha256,
            0o555,
        )?,
        max_stdout_bytes: execution.max_stdout_bytes,
        max_stderr_bytes: execution.max_stderr_bytes,
        max_memory_bytes: execution.max_memory_bytes,
        max_processes: execution.max_processes,
        max_wall_seconds: execution.max_wall_seconds,
    };
    contract.declaration_digest = static_execution_digest(&contract);
    if hex::encode(contract.declaration_digest) != execution.declaration_digest {
        return Err(ProductionV2Error::Closed);
    }
    contract.verify_sources()?;
    Ok(contract)
}

fn static_execution_digest(value: &StaticExecutionContract) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(STATIC_EXECUTION_DIGEST_DOMAIN);
    update_oid(&mut digest, value.candidate);
    digest.update(value.activation_package_digest);
    digest.update(value.lane_manifest_digest);
    digest.update(value.isolation_profile_digest);
    update_wire_text(&mut digest, value.workflow_id);
    digest.update(value.workflow_digest);
    update_wire_text(&mut digest, value.job_id);
    update_wire_text(&mut digest, value.artifact.artifact_id);
    update_wire_text(&mut digest, value.artifact.name);
    update_wire_text(&mut digest, value.artifact.media_type);
    update_wire_text(&mut digest, value.artifact.relative_name);
    digest.update(value.artifact.max_bytes.to_be_bytes());
    digest.update(decode_hex::<32>(&value.fixture_manifest.sha256).unwrap_or([0; 32]));
    digest.update(decode_hex::<32>(&value.fixture_input.sha256).unwrap_or([0; 32]));
    digest.update(decode_hex::<32>(&value.fixture_script.sha256).unwrap_or([0; 32]));
    digest.update(value.max_stdout_bytes.to_be_bytes());
    digest.update(value.max_stderr_bytes.to_be_bytes());
    digest.update(value.max_memory_bytes.to_be_bytes());
    digest.update(value.max_processes.to_be_bytes());
    digest.update(value.max_wall_seconds.to_be_bytes());
    digest.finalize().into()
}

fn update_oid(digest: &mut Sha256, oid: GitOid) {
    match oid {
        GitOid::Sha1(bytes) => {
            digest.update([1]);
            digest.update(bytes);
        }
        GitOid::Sha256(bytes) => {
            digest.update([2]);
            digest.update(bytes);
        }
    }
}

fn update_wire_text(digest: &mut Sha256, value: WireText64) {
    digest.update([value.len]);
    digest.update(value.bytes);
}

fn mapped_program(
    value: &ProgramProvenance,
    paths: &RuntimePaths,
) -> Result<ProgramProvenance, ProductionV2Error> {
    let mut mapped = value.clone();
    mapped.path = paths.resolve(&value.path)?.to_string_lossy().into_owned();
    Ok(mapped)
}

fn verify_program(value: &ProgramProvenance) -> Result<(), ProductionV2Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&value.path)
        .map_err(|_| ProductionV2Error::Closed)?;
    let metadata = file.metadata().map_err(|_| ProductionV2Error::Closed)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != value.uid
        || metadata.gid() != value.gid
        || metadata.permissions().mode() & 0o7777 != value.mode
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > 128 * 1024 * 1024
    {
        return Err(ProductionV2Error::Closed);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| ProductionV2Error::Closed)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if hex::encode(digest.finalize()) != value.sha256 {
        return Err(ProductionV2Error::Closed);
    }
    Ok(())
}

fn read_verified_program(value: &ProgramProvenance) -> Result<Vec<u8>, BindingError> {
    verify_program(value).map_err(binding_error)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&value.path)
        .map_err(|_| BindingError::HostRefused)?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BindingError::HostRefused)?;
    if bytes.is_empty()
        || bytes.len() as u64 > MAX_RECORD
        || hex::encode(Sha256::digest(&bytes)) != value.sha256
    {
        return Err(BindingError::HostRefused);
    }
    Ok(bytes)
}

fn verify_materialized_attempt(
    attempt: &SafeDirectory,
    owner: u32,
    contract: &StaticExecutionContract,
    artifact_complete: bool,
) -> Result<(), ProductionV2Error> {
    verify_materialized_files(
        attempt,
        owner,
        &contract.fixture_manifest.sha256,
        &contract.fixture_input.sha256,
        &contract.fixture_script.sha256,
        artifact_complete,
        contract
            .artifact
            .relative_name
            .as_str()
            .map_err(|_| ProductionV2Error::Closed)?,
    )
}

fn verify_materialized_files(
    attempt: &SafeDirectory,
    owner: u32,
    fixture_manifest_sha256: &str,
    fixture_input_sha256: &str,
    fixture_script_sha256: &str,
    artifact_complete: bool,
    artifact_name: &str,
) -> Result<(), ProductionV2Error> {
    if attempt.names(2)?
        != [
            MATERIALIZED_ARTIFACT_ROOT.to_owned(),
            MATERIALIZED_SOURCE_ROOT.to_owned(),
        ]
    {
        return Err(ProductionV2Error::Closed);
    }
    let mut source = attempt.open_child(MATERIALIZED_SOURCE_ROOT, owner, 0o500)?;
    for component in FIXTURE_TREE {
        if source.names(1)? != [component.to_owned()] {
            return Err(ProductionV2Error::Closed);
        }
        source = source.open_child(component, owner, 0o500)?;
    }
    if source.names(3)?
        != [
            FIXTURE_MANIFEST_NAME.to_owned(),
            FIXTURE_INPUT_NAME.to_owned(),
            FIXTURE_SCRIPT_NAME.to_owned(),
        ]
    {
        return Err(ProductionV2Error::Closed);
    }
    for (name, mode, expected) in [
        (FIXTURE_MANIFEST_NAME, 0o400, fixture_manifest_sha256),
        (FIXTURE_INPUT_NAME, 0o400, fixture_input_sha256),
        (FIXTURE_SCRIPT_NAME, 0o500, fixture_script_sha256),
    ] {
        let mut file = source.open_file(name, owner, mode, MAX_RECORD, false)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| ProductionV2Error::Closed)?;
        if bytes.is_empty() || hex::encode(Sha256::digest(bytes)) != expected {
            return Err(ProductionV2Error::Closed);
        }
    }
    let artifacts = attempt.open_child(MATERIALIZED_ARTIFACT_ROOT, owner, 0o700)?;
    let expected = if artifact_complete {
        vec![artifact_name.to_owned()]
    } else {
        Vec::new()
    };
    if artifacts.names(1)? != expected {
        return Err(ProductionV2Error::Closed);
    }
    Ok(())
}

fn verify_executor_attempt(
    attempt_root: &Path,
    request: &ExecutorRequest,
    artifact_complete: bool,
) -> Result<(), ProductionV2Error> {
    let owner = Uid::effective().as_raw();
    let attempt = SafeDirectory::open(attempt_root.join(&request.attempt_id), owner, 0o500)?;
    verify_materialized_files(
        &attempt,
        owner,
        &request.fixture_manifest_sha256,
        &request.fixture_input_sha256,
        &request.fixture_script_sha256,
        artifact_complete,
        "result.json",
    )
}

fn validate_access_group(
    config: &IdentityConfig,
    paths: &RuntimePaths,
) -> Result<(), ProductionV2Error> {
    let bytes = fs::read(paths.resolve("/etc/group")?).map_err(|_| ProductionV2Error::Closed)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ProductionV2Error::Closed);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ProductionV2Error::Closed)?;
    let mut matches = text
        .lines()
        .filter(|line| line.starts_with("buzzci-execd:"));
    let line = matches.next().ok_or(ProductionV2Error::Closed)?;
    if matches.next().is_some() {
        return Err(ProductionV2Error::Closed);
    }
    let fields: Vec<_> = line.split(':').collect();
    let mut members = fields
        .get(3)
        .ok_or(ProductionV2Error::Closed)?
        .split(',')
        .collect::<Vec<_>>();
    members.sort_unstable();
    if fields.len() != 4
        || fields[2].parse::<u32>().ok() != Some(config.access_group_gid)
        || members != ["buzzci-ctl", "buzzci-runner"]
    {
        return Err(ProductionV2Error::Closed);
    }
    Ok(())
}

fn validate_named_group(
    name: &str,
    gid: u32,
    paths: &RuntimePaths,
) -> Result<(), ProductionV2Error> {
    let bytes = fs::read(paths.resolve("/etc/group")?).map_err(|_| ProductionV2Error::Closed)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ProductionV2Error::Closed);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ProductionV2Error::Closed)?;
    let mut matches = text
        .lines()
        .filter(|line| line.split(':').next() == Some(name));
    let line = matches.next().ok_or(ProductionV2Error::Closed)?;
    if matches.next().is_some() {
        return Err(ProductionV2Error::Closed);
    }
    let fields: Vec<_> = line.split(':').collect();
    if fields.len() != 4 || fields[2].parse::<u32>().ok() != Some(gid) {
        return Err(ProductionV2Error::Closed);
    }
    Ok(())
}

fn validate_principal(
    name: &str,
    uid: u32,
    gid: u32,
    home: Option<&str>,
    shell: &str,
    paths: &RuntimePaths,
) -> Result<(), ProductionV2Error> {
    let bytes = fs::read(paths.resolve("/etc/passwd")?).map_err(|_| ProductionV2Error::Closed)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ProductionV2Error::Closed);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ProductionV2Error::Closed)?;
    let mut matches = text
        .lines()
        .filter(|line| line.split(':').next() == Some(name));
    let line = matches.next().ok_or(ProductionV2Error::Closed)?;
    if matches.next().is_some() {
        return Err(ProductionV2Error::Closed);
    }
    let fields: Vec<_> = line.split(':').collect();
    if fields.len() != 7
        || fields[2].parse::<u32>().ok() != Some(uid)
        || fields[3].parse::<u32>().ok() != Some(gid)
        || home.is_some_and(|expected| fields[5] != expected)
        || fields[6] != shell
    {
        return Err(ProductionV2Error::Closed);
    }
    Ok(())
}

impl ManifestDocument {
    fn into_manifest(self) -> Result<LaneActivationManifestV1, ProductionV2Error> {
        Ok(LaneActivationManifestV1 {
            schema_version: self.schema_version,
            lane_id: decode_hex(&self.lane_id)?,
            lane_epoch: self.lane_epoch,
            admission_signature_algorithm: AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
            admission_verifying_key: decode_hex(&self.admission_verifying_key)?,
            admission_key_generation: self.admission_key_generation,
            broker_build_identity: decode_hex(&self.broker_build_identity)?,
            host_profile_digest: decode_hex(&self.host_profile_digest)?,
            suite_identity: decode_hex(&self.suite_identity)?,
            isolation_profile_digest: decode_hex(&self.isolation_profile_digest)?,
            not_before: self.not_before,
            expires_at: self.expires_at,
            max_wall_timeout_seconds: self.max_wall_timeout_seconds,
        })
    }
}

impl OidDocument {
    fn into_oid(self) -> Result<GitOid, ProductionV2Error> {
        match self.algorithm.as_str() {
            "sha1" => Ok(GitOid::Sha1(decode_hex(&self.hex)?)),
            "sha256" => Ok(GitOid::Sha256(decode_hex(&self.hex)?)),
            _ => Err(ProductionV2Error::Closed),
        }
    }

    fn from_oid(value: GitOid) -> Self {
        match value {
            GitOid::Sha1(value) => Self {
                algorithm: "sha1".into(),
                hex: hex::encode(value),
            },
            GitOid::Sha256(value) => Self {
                algorithm: "sha256".into(),
                hex: hex::encode(value),
            },
        }
    }
}

impl From<ExecutionBindingRecord> for BindingDocument {
    fn from(record: ExecutionBindingRecord) -> Self {
        let binding = record.binding;
        Self {
            schema_version: binding.schema_version,
            lane_manifest_digest: hex::encode(binding.lane_manifest_digest),
            lane_epoch: binding.lane_epoch,
            job_intent_digest: hex::encode(binding.job_intent_digest),
            admission_message_digest: hex::encode(binding.admission_message_digest),
            signed_request_digest: hex::encode(binding.signed_request_digest),
            actor_pubkey: hex::encode(binding.actor_pubkey),
            idempotency_digest: hex::encode(binding.idempotency_digest),
            run_id: hex::encode(binding.run_id),
            attempt: binding.attempt,
            attempt_id: hex::encode(binding.attempt_id),
            lease_id: hex::encode(binding.lease_id),
            lease_generation: binding.lease_generation,
            tip_oid: OidDocument::from_oid(binding.tip_oid),
            base_oid: OidDocument::from_oid(binding.base_oid),
            admitted_at: binding.admitted_at,
            deadline_at: binding.deadline_at,
            execution_binding_digest: hex::encode(binding.execution_binding_digest),
            phase: phase_name(record.phase).into(),
            generation: record.generation,
            updated_at: record.updated_at,
            conclusion: conclusion_name(record.conclusion).into(),
            host_receipt_digest: hex::encode(record.host_receipt_digest),
            evidence_set_digest: hex::encode(record.evidence_set_digest),
            teardown_digest: hex::encode(record.teardown_digest),
            request_event_id: hex::encode(binding.request_event_id),
            workflow_digest: hex::encode(binding.workflow_digest),
            workflow_id: binding.workflow_id.as_str().unwrap_or_default().into(),
            job_id: binding.job_id.as_str().unwrap_or_default().into(),
            artifacts: binding
                .artifacts
                .iter()
                .flatten()
                .map(ArtifactDocument::from)
                .collect(),
        }
    }
}

impl BindingDocument {
    fn into_record(self) -> Result<ExecutionBindingRecord, ProductionV2Error> {
        let artifacts = artifact_array(&self.artifacts)?;
        let binding = ExecutionBindingV1 {
            schema_version: self.schema_version,
            lane_manifest_digest: decode_hex(&self.lane_manifest_digest)?,
            lane_epoch: self.lane_epoch,
            job_intent_digest: decode_hex(&self.job_intent_digest)?,
            admission_message_digest: decode_hex(&self.admission_message_digest)?,
            signed_request_digest: decode_hex(&self.signed_request_digest)?,
            actor_pubkey: decode_hex(&self.actor_pubkey)?,
            idempotency_digest: decode_hex(&self.idempotency_digest)?,
            run_id: decode_hex(&self.run_id)?,
            attempt: self.attempt,
            attempt_id: decode_hex(&self.attempt_id)?,
            lease_id: decode_hex(&self.lease_id)?,
            lease_generation: self.lease_generation,
            tip_oid: self.tip_oid.into_oid()?,
            base_oid: self.base_oid.into_oid()?,
            admitted_at: self.admitted_at,
            deadline_at: self.deadline_at,
            execution_binding_digest: decode_hex(&self.execution_binding_digest)?,
            request_event_id: decode_hex(&self.request_event_id)?,
            workflow_digest: decode_hex(&self.workflow_digest)?,
            workflow_id: wire_text(&self.workflow_id)?,
            job_id: wire_text(&self.job_id)?,
            artifact_count: self.artifacts.len() as u8,
            artifacts,
        };
        if binding.schema_version != EXECUTION_BINDING_SCHEMA_V1
            || binding.execution_binding_digest != binding.computed_digest()
            || usize::from(binding.artifact_count) != self.artifacts.len()
            || binding
                .artifacts
                .iter()
                .flatten()
                .any(|item| !item.validate())
        {
            return Err(ProductionV2Error::Closed);
        }
        Ok(ExecutionBindingRecord {
            binding,
            phase: parse_phase(&self.phase)?,
            generation: self.generation,
            updated_at: self.updated_at,
            conclusion: parse_conclusion(Some(&self.conclusion))
                .map_err(|_| ProductionV2Error::Closed)?,
            host_receipt_digest: decode_hex(&self.host_receipt_digest)?,
            evidence_set_digest: decode_hex(&self.evidence_set_digest)?,
            teardown_digest: decode_hex(&self.teardown_digest)?,
        })
    }
}

impl From<&ArtifactDeclarationV1> for ArtifactDocument {
    fn from(value: &ArtifactDeclarationV1) -> Self {
        Self {
            artifact_id: value.artifact_id.as_str().unwrap_or_default().into(),
            name: value.name.as_str().unwrap_or_default().into(),
            media_type: value.media_type.as_str().unwrap_or_default().into(),
            relative_name: value.relative_name.as_str().unwrap_or_default().into(),
            max_bytes: value.max_bytes,
        }
    }
}

fn artifact_array(
    documents: &[ArtifactDocument],
) -> Result<[Option<ArtifactDeclarationV1>; 1], ProductionV2Error> {
    if documents.len() > 1 {
        return Err(ProductionV2Error::Closed);
    }
    let mut artifacts = [None];
    if let Some(value) = documents.first() {
        artifacts[0] = Some(ArtifactDeclarationV1 {
            artifact_id: wire_text(&value.artifact_id)?,
            name: wire_text(&value.name)?,
            media_type: wire_text(&value.media_type)?,
            relative_name: wire_text(&value.relative_name)?,
            max_bytes: value.max_bytes,
        });
    }
    Ok(artifacts)
}

fn wire_text(value: &str) -> Result<WireText64, ProductionV2Error> {
    WireText64::from_ascii(value).map_err(|_| ProductionV2Error::Closed)
}

fn read_document<T: for<'de> Deserialize<'de> + Serialize>(
    path: &Path,
    owner: u32,
    mode: u32,
    maximum: u64,
) -> Result<T, ProductionV2Error> {
    let parent = path.parent().ok_or(ProductionV2Error::Closed)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ProductionV2Error::Closed)?;
    let directory = SafeDirectory::open(parent.to_owned(), owner, 0o755)?;
    let bytes = directory.read(name, mode, maximum)?;
    canonical_parse(&bytes)
}

fn canonical_parse<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
) -> Result<T, ProductionV2Error> {
    let value: T = serde_json::from_slice(bytes).map_err(|_| ProductionV2Error::Closed)?;
    if canonical_bytes(&value)? != bytes {
        return Err(ProductionV2Error::Closed);
    }
    Ok(value)
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ProductionV2Error> {
    serde_json::to_vec(value).map_err(|_| ProductionV2Error::Closed)
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ProductionV2Error> {
    if value.len() != N * 2 || !lower_hex(value) {
        return Err(ProductionV2Error::Closed);
    }
    hex::decode(value)
        .map_err(|_| ProductionV2Error::Closed)?
        .try_into()
        .map_err(|_| ProductionV2Error::Closed)
}

fn decode_nonzero(value: &str) -> Result<[u8; 32], BindingError> {
    let digest = decode_hex(value).map_err(binding_error)?;
    (digest != [0; 32])
        .then_some(digest)
        .ok_or(BindingError::HostRefused)
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn safe_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && !value.starts_with('.')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn binding_error(_: ProductionV2Error) -> BindingError {
    BindingError::StorageUnavailable
}

fn phase_name(value: BindingPhase) -> &'static str {
    match value {
        BindingPhase::Admitted => "admitted",
        BindingPhase::Running => "running",
        BindingPhase::Draining => "draining",
        BindingPhase::Terminal => "terminal",
        BindingPhase::CapacityReturned => "capacity_returned",
        BindingPhase::Quarantined => "quarantined",
    }
}

fn parse_phase(value: &str) -> Result<BindingPhase, ProductionV2Error> {
    match value {
        "admitted" => Ok(BindingPhase::Admitted),
        "running" => Ok(BindingPhase::Running),
        "draining" => Ok(BindingPhase::Draining),
        "terminal" => Ok(BindingPhase::Terminal),
        "capacity_returned" => Ok(BindingPhase::CapacityReturned),
        "quarantined" => Ok(BindingPhase::Quarantined),
        _ => Err(ProductionV2Error::Closed),
    }
}

fn stop_name(value: HostStopReason) -> &'static str {
    match value {
        HostStopReason::Cancelled => "cancelled",
        HostStopReason::Completed => "completed",
        HostStopReason::Expired => "expired",
        HostStopReason::Recovery => "recovery",
    }
}

fn conclusion_name(value: Conclusion) -> &'static str {
    match value {
        Conclusion::None => "none",
        Conclusion::Success => "success",
        Conclusion::Failure => "failure",
        Conclusion::Cancelled => "cancelled",
        Conclusion::TimedOut => "timed_out",
        Conclusion::InfrastructureFailure => "infrastructure_failure",
    }
}

fn terminal_output(response: &ExecutorResponse) -> String {
    let stdout = response.raw_stdout.as_deref().unwrap_or_default();
    let stderr = response.raw_stderr.as_deref().unwrap_or_default();
    match (stdout.is_empty(), stderr.is_empty()) {
        (false, true) => stdout.into(),
        (true, false) => stderr.into(),
        (false, false) => format!("{stdout}{stderr}"),
        (true, true) => "execution stopped before terminal output\n".into(),
    }
}

fn parse_conclusion(value: Option<&str>) -> Result<Conclusion, BindingError> {
    match value {
        Some("none") => Ok(Conclusion::None),
        Some("success") => Ok(Conclusion::Success),
        Some("failure") => Ok(Conclusion::Failure),
        Some("cancelled") => Ok(Conclusion::Cancelled),
        Some("timed_out") => Ok(Conclusion::TimedOut),
        Some("infrastructure_failure") => Ok(Conclusion::InfrastructureFailure),
        _ => Err(BindingError::HostRefused),
    }
}

fn scrub(raw: &[u8]) -> Result<Vec<u8>, BindingError> {
    let text = std::str::from_utf8(raw).map_err(|_| BindingError::HostRefused)?;
    if text.contains('\0') || text.lines().any(|line| line.len() > 4096) {
        return Err(BindingError::HostRefused);
    }
    let mut output = String::with_capacity(text.len());
    let mut private_key_block = false;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if private_key_block {
            if lower.contains("-----end ") && lower.contains(" private key-----") {
                private_key_block = false;
            }
            continue;
        }
        if lower.contains("-----begin ") && lower.contains(" private key-----") {
            output.push_str("[REDACTED]\n");
            private_key_block = true;
            continue;
        }
        if sensitive_assignment(&lower) || sensitive_authorization(&lower) {
            output.push_str("[REDACTED]\n");
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    Ok(output.into_bytes())
}

fn sensitive_assignment(lower: &str) -> bool {
    const KEYS: [&str; 10] = [
        "aws_secret_access_key",
        "buzz_s3_secret_key",
        "access_token",
        "private_key",
        "api_key",
        "password",
        "passwd",
        "secret",
        "token",
        "private key",
    ];
    lower
        .char_indices()
        .filter(|(_, character)| matches!(character, '=' | ':'))
        .any(|(separator, _)| {
            let left = lower[..separator].trim_end().trim_end_matches(['"', '\'']);
            let start = left
                .char_indices()
                .rev()
                .find(|(_, character)| {
                    !character.is_ascii_alphanumeric()
                        && !matches!(character, '_' | '-' | '.' | ' ')
                })
                .map_or(0, |(index, character)| index + character.len_utf8());
            let key = left[start..].trim();
            KEYS.iter().any(|suffix| {
                key == *suffix
                    || key.strip_suffix(suffix).is_some_and(|prefix| {
                        prefix
                            .chars()
                            .last()
                            .is_some_and(|character| !character.is_ascii_alphanumeric())
                    })
            })
        })
}

fn sensitive_authorization(lower: &str) -> bool {
    let Some((name, value)) = lower.split_once(':') else {
        return false;
    };
    name.trim().trim_matches('"').ends_with("authorization")
        && matches!(
            value
                .trim_start()
                .trim_matches('"')
                .split_ascii_whitespace()
                .next(),
            Some("bearer" | "basic")
        )
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ExecutorStage {
    Handoff,
    Runtime,
    Materialized,
    Running,
    Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutorBinding {
    attempt_id: String,
    job_intent_digest: String,
    static_execution_digest: String,
    fixture_manifest_sha256: String,
    fixture_input_sha256: String,
    fixture_script_sha256: String,
    deadline_at: u64,
    max_stdout_bytes: u32,
    max_stderr_bytes: u32,
    max_memory_bytes: u64,
    max_processes: u32,
}

struct ExecutorLease {
    stage: ExecutorStage,
    contract: ExecutorBinding,
    process: Option<RunningJob>,
    result: Option<JobResult>,
}

struct RunningJob {
    child: Child,
    stdout: JoinHandle<std::io::Result<Vec<u8>>>,
    stderr: JoinHandle<std::io::Result<Vec<u8>>>,
}

#[derive(Clone, Debug)]
struct JobResult {
    conclusion: Conclusion,
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Serve the fixed unprivileged executor protocol on a systemd-owned socket.
///
/// The process retains only the active capacity-one binding in memory. It has
/// no path in the protocol for commands, environment, prior evidence, or logs.
pub fn run_executor_service(listener: UnixListener) -> std::io::Result<()> {
    let executable_sha256 = executable_sha256()?;
    verify_executor_dac_contract()?;
    verify_executor_seccomp_profile()?;
    let mut active: BTreeMap<String, ExecutorLease> = BTreeMap::new();
    loop {
        let (mut stream, _) = listener.accept()?;
        let result = serve_executor_stream(&mut stream, &executable_sha256, &mut active);
        if result.is_err() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn verify_executor_dac_contract() -> std::io::Result<()> {
    for path in [
        SHARED_STATE_ROOT,
        EXECD_STATE_ROOT,
        ATTEMPT_ROOT,
        "/var/lib/buzzci/seccomp",
        "/var/lib/buzzci/seccomp/v1",
        "/var/lib/buzzci/seccomp/v1/sha256",
    ] {
        verify_exact_directory(Path::new(path), 0, 0, 0o711)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))?;
    }
    Ok(())
}

fn serve_executor_stream(
    stream: &mut UnixStream,
    executable_sha256: &str,
    active: &mut BTreeMap<String, ExecutorLease>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let credentials = getsockopt(&*stream, PeerCredentials).map_err(std::io::Error::from)?;
    if credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_RPC {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    let request: ExecutorRequest = canonical_parse(&body)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    let binding: [u8; 32] = decode_hex(&request.execution_binding_digest)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    if request.schema_version != RPC_SCHEMA
        || binding == [0; 32]
        || request.executor_program_sha256 != executable_sha256
        || !valid_executor_seccomp(&request)
        || active.len() > 1
    {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let response = executor_transition(request, active, Path::new(ATTEMPT_ROOT))
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    let body = canonical_bytes(&response)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(&body)
}

fn executor_transition(
    request: ExecutorRequest,
    active: &mut BTreeMap<String, ExecutorLease>,
    attempt_root: &Path,
) -> Result<ExecutorResponse, ProductionV2Error> {
    if !valid_executor_request(&request) {
        return Err(ProductionV2Error::Closed);
    }
    let binding = request.execution_binding_digest.clone();
    let operation = request.operation.clone();
    let receipt = |name: &str| -> String {
        let mut digest = Sha256::new();
        digest.update(EXECUTOR_RECEIPT_DOMAIN);
        digest.update(name.as_bytes());
        digest.update(binding.as_bytes());
        digest.update(request.attempt_id.as_bytes());
        digest.update(request.static_execution_digest.as_bytes());
        digest.update(request.fixture_manifest_sha256.as_bytes());
        digest.update(request.fixture_input_sha256.as_bytes());
        digest.update(request.fixture_script_sha256.as_bytes());
        digest.update(request.deadline_at.to_be_bytes());
        digest.update(request.max_stdout_bytes.to_be_bytes());
        digest.update(request.max_stderr_bytes.to_be_bytes());
        digest.update(request.max_memory_bytes.to_be_bytes());
        digest.update(request.max_processes.to_be_bytes());
        digest.update(request.seccomp_profile_sha256.as_bytes());
        digest.update(request.seccomp_install_receipt_sha256.as_bytes());
        hex::encode(digest.finalize())
    };
    let mut response = ExecutorResponse {
        schema_version: RPC_SCHEMA,
        operation: operation.clone(),
        execution_binding_digest: binding.clone(),
        receipt_digest: receipt(&operation),
        conclusion: None,
        evidence_set_digest: None,
        teardown_digest: None,
        raw_stdout: None,
        raw_stderr: None,
        exit_code: None,
        running: None,
        capacity_returned: None,
        quarantine: None,
    };
    match operation.as_str() {
        "executor_handoff" => {
            let job_intent_digest = request
                .job_intent_digest
                .as_deref()
                .filter(|value| value.len() == 64 && lower_hex(value))
                .ok_or(ProductionV2Error::Closed)?;
            let contract = ExecutorBinding::from_request(&request, job_intent_digest)?;
            if !active.is_empty()
                || active
                    .insert(
                        binding,
                        ExecutorLease {
                            stage: ExecutorStage::Handoff,
                            contract,
                            process: None,
                            result: None,
                        },
                    )
                    .is_some()
            {
                return Err(ProductionV2Error::Closed);
            }
        }
        "runtime_descriptor" => {
            verify_executor_binding(active, &binding, &request)?;
            transition(
                active,
                &binding,
                ExecutorStage::Handoff,
                ExecutorStage::Runtime,
            )?;
        }
        "materialization" => {
            if request.job_intent_digest.is_none() {
                return Err(ProductionV2Error::Closed);
            }
            verify_executor_binding(active, &binding, &request)?;
            verify_executor_attempt(attempt_root, &request, false)?;
            transition(
                active,
                &binding,
                ExecutorStage::Runtime,
                ExecutorStage::Materialized,
            )?;
        }
        "proxy_lease" => {
            verify_executor_binding(active, &binding, &request)?;
            let lease = active.get_mut(&binding).ok_or(ProductionV2Error::Closed)?;
            if lease.stage != ExecutorStage::Materialized || lease.process.is_some() {
                return Err(ProductionV2Error::Closed);
            }
            lease.process = Some(spawn_fixed_job(attempt_root, &request)?);
            lease.stage = ExecutorStage::Running;
        }
        "terminal_evidence" => {
            verify_executor_binding(active, &binding, &request)?;
            let now = unix_seconds()?;
            let lease = active.get_mut(&binding).ok_or(ProductionV2Error::Closed)?;
            if lease.stage == ExecutorStage::Running {
                match poll_running_job(lease, now)? {
                    Some(result) => {
                        lease.result = Some(result);
                        lease.stage = ExecutorStage::Terminal;
                    }
                    None => {
                        response.running = Some(true);
                        return Ok(response);
                    }
                }
            }
            if lease.stage != ExecutorStage::Terminal {
                return Err(ProductionV2Error::Closed);
            }
            let result = lease.result.as_ref().ok_or(ProductionV2Error::Closed)?;
            let evidence = evidence_document_digest(&binding, result.conclusion, &result.stdout)?;
            if request
                .claimed_evidence_digest
                .as_ref()
                .is_some_and(|claimed| claimed != &hex::encode(evidence))
            {
                return Err(ProductionV2Error::Closed);
            }
            response.receipt_digest = hex::encode(evidence);
            response.evidence_set_digest = Some(hex::encode(evidence));
            fill_job_response(&mut response, result)?;
        }
        "teardown" => {
            verify_executor_binding(active, &binding, &request)?;
            let reason = request
                .stop_reason
                .as_deref()
                .ok_or(ProductionV2Error::Closed)?;
            let forced = match reason {
                "completed" => None,
                "cancelled" => Some(Conclusion::Cancelled),
                "expired" => Some(Conclusion::TimedOut),
                "recovery" => Some(Conclusion::InfrastructureFailure),
                _ => return Err(ProductionV2Error::Closed),
            };
            let lease = active.get_mut(&binding).ok_or(ProductionV2Error::Closed)?;
            if lease.stage == ExecutorStage::Running {
                let result = stop_running_job(lease, forced.unwrap_or(Conclusion::Cancelled))?;
                lease.result = Some(result);
                lease.stage = ExecutorStage::Terminal;
            }
            let mut result = lease.result.clone().unwrap_or(JobResult {
                conclusion: forced.unwrap_or(Conclusion::InfrastructureFailure),
                exit_code: -1,
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
            if let Some(conclusion) = forced {
                result.conclusion = conclusion;
            } else if result.conclusion != Conclusion::Success {
                return Err(ProductionV2Error::Closed);
            }
            fill_job_response(&mut response, &result)?;
            active.remove(&binding);
        }
        "crash_recovery" => {
            if active.contains_key(&binding) {
                verify_executor_binding(active, &binding, &request)?;
            }
            let mut result = JobResult {
                conclusion: Conclusion::InfrastructureFailure,
                exit_code: -1,
                stdout: Vec::new(),
                stderr: b"executor state reconciled after restart\n".to_vec(),
            };
            if let Some(lease) = active.get_mut(&binding) {
                if lease.process.is_some() {
                    result = stop_running_job(lease, Conclusion::InfrastructureFailure)?;
                } else if let Some(existing) = lease.result.clone() {
                    result = existing;
                    result.conclusion = Conclusion::InfrastructureFailure;
                }
            }
            active.remove(&binding);
            fill_job_response(&mut response, &result)?;
            response.capacity_returned = Some(true);
            response.quarantine = Some(false);
        }
        _ => return Err(ProductionV2Error::Closed),
    }
    Ok(response)
}

impl ExecutorBinding {
    fn from_request(
        request: &ExecutorRequest,
        job_intent_digest: &str,
    ) -> Result<Self, ProductionV2Error> {
        let value = Self {
            attempt_id: request.attempt_id.clone(),
            job_intent_digest: job_intent_digest.into(),
            static_execution_digest: request.static_execution_digest.clone(),
            fixture_manifest_sha256: request.fixture_manifest_sha256.clone(),
            fixture_input_sha256: request.fixture_input_sha256.clone(),
            fixture_script_sha256: request.fixture_script_sha256.clone(),
            deadline_at: request.deadline_at,
            max_stdout_bytes: request.max_stdout_bytes,
            max_stderr_bytes: request.max_stderr_bytes,
            max_memory_bytes: request.max_memory_bytes,
            max_processes: request.max_processes,
        };
        value
            .valid()
            .then_some(value)
            .ok_or(ProductionV2Error::Closed)
    }

    fn valid(&self) -> bool {
        self.attempt_id.len() == 32
            && lower_hex(&self.attempt_id)
            && self.job_intent_digest.len() == 64
            && lower_hex(&self.job_intent_digest)
            && self.static_execution_digest.len() == 64
            && lower_hex(&self.static_execution_digest)
            && self.fixture_manifest_sha256 == FIXTURE_MANIFEST_SHA256
            && self.fixture_input_sha256 == FIXTURE_INPUT_SHA256
            && self.fixture_script_sha256 == FIXTURE_SCRIPT_SHA256
            && self.deadline_at > 0
            && self.deadline_at <= MAX_SAFE_INTEGER
            && self.max_stdout_bytes == FIXED_MAX_STDOUT_BYTES
            && self.max_stderr_bytes == FIXED_MAX_STDERR_BYTES
            && self.max_memory_bytes == FIXED_MAX_MEMORY_BYTES
            && self.max_processes == FIXED_MAX_PROCESSES
    }
}

fn valid_executor_request(request: &ExecutorRequest) -> bool {
    let digest = |value: &str| {
        value.len() == 64 && lower_hex(value) && !value.bytes().all(|byte| byte == b'0')
    };
    request.schema_version == RPC_SCHEMA
        && request.attempt_id.len() == 32
        && lower_hex(&request.attempt_id)
        && digest(&request.execution_binding_digest)
        && digest(&request.static_execution_digest)
        && digest(&request.fixture_manifest_sha256)
        && digest(&request.fixture_input_sha256)
        && digest(&request.fixture_script_sha256)
        && request.deadline_at > 0
        && request.deadline_at <= MAX_SAFE_INTEGER
        && request.max_stdout_bytes == FIXED_MAX_STDOUT_BYTES
        && request.max_stderr_bytes == FIXED_MAX_STDERR_BYTES
        && request.max_memory_bytes == FIXED_MAX_MEMORY_BYTES
        && request.max_processes == FIXED_MAX_PROCESSES
        && valid_executor_seccomp(request)
}

fn valid_executor_seccomp(request: &ExecutorRequest) -> bool {
    request.seccomp_profile_path == PHASE1_SECCOMP_PROFILE_PATH
        && request.seccomp_profile_sha256 == PHASE1_SECCOMP_PROFILE_DIGEST
        && request.seccomp_install_receipt_sha256.len() == 64
        && lower_hex(&request.seccomp_install_receipt_sha256)
        && !request
            .seccomp_install_receipt_sha256
            .bytes()
            .all(|byte| byte == b'0')
}

fn verify_executor_binding(
    active: &BTreeMap<String, ExecutorLease>,
    binding: &str,
    request: &ExecutorRequest,
) -> Result<(), ProductionV2Error> {
    let lease = active.get(binding).ok_or(ProductionV2Error::Closed)?;
    let job_intent = request
        .job_intent_digest
        .as_deref()
        .unwrap_or(&lease.contract.job_intent_digest);
    let observed = ExecutorBinding::from_request(request, job_intent)?;
    (observed == lease.contract)
        .then_some(())
        .ok_or(ProductionV2Error::Closed)
}

fn transition(
    active: &mut BTreeMap<String, ExecutorLease>,
    binding: &str,
    expected: ExecutorStage,
    next: ExecutorStage,
) -> Result<(), ProductionV2Error> {
    let lease = active.get_mut(binding).ok_or(ProductionV2Error::Closed)?;
    if lease.stage != expected {
        return Err(ProductionV2Error::Closed);
    }
    lease.stage = next;
    Ok(())
}

fn spawn_fixed_job(
    attempt_root: &Path,
    request: &ExecutorRequest,
) -> Result<RunningJob, ProductionV2Error> {
    verify_executor_attempt(attempt_root, request, false)?;
    let attempt = attempt_root.join(&request.attempt_id);
    let script = attempt
        .join(MATERIALIZED_SOURCE_ROOT)
        .join(FIXTURE_TREE.join("/"))
        .join(FIXTURE_SCRIPT_NAME);
    let mut command = Command::new(script);
    command
        .arg(MATERIALIZED_ARTIFACT_ROOT)
        .current_dir(&attempt)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("HOME", "/var/empty")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().map_err(|_| ProductionV2Error::Closed)?;
    let stdout = child.stdout.take().ok_or(ProductionV2Error::Closed)?;
    let stderr = child.stderr.take().ok_or(ProductionV2Error::Closed)?;
    Ok(RunningJob {
        child,
        stdout: capture_pipe(stdout, request.max_stdout_bytes as usize),
        stderr: capture_pipe(stderr, request.max_stderr_bytes as usize),
    })
}

fn capture_pipe<R: Read + Send + 'static>(
    mut pipe: R,
    maximum: usize,
) -> JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut captured = Vec::with_capacity(maximum.min(4096));
        let mut buffer = [0_u8; 4096];
        loop {
            let read = pipe.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            if captured.len() <= maximum {
                let keep = (maximum + 1 - captured.len()).min(read);
                captured.extend_from_slice(&buffer[..keep]);
            }
        }
        Ok(captured)
    })
}

fn poll_running_job(
    lease: &mut ExecutorLease,
    now: u64,
) -> Result<Option<JobResult>, ProductionV2Error> {
    if now >= lease.contract.deadline_at {
        return stop_running_job(lease, Conclusion::TimedOut).map(Some);
    }
    let status = lease
        .process
        .as_mut()
        .ok_or(ProductionV2Error::Closed)?
        .child
        .try_wait()
        .map_err(|_| ProductionV2Error::Closed)?;
    status
        .map(|status| finish_running_job(lease, status, None))
        .transpose()
}

fn stop_running_job(
    lease: &mut ExecutorLease,
    conclusion: Conclusion,
) -> Result<JobResult, ProductionV2Error> {
    let process = lease.process.as_mut().ok_or(ProductionV2Error::Closed)?;
    let pid = i32::try_from(process.child.id()).map_err(|_| ProductionV2Error::Closed)?;
    match killpg(Pid::from_raw(pid), Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        Err(_) => return Err(ProductionV2Error::Closed),
    }
    let status = process
        .child
        .wait()
        .map_err(|_| ProductionV2Error::Closed)?;
    finish_running_job(lease, status, Some(conclusion))
}

fn finish_running_job(
    lease: &mut ExecutorLease,
    status: ExitStatus,
    forced: Option<Conclusion>,
) -> Result<JobResult, ProductionV2Error> {
    let process = lease.process.take().ok_or(ProductionV2Error::Closed)?;
    let stdout = process
        .stdout
        .join()
        .map_err(|_| ProductionV2Error::Closed)?
        .map_err(|_| ProductionV2Error::Closed)?;
    let stderr = process
        .stderr
        .join()
        .map_err(|_| ProductionV2Error::Closed)?
        .map_err(|_| ProductionV2Error::Closed)?;
    if stdout.len() > lease.contract.max_stdout_bytes as usize
        || stderr.len() > lease.contract.max_stderr_bytes as usize
    {
        return Err(ProductionV2Error::Closed);
    }
    let exit_code = status.code().unwrap_or(-1);
    let conclusion = forced.unwrap_or_else(|| {
        if status.success() && stderr.is_empty() {
            Conclusion::Success
        } else {
            Conclusion::InfrastructureFailure
        }
    });
    Ok(JobResult {
        conclusion,
        exit_code,
        stdout,
        stderr,
    })
}

fn fill_job_response(
    response: &mut ExecutorResponse,
    result: &JobResult,
) -> Result<(), ProductionV2Error> {
    response.conclusion = Some(conclusion_name(result.conclusion).into());
    response.exit_code = Some(result.exit_code);
    response.running = Some(false);
    response.raw_stdout = Some(
        std::str::from_utf8(&result.stdout)
            .map_err(|_| ProductionV2Error::Closed)?
            .into(),
    );
    response.raw_stderr = Some(
        std::str::from_utf8(&result.stderr)
            .map_err(|_| ProductionV2Error::Closed)?
            .into(),
    );
    Ok(())
}

fn evidence_document_digest(
    execution_binding_digest: &str,
    conclusion: Conclusion,
    raw: &[u8],
) -> Result<[u8; 32], ProductionV2Error> {
    let binding = decode_hex::<32>(execution_binding_digest)?;
    let scrubbed = scrub(raw).map_err(|_| ProductionV2Error::Closed)?;
    let document = EvidenceDocument {
        schema_version: 1,
        execution_binding_digest: hex::encode(binding),
        conclusion: conclusion_name(conclusion).into(),
        output_sha256: hex::encode(Sha256::digest(&scrubbed)),
        output_length: scrubbed.len() as u32,
        output: String::from_utf8(scrubbed).map_err(|_| ProductionV2Error::Closed)?,
    };
    Ok(Sha256::digest(canonical_bytes(&document)?).into())
}

fn unix_seconds() -> Result<u64, ProductionV2Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ProductionV2Error::Closed)
}

fn verify_executor_seccomp_profile() -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(PHASE1_SECCOMP_PROFILE_PATH)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o7777 != 0o444
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > 1024 * 1024
    {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if hex::encode(digest.finalize()) != PHASE1_SECCOMP_PROFILE_DIGEST {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn executable_sha256() -> std::io::Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        // `/proc/self/exe` is a kernel-owned magic link to the already-open
        // executable image. Following this one link avoids reopening argv.
        .custom_flags(nix::libc::O_CLOEXEC)
        .open("/proc/self/exe")?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        os::unix::fs::{symlink, PermissionsExt},
    };

    fn valid_record() -> ExecutionBindingRecord {
        let mut binding = ExecutionBindingV1 {
            schema_version: EXECUTION_BINDING_SCHEMA_V1,
            lane_manifest_digest: [1; 32],
            lane_epoch: 1,
            job_intent_digest: [2; 32],
            admission_message_digest: [3; 32],
            signed_request_digest: [4; 32],
            actor_pubkey: [5; 32],
            idempotency_digest: [6; 32],
            run_id: [7; 16],
            attempt: 1,
            attempt_id: [8; 16],
            lease_id: [9; 16],
            lease_generation: 1,
            tip_oid: GitOid::Sha256([10; 32]),
            base_oid: GitOid::Sha256([11; 32]),
            admitted_at: 1,
            deadline_at: 2,
            execution_binding_digest: [0; 32],
            request_event_id: [12; 32],
            workflow_digest: [13; 32],
            workflow_id: WireText64::from_ascii("workflow").unwrap(),
            job_id: WireText64::from_ascii("job").unwrap(),
            artifact_count: 0,
            artifacts: [None],
        };
        binding.execution_binding_digest = binding.computed_digest();
        ExecutionBindingRecord {
            binding,
            phase: BindingPhase::Admitted,
            generation: 1,
            updated_at: 1,
            conclusion: Conclusion::None,
            host_receipt_digest: [0; 32],
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
        }
    }

    fn valid_intent() -> JobIntentV2 {
        JobIntentV2 {
            schema_version: 2,
            signed_request_digest: [4; 32],
            actor_pubkey: [5; 32],
            audience_digest: [6; 32],
            idempotency_digest: [7; 32],
            source_pin_event_id: [8; 32],
            workflow_digest: [9; 32],
            isolation_profile_digest: [10; 32],
            lane_manifest_digest: [11; 32],
            lane_epoch: 1,
            admission_signature_algorithm: AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
            admission_key_generation: 1,
            run_id: [12; 16],
            tip_oid: GitOid::Sha256([13; 32]),
            base_oid: GitOid::Sha256([14; 32]),
            issued_at: 1,
            expires_at: 100,
            wall_timeout_seconds: 30,
            attempt: 1,
            parent_attempt: 0,
            trust_class: buzz_ci_broker_protocol::TrustClass::AcceptedReviewed,
            request_event_id: [4; 32],
            workflow_id: WireText64::from_ascii("workflow").unwrap(),
            job_id: WireText64::from_ascii("job").unwrap(),
            artifact_count: 0,
            artifacts: [None],
        }
    }

    fn static_job_fixture(artifact: ArtifactDeclarationV1) -> StaticExecutionContract {
        let provenance = |path: &str, digest: &str, mode: u32| ProgramProvenance {
            path: path.into(),
            sha256: digest.into(),
            source_commit: "1".repeat(40),
            uid: Uid::effective().as_raw(),
            gid: Gid::effective().as_raw(),
            mode,
        };
        let mut contract = StaticExecutionContract {
            declaration_digest: [0; 32],
            candidate: GitOid::Sha256([10; 32]),
            activation_package_digest: [2; 32],
            lane_manifest_digest: [1; 32],
            isolation_profile_digest: [3; 32],
            workflow_id: wire_text("workflow").unwrap(),
            workflow_digest: [13; 32],
            job_id: wire_text("job").unwrap(),
            artifact,
            fixture_manifest: provenance(FIXTURE_MANIFEST_SOURCE, FIXTURE_MANIFEST_SHA256, 0o444),
            fixture_input: provenance(FIXTURE_INPUT_SOURCE, FIXTURE_INPUT_SHA256, 0o444),
            fixture_script: provenance(FIXTURE_SCRIPT_SOURCE, FIXTURE_SCRIPT_SHA256, 0o555),
            max_stdout_bytes: FIXED_MAX_STDOUT_BYTES,
            max_stderr_bytes: FIXED_MAX_STDERR_BYTES,
            max_memory_bytes: FIXED_MAX_MEMORY_BYTES,
            max_processes: FIXED_MAX_PROCESSES,
            max_wall_seconds: FIXED_MAX_WALL_SECONDS,
        };
        contract.declaration_digest = static_execution_digest(&contract);
        contract
    }

    fn no_artifact_fixture() -> ArtifactDeclarationV1 {
        ArtifactDeclarationV1 {
            artifact_id: wire_text("result").unwrap(),
            name: wire_text("result.json").unwrap(),
            media_type: wire_text("application/json").unwrap(),
            relative_name: wire_text("result.json").unwrap(),
            max_bytes: 32 * 1024,
        }
    }

    fn create_materialized_attempt(attempts: &Path, attempt_id: [u8; 16]) -> PathBuf {
        let attempt = attempts.join(hex::encode(attempt_id));
        let source = attempt
            .join(MATERIALIZED_SOURCE_ROOT)
            .join(FIXTURE_TREE.join("/"));
        let artifacts = attempt.join(MATERIALIZED_ARTIFACT_ROOT);
        fs::create_dir_all(&source).unwrap();
        fs::create_dir(&artifacts).unwrap();
        for (name, bytes, mode) in [
            (
                FIXTURE_MANIFEST_NAME,
                include_bytes!(
                    "../../../deploy/native-ci/acceptance/fixtures/fixture-manifest.json"
                )
                .as_slice(),
                0o400,
            ),
            (
                FIXTURE_INPUT_NAME,
                include_bytes!("../../../deploy/native-ci/acceptance/fixtures/input.txt")
                    .as_slice(),
                0o400,
            ),
            (
                FIXTURE_SCRIPT_NAME,
                include_bytes!("../../../deploy/native-ci/acceptance/fixtures/run-fixture.sh")
                    .as_slice(),
                0o500,
            ),
        ] {
            let path = source.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let mut directory = attempt.join(MATERIALIZED_SOURCE_ROOT);
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        for component in FIXTURE_TREE {
            directory = directory.join(component);
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        }
        fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&attempt, fs::Permissions::from_mode(0o500)).unwrap();
        attempt
    }

    fn executor_request_fixture(
        operation: &str,
        binding: [u8; 32],
        attempt_id: [u8; 16],
        deadline_at: u64,
    ) -> ExecutorRequest {
        ExecutorRequest {
            schema_version: RPC_SCHEMA,
            operation: operation.into(),
            execution_binding_digest: hex::encode(binding),
            attempt_id: hex::encode(attempt_id),
            job_intent_digest: None,
            static_execution_digest: hex::encode([6; 32]),
            fixture_manifest_sha256: FIXTURE_MANIFEST_SHA256.into(),
            fixture_input_sha256: FIXTURE_INPUT_SHA256.into(),
            fixture_script_sha256: FIXTURE_SCRIPT_SHA256.into(),
            deadline_at,
            max_stdout_bytes: FIXED_MAX_STDOUT_BYTES,
            max_stderr_bytes: FIXED_MAX_STDERR_BYTES,
            max_memory_bytes: FIXED_MAX_MEMORY_BYTES,
            max_processes: FIXED_MAX_PROCESSES,
            claimed_evidence_digest: None,
            phase: None,
            stop_reason: None,
            executor_program_sha256: hex::encode([9; 32]),
            seccomp_profile_path: PHASE1_SECCOMP_PROFILE_PATH.into(),
            seccomp_profile_sha256: PHASE1_SECCOMP_PROFILE_DIGEST.into(),
            seccomp_install_receipt_sha256: "11".repeat(32),
        }
    }

    fn valid_registration(
        intent: JobIntentV2,
        request_id: [u8; 16],
    ) -> (FrameHeader, RegisterJobIntentRequest) {
        let admission = buzz_ci_broker_protocol::v2::AdmitAttemptRequest {
            signed_request_digest: intent.signed_request_digest,
            actor_pubkey: intent.actor_pubkey,
            audience_digest: intent.audience_digest,
            idempotency_digest: intent.idempotency_digest,
            source_pin_event_id: intent.source_pin_event_id,
            workflow_digest: intent.workflow_digest,
            job_intent_digest: intent.digest(),
            isolation_profile_digest: intent.isolation_profile_digest,
            lane_manifest_digest: intent.lane_manifest_digest,
            admission_signature: [1; 64],
            run_id: intent.run_id,
            tip_oid: intent.tip_oid,
            base_oid: intent.base_oid,
            issued_at: intent.issued_at,
            expires_at: intent.expires_at,
            lane_epoch: intent.lane_epoch,
            admission_key_generation: intent.admission_key_generation,
            wall_timeout_seconds: intent.wall_timeout_seconds,
            attempt: intent.attempt,
            parent_attempt: intent.parent_attempt,
            trust_class: intent.trust_class,
            admission_signature_algorithm: intent.admission_signature_algorithm,
        };
        let header = FrameHeader {
            operation: buzz_ci_broker_protocol::Operation::RegisterJobIntent,
            request_id,
        };
        let mut request = crate::production_binding::registration_from_intent(admission, intent);
        request.request_frame_digest =
            intent_registration_request_frame_digest(header, &request).unwrap();
        (header, request)
    }

    #[test]
    fn scrub_is_bounded_and_removes_secret_shaped_lines() {
        assert_eq!(
            scrub(b"ok\nTOKEN=secret\ndone\n").unwrap(),
            b"ok\n[REDACTED]\ndone\n"
        );
        let hostile = b"safe\naws_secret_access_key = abc\nDb_Password: nope\nauthorization: Bearer abc\nAUTHORIZATION: basic Zm9v\n{\"private_key\":\"raw\"}\n{\"safe\":1,\"password\":\"jsonsecret\"}\n-----BEGIN PRIVATE KEY-----\nsecret pem bytes\n-----END PRIVATE KEY-----\nafter\n";
        let scrubbed = scrub(hostile).unwrap();
        assert_eq!(
            scrubbed,
            b"safe\n[REDACTED]\n[REDACTED]\n[REDACTED]\n[REDACTED]\n[REDACTED]\n[REDACTED]\n[REDACTED]\nafter\n"
        );
        let lower = String::from_utf8(scrubbed).unwrap().to_ascii_lowercase();
        for secret in [
            "abc",
            "nope",
            "bearer",
            "basic",
            "private_key",
            "jsonsecret",
            "pem bytes",
        ] {
            assert!(!lower.contains(secret), "secret escaped scrub: {secret}");
        }
        assert_eq!(
            scrub(b"before\n-----BEGIN RSA PRIVATE KEY-----\nunterminated\nraw\n").unwrap(),
            b"before\n[REDACTED]\n"
        );
        assert!(scrub(&vec![b'x'; MAX_RAW_OUTPUT + 1]).is_err());
    }

    #[test]
    fn declared_artifact_capture_is_exact_scrubbed_restartable_and_hostile_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let evidence_path = temporary.path().join("evidence");
        let teardown_path = temporary.path().join("teardown");
        let attempts_path = temporary.path().join("attempts");
        for (path, mode) in [
            (&evidence_path, 0o700),
            (&teardown_path, 0o700),
            (&attempts_path, 0o711),
        ] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let owner = fs::metadata(&evidence_path).unwrap().uid();
        let make_system = || LocalHostSystem {
            identity: HostIdentity {
                broker_build_identity: [1; 32],
                host_profile_digest: [2; 32],
                suite_identity: [3; 32],
            },
            socket: "/nonexistent".into(),
            executor_uid: owner,
            executor_gid: fs::metadata(&evidence_path).unwrap().gid(),
            executor: ProgramProvenance {
                path: "/nonexistent".into(),
                sha256: hex::encode([4; 32]),
                source_commit: "1".repeat(40),
                uid: owner,
                gid: 0,
                mode: 0o755,
            },
            seccomp: SeccompRuntimeBinding::fixture(),
            evidence: SafeDirectory::open(evidence_path.clone(), owner, 0o700).unwrap(),
            teardown: SafeDirectory::open(teardown_path.clone(), owner, 0o700).unwrap(),
            evidence_by_binding: BTreeMap::new(),
            attempts: SafeDirectory::open(attempts_path.clone(), owner, 0o711).unwrap(),
            job_uid: owner,
            job_gid: fs::metadata(&evidence_path).unwrap().gid(),
            static_job: static_job_fixture(no_artifact_fixture()),
        };

        let mut empty_binding = valid_record().binding;
        empty_binding.execution_binding_digest = empty_binding.computed_digest();
        assert!(make_system()
            .sealed_artifacts(empty_binding)
            .unwrap()
            .0
            .is_empty());

        let declaration = no_artifact_fixture();
        let mut binding = empty_binding;
        binding.artifact_count = 1;
        binding.artifacts = [Some(declaration)];
        binding.execution_binding_digest = binding.computed_digest();
        let attempt_path = create_materialized_attempt(&attempts_path, binding.attempt_id);
        let artifact_path = attempt_path
            .join(MATERIALIZED_ARTIFACT_ROOT)
            .join("result.json");
        fs::write(&artifact_path, b"ok\nTOKEN=secret\n").unwrap();
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o600)).unwrap();

        let captured = make_system().sealed_artifacts(binding).unwrap().0;
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].descriptor.kind, EvidenceKind::Artifact);
        assert_eq!(captured[0].descriptor.artifact_id, declaration.artifact_id);
        assert_eq!(captured[0].bytes, b"ok\n[REDACTED]\n");
        make_system().cleanup_attempt(binding).unwrap();
        assert_eq!(make_system().sealed_artifacts(binding).unwrap().0, captured);

        let mut maximum = binding;
        maximum.attempt_id = [54; 16];
        maximum.execution_binding_digest = maximum.computed_digest();
        let maximum_root = create_materialized_attempt(&attempts_path, maximum.attempt_id);
        let maximum_bytes = [vec![b'x'; 4095], vec![b'\n']].concat().repeat(8);
        assert_eq!(maximum_bytes.len(), 32 * 1024);
        let maximum_path = maximum_root
            .join(MATERIALIZED_ARTIFACT_ROOT)
            .join("result.json");
        fs::write(&maximum_path, &maximum_bytes).unwrap();
        fs::set_permissions(&maximum_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut maximum_system = make_system();
        let maximum_artifact = maximum_system.sealed_artifacts(maximum).unwrap().0;
        assert_eq!(maximum_artifact[0].bytes, maximum_bytes);
        let evidence_digest = maximum_system
            .write_evidence(
                maximum,
                Conclusion::Success,
                std::str::from_utf8(&maximum_bytes).unwrap(),
                None,
            )
            .unwrap();
        assert_eq!(
            maximum_system.existing_evidence(maximum).unwrap(),
            Some(evidence_digest)
        );
        maximum_system.cleanup_attempt(maximum).unwrap();

        let mut hostile = binding;
        hostile.attempt_id = [55; 16];
        hostile.execution_binding_digest = hostile.computed_digest();
        let hostile_root = create_materialized_attempt(&attempts_path, hostile.attempt_id);
        symlink(
            "../outside",
            hostile_root
                .join(MATERIALIZED_ARTIFACT_ROOT)
                .join("result.json"),
        )
        .unwrap();
        assert!(make_system().sealed_artifacts(hostile).is_err());

        let mut undeclared = binding;
        undeclared.attempt_id = [56; 16];
        undeclared.execution_binding_digest = undeclared.computed_digest();
        let undeclared_root = create_materialized_attempt(&attempts_path, undeclared.attempt_id);
        for name in ["result.json", "extra.txt"] {
            let path = undeclared_root.join(MATERIALIZED_ARTIFACT_ROOT).join(name);
            fs::write(&path, b"content\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(make_system().sealed_artifacts(undeclared).is_err());

        let mut hardlinked = binding;
        hardlinked.attempt_id = [57; 16];
        hardlinked.execution_binding_digest = hardlinked.computed_digest();
        let hardlink_root = create_materialized_attempt(&attempts_path, hardlinked.attempt_id);
        let outside = temporary.path().join("outside-artifact");
        fs::write(&outside, b"content\n").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(
            &outside,
            hardlink_root
                .join(MATERIALIZED_ARTIFACT_ROOT)
                .join("result.json"),
        )
        .unwrap();
        assert!(make_system().sealed_artifacts(hardlinked).is_err());
    }

    #[test]
    fn binding_document_rejects_digest_tampering() {
        let binding = ExecutionBindingV1 {
            schema_version: EXECUTION_BINDING_SCHEMA_V1,
            lane_manifest_digest: [1; 32],
            lane_epoch: 1,
            job_intent_digest: [2; 32],
            admission_message_digest: [3; 32],
            signed_request_digest: [4; 32],
            actor_pubkey: [5; 32],
            idempotency_digest: [6; 32],
            run_id: [7; 16],
            attempt: 1,
            attempt_id: [8; 16],
            lease_id: [9; 16],
            lease_generation: 1,
            tip_oid: GitOid::Sha256([10; 32]),
            base_oid: GitOid::Sha256([11; 32]),
            admitted_at: 1,
            deadline_at: 2,
            execution_binding_digest: [12; 32],
            request_event_id: [13; 32],
            workflow_digest: [14; 32],
            workflow_id: WireText64::from_ascii("workflow").unwrap(),
            job_id: WireText64::from_ascii("job").unwrap(),
            artifact_count: 0,
            artifacts: [None],
        };
        let record = ExecutionBindingRecord {
            binding,
            phase: BindingPhase::Admitted,
            generation: 1,
            updated_at: 1,
            conclusion: Conclusion::None,
            host_receipt_digest: [0; 32],
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
        };
        assert!(BindingDocument::from(record).into_record().is_err());
    }

    #[test]
    fn durable_binding_reopens_after_restart_and_rejects_tamper() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(temporary.path()).unwrap().uid();
        let record = valid_record();
        let root = SafeDirectory::open(temporary.path().to_owned(), owner, 0o700).unwrap();
        let mut journal = DurableBindingFiles { root };
        assert_eq!(journal.insert(record).unwrap(), JournalWrite::Written);
        drop(journal);

        let root = SafeDirectory::open(temporary.path().to_owned(), owner, 0o700).unwrap();
        let mut restarted = DurableBindingFiles { root };
        assert_eq!(
            restarted.load(record.binding.attempt_id).unwrap(),
            Some(record)
        );

        let mut running = record;
        running.phase = BindingPhase::Running;
        running.generation = 2;
        running.updated_at = 2;
        running.host_receipt_digest = [13; 32];
        assert_eq!(
            restarted.replace(1, running).unwrap(),
            JournalWrite::Written
        );
        assert_eq!(
            restarted.load(record.binding.attempt_id).unwrap(),
            Some(running)
        );

        let path = temporary
            .path()
            .join(DurableBindingFiles::name(record.binding.attempt_id));
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            restarted.load(record.binding.attempt_id),
            Err(BindingError::StorageUnavailable)
        );
    }

    #[test]
    fn intent_registry_is_mode_0400_create_once_restartable_and_tamper_closed() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(temporary.path()).unwrap().uid();
        let intent = valid_intent();
        let (header, request) = valid_registration(intent, [21; 16]);
        let key = intent_registration_key_digest_for_admission(request.admission);
        let root = SafeDirectory::open(temporary.path().to_owned(), owner, 0o700).unwrap();
        let mut registry = StaticIntentFiles { root };
        assert_eq!(
            registry.register(header, request, intent).unwrap(),
            IntentRegistrationWrite::Written
        );
        let path = temporary.path().join(format!("{}.json", hex::encode(key)));
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o400);
        assert_eq!(metadata.nlink(), 1);
        drop(registry);

        let root = SafeDirectory::open(temporary.path().to_owned(), owner, 0o700).unwrap();
        let mut restarted = StaticIntentFiles { root };
        assert_eq!(
            restarted.load(key, intent.digest()).unwrap(),
            RegisteredJobIntent {
                admission: request.admission,
                intent,
            }
        );
        assert_eq!(
            restarted.register(header, request, intent).unwrap(),
            IntentRegistrationWrite::Existing
        );

        let mut mismatch = intent;
        mismatch.job_id = WireText64::from_ascii("other-job").unwrap();
        let (mismatch_header, mismatch_request) = valid_registration(mismatch, [22; 16]);
        assert_eq!(
            restarted
                .register(mismatch_header, mismatch_request, mismatch)
                .unwrap(),
            IntentRegistrationWrite::Conflict
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            restarted.load(key, intent.digest()),
            Err(BindingError::StorageUnavailable)
        );
        assert_eq!(
            restarted.register(header, request, intent),
            Err(BindingError::StorageUnavailable)
        );
    }

    #[test]
    fn executor_partial_start_and_restart_recovery_are_fail_closed() {
        let binding = hex::encode([42; 32]);
        let request = |operation: &str| ExecutorRequest {
            schema_version: RPC_SCHEMA,
            operation: operation.into(),
            execution_binding_digest: binding.clone(),
            attempt_id: hex::encode([8; 16]),
            job_intent_digest: Some(hex::encode([7; 32])),
            static_execution_digest: hex::encode([6; 32]),
            fixture_manifest_sha256: FIXTURE_MANIFEST_SHA256.into(),
            fixture_input_sha256: FIXTURE_INPUT_SHA256.into(),
            fixture_script_sha256: FIXTURE_SCRIPT_SHA256.into(),
            deadline_at: 100,
            max_stdout_bytes: FIXED_MAX_STDOUT_BYTES,
            max_stderr_bytes: FIXED_MAX_STDERR_BYTES,
            max_memory_bytes: FIXED_MAX_MEMORY_BYTES,
            max_processes: FIXED_MAX_PROCESSES,
            claimed_evidence_digest: None,
            phase: None,
            stop_reason: None,
            executor_program_sha256: hex::encode([9; 32]),
            seccomp_profile_path: PHASE1_SECCOMP_PROFILE_PATH.into(),
            seccomp_profile_sha256: PHASE1_SECCOMP_PROFILE_DIGEST.into(),
            seccomp_install_receipt_sha256: "11".repeat(32),
        };
        let mut active = BTreeMap::new();
        executor_transition(
            request("executor_handoff"),
            &mut active,
            Path::new("/nonexistent"),
        )
        .unwrap();
        assert!(executor_transition(
            request("proxy_lease"),
            &mut active,
            Path::new("/nonexistent")
        )
        .is_err());
        let mut recovery = request("crash_recovery");
        recovery.job_intent_digest = None;
        recovery.phase = Some("admitted".into());
        recovery.stop_reason = Some("recovery".into());
        let response =
            executor_transition(recovery, &mut active, Path::new("/nonexistent")).unwrap();
        assert_eq!(response.capacity_returned, Some(true));
        assert!(active.is_empty());

        let mut wrong_path = request("executor_handoff");
        wrong_path.seccomp_profile_path = "/tmp/unconfined.json".into();
        assert!(
            executor_transition(wrong_path, &mut BTreeMap::new(), Path::new("/nonexistent"))
                .is_err()
        );
        let mut wrong_digest = request("executor_handoff");
        wrong_digest.seccomp_profile_sha256 = "22".repeat(32);
        assert!(executor_transition(
            wrong_digest,
            &mut BTreeMap::new(),
            Path::new("/nonexistent")
        )
        .is_err());
        let mut missing_receipt = request("executor_handoff");
        missing_receipt.seccomp_install_receipt_sha256 = "0".repeat(64);
        assert!(executor_transition(
            missing_receipt,
            &mut BTreeMap::new(),
            Path::new("/nonexistent")
        )
        .is_err());
    }

    #[test]
    fn fixed_executor_runs_frozen_fixture_and_returns_exact_bounded_outputs() {
        let temporary = tempfile::tempdir().unwrap();
        let attempts = temporary.path().join("attempts");
        let evidence = temporary.path().join("evidence");
        let teardown_root = temporary.path().join("teardown");
        let package = temporary.path().join("package");
        fs::create_dir(&attempts).unwrap();
        fs::create_dir(&evidence).unwrap();
        fs::create_dir(&teardown_root).unwrap();
        fs::create_dir(&package).unwrap();
        fs::set_permissions(&attempts, fs::Permissions::from_mode(0o711)).unwrap();
        for path in [&evidence, &teardown_root] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let sources = [
            (
                FIXTURE_MANIFEST_NAME,
                include_bytes!(
                    "../../../deploy/native-ci/acceptance/fixtures/fixture-manifest.json"
                )
                .as_slice(),
                0o444,
                FIXTURE_MANIFEST_SHA256,
            ),
            (
                FIXTURE_INPUT_NAME,
                include_bytes!("../../../deploy/native-ci/acceptance/fixtures/input.txt")
                    .as_slice(),
                0o444,
                FIXTURE_INPUT_SHA256,
            ),
            (
                FIXTURE_SCRIPT_NAME,
                include_bytes!("../../../deploy/native-ci/acceptance/fixtures/run-fixture.sh")
                    .as_slice(),
                0o555,
                FIXTURE_SCRIPT_SHA256,
            ),
        ];
        for (name, bytes, mode, _) in sources {
            let path = package.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let owner = Uid::effective().as_raw();
        let group = Gid::effective().as_raw();
        let artifact_declaration = no_artifact_fixture();
        let mut static_job = static_job_fixture(artifact_declaration);
        for (program, name, mode, digest) in [
            (
                &mut static_job.fixture_manifest,
                FIXTURE_MANIFEST_NAME,
                0o444,
                FIXTURE_MANIFEST_SHA256,
            ),
            (
                &mut static_job.fixture_input,
                FIXTURE_INPUT_NAME,
                0o444,
                FIXTURE_INPUT_SHA256,
            ),
            (
                &mut static_job.fixture_script,
                FIXTURE_SCRIPT_NAME,
                0o555,
                FIXTURE_SCRIPT_SHA256,
            ),
        ] {
            *program = ProgramProvenance {
                path: package.join(name).to_string_lossy().into_owned(),
                sha256: digest.into(),
                source_commit: "1".repeat(40),
                uid: owner,
                gid: group,
                mode,
            };
        }
        static_job.declaration_digest = static_execution_digest(&static_job);
        let static_execution_digest = static_job.declaration_digest;
        let mut intent = valid_intent();
        intent.tip_oid = static_job.candidate;
        intent.base_oid = static_job.candidate;
        intent.lane_manifest_digest = static_job.lane_manifest_digest;
        intent.isolation_profile_digest = static_job.isolation_profile_digest;
        intent.workflow_digest = static_job.workflow_digest;
        intent.workflow_id = static_job.workflow_id;
        intent.job_id = static_job.job_id;
        intent.artifact_count = 1;
        intent.artifacts = [Some(artifact_declaration)];
        let mut binding_record = valid_record();
        binding_record.binding.job_intent_digest = intent.digest();
        binding_record.binding.tip_oid = static_job.candidate;
        binding_record.binding.base_oid = static_job.candidate;
        binding_record.binding.lane_manifest_digest = static_job.lane_manifest_digest;
        binding_record.binding.workflow_digest = static_job.workflow_digest;
        binding_record.binding.workflow_id = static_job.workflow_id;
        binding_record.binding.job_id = static_job.job_id;
        binding_record.binding.artifact_count = 1;
        binding_record.binding.artifacts = [Some(artifact_declaration)];
        binding_record.binding.execution_binding_digest = binding_record.binding.computed_digest();
        let binding = binding_record.binding;
        let attempt_id = binding.attempt_id;
        let mut system = LocalHostSystem {
            identity: HostIdentity {
                broker_build_identity: [1; 32],
                host_profile_digest: [2; 32],
                suite_identity: [3; 32],
            },
            socket: temporary.path().join("unused.sock"),
            executor_uid: owner,
            executor_gid: group,
            executor: static_job.fixture_script.clone(),
            seccomp: SeccompRuntimeBinding::fixture(),
            evidence: SafeDirectory::open(evidence, owner, 0o700).unwrap(),
            teardown: SafeDirectory::open(teardown_root, owner, 0o700).unwrap(),
            evidence_by_binding: BTreeMap::new(),
            attempts: SafeDirectory::open(attempts.clone(), owner, 0o711).unwrap(),
            job_uid: owner,
            job_gid: group,
            static_job,
        };
        let materialization_receipt = system.materialize(binding, intent).unwrap();
        assert_ne!(materialization_receipt, [0; 32]);
        let deadline = unix_seconds().unwrap() + 10;
        let request = |operation: &str| {
            let mut request = executor_request_fixture(
                operation,
                binding.execution_binding_digest,
                attempt_id,
                deadline,
            );
            request.static_execution_digest = hex::encode(static_execution_digest);
            request
        };
        let mut active = BTreeMap::new();
        let mut handoff = request("executor_handoff");
        handoff.job_intent_digest = Some(hex::encode(binding.job_intent_digest));
        executor_transition(handoff, &mut active, &attempts).unwrap();
        executor_transition(request("runtime_descriptor"), &mut active, &attempts).unwrap();
        let mut materialized = request("materialization");
        materialized.job_intent_digest = Some(hex::encode(binding.job_intent_digest));
        executor_transition(materialized, &mut active, &attempts).unwrap();
        executor_transition(request("proxy_lease"), &mut active, &attempts).unwrap();

        let response = loop {
            let response =
                executor_transition(request("terminal_evidence"), &mut active, &attempts).unwrap();
            if response.running != Some(true) {
                break response;
            }
            thread::sleep(Duration::from_millis(10));
        };
        let expected_log = b"fixture=buzz-ci-capacity-one-v1 input_sha256=967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6 artifact=result.json\n";
        let expected_artifact = b"{\"fixture_version\":\"v1\",\"input_sha256\":\"967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6\"}\n";
        assert_eq!(response.conclusion.as_deref(), Some("success"));
        assert_eq!(response.exit_code, Some(0));
        assert_eq!(
            response.raw_stdout.as_deref(),
            std::str::from_utf8(expected_log).ok()
        );
        assert_eq!(response.raw_stderr.as_deref(), Some(""));
        assert_eq!(
            hex::encode(Sha256::digest(expected_log)),
            "54e15345b0e920fd0b3c3864422c336f4f66f023b5b2a9cf7874c8a6fe2984ff"
        );
        let artifact = attempts
            .join(hex::encode(attempt_id))
            .join(MATERIALIZED_ARTIFACT_ROOT)
            .join("result.json");
        assert_eq!(fs::read(&artifact).unwrap(), expected_artifact);
        assert_eq!(
            hex::encode(Sha256::digest(expected_artifact)),
            "fde27be36048dd6a5bdc9961882391f46102d86dac76c106787dba9ff7551d66"
        );
        let mut teardown = request("teardown");
        teardown.stop_reason = Some("completed".into());
        let teardown = executor_transition(teardown, &mut active, &attempts).unwrap();
        assert_eq!(teardown.conclusion.as_deref(), Some("success"));
        assert!(active.is_empty());
        let (artifacts, artifact_set_digest) = system.sealed_artifacts(binding).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].bytes, expected_artifact);
        let terminal = system
            .persist_teardown(
                binding,
                HostStopReason::Completed,
                teardown,
                Some(artifact_set_digest),
            )
            .unwrap();
        assert_eq!(terminal.conclusion, Conclusion::Success);
        assert!(!attempts.join(hex::encode(attempt_id)).exists());

        let hostile_attempt = [9; 16];
        let hostile = create_materialized_attempt(&attempts, hostile_attempt);
        fs::set_permissions(
            hostile
                .join(MATERIALIZED_SOURCE_ROOT)
                .join(FIXTURE_TREE.join("/")),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::remove_file(
            hostile
                .join(MATERIALIZED_SOURCE_ROOT)
                .join(FIXTURE_TREE.join("/"))
                .join(FIXTURE_INPUT_NAME),
        )
        .unwrap();
        symlink(
            "/etc/passwd",
            hostile
                .join(MATERIALIZED_SOURCE_ROOT)
                .join(FIXTURE_TREE.join("/"))
                .join(FIXTURE_INPUT_NAME),
        )
        .unwrap();
        let hostile_request =
            executor_request_fixture("materialization", [43; 32], hostile_attempt, deadline);
        assert!(verify_executor_attempt(&attempts, &hostile_request, false).is_err());
        let mut wrong_limit =
            executor_request_fixture("executor_handoff", [44; 32], [10; 16], deadline);
        wrong_limit.max_processes += 1;
        assert!(executor_transition(wrong_limit, &mut BTreeMap::new(), &attempts).is_err());
    }

    #[test]
    fn cancellation_and_restart_reconciliation_kill_the_live_process_group() {
        fn live_process() -> RunningJob {
            let mut child = Command::new("/bin/sh")
                .args(["-c", "sleep 30 & wait"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            RunningJob {
                child,
                stdout: capture_pipe(stdout, FIXED_MAX_STDOUT_BYTES as usize),
                stderr: capture_pipe(stderr, FIXED_MAX_STDERR_BYTES as usize),
            }
        }
        let deadline = unix_seconds().unwrap() + 60;
        for (binding, operation, reason, expected) in [
            ([51; 32], "teardown", "cancelled", "cancelled"),
            (
                [52; 32],
                "crash_recovery",
                "recovery",
                "infrastructure_failure",
            ),
        ] {
            let request = executor_request_fixture(operation, binding, [12; 16], deadline);
            let contract = ExecutorBinding::from_request(&request, &hex::encode([7; 32])).unwrap();
            let mut active = BTreeMap::from([(
                hex::encode(binding),
                ExecutorLease {
                    stage: ExecutorStage::Running,
                    contract,
                    process: Some(live_process()),
                    result: None,
                },
            )]);
            let mut stop = request;
            stop.stop_reason = Some(reason.into());
            let response =
                executor_transition(stop, &mut active, Path::new("/nonexistent")).unwrap();
            assert_eq!(response.conclusion.as_deref(), Some(expected));
            if operation == "crash_recovery" {
                assert_eq!(response.capacity_returned, Some(true));
            }
            assert!(active.is_empty());
        }

        let synthetic = executor_request_fixture("crash_recovery", [53; 32], [13; 16], deadline);
        let response =
            executor_transition(synthetic, &mut BTreeMap::new(), Path::new("/nonexistent"))
                .unwrap();
        assert_eq!(response.capacity_returned, Some(true));
        assert_eq!(
            response.conclusion.as_deref(),
            Some("infrastructure_failure")
        );
    }

    #[test]
    fn privilege_dropped_job_traverses_only_frozen_attempt_and_seccomp_paths() {
        const ROOT_HELPER: &str = "BUZZ_EXECD_DAC_ROOT_HELPER";
        const TEST_ROOT: &str = "BUZZ_EXECD_DAC_TEST_ROOT";
        const TEST_NAME: &str =
            "production_v2::tests::privilege_dropped_job_traverses_only_frozen_attempt_and_seccomp_paths";

        if std::env::var_os(ROOT_HELPER).is_some() {
            let temporary = tempfile::Builder::new()
                .prefix("buzz-execd-dac-")
                .tempdir_in("/tmp")
                .unwrap();
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o711)).unwrap();
            let buzzci = temporary.path().join("var/lib/buzzci");
            let execd = buzzci.join("execd-v2");
            let attempts = execd.join("attempts");
            let intents = execd.join("intents");
            let seccomp_root = buzzci.join("seccomp");
            let seccomp_v1 = seccomp_root.join("v1");
            let seccomp = seccomp_v1.join("sha256");
            fs::create_dir_all(&attempts).unwrap();
            fs::create_dir(&intents).unwrap();
            fs::create_dir_all(&seccomp).unwrap();
            for path in [
                temporary.path().join("var"),
                temporary.path().join("var/lib"),
            ] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
            for path in [
                buzzci.as_path(),
                execd.as_path(),
                attempts.as_path(),
                seccomp_root.as_path(),
                seccomp_v1.as_path(),
                seccomp.as_path(),
            ] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o711)).unwrap();
            }
            fs::set_permissions(&intents, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(intents.join("private.json"), b"private\n").unwrap();
            fs::set_permissions(
                intents.join("private.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            fs::write(seccomp.join("profile.json"), b"pinned profile\n").unwrap();
            fs::set_permissions(
                seccomp.join("profile.json"),
                fs::Permissions::from_mode(0o444),
            )
            .unwrap();
            let attempt = create_materialized_attempt(&attempts, [77; 16]);
            fn assign_job(path: &Path) {
                if path.is_dir() {
                    for entry in fs::read_dir(path).unwrap() {
                        assign_job(&entry.unwrap().path());
                    }
                }
                nix::unistd::chown(path, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000)))
                    .unwrap();
            }
            assign_job(&attempt);
            let output = Command::new("/bin/sh")
                .arg("-c")
                .arg(
                    "set -eu\n\
                     if ls \"$BUZZ_EXECD_DAC_TEST_ROOT/var/lib/buzzci\" >/dev/null 2>&1; then exit 31; fi\n\
                     if ls \"$BUZZ_EXECD_DAC_TEST_ROOT/var/lib/buzzci/execd-v2\" >/dev/null 2>&1; then exit 32; fi\n\
                     if ls \"$BUZZ_EXECD_DAC_TEST_ROOT/var/lib/buzzci/seccomp\" >/dev/null 2>&1; then exit 33; fi\n\
                     if cat \"$BUZZ_EXECD_DAC_TEST_ROOT/var/lib/buzzci/execd-v2/intents/private.json\" >/dev/null 2>&1; then exit 34; fi\n\
                     test \"$(cat \"$BUZZ_EXECD_DAC_TEST_ROOT/var/lib/buzzci/seccomp/v1/sha256/profile.json\")\" = \"pinned profile\"\n\
                     cd \"$BUZZ_EXECD_DAC_TEST_ROOT/var/lib/buzzci/execd-v2/attempts/4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d\"\n\
                     exec source/deploy/native-ci/acceptance/fixtures/run-fixture.sh artifacts",
                )
                .env(TEST_ROOT, temporary.path())
                .uid(1000)
                .gid(1000)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                output.stdout,
                b"fixture=buzz-ci-capacity-one-v1 input_sha256=967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6 artifact=result.json\n"
            );
            assert_eq!(
                fs::read(attempt.join("artifacts/result.json")).unwrap(),
                b"{\"fixture_version\":\"v1\",\"input_sha256\":\"967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6\"}\n"
            );
            return;
        }

        let output = Command::new("unshare")
            .arg("--map-root-user")
            .arg("--map-auto")
            .arg(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(ROOT_HELPER, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn static_execution_digest_matches_activation_package_vector() {
        let manifest = LaneActivationManifestV1 {
            schema_version: 1,
            lane_id: [0x10; 32],
            lane_epoch: 4,
            admission_signature_algorithm: AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
            admission_verifying_key: [0x20; 32],
            admission_key_generation: 9,
            broker_build_identity: [0x30; 32],
            host_profile_digest: [0x40; 32],
            suite_identity: [0x50; 32],
            isolation_profile_digest: [0x60; 32],
            not_before: 1,
            expires_at: 4_102_444_800,
            max_wall_timeout_seconds: 300,
        };
        let mut execution = static_job_fixture(no_artifact_fixture());
        execution.candidate = GitOid::Sha1([0xaa; 20]);
        execution.activation_package_digest = [0x70; 32];
        execution.lane_manifest_digest = manifest.digest();
        execution.isolation_profile_digest = manifest.isolation_profile_digest;
        execution.workflow_id = wire_text("capacity-one").unwrap();
        execution.workflow_digest = [0x80; 32];
        execution.job_id = wire_text("capacity-one-fixture").unwrap();
        assert_eq!(
            hex::encode(manifest.digest()),
            "12ede37672233a144707bc49efa5d8f86ec5803e6b9d623347472702b2c98f04"
        );
        assert_eq!(
            hex::encode(static_execution_digest(&execution)),
            "a0c535305d1e1f370c39aaaa077f0a01f88993d76fb743892d5d161e8411f438"
        );
    }

    #[test]
    fn create_once_evidence_refuses_prior_claim_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(temporary.path()).unwrap().uid();
        let root = SafeDirectory::open(temporary.path().to_owned(), owner, 0o700).unwrap();
        root.write_once("claim.json", b"first", 0o600).unwrap();
        assert!(root.write_once("claim.json", b"second", 0o600).is_err());
        assert_eq!(
            root.read("claim.json", 0o600, MAX_RECORD).unwrap(),
            b"first"
        );
    }

    #[test]
    fn restart_reopens_exact_scrubbed_evidence_and_rejects_tamper() {
        let temporary = tempfile::tempdir().unwrap();
        let evidence_path = temporary.path().join("evidence");
        let teardown_path = temporary.path().join("teardown");
        let attempts_path = temporary.path().join("attempts");
        fs::create_dir(&evidence_path).unwrap();
        fs::create_dir(&teardown_path).unwrap();
        fs::create_dir(&attempts_path).unwrap();
        fs::set_permissions(&evidence_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&teardown_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&attempts_path, fs::Permissions::from_mode(0o711)).unwrap();
        let owner = fs::metadata(&evidence_path).unwrap().uid();
        let make_system = || LocalHostSystem {
            identity: HostIdentity {
                broker_build_identity: [1; 32],
                host_profile_digest: [2; 32],
                suite_identity: [3; 32],
            },
            socket: "/nonexistent".into(),
            executor_uid: owner,
            executor_gid: fs::metadata(&evidence_path).unwrap().gid(),
            executor: ProgramProvenance {
                path: "/nonexistent".into(),
                sha256: hex::encode([4; 32]),
                source_commit: "1".repeat(40),
                uid: owner,
                gid: 0,
                mode: 0o755,
            },
            seccomp: SeccompRuntimeBinding::fixture(),
            evidence: SafeDirectory::open(evidence_path.clone(), owner, 0o700).unwrap(),
            teardown: SafeDirectory::open(teardown_path.clone(), owner, 0o700).unwrap(),
            evidence_by_binding: BTreeMap::new(),
            attempts: SafeDirectory::open(attempts_path.clone(), owner, 0o711).unwrap(),
            job_uid: owner,
            job_gid: fs::metadata(&evidence_path).unwrap().gid(),
            static_job: static_job_fixture(no_artifact_fixture()),
        };
        let binding = valid_record().binding;
        let mut first = make_system();
        let digest = first
            .write_evidence(binding, Conclusion::Success, "ok\n", None)
            .unwrap();
        let teardown = TeardownDocument {
            schema_version: 1,
            execution_binding_digest: hex::encode(binding.execution_binding_digest),
            evidence_set_digest: hex::encode(digest),
            stop_reason: "completed".into(),
            executor_receipt_digest: hex::encode([15; 32]),
            request_event_id: hex::encode(binding.request_event_id),
            run_id: hex::encode(binding.run_id),
            workflow_id: binding.workflow_id.as_str().unwrap().into(),
            workflow_digest: hex::encode(binding.workflow_digest),
            job_id: binding.job_id.as_str().unwrap().into(),
            attempt: binding.attempt,
            lease_id: hex::encode(binding.lease_id),
            lease_generation: binding.lease_generation,
            artifact_receipt_set_digest: hex::encode(first.sealed_artifacts(binding).unwrap().1),
        };
        first
            .teardown
            .write_once(
                &format!("{}.json", hex::encode(binding.attempt_id)),
                &canonical_bytes(&teardown).unwrap(),
                0o600,
            )
            .unwrap();
        let reopened_teardown: TeardownDocument = canonical_parse(
            &first
                .teardown
                .read(
                    &format!("{}.json", hex::encode(binding.attempt_id)),
                    0o600,
                    MAX_RECORD,
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened_teardown.request_event_id,
            hex::encode(binding.request_event_id)
        );
        assert_eq!(reopened_teardown.run_id, hex::encode(binding.run_id));
        assert_eq!(
            reopened_teardown.workflow_id,
            binding.workflow_id.as_str().unwrap()
        );
        assert_eq!(
            reopened_teardown.workflow_digest,
            hex::encode(binding.workflow_digest)
        );
        assert_eq!(reopened_teardown.job_id, binding.job_id.as_str().unwrap());
        assert_eq!(reopened_teardown.attempt, binding.attempt);
        assert_eq!(reopened_teardown.lease_id, hex::encode(binding.lease_id));
        assert_eq!(reopened_teardown.lease_generation, binding.lease_generation);
        drop(first);

        let mut restarted = make_system();
        assert_eq!(restarted.existing_evidence(binding).unwrap(), Some(digest));
        let exported = restarted.sealed_attempt_evidence(binding).unwrap();
        assert_eq!(exported.len(), 2);
        assert_eq!(exported[0].descriptor.digest, digest);
        assert_eq!(exported[1].descriptor.teardown_lease_id, binding.lease_id);

        let path = evidence_path.join(format!("{}.json", hex::encode(binding.attempt_id)));
        let mut bytes = fs::read(&path).unwrap();
        let index = bytes.len() - 2;
        bytes[index] ^= 1;
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut tampered = make_system();
        assert!(tampered.existing_evidence(binding).is_err());
        assert!(tampered.sealed_attempt_evidence(binding).is_err());
    }

    #[test]
    fn exact_fake_root_capacity_one_config_selects_v2() {
        let temporary = tempfile::tempdir().unwrap();
        let prefix = temporary.path();
        for relative in [
            "etc/buzzci",
            "var/lib/buzzci/execd-v2/intents",
            "var/lib/buzzci/execd-v2/bindings",
            "var/lib/buzzci/execd-v2/evidence",
            "var/lib/buzzci/execd-v2/teardown",
            "var/lib/buzzci/execd-v2/attempts",
            "var/lib/buzzci/execd-v2/qualification",
            "usr/libexec",
            "usr/share/buzzci/execd-v2/fixture",
            "run/buzzci",
        ] {
            let path = prefix.join(relative);
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::set_permissions(prefix.join("etc/buzzci"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            prefix.join("var/lib/buzzci"),
            fs::Permissions::from_mode(0o711),
        )
        .unwrap();
        fs::set_permissions(
            prefix.join("var/lib/buzzci/execd-v2"),
            fs::Permissions::from_mode(0o711),
        )
        .unwrap();
        fs::set_permissions(
            prefix.join("var/lib/buzzci/execd-v2/attempts"),
            fs::Permissions::from_mode(0o711),
        )
        .unwrap();
        let owner = fs::metadata(prefix).unwrap().uid();
        let group = fs::metadata(prefix).unwrap().gid();
        let program_path = prefix.join("usr/libexec/buzz-ci-executor");
        fs::write(&program_path, b"fixed executor fixture\n").unwrap();
        fs::set_permissions(&program_path, fs::Permissions::from_mode(0o755)).unwrap();
        let program_sha256 = hex::encode(Sha256::digest(fs::read(&program_path).unwrap()));
        for (relative, bytes, mode) in [
            (
                "usr/share/buzzci/execd-v2/fixture/fixture-manifest.json",
                include_bytes!(
                    "../../../deploy/native-ci/acceptance/fixtures/fixture-manifest.json"
                )
                .as_slice(),
                0o444,
            ),
            (
                "usr/share/buzzci/execd-v2/fixture/input.txt",
                include_bytes!("../../../deploy/native-ci/acceptance/fixtures/input.txt")
                    .as_slice(),
                0o444,
            ),
            (
                "usr/libexec/buzz-ci-capacity-one-fixture",
                include_bytes!("../../../deploy/native-ci/acceptance/fixtures/run-fixture.sh")
                    .as_slice(),
                0o555,
            ),
        ] {
            let path = prefix.join(relative);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let manifest_document = ManifestDocument {
            schema_version: 1,
            lane_id: hex::encode([1; 32]),
            lane_epoch: 1,
            admission_verifying_key: hex::encode([2; 32]),
            admission_key_generation: 1,
            broker_build_identity: hex::encode([3; 32]),
            host_profile_digest: hex::encode([4; 32]),
            suite_identity: hex::encode([5; 32]),
            isolation_profile_digest: hex::encode([6; 32]),
            not_before: 1,
            expires_at: 100,
            max_wall_timeout_seconds: 30,
        };
        let manifest_digest =
            hex::encode(manifest_document.clone().into_manifest().unwrap().digest());
        let mut config = ProductionConfig {
            schema_version: CONFIG_SCHEMA,
            enabled_protocol: 2,
            capacity: 1,
            identities: IdentityConfig {
                execd_uid: owner,
                execd_gid: group,
                runner_uid: owner + 1,
                runner_gid: group + 1,
                control_uid: CONTROL_UID,
                control_gid: CONTROL_GID,
                control_user: CONTROL_USER.into(),
                control_group: CONTROL_GROUP.into(),
                control_home: CONTROL_HOME.into(),
                control_shell: "/usr/sbin/nologin".into(),
                control_supplementary_groups: vec![ACCESS_GROUP.into()],
                job_uid: owner + 3,
                job_gid: group + 3,
                access_group: ACCESS_GROUP.into(),
                access_group_gid: group + 4,
                access_group_members: vec!["buzzci-ctl".into(), "buzzci-runner".into()],
            },
            paths: PathConfig {
                intent_root: INTENT_ROOT.into(),
                binding_root: BINDING_ROOT.into(),
                evidence_root: EVIDENCE_ROOT.into(),
                teardown_root: TEARDOWN_ROOT.into(),
                executor_socket: EXECUTOR_SOCKET.into(),
                attempt_root: ATTEMPT_ROOT.into(),
                qualification_root: QUALIFICATION_ROOT.into(),
            },
            lane_manifest: manifest_document,
            lane_manifest_digest: manifest_digest,
            executor: ProgramProvenance {
                path: EXECUTOR_PROGRAM.into(),
                sha256: program_sha256,
                source_commit: "1".repeat(40),
                uid: owner,
                gid: group,
                mode: 0o755,
            },
            execution: StaticExecutionConfig {
                schema_version: STATIC_EXECUTION_SCHEMA,
                declaration_digest: "0".repeat(64),
                workflow_id: "capacity-one".into(),
                workflow_digest: "88".repeat(32),
                job_id: "capacity-one-fixture".into(),
                artifact: ArtifactDocument {
                    artifact_id: "result".into(),
                    name: "result.json".into(),
                    media_type: "application/json".into(),
                    relative_name: "result.json".into(),
                    max_bytes: 32 * 1024,
                },
                fixture_manifest_sha256: FIXTURE_MANIFEST_SHA256.into(),
                fixture_input_sha256: FIXTURE_INPUT_SHA256.into(),
                fixture_script_sha256: FIXTURE_SCRIPT_SHA256.into(),
                max_stdout_bytes: FIXED_MAX_STDOUT_BYTES,
                max_stderr_bytes: FIXED_MAX_STDERR_BYTES,
                max_memory_bytes: FIXED_MAX_MEMORY_BYTES,
                max_processes: FIXED_MAX_PROCESSES,
                max_wall_seconds: FIXED_MAX_WALL_SECONDS,
            },
            qualification: QualificationConfig {
                integrated_candidate_sha: "1".repeat(40),
                activation_package_digest: "22".repeat(32),
                fixture_digest: "33".repeat(32),
                controller_generation: 1,
                runner_generation: 1,
            },
        };
        let mut static_contract = static_job_fixture(no_artifact_fixture());
        static_contract.candidate = GitOid::Sha1([0x11; 20]);
        static_contract.activation_package_digest = [0x22; 32];
        static_contract.lane_manifest_digest = decode_hex(&config.lane_manifest_digest).unwrap();
        static_contract.isolation_profile_digest = [6; 32];
        static_contract.workflow_id = wire_text("capacity-one").unwrap();
        static_contract.workflow_digest = [0x88; 32];
        static_contract.job_id = wire_text("capacity-one-fixture").unwrap();
        static_contract.fixture_manifest = mapped_program(
            &ProgramProvenance {
                path: FIXTURE_MANIFEST_SOURCE.into(),
                sha256: FIXTURE_MANIFEST_SHA256.into(),
                source_commit: "1".repeat(40),
                uid: owner,
                gid: group,
                mode: 0o444,
            },
            &RuntimePaths {
                prefix: prefix.to_owned(),
            },
        )
        .unwrap();
        static_contract.fixture_input = mapped_program(
            &ProgramProvenance {
                path: FIXTURE_INPUT_SOURCE.into(),
                sha256: FIXTURE_INPUT_SHA256.into(),
                source_commit: "1".repeat(40),
                uid: owner,
                gid: group,
                mode: 0o444,
            },
            &RuntimePaths {
                prefix: prefix.to_owned(),
            },
        )
        .unwrap();
        static_contract.fixture_script = mapped_program(
            &ProgramProvenance {
                path: FIXTURE_SCRIPT_SOURCE.into(),
                sha256: FIXTURE_SCRIPT_SHA256.into(),
                source_commit: "1".repeat(40),
                uid: owner,
                gid: group,
                mode: 0o555,
            },
            &RuntimePaths {
                prefix: prefix.to_owned(),
            },
        )
        .unwrap();
        config.execution.declaration_digest =
            hex::encode(static_execution_digest(&static_contract));
        let config_path = prefix.join("etc/buzzci/execd-v2.json");
        fs::write(&config_path, canonical_bytes(&config).unwrap()).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        let passwd_path = prefix.join("etc/passwd");
        let passwd = format!(
            "buzzci-runner:x:{}:{}::/var/lib/buzzci/runner:/usr/sbin/nologin\nbuzzci-ctl:x:{}:{}::{CONTROL_HOME}:/usr/sbin/nologin\nbuzzci-job:x:{}:{}::/var/empty:/usr/sbin/nologin\n",
            owner + 1,
            group + 1,
            CONTROL_UID,
            CONTROL_GID,
            owner + 3,
            group + 3,
        );
        fs::write(&passwd_path, &passwd).unwrap();
        fs::write(
            prefix.join("etc/group"),
            format!(
                "buzzci-execd:x:{}:buzzci-ctl,buzzci-runner\nbuzzci-ctl:x:{}:\n",
                group + 4,
                CONTROL_GID
            ),
        )
        .unwrap();

        let activated = Cell::new(false);
        assert!(load_from(
            RuntimePaths {
                prefix: prefix.to_owned(),
            },
            owner,
            2,
            true,
            || {
                activated.set(true);
                Ok(SeccompRuntimeBinding::fixture())
            },
        )
        .is_ok());
        assert!(activated.get());

        fs::write(
            &passwd_path,
            passwd.replace(CONTROL_HOME, "/var/lib/buzzci/ctl"),
        )
        .unwrap();
        let drift_activation = Cell::new(false);
        assert!(load_from(
            RuntimePaths {
                prefix: prefix.to_owned(),
            },
            owner,
            2,
            true,
            || {
                drift_activation.set(true);
                Ok(SeccompRuntimeBinding::fixture())
            },
        )
        .is_err());
        assert!(!drift_activation.get());
        fs::write(&passwd_path, &passwd).unwrap();

        let mut capacity_zero = config.clone();
        capacity_zero.capacity = 0;
        fs::write(&config_path, canonical_bytes(&capacity_zero).unwrap()).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut runtime = load_from(
            RuntimePaths {
                prefix: prefix.to_owned(),
            },
            owner,
            2,
            false,
            || Ok(SeccompRuntimeBinding::fixture()),
        )
        .unwrap();
        let header = FrameHeader {
            operation: buzz_ci_broker_protocol::Operation::AdmitQualification,
            request_id: [9; 16],
        };
        let seccomp = SeccompRuntimeBinding::fixture();
        let mut qualification = ProductionQualificationRequest {
            integrated_candidate_sha: GitOid::Sha1([0x11; 20]),
            activation_package_digest: [0x22; 32],
            fixture_digest: [0x33; 32],
            principal_digest: production_qualification_principal_digest(
                CONTROL_USER,
                CONTROL_GROUP,
                CONTROL_UID,
                CONTROL_GID,
                CONTROL_HOME,
                "/usr/sbin/nologin",
                &[ACCESS_GROUP.into()],
            )
            .unwrap(),
            lane_manifest_digest: decode_hex(&capacity_zero.lane_manifest_digest).unwrap(),
            broker_build_identity: [3; 32],
            host_profile_digest: [4; 32],
            suite_identity: [5; 32],
            isolation_profile_digest: [6; 32],
            seccomp_profile_digest: decode_hex(&seccomp.profile_digest).unwrap(),
            executor_program_digest: decode_hex(&capacity_zero.executor.sha256).unwrap(),
            executor_provenance_digest: production_qualification_executor_provenance_digest(
                EXECUTOR_PROGRAM,
                decode_hex(&capacity_zero.executor.sha256).unwrap(),
                GitOid::Sha1([0x11; 20]),
                owner,
                group,
                0o755,
            )
            .unwrap(),
            nonce: [7; 32],
            controller_generation: 1,
            runner_generation: 1,
            lane_epoch: 1,
            admission_key_generation: 1,
            issued_at: 1,
            expires_at: 60,
            request_frame_digest: [0; 32],
        };
        qualification.request_frame_digest =
            production_qualification_request_frame_digest(header, &qualification).unwrap();
        let first = runtime.dispatch.dispatch_v2_encoded(
            header,
            Request::AdmitQualification(qualification),
            2,
        );
        assert_eq!(
            decode_production_qualification_response(header, first.as_bytes())
                .unwrap()
                .code,
            ResponseCode::Ok
        );
        let replay = runtime.dispatch.dispatch_v2_encoded(
            header,
            Request::AdmitQualification(qualification),
            2,
        );
        assert_eq!(
            decode_production_qualification_response(header, replay.as_bytes())
                .unwrap()
                .code,
            ResponseCode::Existing
        );
        let mut drift = qualification;
        drift.nonce = [8; 32];
        drift.request_frame_digest = [0; 32];
        drift.request_frame_digest =
            production_qualification_request_frame_digest(header, &drift).unwrap();
        let conflict =
            runtime
                .dispatch
                .dispatch_v2_encoded(header, Request::AdmitQualification(drift), 2);
        assert_eq!(
            decode_production_qualification_response(header, conflict.as_bytes())
                .unwrap()
                .code,
            ResponseCode::ReplayConflict
        );
        let mut wrong_principal = qualification;
        wrong_principal.principal_digest[0] ^= 1;
        let mut wrong_package = qualification;
        wrong_package.activation_package_digest[0] ^= 1;
        let mut wrong_fixture = qualification;
        wrong_fixture.fixture_digest[0] ^= 1;
        let mut wrong_generation = qualification;
        wrong_generation.controller_generation += 1;
        for mut mismatch in [
            wrong_principal,
            wrong_package,
            wrong_fixture,
            wrong_generation,
        ] {
            mismatch.request_frame_digest = [0; 32];
            mismatch.request_frame_digest =
                production_qualification_request_frame_digest(header, &mismatch).unwrap();
            let denied = runtime.dispatch.dispatch_v2_encoded(
                header,
                Request::AdmitQualification(mismatch),
                2,
            );
            assert_eq!(
                decode_production_qualification_response(header, denied.as_bytes())
                    .unwrap()
                    .code,
                ResponseCode::PolicyDenied
            );
        }
        let hello_header = FrameHeader {
            operation: buzz_ci_broker_protocol::Operation::Hello,
            request_id: [10; 16],
        };
        let ordinary = runtime.dispatch.dispatch_v2_encoded(
            hello_header,
            Request::Hello(buzz_ci_broker_protocol::HelloRequest {
                controller_instance: [1; 32],
                nonce: [2; 32],
            }),
            2,
        );
        assert_eq!(
            buzz_ci_broker_protocol::v2::decode_response(hello_header, ordinary.as_bytes())
                .unwrap()
                .code,
            ResponseCode::NotProvisioned
        );
        drop(runtime);
        let mut restarted = load_from(
            RuntimePaths {
                prefix: prefix.to_owned(),
            },
            owner,
            2,
            false,
            || Ok(SeccompRuntimeBinding::fixture()),
        )
        .unwrap();
        let replay = restarted.dispatch.dispatch_v2_encoded(
            header,
            Request::AdmitQualification(qualification),
            3,
        );
        assert_eq!(
            decode_production_qualification_response(header, replay.as_bytes())
                .unwrap()
                .code,
            ResponseCode::Existing
        );
        drop(restarted);
        let receipt_path = fs::read_dir(prefix.join("var/lib/buzzci/execd-v2/qualification"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let receipt_bytes = fs::read(&receipt_path).unwrap();
        let mut tampered = receipt_bytes.clone();
        tampered[0] ^= 1;
        fs::write(&receipt_path, tampered).unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_from(
            RuntimePaths {
                prefix: prefix.to_owned(),
            },
            owner,
            2,
            false,
            || Ok(SeccompRuntimeBinding::fixture()),
        )
        .is_err());
        fs::write(&receipt_path, receipt_bytes).unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();

        let refused = Cell::new(false);
        assert!(load_from(
            RuntimePaths {
                prefix: prefix.to_owned(),
            },
            owner,
            2,
            false,
            || {
                refused.set(true);
                Err(ProductionV2Error::Closed)
            },
        )
        .is_err());
        assert!(refused.get());

        let mut drifted = config;
        drifted.capacity = 2;
        fs::write(&config_path, canonical_bytes(&drifted).unwrap()).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        let invalid_called = Cell::new(false);
        assert!(load_from(
            RuntimePaths {
                prefix: prefix.to_owned(),
            },
            owner,
            2,
            false,
            || {
                invalid_called.set(true);
                Ok(SeccompRuntimeBinding::fixture())
            },
        )
        .is_err());
        assert!(!invalid_called.get());
    }
}
