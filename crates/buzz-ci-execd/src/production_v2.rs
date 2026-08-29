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
    },
    path::{Component, Path, PathBuf},
    time::Duration,
};

use buzz_ci_broker_protocol::{
    v2::{AdmissionSignatureAlgorithm, EvidenceDescriptor, EvidenceKind, WireText64},
    Conclusion, GitOid, TrustClass,
};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    control::ControlDispatch,
    production_binding::{
        ArtifactDeclarationV1, BindingError, BindingPhase, ExecutionBindingJournal,
        ExecutionBindingRecord, ExecutionBindingV1, HostEvidenceItem, HostIdentity,
        HostRecoveryReceipt, HostStepReceipt, HostStopReason, HostTerminalReceipt, JobIntentSource,
        JobIntentV2, JournalWrite, LaneActivationManifestV1, PrivilegedHostSystem,
        ProductionBindingController, StaticLaneManifest, EXECUTION_BINDING_SCHEMA_V1,
    },
};

pub const CONFIG_PATH: &str = "/etc/buzzci/execd-v2.json";
pub const INTENT_ROOT: &str = "/var/lib/buzzci/execd-v2/intents";
pub const BINDING_ROOT: &str = "/var/lib/buzzci/execd-v2/bindings";
pub const EVIDENCE_ROOT: &str = "/var/lib/buzzci/execd-v2/evidence";
pub const TEARDOWN_ROOT: &str = "/var/lib/buzzci/execd-v2/teardown";
pub const ATTEMPT_ROOT: &str = "/var/lib/buzzci/execd-v2/attempts";
pub const EXECUTOR_SOCKET: &str = "/run/buzzci/executor.sock";
pub const EXECUTOR_PROGRAM: &str = "/usr/libexec/buzz-ci-executor";
pub const ACCESS_GROUP: &str = "buzzci-execd";
pub const JOB_USER: &str = "buzzci-job";
const CONFIG_SCHEMA: u16 = 2;
const RPC_SCHEMA: u16 = 1;
const MAX_CONFIG: u64 = 64 * 1024;
const MAX_INTENT: u64 = 32 * 1024;
const MAX_RECORD: u64 = 32 * 1024;
const MAX_RPC: usize = 64 * 1024;
const MAX_RAW_OUTPUT: usize = 32 * 1024;

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
struct IntentDocument {
    schema_version: u16,
    signed_request_digest: String,
    actor_pubkey: String,
    audience_digest: String,
    idempotency_digest: String,
    source_pin_event_id: String,
    workflow_digest: String,
    isolation_profile_digest: String,
    lane_manifest_digest: String,
    lane_epoch: u64,
    admission_key_generation: u64,
    run_id: String,
    tip_oid: OidDocument,
    base_oid: OidDocument,
    issued_at: u64,
    expires_at: u64,
    wall_timeout_seconds: u32,
    attempt: u32,
    parent_attempt: u32,
    trust_class: String,
    request_event_id: String,
    workflow_id: String,
    job_id: String,
    artifacts: Vec<ArtifactDocument>,
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
    job_intent_digest: Option<String>,
    claimed_evidence_digest: Option<String>,
    phase: Option<String>,
    stop_reason: Option<String>,
    executor_program_sha256: String,
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
    raw_output: Option<String>,
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
        if !safe_name(name) || bytes.is_empty() || bytes.len() as u64 > MAX_RECORD {
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

impl JobIntentSource for StaticIntentFiles {
    fn load(&mut self, digest: [u8; 32]) -> Result<JobIntentV2, BindingError> {
        let name = format!("{}.json", hex::encode(digest));
        let bytes = self
            .root
            .read(&name, 0o400, MAX_INTENT)
            .map_err(binding_error)?;
        let document: IntentDocument = canonical_parse(&bytes).map_err(binding_error)?;
        let intent = document.into_intent().map_err(binding_error)?;
        (intent.digest() == digest)
            .then_some(intent)
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

struct LocalHostSystem {
    identity: HostIdentity,
    socket: PathBuf,
    executor_uid: u32,
    executor_gid: u32,
    executor: ProgramProvenance,
    evidence: SafeDirectory,
    teardown: SafeDirectory,
    evidence_by_binding: BTreeMap<[u8; 32], [u8; 32]>,
    attempts: SafeDirectory,
    job_uid: u32,
}

impl LocalHostSystem {
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
            job_intent_digest: intent.map(|value| hex::encode(value.digest())),
            claimed_evidence_digest: claimed.map(hex::encode),
            phase: phase.map(phase_name).map(str::to_owned),
            stop_reason: reason.map(stop_name).map(str::to_owned),
            executor_program_sha256: self.executor.sha256.clone(),
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
        match self.evidence.write_once(&name, &bytes, 0o600) {
            Ok(()) => {}
            Err(_) => {
                let existing = self
                    .evidence
                    .read(&name, 0o600, MAX_RECORD)
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
        let bytes = match self.evidence.read(&name, 0o600, MAX_RECORD) {
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
        let attempt = match self.attempts.open_child(&attempt_name, self.job_uid, 0o700) {
            Ok(directory) => Some(directory),
            Err(_) if all_sealed => None,
            Err(_) if declarations.is_empty() && !attempt_path.exists() => None,
            Err(_) => return Err(BindingError::HostRefused),
        };
        if let Some(attempt) = &attempt {
            let mut observed = Vec::new();
            for entry in
                fs::read_dir(attempt.descriptor_path()).map_err(|_| BindingError::HostRefused)?
            {
                let name = entry
                    .map_err(|_| BindingError::HostRefused)?
                    .file_name()
                    .into_string()
                    .map_err(|_| BindingError::HostRefused)?;
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
        }

        let mut items = Vec::new();
        let mut set_material = Vec::from(b"buzz-ci-execd:artifact-receipt-set:v1\0".as_slice());
        set_material.extend_from_slice(&binding.execution_binding_digest);
        for declaration in declarations {
            let artifact_id = declaration
                .artifact_id
                .as_str()
                .map_err(|_| BindingError::HostRefused)?;
            let receipt_name = format!("{}-{}.json", attempt_name, artifact_id);
            let bytes = match self.evidence.read(&receipt_name, 0o600, MAX_RECORD) {
                Ok(bytes) => bytes,
                Err(_) => {
                    let attempt = attempt.as_ref().ok_or(BindingError::HostRefused)?;
                    let raw = attempt
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
                    match self.evidence.write_once(&receipt_name, &bytes, 0o600) {
                        Ok(()) => bytes,
                        Err(_) => self
                            .evidence
                            .read(&receipt_name, 0o600, MAX_RECORD)
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
        self.step("materialization", binding, Some(intent))
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
        let conclusion = parse_conclusion(response.conclusion.as_deref())?;
        self.sealed_artifacts(binding)?;
        let digest = self.write_evidence(
            binding,
            conclusion,
            response
                .raw_output
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
        let conclusion = parse_conclusion(response.conclusion.as_deref())?;
        let evidence = match self.existing_evidence(binding)? {
            Some(value) => value,
            None => self.write_evidence(
                binding,
                conclusion,
                response
                    .raw_output
                    .as_deref()
                    .unwrap_or("execution stopped before terminal output"),
                None,
            )?,
        };
        let executor_receipt = decode_nonzero(&response.receipt_digest)?;
        let artifact_receipt_set_digest = match captured {
            Some((_, digest)) => digest,
            None => self.sealed_artifacts(binding)?.1,
        };
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
        Ok(HostTerminalReceipt {
            execution_binding_digest: binding.execution_binding_digest,
            conclusion,
            evidence_set_digest: evidence,
            teardown_digest,
        })
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
        self.teardown_provider(binding, HostStopReason::Recovery)
            .map(HostRecoveryReceipt::CapacityReturned)
            .or(Ok(HostRecoveryReceipt::Quarantine))
    }

    fn sealed_attempt_evidence(
        &mut self,
        binding: ExecutionBindingV1,
    ) -> Result<Vec<HostEvidenceItem>, BindingError> {
        let name = format!("{}.json", hex::encode(binding.attempt_id));
        let evidence_bytes = self
            .evidence
            .read(&name, 0o600, MAX_RECORD)
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

/// Open exact capacity-one production state. Any ambiguity returns a closed dispatcher.
pub fn load_canonical(now: u64) -> Result<Box<dyn ControlDispatch>, ProductionV2Error> {
    load_from(RuntimePaths::canonical(), 0, now, true)
}

fn load_from(
    paths: RuntimePaths,
    owner: u32,
    now: u64,
    validate_group: bool,
) -> Result<Box<dyn ControlDispatch>, ProductionV2Error> {
    let config_path = paths.resolve(CONFIG_PATH)?;
    let config = read_document::<ProductionConfig>(&config_path, owner, 0o600, MAX_CONFIG)?;
    validate_config(&config, &paths, owner, validate_group)?;
    let manifest = config.lane_manifest.clone().into_manifest()?;
    let identity = HostIdentity {
        broker_build_identity: manifest.broker_build_identity,
        host_profile_digest: manifest.host_profile_digest,
        suite_identity: manifest.suite_identity,
    };
    let intents = StaticIntentFiles {
        root: SafeDirectory::open(paths.resolve(INTENT_ROOT)?, owner, 0o700)?,
    };
    let journal = DurableBindingFiles {
        root: SafeDirectory::open(paths.resolve(BINDING_ROOT)?, owner, 0o700)?,
    };
    let host = LocalHostSystem {
        identity,
        socket: paths.resolve(EXECUTOR_SOCKET)?,
        executor_uid: config.identities.job_uid,
        executor_gid: config.identities.job_gid,
        executor: mapped_program(&config.executor, &paths)?,
        evidence: SafeDirectory::open(paths.resolve(EVIDENCE_ROOT)?, owner, 0o700)?,
        teardown: SafeDirectory::open(paths.resolve(TEARDOWN_ROOT)?, owner, 0o700)?,
        evidence_by_binding: BTreeMap::new(),
        attempts: SafeDirectory::open(paths.resolve(ATTEMPT_ROOT)?, owner, 0o711)?,
        job_uid: config.identities.job_uid,
    };
    let mut controller =
        ProductionBindingController::new(StaticLaneManifest::new(manifest), intents, journal, host);
    controller
        .recover_open(now)
        .map_err(|_| ProductionV2Error::Closed)?;
    Ok(Box::new(controller))
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
        || config.capacity != 1
        || identities.execd_uid != owner
        || identities.execd_uid == identities.runner_uid
        || identities.execd_uid == identities.control_uid
        || identities.job_uid == 0
        || identities.job_gid == 0
        || [
            identities.runner_uid,
            identities.control_uid,
            identities.job_uid,
        ]
        .contains(&0)
        || identities.runner_uid == identities.control_uid
        || identities.runner_uid == identities.job_uid
        || identities.control_uid == identities.job_uid
        || identities.access_group != ACCESS_GROUP
        || identities.access_group_members != ["buzzci-ctl", "buzzci-runner"]
        || config.paths.intent_root != INTENT_ROOT
        || config.paths.binding_root != BINDING_ROOT
        || config.paths.evidence_root != EVIDENCE_ROOT
        || config.paths.teardown_root != TEARDOWN_ROOT
        || config.paths.attempt_root != ATTEMPT_ROOT
        || config.paths.executor_socket != EXECUTOR_SOCKET
        || config.executor.path != EXECUTOR_PROGRAM
        || config.executor.source_commit.len() != 40
        || !lower_hex(&config.executor.source_commit)
        || config.executor.uid != owner
        || config.executor.gid != identities.execd_gid
        || config.executor.mode != 0o755
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
        validate_access_group(identities)?;
        validate_principal(
            "buzzci-runner",
            identities.runner_uid,
            identities.runner_gid,
            "/usr/sbin/nologin",
        )?;
        validate_principal(
            "buzzci-ctl",
            identities.control_uid,
            identities.control_gid,
            "/usr/sbin/nologin",
        )?;
        validate_principal(
            JOB_USER,
            identities.job_uid,
            identities.job_gid,
            "/usr/sbin/nologin",
        )?;
    }
    Ok(())
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

fn validate_access_group(config: &IdentityConfig) -> Result<(), ProductionV2Error> {
    let bytes = fs::read("/etc/group").map_err(|_| ProductionV2Error::Closed)?;
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

fn validate_principal(
    name: &str,
    uid: u32,
    gid: u32,
    shell: &str,
) -> Result<(), ProductionV2Error> {
    let bytes = fs::read("/etc/passwd").map_err(|_| ProductionV2Error::Closed)?;
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

impl IntentDocument {
    fn into_intent(self) -> Result<JobIntentV2, ProductionV2Error> {
        let artifacts = artifact_array(&self.artifacts)?;
        Ok(JobIntentV2 {
            schema_version: self.schema_version,
            signed_request_digest: decode_hex(&self.signed_request_digest)?,
            actor_pubkey: decode_hex(&self.actor_pubkey)?,
            audience_digest: decode_hex(&self.audience_digest)?,
            idempotency_digest: decode_hex(&self.idempotency_digest)?,
            source_pin_event_id: decode_hex(&self.source_pin_event_id)?,
            workflow_digest: decode_hex(&self.workflow_digest)?,
            isolation_profile_digest: decode_hex(&self.isolation_profile_digest)?,
            lane_manifest_digest: decode_hex(&self.lane_manifest_digest)?,
            lane_epoch: self.lane_epoch,
            admission_signature_algorithm: AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
            admission_key_generation: self.admission_key_generation,
            run_id: decode_hex(&self.run_id)?,
            tip_oid: self.tip_oid.into_oid()?,
            base_oid: self.base_oid.into_oid()?,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            wall_timeout_seconds: self.wall_timeout_seconds,
            attempt: self.attempt,
            parent_attempt: self.parent_attempt,
            trust_class: match self.trust_class.as_str() {
                "accepted_reviewed" => TrustClass::AcceptedReviewed,
                _ => return Err(ProductionV2Error::Closed),
            },
            request_event_id: decode_hex(&self.request_event_id)?,
            workflow_id: wire_text(&self.workflow_id)?,
            job_id: wire_text(&self.job_id)?,
            artifact_count: self.artifacts.len() as u8,
            artifacts,
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
    for line in text.lines() {
        if line.contains("PRIVATE_KEY=")
            || line.contains("TOKEN=")
            || line.contains("PASSWORD=")
            || line.contains("AUTHORIZATION:")
        {
            output.push_str("[redacted]\n");
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    Ok(output.into_bytes())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ExecutorStage {
    Handoff,
    Runtime,
    Materialized,
    Running,
    Terminal,
}

/// Serve the fixed unprivileged executor protocol on a systemd-owned socket.
///
/// The process retains only the active capacity-one binding in memory. It has
/// no path in the protocol for commands, environment, prior evidence, or logs.
pub fn run_executor_service(listener: UnixListener) -> std::io::Result<()> {
    let executable_sha256 = executable_sha256()?;
    let mut active: BTreeMap<String, ExecutorStage> = BTreeMap::new();
    loop {
        let (mut stream, _) = listener.accept()?;
        let result = serve_executor_stream(&mut stream, &executable_sha256, &mut active);
        if result.is_err() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn serve_executor_stream(
    stream: &mut UnixStream,
    executable_sha256: &str,
    active: &mut BTreeMap<String, ExecutorStage>,
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
        || active.len() > 1
    {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let response = executor_transition(request, active)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    let body = canonical_bytes(&response)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(&body)
}

fn executor_transition(
    request: ExecutorRequest,
    active: &mut BTreeMap<String, ExecutorStage>,
) -> Result<ExecutorResponse, ProductionV2Error> {
    let binding = request.execution_binding_digest.clone();
    let operation = request.operation.clone();
    let receipt = |name: &str| {
        let mut digest = Sha256::new();
        digest.update(b"buzz-ci-executor:receipt:v1\0");
        digest.update(name.as_bytes());
        digest.update(binding.as_bytes());
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
        raw_output: None,
        capacity_returned: None,
        quarantine: None,
    };
    match operation.as_str() {
        "executor_handoff" => {
            if request.job_intent_digest.is_none()
                || active.insert(binding, ExecutorStage::Handoff).is_some()
            {
                return Err(ProductionV2Error::Closed);
            }
        }
        "runtime_descriptor" => transition(
            active,
            &binding,
            ExecutorStage::Handoff,
            ExecutorStage::Runtime,
        )?,
        "materialization" => {
            if request.job_intent_digest.is_none() {
                return Err(ProductionV2Error::Closed);
            }
            transition(
                active,
                &binding,
                ExecutorStage::Runtime,
                ExecutorStage::Materialized,
            )?;
        }
        "proxy_lease" => transition(
            active,
            &binding,
            ExecutorStage::Materialized,
            ExecutorStage::Running,
        )?,
        "terminal_evidence" => {
            transition(
                active,
                &binding,
                ExecutorStage::Running,
                ExecutorStage::Terminal,
            )?;
            let claimed = request
                .claimed_evidence_digest
                .filter(|value| value.len() == 64 && lower_hex(value))
                .ok_or(ProductionV2Error::Closed)?;
            response.receipt_digest = claimed.clone();
            response.evidence_set_digest = Some(claimed);
            response.conclusion = Some("success".into());
            response.raw_output = Some(format!("execution {binding} completed\n"));
        }
        "teardown" => {
            active.remove(&binding);
            let reason = request
                .stop_reason
                .as_deref()
                .ok_or(ProductionV2Error::Closed)?;
            response.conclusion = Some(
                match reason {
                    "completed" => "success",
                    "cancelled" => "cancelled",
                    "expired" => "timed_out",
                    "recovery" => "infrastructure_failure",
                    _ => return Err(ProductionV2Error::Closed),
                }
                .into(),
            );
            response.raw_output = Some(format!("execution {binding} stopped: {reason}\n"));
        }
        "crash_recovery" => {
            active.remove(&binding);
            response.capacity_returned = Some(true);
            response.quarantine = Some(false);
        }
        _ => return Err(ProductionV2Error::Closed),
    }
    Ok(response)
}

fn transition(
    active: &mut BTreeMap<String, ExecutorStage>,
    binding: &str,
    expected: ExecutorStage,
    next: ExecutorStage,
) -> Result<(), ProductionV2Error> {
    let stage = active.get_mut(binding).ok_or(ProductionV2Error::Closed)?;
    if *stage != expected {
        return Err(ProductionV2Error::Closed);
    }
    *stage = next;
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
    use std::os::unix::fs::{symlink, PermissionsExt};

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

    #[test]
    fn scrub_is_bounded_and_removes_secret_shaped_lines() {
        assert_eq!(
            scrub(b"ok\nTOKEN=secret\ndone\n").unwrap(),
            b"ok\n[redacted]\ndone\n"
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
            evidence: SafeDirectory::open(evidence_path.clone(), owner, 0o700).unwrap(),
            teardown: SafeDirectory::open(teardown_path.clone(), owner, 0o700).unwrap(),
            evidence_by_binding: BTreeMap::new(),
            attempts: SafeDirectory::open(attempts_path.clone(), owner, 0o711).unwrap(),
            job_uid: owner,
        };

        let mut empty_binding = valid_record().binding;
        empty_binding.execution_binding_digest = empty_binding.computed_digest();
        assert!(make_system()
            .sealed_artifacts(empty_binding)
            .unwrap()
            .0
            .is_empty());

        let declaration = ArtifactDeclarationV1 {
            artifact_id: wire_text("canary-report").unwrap(),
            name: wire_text("report.txt").unwrap(),
            media_type: wire_text("text/plain").unwrap(),
            relative_name: wire_text("report.txt").unwrap(),
            max_bytes: 1024,
        };
        let mut binding = empty_binding;
        binding.artifact_count = 1;
        binding.artifacts = [Some(declaration)];
        binding.execution_binding_digest = binding.computed_digest();
        let attempt_path = attempts_path.join(hex::encode(binding.attempt_id));
        fs::create_dir(&attempt_path).unwrap();
        fs::set_permissions(&attempt_path, fs::Permissions::from_mode(0o700)).unwrap();
        let artifact_path = attempt_path.join("report.txt");
        fs::write(&artifact_path, b"ok\nTOKEN=secret\n").unwrap();
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o600)).unwrap();

        let captured = make_system().sealed_artifacts(binding).unwrap().0;
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].descriptor.kind, EvidenceKind::Artifact);
        assert_eq!(captured[0].descriptor.artifact_id, declaration.artifact_id);
        assert_eq!(captured[0].bytes, b"ok\n[redacted]\n");
        fs::remove_file(&artifact_path).unwrap();
        fs::remove_dir(&attempt_path).unwrap();
        assert_eq!(make_system().sealed_artifacts(binding).unwrap().0, captured);

        let mut hostile = binding;
        hostile.attempt_id = [55; 16];
        hostile.execution_binding_digest = hostile.computed_digest();
        let hostile_root = attempts_path.join(hex::encode(hostile.attempt_id));
        fs::create_dir(&hostile_root).unwrap();
        fs::set_permissions(&hostile_root, fs::Permissions::from_mode(0o700)).unwrap();
        symlink("../outside", hostile_root.join("report.txt")).unwrap();
        assert!(make_system().sealed_artifacts(hostile).is_err());

        let mut undeclared = binding;
        undeclared.attempt_id = [56; 16];
        undeclared.execution_binding_digest = undeclared.computed_digest();
        let undeclared_root = attempts_path.join(hex::encode(undeclared.attempt_id));
        fs::create_dir(&undeclared_root).unwrap();
        fs::set_permissions(&undeclared_root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["report.txt", "extra.txt"] {
            let path = undeclared_root.join(name);
            fs::write(&path, b"content\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(make_system().sealed_artifacts(undeclared).is_err());

        let mut hardlinked = binding;
        hardlinked.attempt_id = [57; 16];
        hardlinked.execution_binding_digest = hardlinked.computed_digest();
        let hardlink_root = attempts_path.join(hex::encode(hardlinked.attempt_id));
        fs::create_dir(&hardlink_root).unwrap();
        fs::set_permissions(&hardlink_root, fs::Permissions::from_mode(0o700)).unwrap();
        let outside = temporary.path().join("outside-artifact");
        fs::write(&outside, b"content\n").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&outside, hardlink_root.join("report.txt")).unwrap();
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
    fn executor_partial_start_and_restart_recovery_are_fail_closed() {
        let binding = hex::encode([42; 32]);
        let request = |operation: &str| ExecutorRequest {
            schema_version: RPC_SCHEMA,
            operation: operation.into(),
            execution_binding_digest: binding.clone(),
            job_intent_digest: Some(hex::encode([7; 32])),
            claimed_evidence_digest: None,
            phase: None,
            stop_reason: None,
            executor_program_sha256: hex::encode([9; 32]),
        };
        let mut active = BTreeMap::new();
        executor_transition(request("executor_handoff"), &mut active).unwrap();
        assert!(executor_transition(request("proxy_lease"), &mut active).is_err());
        let mut recovery = request("crash_recovery");
        recovery.job_intent_digest = None;
        recovery.phase = Some("admitted".into());
        recovery.stop_reason = Some("recovery".into());
        let response = executor_transition(recovery, &mut active).unwrap();
        assert_eq!(response.capacity_returned, Some(true));
        assert!(active.is_empty());
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
            evidence: SafeDirectory::open(evidence_path.clone(), owner, 0o700).unwrap(),
            teardown: SafeDirectory::open(teardown_path.clone(), owner, 0o700).unwrap(),
            evidence_by_binding: BTreeMap::new(),
            attempts: SafeDirectory::open(attempts_path.clone(), owner, 0o711).unwrap(),
            job_uid: owner,
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
            "usr/libexec",
            "run/buzzci",
        ] {
            let path = prefix.join(relative);
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::set_permissions(prefix.join("etc/buzzci"), fs::Permissions::from_mode(0o755)).unwrap();
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
        let config = ProductionConfig {
            schema_version: CONFIG_SCHEMA,
            enabled_protocol: 2,
            capacity: 1,
            identities: IdentityConfig {
                execd_uid: owner,
                execd_gid: group,
                runner_uid: owner + 1,
                runner_gid: group + 1,
                control_uid: owner + 2,
                control_gid: group + 2,
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
        };
        let config_path = prefix.join("etc/buzzci/execd-v2.json");
        fs::write(&config_path, canonical_bytes(&config).unwrap()).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(load_from(
            RuntimePaths {
                prefix: prefix.to_owned(),
            },
            owner,
            2,
            false,
        )
        .is_ok());

        let mut drifted = config;
        drifted.capacity = 2;
        fs::write(&config_path, canonical_bytes(&drifted).unwrap()).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_from(
            RuntimePaths {
                prefix: prefix.to_owned(),
            },
            owner,
            2,
            false,
        )
        .is_err());
    }
}
