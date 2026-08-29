//! Root-owned materialization inputs for one validated ordinary lease.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;
use buzz_ci_materializer::{
    MaterializationLimits, MaterializationManifest, RootOwnedPolicy, Sha256Digest,
};
use nix::errno::Errno;
use nix::fcntl::{open, openat, OFlag};
use nix::sys::stat::{fstat, Mode, SFlag};
use nix::unistd::fsync;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::activation::LeaseToken;
use crate::dns_isolation::{PrincipalRole, TransientUnitPlan, UnitNetworkMode};
use crate::durable_dispatch::{ExecutionUnavailable, OrdinaryStop};
use crate::evidence::{Digest32, MaterializedInputDigest};
use crate::host_composition::HostCompositionContract;
use crate::materializer_evidence::MaterializerEvidenceContext;
use crate::normal_backend::{NormalMaterializationInputs, NormalMaterializationSource};
use crate::normal_engine::NormalJobPlan;

const SCHEMA_VERSION: u16 = 1;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const WORKSPACE_MODE: u32 = 0o700;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) struct ExpectedOwner {
    pub(super) uid: u32,
    pub(super) gid: u32,
}

pub(super) struct DescriptorRoot {
    descriptor: OwnedFd,
    owner: ExpectedOwner,
}

impl DescriptorRoot {
    pub(super) fn open(path: &Path, owner: ExpectedOwner) -> Result<Self, ExecutionUnavailable> {
        let descriptor = open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ExecutionUnavailable)?;
        validate_directory(&descriptor, owner)?;
        Ok(Self { descriptor, owner })
    }

    pub(super) fn read<T>(&self, name: &str) -> Result<T, ExecutionUnavailable>
    where
        T: DeserializeOwned + Serialize,
    {
        if !safe_record_name(name) {
            return Err(ExecutionUnavailable);
        }
        let descriptor = match openat(
            &self.descriptor,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::ENOENT) => return Err(ExecutionUnavailable),
            Err(_) => return Err(ExecutionUnavailable),
        };
        let mut file = File::from(descriptor);
        let identity = validate_regular(&file, self.owner)?;
        let mut bytes = Vec::with_capacity(identity.size);
        (&mut file)
            .take(MAX_RECORD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ExecutionUnavailable)?;
        if bytes.len() != identity.size || file_identity(&file)? != identity {
            return Err(ExecutionUnavailable);
        }
        let named = openat(
            &self.descriptor,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| ExecutionUnavailable)?;
        let named = File::from(named);
        if file_identity(&named)? != identity {
            return Err(ExecutionUnavailable);
        }
        let value: T = serde_json::from_slice(&bytes).map_err(|_| ExecutionUnavailable)?;
        if serde_json::to_vec(&value).map_err(|_| ExecutionUnavailable)? != bytes {
            return Err(ExecutionUnavailable);
        }
        Ok(value)
    }

    pub(super) fn ensure_unclaimed(&self, name: &str) -> Result<(), ExecutionUnavailable> {
        if !safe_claim_name(name) {
            return Err(ExecutionUnavailable);
        }
        match openat(
            &self.descriptor,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        ) {
            Err(Errno::ENOENT) => Ok(()),
            _ => Err(ExecutionUnavailable),
        }
    }

    pub(super) fn claim(&self, name: &str) -> Result<(), ExecutionUnavailable> {
        if !safe_claim_name(name) {
            return Err(ExecutionUnavailable);
        }
        let descriptor = openat(
            &self.descriptor,
            name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(FILE_MODE),
        )
        .map_err(|_| ExecutionUnavailable)?;
        let mut file = File::from(descriptor);
        file.write_all(b"claimed\n")
            .map_err(|_| ExecutionUnavailable)?;
        file.sync_all().map_err(|_| ExecutionUnavailable)?;
        validate_regular(&file, self.owner)?;
        fsync(&self.descriptor).map_err(|_| ExecutionUnavailable)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: usize,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
}

fn validate_directory(
    descriptor: &OwnedFd,
    owner: ExpectedOwner,
) -> Result<(), ExecutionUnavailable> {
    let metadata = fstat(descriptor).map_err(|_| ExecutionUnavailable)?;
    if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFDIR
        || metadata.st_uid != owner.uid
        || metadata.st_gid != owner.gid
        || metadata.st_mode & 0o7777 != DIRECTORY_MODE
    {
        return Err(ExecutionUnavailable);
    }
    Ok(())
}

fn validate_regular(
    file: &File,
    owner: ExpectedOwner,
) -> Result<FileIdentity, ExecutionUnavailable> {
    let metadata = fstat(file).map_err(|_| ExecutionUnavailable)?;
    if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFREG
        || metadata.st_uid != owner.uid
        || metadata.st_gid != owner.gid
        || metadata.st_mode & 0o7777 != FILE_MODE
        || metadata.st_nlink != 1
        || metadata.st_size <= 0
        || metadata.st_size as usize > MAX_RECORD_BYTES
    {
        return Err(ExecutionUnavailable);
    }
    file_identity(file)
}

fn file_identity(file: &File) -> Result<FileIdentity, ExecutionUnavailable> {
    let metadata = fstat(file).map_err(|_| ExecutionUnavailable)?;
    Ok(FileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        size: usize::try_from(metadata.st_size).map_err(|_| ExecutionUnavailable)?,
        uid: metadata.st_uid,
        gid: metadata.st_gid,
        mode: metadata.st_mode,
        links: metadata.st_nlink,
    })
}

fn safe_record_name(name: &str) -> bool {
    name.len() > 5
        && name.len() <= 128
        && name.ends_with(".json")
        && name[..name.len() - 5]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn safe_claim_name(name: &str) -> bool {
    name.len() > 5
        && name.len() <= 160
        && name.ends_with(".used")
        && name[..name.len() - 5]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterializationPolicyRecord {
    git_program: PathBuf,
    git_exec_path: PathBuf,
    origins: BTreeMap<String, String>,
    limits: MaterializationLimits,
}

impl MaterializationPolicyRecord {
    fn build(&self) -> Result<RootOwnedPolicy, ExecutionUnavailable> {
        let origins = self
            .origins
            .iter()
            .map(|(coordinate, origin)| {
                origin
                    .parse()
                    .map(|url| (coordinate.clone(), url))
                    .map_err(|_| ExecutionUnavailable)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        RootOwnedPolicy::new(
            self.git_program.clone(),
            self.git_exec_path.clone(),
            origins,
            self.limits.clone(),
        )
        .map_err(|_| ExecutionUnavailable)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterializerUnitRecord {
    role: PrincipalRole,
    uid: u32,
    unit_name: String,
    cgroup_path: PathBuf,
    properties: BTreeMap<String, String>,
    network_mode: UnitNetworkMode,
}

impl MaterializerUnitRecord {
    fn plan(&self) -> TransientUnitPlan {
        TransientUnitPlan {
            role: self.role,
            uid: self.uid,
            unit_name: self.unit_name.clone(),
            cgroup_path: self.cgroup_path.clone(),
            properties: self.properties.clone(),
            network_mode: self.network_mode.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterializationAuthorityRecord {
    schema_version: u16,
    lease_id: String,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    manifest: MaterializationManifest,
    canonical_inputs: Vec<u8>,
    policy: MaterializationPolicyRecord,
    materializer_unit: MaterializerUnitRecord,
    manifest_sha256: Digest32,
    input_digests: Vec<MaterializedInputDigest>,
}

impl MaterializationAuthorityRecord {
    fn validate(
        &self,
        now: u64,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<RootOwnedPolicy, ExecutionUnavailable> {
        let expected = binding.as_binding();
        let workflow_path = trusted_workflow_path(expected, &self.manifest.workflow_path)?;
        if self.schema_version != SCHEMA_VERSION
            || self.lease_id != expected.lease_id
            || self.issued_at_unix_seconds == 0
            || self.issued_at_unix_seconds > now
            || self.expires_at_unix_seconds != expected.expires_at_unix_seconds
            || self.expires_at_unix_seconds <= now
            || plan.lease_record.lease_id != expected.lease_id
            || plan.lease_record.workspace_dir != Path::new(&expected.workspace.path)
            || plan.lease_record.seccomp_profile.path
                != Path::new(&expected.isolation_profile.seccomp_profile_path)
            || plan.lease_record.seccomp_profile.sha256
                != expected.isolation_profile.seccomp_profile_digest
            || self.manifest.request_event_id != expected.request_event_id
            || self.manifest.run_id != expected.run_id
            || self.manifest.source_sha != expected.source_sha
            || self.manifest.trusted_base_sha != expected.base_oid
            || self.manifest.repo_coordinate != expected.target_repo_a
            || self.manifest.workflow_id != expected.workflow_id
            || workflow_path != plan.act.workflow_path
            || self.manifest.workflow_sha256.as_str() != expected.workflow_digest
            || self.manifest.job_id != expected.job_id
            || self.manifest.attempt != expected.attempt
            || self.manifest.lease_id != expected.lease_id
            || self.materializer_unit.role != PrincipalRole::Materializer
            || self.materializer_unit.uid != expected.principals.materializer
            || self.manifest_sha256.0 != plan.job_manifest_digest
            || self.input_digests.len() > 127
            || self.canonical_inputs.is_empty()
            || self.canonical_inputs.len() > MAX_RECORD_BYTES / 2
            || Sha256Digest::digest(&self.canonical_inputs) != self.manifest.inputs_sha256
            || !canonical_non_secret_inputs(&self.canonical_inputs)
        {
            return Err(ExecutionUnavailable);
        }
        let policy = self.policy.build()?;
        if policy.digest() != &self.manifest.policy_sha256 {
            return Err(ExecutionUnavailable);
        }
        Ok(policy)
    }
}

pub(super) fn canonical_non_secret_inputs(bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    if serde_json::to_vec(&value).ok().as_deref() != Some(bytes) {
        return false;
    }
    non_secret_json(&value)
}

pub(super) fn non_secret_json(value: &serde_json::Value) -> bool {
    fn safe(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(map) => map
                .iter()
                .all(|(name, value)| !sensitive_name(name) && safe(value)),
            serde_json::Value::Array(values) => values.iter().all(safe),
            serde_json::Value::String(value) => safe_string(value),
            _ => true,
        }
    }
    safe(value)
}

fn trusted_workflow_path(
    binding: &buzz_ci_isolation_contract::AttemptLeaseBinding,
    workflow_path: &str,
) -> Result<PathBuf, ExecutionUnavailable> {
    let relative = Path::new(workflow_path);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(ExecutionUnavailable);
    }
    Ok(Path::new(&binding.workspace.path)
        .join("source")
        .join(relative))
}

fn sensitive_name(name: &str) -> bool {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prior_lower = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase() && prior_lower && !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            current.push(character.to_ascii_uppercase());
            prior_lower = character.is_ascii_lowercase();
        } else {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            prior_lower = false;
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words.iter().any(|word| {
        matches!(
            word.as_str(),
            "SECRET" | "TOKEN" | "PASSWORD" | "CREDENTIAL" | "CREDENTIALS"
        )
    }) || words
        .windows(2)
        .any(|words| words[0] == "PRIVATE" && words[1] == "KEY")
}

fn safe_string(value: &str) -> bool {
    let trimmed = value.trim();
    if sensitive_name(trimmed)
        || trimmed
            .split_once('=')
            .is_some_and(|(name, _)| valid_env_name(name) && sensitive_name(name))
    {
        return false;
    }
    let upper = trimmed.to_ascii_uppercase();
    !upper.contains("-----BEGIN PRIVATE KEY-----")
        && !upper.starts_with("BEARER ")
        && !looks_like_aws_access_key(trimmed)
        && !["ghp_", "github_pat_", "glpat-"]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
}

fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn looks_like_aws_access_key(value: &str) -> bool {
    value.len() == 20
        && (value.starts_with("AKIA") || value.starts_with("ASIA"))
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

/// Descriptor-relative source for broker-authored materialization records.
pub struct MaterializationInputProvider {
    root: DescriptorRoot,
    consumed: BTreeSet<String>,
    now: fn() -> Result<u64, ExecutionUnavailable>,
}

impl MaterializationInputProvider {
    /// Open the root-owned materialization authority named by host composition.
    pub fn from_contract(contract: &HostCompositionContract) -> Result<Self, ExecutionUnavailable> {
        Self::open_for_owner(&contract.materialization_authority_root, 0, 0, system_now)
    }

    fn open_for_owner(
        path: &Path,
        uid: u32,
        gid: u32,
        now: fn() -> Result<u64, ExecutionUnavailable>,
    ) -> Result<Self, ExecutionUnavailable> {
        Ok(Self {
            root: DescriptorRoot::open(path, ExpectedOwner { uid, gid })?,
            consumed: BTreeSet::new(),
            now,
        })
    }

    fn record(
        &self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(MaterializationAuthorityRecord, RootOwnedPolicy), ExecutionUnavailable> {
        let name = format!("{}.json", binding.as_binding().lease_id);
        let record: MaterializationAuthorityRecord = self.root.read(&name)?;
        let policy = record.validate((self.now)()?, plan, binding)?;
        Ok((record, policy))
    }

    fn claim_name(binding: &ValidatedAttemptLeaseBinding) -> String {
        format!("{}_materialization.used", binding.as_binding().lease_id)
    }

    fn workspace(binding: &ValidatedAttemptLeaseBinding) -> Result<File, ExecutionUnavailable> {
        let expected = binding.as_binding();
        let descriptor = open(
            Path::new(&expected.workspace.path),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ExecutionUnavailable)?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(|_| ExecutionUnavailable)?;
        let named = std::fs::symlink_metadata(&expected.workspace.path)
            .map_err(|_| ExecutionUnavailable)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != expected.principals.materializer
            || metadata.gid() == 0
            || metadata.mode() & 0o7777 != WORKSPACE_MODE
            || metadata.dev() != expected.workspace.object.device
            || metadata.ino() != expected.workspace.object.inode
            || named.dev() != metadata.dev()
            || named.ino() != metadata.ino()
            || named.file_type().is_symlink()
        {
            return Err(ExecutionUnavailable);
        }
        Ok(file)
    }
}

fn system_now() -> Result<u64, ExecutionUnavailable> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ExecutionUnavailable)
}

impl NormalMaterializationSource for MaterializationInputProvider {
    fn preflight(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable> {
        let lease_id = &binding.as_binding().lease_id;
        if self.consumed.contains(lease_id) {
            return Err(ExecutionUnavailable);
        }
        self.root.ensure_unclaimed(&Self::claim_name(binding))?;
        self.record(plan, binding)?;
        Self::workspace(binding)?;
        Ok(())
    }

    fn prepare(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<NormalMaterializationInputs, ExecutionUnavailable> {
        self.preflight(plan, binding)?;
        let (record, policy) = self.record(plan, binding)?;
        let workspace_directory = Self::workspace(binding)?;
        let handoff = crate::dns_exec::MaterializerHandoffBinding::from_lease(
            record.materializer_unit.plan(),
            binding,
        )
        .map_err(|_| ExecutionUnavailable)?;
        self.root.claim(&Self::claim_name(binding))?;
        self.consumed.insert(record.lease_id.clone());
        Ok(NormalMaterializationInputs {
            manifest: record.manifest,
            canonical_inputs: record.canonical_inputs,
            policy,
            workspace_directory,
            handoff,
            evidence_context: MaterializerEvidenceContext {
                manifest_sha256: record.manifest_sha256.0,
                input_digests: record.input_digests,
            },
        })
    }

    fn reconcile(
        &mut self,
        lease: LeaseToken,
        _stop: OrdinaryStop,
        pending: &buzz_ci_materializer::PendingSeal,
    ) -> Result<(), ExecutionUnavailable> {
        if lease.generation() == 0 || pending.receipt().lease_id().is_empty() {
            return Err(ExecutionUnavailable);
        }
        let metadata = pending
            .workspace_directory()
            .metadata()
            .map_err(|_| ExecutionUnavailable)?;
        let named =
            std::fs::symlink_metadata(pending.workspace()).map_err(|_| ExecutionUnavailable)?;
        if !metadata.file_type().is_dir()
            || pending.workspace_identity() != (metadata.dev(), metadata.ino())
            || named.dev() != metadata.dev()
            || named.ino() != metadata.ino()
            || named.file_type().is_symlink()
        {
            return Err(ExecutionUnavailable);
        }
        std::fs::remove_dir_all(pending.workspace()).map_err(|_| ExecutionUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    use buzz_ci_isolation_contract::{PrincipalUids, RuntimeEndpointIdentity};
    use buzz_ci_materializer::{MaterializationLimits, Sha256Digest};
    use nix::unistd::{getegid, geteuid};
    use tempfile::TempDir;

    use super::*;

    fn fixed_now() -> Result<u64, ExecutionUnavailable> {
        Ok(20)
    }

    fn write_record<T: Serialize>(root: &Path, name: &str, value: &T) {
        let path = root.join(name);
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE)).unwrap();
    }

    #[test]
    fn descriptor_root_rejects_missing_symlink_mode_and_noncanonical_records() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let metadata = fs::metadata(root.path()).unwrap();
        let owner = ExpectedOwner {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        let source = DescriptorRoot::open(root.path(), owner).unwrap();
        assert!(source.read::<serde_json::Value>("missing.json").is_err());

        let target = root.path().join("target");
        fs::write(&target, b"{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        symlink(&target, root.path().join("link.json")).unwrap();
        assert!(source.read::<serde_json::Value>("link.json").is_err());

        let loose = root.path().join("loose.json");
        fs::write(&loose, b"{}").unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(source.read::<serde_json::Value>("loose.json").is_err());

        let padded = root.path().join("padded.json");
        fs::write(&padded, b"{ } ").unwrap();
        fs::set_permissions(&padded, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        assert!(source.read::<serde_json::Value>("padded.json").is_err());
    }

    #[test]
    fn policy_and_inputs_reject_credentials_and_digest_tampering() {
        let policy = MaterializationPolicyRecord {
            git_program: "/usr/bin/git".into(),
            git_exec_path: "/usr/libexec/git-core".into(),
            origins: BTreeMap::from([(
                format!("30617:{}:buzz", "a".repeat(64)),
                "https://user:pass@example.invalid/buzz.git".into(),
            )]),
            limits: MaterializationLimits {
                max_wire_bytes: 1,
                max_blob_bytes: 1,
                max_checkout_bytes: 1,
                max_entries: 1,
                max_path_bytes: 1,
                max_depth: 1,
                deadline_seconds: 1,
            },
        };
        assert!(policy.build().is_err());
        assert!(!canonical_non_secret_inputs(br#"{"secret":"value"}"#));
        assert!(!canonical_non_secret_inputs(
            br#"{"values":["AWS_SECRET_ACCESS_KEY"]}"#
        ));
        assert!(!canonical_non_secret_inputs(
            br#"{"env":["MY_TOKEN=value"]}"#
        ));
        assert!(canonical_non_secret_inputs(
            br#"{"note":"tokenize source","secretary":"public"}"#
        ));
        assert!(!canonical_non_secret_inputs(br#"{ "safe":1}"#));
        assert!(canonical_non_secret_inputs(br#"{"safe":1}"#));
    }

    #[test]
    fn record_names_are_lease_tokens_only() {
        assert!(safe_record_name("01ARZ3NDEKTSV4RRFFQ69G5FAV.json"));
        assert!(!safe_record_name("../lease.json"));
        assert!(!safe_record_name("lease/other.json"));
    }

    #[test]
    fn provider_binds_workspace_policy_inputs_and_consumes_once() {
        let authority = TempDir::new().unwrap();
        fs::set_permissions(authority.path(), fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let workspace_root = TempDir::new().unwrap();
        let workspace = workspace_root.path().join("attempt");
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(WORKSPACE_MODE)).unwrap();
        let workspace_metadata = fs::metadata(&workspace).unwrap();

        let fixture = crate::normal_engine::tests::ordinary_fixture();
        let mut plan = fixture.plan;
        let materializer_uid = geteuid().as_raw();
        plan.binding.principals = PrincipalUids {
            materializer: materializer_uid,
            executor: materializer_uid + 1,
            runtime: materializer_uid + 2,
        };
        plan.binding.workspace.path = workspace.display().to_string();
        plan.binding.workspace.owner_uid = materializer_uid;
        plan.binding.workspace.object.device = workspace_metadata.dev();
        plan.binding.workspace.object.inode = workspace_metadata.ino();
        plan.binding.runtime_endpoint = RuntimeEndpointIdentity::InheritedFd {
            token: "2".repeat(64),
            owner_uid: materializer_uid + 2,
        };
        plan.lease_record.workspace_dir = workspace.clone();
        plan.act.workflow_path = workspace.join("source/.github/workflows/ci.yml");
        let binding = plan
            .binding
            .clone()
            .validate_phase1(&plan.validation.context())
            .unwrap();

        let policy_record = MaterializationPolicyRecord {
            git_program: "/usr/bin/git".into(),
            git_exec_path: "/usr/libexec/git-core".into(),
            origins: BTreeMap::from([(
                binding.as_binding().target_repo_a.clone(),
                "https://example.invalid/buzz.git".into(),
            )]),
            limits: MaterializationLimits {
                max_wire_bytes: 1024,
                max_blob_bytes: 1024,
                max_checkout_bytes: 4096,
                max_entries: 10,
                max_path_bytes: 128,
                max_depth: 8,
                deadline_seconds: 30,
            },
        };
        let policy = policy_record.build().unwrap();
        let inputs = br#"{"safe":1}"#.to_vec();
        let expected = binding.as_binding();
        let manifest = MaterializationManifest {
            schema_version: 1,
            request_event_id: expected.request_event_id.clone(),
            run_id: expected.run_id.clone(),
            source_sha: expected.source_sha.clone(),
            job_id: expected.job_id.clone(),
            attempt: expected.attempt,
            repo_coordinate: expected.target_repo_a.clone(),
            workflow_id: expected.workflow_id.clone(),
            lease_id: expected.lease_id.clone(),
            tree_oid: expected.source_sha.clone(),
            trusted_base_sha: expected.base_oid.clone(),
            workflow_path: ".github/workflows/ci.yml".into(),
            workflow_sha256: Sha256Digest::parse(expected.workflow_digest.clone()).unwrap(),
            checkout_sha256: Sha256Digest::digest(b"checkout"),
            inputs_sha256: Sha256Digest::digest(&inputs),
            policy_sha256: policy.digest().clone(),
        };
        let unit = MaterializerUnitRecord {
            role: PrincipalRole::Materializer,
            uid: materializer_uid,
            unit_name: "buzzci-materializer.service".into(),
            cgroup_path: "/buzzci.slice/buzzci-materializer.service".into(),
            properties: BTreeMap::from([
                ("RuntimeDirectory".into(), "buzzci-materializer".into()),
                ("RuntimeDirectoryMode".into(), "0700".into()),
            ]),
            network_mode: UnitNetworkMode::BrokerNoEgressNamespace {
                path: "/run/netns/buzzci-test".into(),
            },
        };
        let record = MaterializationAuthorityRecord {
            schema_version: 1,
            lease_id: expected.lease_id.clone(),
            issued_at_unix_seconds: plan.validation.now_unix_seconds,
            expires_at_unix_seconds: expected.expires_at_unix_seconds,
            manifest,
            canonical_inputs: inputs,
            policy: policy_record,
            materializer_unit: unit,
            manifest_sha256: Digest32(plan.job_manifest_digest),
            input_digests: Vec::new(),
        };
        write_record(
            authority.path(),
            &format!("{}.json", expected.lease_id),
            &record,
        );

        let mut provider = MaterializationInputProvider::open_for_owner(
            authority.path(),
            geteuid().as_raw(),
            getegid().as_raw(),
            fixed_now,
        )
        .unwrap();
        provider.preflight(&plan, &binding).unwrap();
        let prepared = provider.prepare(&plan, &binding).unwrap();
        assert_eq!(
            prepared.workspace_directory.metadata().unwrap().ino(),
            workspace_metadata.ino()
        );
        assert_eq!(prepared.policy.digest(), &record.manifest.policy_sha256);
        assert!(provider.prepare(&plan, &binding).is_err());
        let mut restarted = MaterializationInputProvider::open_for_owner(
            authority.path(),
            geteuid().as_raw(),
            getegid().as_raw(),
            fixed_now,
        )
        .unwrap();
        assert!(restarted.preflight(&plan, &binding).is_err());

        let mut wrong_workflow = record.clone();
        wrong_workflow.manifest.workflow_path = ".github/workflows/other.yml".into();
        let wrong_workflow_root = TempDir::new().unwrap();
        fs::set_permissions(
            wrong_workflow_root.path(),
            fs::Permissions::from_mode(DIRECTORY_MODE),
        )
        .unwrap();
        write_record(
            wrong_workflow_root.path(),
            &format!("{}.json", expected.lease_id),
            &wrong_workflow,
        );
        let mut wrong_workflow_provider = MaterializationInputProvider::open_for_owner(
            wrong_workflow_root.path(),
            geteuid().as_raw(),
            getegid().as_raw(),
            fixed_now,
        )
        .unwrap();
        assert!(wrong_workflow_provider.preflight(&plan, &binding).is_err());

        let mut wrong_digest = record.clone();
        wrong_digest.manifest_sha256 = Digest32([42; 32]);
        let wrong_digest_root = TempDir::new().unwrap();
        fs::set_permissions(
            wrong_digest_root.path(),
            fs::Permissions::from_mode(DIRECTORY_MODE),
        )
        .unwrap();
        write_record(
            wrong_digest_root.path(),
            &format!("{}.json", expected.lease_id),
            &wrong_digest,
        );
        let mut wrong_digest_provider = MaterializationInputProvider::open_for_owner(
            wrong_digest_root.path(),
            geteuid().as_raw(),
            getegid().as_raw(),
            fixed_now,
        )
        .unwrap();
        assert!(wrong_digest_provider.preflight(&plan, &binding).is_err());

        let mut stale = record;
        stale.expires_at_unix_seconds -= 1;
        let stale_root = TempDir::new().unwrap();
        fs::set_permissions(
            stale_root.path(),
            fs::Permissions::from_mode(DIRECTORY_MODE),
        )
        .unwrap();
        write_record(
            stale_root.path(),
            &format!("{}.json", expected.lease_id),
            &stale,
        );
        let mut stale_provider = MaterializationInputProvider::open_for_owner(
            stale_root.path(),
            geteuid().as_raw(),
            getegid().as_raw(),
            fixed_now,
        )
        .unwrap();
        assert!(stale_provider.preflight(&plan, &binding).is_err());
    }
}
