use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};

use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{MaterializationLimits, MaterializationManifest, MaterializeError, Sha256Digest};

/// Broker-owned policy. None of these values may come from a CI request.
#[derive(Clone, Debug)]
pub struct RootOwnedPolicy {
    git_program: PathBuf,
    git_exec_path: PathBuf,
    origins: BTreeMap<String, Url>,
    limits: MaterializationLimits,
    digest: Sha256Digest,
}

impl RootOwnedPolicy {
    /// Build a root-owned policy after configuration loading.
    pub fn new(
        git_program: PathBuf,
        git_exec_path: PathBuf,
        origins: BTreeMap<String, Url>,
        limits: MaterializationLimits,
    ) -> Result<Self, MaterializeError> {
        validate_absolute_file_path("git_program", &git_program)?;
        validate_absolute_file_path("git_exec_path", &git_exec_path)?;
        limits.validate()?;
        if origins.is_empty() {
            return Err(MaterializeError::InvalidPolicy(
                "at least one repository coordinate is required".into(),
            ));
        }
        for (coordinate, origin) in &origins {
            if coordinate.is_empty() || origin.scheme() != "https" || origin.username() != "" {
                return Err(MaterializeError::InvalidPolicy(
                    "origins must be credential-free HTTPS URLs with non-empty coordinates".into(),
                ));
            }
            if origin.password().is_some()
                || origin.fragment().is_some()
                || origin.query().is_some()
            {
                return Err(MaterializeError::InvalidPolicy(
                    "origin URLs may not contain credentials, queries, or fragments".into(),
                ));
            }
        }
        let digest = policy_digest(&git_program, &git_exec_path, &origins, &limits)?;
        Ok(Self {
            git_program,
            git_exec_path,
            origins,
            limits,
            digest,
        })
    }

    /// Return the configured ceilings.
    pub fn limits(&self) -> &MaterializationLimits {
        &self.limits
    }

    /// Digest of the exact effective policy, using the frozen v1 encoding.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

/// A broker-created private slot for exactly one attempt.
#[derive(Debug)]
pub struct MaterializationSlot {
    workspace: PathBuf,
    workspace_directory: Option<File>,
    account_uid: u32,
    expected_device: u64,
    expected_inode: u64,
    request_event_id: String,
    run_id: String,
    repo_coordinate: String,
    source_sha: String,
    base_oid: String,
    workflow_id: String,
    workflow_digest: Sha256Digest,
    job_id: String,
    attempt: u32,
    lease_id: String,
    lease_expires_at_unix_seconds: u64,
    cgroup_token: String,
    netns_token: String,
}

impl MaterializationSlot {
    /// Bind an already-created broker workspace to one validated attempt lease.
    ///
    /// The device/inode and owner checks prevent a caller-selected pathname
    /// from joining the materializer to a different attempt capability.
    pub fn from_lease(
        lease: ValidatedAttemptLeaseBinding,
        workspace_directory: File,
    ) -> Result<Self, MaterializeError> {
        let workspace = PathBuf::from(&lease.as_binding().workspace.path);
        validate_absolute_file_path("workspace", &workspace)?;
        let binding = lease.as_binding();
        let metadata = workspace_directory.metadata()?;
        let path_metadata = fs::symlink_metadata(&workspace)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != binding.principals.materializer
            || metadata.dev() != binding.workspace.object.device
            || metadata.ino() != binding.workspace.object.inode
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
        {
            return Err(MaterializeError::InvalidPolicy(
                "workspace does not match the broker-issued materializer capability".into(),
            ));
        }
        Ok(Self {
            workspace,
            workspace_directory: Some(workspace_directory),
            account_uid: binding.principals.materializer,
            expected_device: binding.workspace.object.device,
            expected_inode: binding.workspace.object.inode,
            request_event_id: binding.request_event_id.clone(),
            run_id: binding.run_id.clone(),
            repo_coordinate: binding.target_repo_a.clone(),
            source_sha: binding.source_sha.clone(),
            base_oid: binding.base_oid.clone(),
            workflow_id: binding.workflow_id.clone(),
            workflow_digest: Sha256Digest::parse(binding.workflow_digest.clone())?,
            job_id: binding.job_id.clone(),
            attempt: binding.attempt,
            lease_id: binding.lease_id.clone(),
            lease_expires_at_unix_seconds: binding.expires_at_unix_seconds,
            cgroup_token: binding.cgroup.object.token.clone(),
            netns_token: binding.netns.object.token.clone(),
        })
    }

    /// Private attempt workspace selected by the broker.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Linux procfs path anchored to the broker-passed workspace descriptor.
    pub(crate) fn filesystem_root(&self) -> Result<PathBuf, MaterializeError> {
        let directory = self.workspace_directory.as_ref().ok_or_else(|| {
            MaterializeError::InvalidPolicy(
                "production materialization requires a broker-passed workspace descriptor".into(),
            )
        })?;
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}",
            directory.as_raw_fd()
        )))
    }

    /// Dedicated materializer account UID.
    pub fn account_uid(&self) -> u32 {
        self.account_uid
    }

    pub(crate) fn verify_manifest(
        &self,
        manifest: &MaterializationManifest,
    ) -> Result<(), MaterializeError> {
        if manifest.request_event_id != self.request_event_id
            || manifest.run_id != self.run_id
            || manifest.repo_coordinate != self.repo_coordinate
            || manifest.source_sha != self.source_sha
            || manifest.trusted_base_sha != self.base_oid
            || manifest.workflow_id != self.workflow_id
            || manifest.workflow_sha256 != self.workflow_digest
            || manifest.job_id != self.job_id
            || manifest.attempt != self.attempt
            || manifest.lease_id != self.lease_id
        {
            return Err(MaterializeError::InvalidPolicy(
                "materialization manifest does not match the validated attempt lease".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn verify_workspace_metadata(
        &self,
        metadata: &fs::Metadata,
    ) -> Result<(), MaterializeError> {
        if !metadata.file_type().is_dir()
            || metadata.uid() != self.account_uid
            || (self.expected_device != 0 && metadata.dev() != self.expected_device)
            || (self.expected_inode != 0 && metadata.ino() != self.expected_inode)
        {
            return Err(MaterializeError::InvalidPolicy(
                "workspace does not match the broker-issued materializer capability".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn verify_workspace_descriptor(&self) -> Result<(), MaterializeError> {
        let directory = self.workspace_directory.as_ref().ok_or_else(|| {
            MaterializeError::InvalidPolicy(
                "production materialization requires a broker-passed workspace descriptor".into(),
            )
        })?;
        self.verify_workspace_metadata(&directory.metadata()?)
    }

    pub(crate) fn workspace_directory(&self) -> Result<&File, MaterializeError> {
        self.workspace_directory.as_ref().ok_or_else(|| {
            MaterializeError::InvalidPolicy(
                "production materialization requires a broker-passed workspace descriptor".into(),
            )
        })
    }

    pub(crate) fn lease_expires_at_unix_seconds(&self) -> u64 {
        self.lease_expires_at_unix_seconds
    }

    pub(crate) fn take_workspace_directory(&mut self) -> Result<File, MaterializeError> {
        self.workspace_directory.take().ok_or_else(|| {
            MaterializeError::InvalidPolicy(
                "production materialization requires a broker-passed workspace descriptor".into(),
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(workspace: PathBuf, account_uid: u32) -> Self {
        let workspace_directory = File::open(&workspace).or_else(|_| File::open(".")).ok();
        Self {
            workspace,
            workspace_directory,
            account_uid,
            expected_device: 0,
            expected_inode: 0,
            request_event_id: "f".repeat(64),
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            repo_coordinate: format!("30617:{}:buzz", "e".repeat(64)),
            source_sha: "a".repeat(40),
            base_oid: "c".repeat(40),
            workflow_id: "required-ci".into(),
            workflow_digest: Sha256Digest::parse("d".repeat(64)).unwrap(),
            job_id: "linux".into(),
            attempt: 1,
            lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            lease_expires_at_unix_seconds: u64::MAX,
            cgroup_token: "3".repeat(64),
            netns_token: "4".repeat(64),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_expiry_for_test(&mut self, expiry: u64) {
        self.lease_expires_at_unix_seconds = expiry;
    }

    #[cfg(test)]
    pub(crate) fn set_workflow_digest_for_test(&mut self, digest: Sha256Digest) {
        self.workflow_digest = digest;
    }
}

/// A command whose executable, arguments, environment, and cwd are completely
/// broker-derived. The executor must honor `clear_environment` before applying
/// `environment`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    /// Root-owned absolute executable.
    pub program: PathBuf,
    /// Exact argument vector.
    pub arguments: Vec<String>,
    /// Private cwd.
    pub current_dir: PathBuf,
    /// Whether the child starts with an empty environment.
    pub clear_environment: bool,
    /// Minimal broker-owned environment.
    pub environment: BTreeMap<String, String>,
    /// Dedicated unprivileged UID under which the backend must execute.
    pub required_uid: u32,
    /// Exact broker lease whose cgroup/network cleanup must be proven.
    pub lease_id: String,
    /// Capability token of the exact materializer cgroup.
    pub cgroup_token: String,
    /// Capability token of the exact root-owned network namespace.
    pub netns_token: String,
    /// Absolute lease expiry; the backend must not start or outlive it.
    pub lease_expires_at_unix_seconds: u64,
    /// Maximum stdout bytes the backend may retain.
    pub maximum_stdout_bytes: u64,
    /// Maximum stderr bytes the backend may retain.
    pub maximum_stderr_bytes: u64,
    /// Maximum wall time for this invocation.
    pub deadline_millis: u64,
    /// Whether this command may use the broker-metered origin egress grant.
    pub network: NetworkScope,
    /// Maximum root-metered network bytes for this command.
    pub maximum_network_bytes: u64,
}

/// Network grant associated with one exact command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkScope {
    /// No network access is permitted.
    None,
    /// Access only to the root-owned origin route is permitted and metered.
    Origin {
        /// Exact root-owned credential-free HTTPS URL admitted for this fetch.
        url: String,
    },
}

/// Ordered Git operations for one materialization.
#[derive(Clone, Debug)]
pub(crate) struct MaterializationPlan {
    /// Private bare repository path.
    pub bare_repository: PathBuf,
    /// Private staging tree path.
    pub staging_tree: PathBuf,
    /// Atomic destination path.
    pub destination_tree: PathBuf,
    /// Git commands in their required order.
    pub commands: Vec<CommandSpec>,
    expected_source_sha: String,
    expected_tree_oid: String,
    expected_trusted_base_sha: String,
    git_program: PathBuf,
    git_dir_argument: String,
    environment: BTreeMap<String, String>,
    deadline_millis: u64,
    maximum_blob_bytes: u64,
}

impl MaterializationPlan {
    /// Construct a plan without executing or contacting the origin.
    pub(crate) fn build(
        manifest: &MaterializationManifest,
        policy: &RootOwnedPolicy,
        slot: &MaterializationSlot,
    ) -> Result<Self, MaterializeError> {
        manifest.validate()?;
        if &manifest.policy_sha256 != policy.digest() {
            return Err(MaterializeError::DigestMismatch {
                field: "policy_sha256",
                expected: manifest.policy_sha256.as_str().into(),
                actual: policy.digest().as_str().into(),
            });
        }
        let origin = policy
            .origins
            .get(&manifest.repo_coordinate)
            .ok_or_else(|| {
                MaterializeError::InvalidPolicy("repository coordinate is not allowlisted".into())
            })?;
        let filesystem_root = slot.filesystem_root()?;
        let bare_repository = filesystem_root.join("objects.git");
        let staging_tree = filesystem_root.join("staging");
        let destination_tree = filesystem_root.join("source");
        let environment = hardened_environment(policy);
        let deadline_millis = policy
            .limits
            .deadline_seconds
            .checked_mul(1_000)
            .ok_or_else(|| MaterializeError::InvalidPolicy("deadline overflow".into()))?;
        let ls_tree_output_limit = u64::from(policy.limits.max_entries)
            .checked_mul(u64::from(policy.limits.max_path_bytes) + 160)
            .ok_or_else(|| {
                MaterializeError::InvalidPolicy("ls-tree output limit overflow".into())
            })?;
        let git = |arguments: Vec<String>, maximum_stdout_bytes: u64, network: NetworkScope| {
            let maximum_network_bytes = if matches!(&network, NetworkScope::Origin { .. }) {
                policy.limits.max_wire_bytes
            } else {
                0
            };
            CommandSpec {
                program: policy.git_program.clone(),
                arguments,
                current_dir: filesystem_root.clone(),
                clear_environment: true,
                environment: environment.clone(),
                required_uid: slot.account_uid(),
                lease_id: slot.lease_id.clone(),
                cgroup_token: slot.cgroup_token.clone(),
                netns_token: slot.netns_token.clone(),
                lease_expires_at_unix_seconds: slot.lease_expires_at_unix_seconds,
                maximum_stdout_bytes,
                maximum_stderr_bytes: 64 * 1024,
                deadline_millis,
                network,
                maximum_network_bytes,
            }
        };
        // Keep Git's own paths relative to the descriptor-anchored cwd. The
        // workspace fd is close-on-exec, so an absolute /proc/self/fd path
        // would disappear after exec even though the pre-exec chdir remains.
        let git_dir = "--git-dir=objects.git".to_string();
        let candidate = "refs/buzz/materialize/candidate";
        let trusted_base = "refs/buzz/materialize/trusted-base";
        let commands = vec![
            git(
                vec![git_dir.clone(), "init".into(), "--bare".into()],
                4 * 1024,
                NetworkScope::None,
            ),
            git(
                vec![
                    git_dir.clone(),
                    "-c".into(),
                    "protocol.allow=never".into(),
                    "-c".into(),
                    "protocol.https.allow=always".into(),
                    "-c".into(),
                    "protocol.http.allow=never".into(),
                    "-c".into(),
                    "protocol.ext.allow=never".into(),
                    "-c".into(),
                    "protocol.file.allow=never".into(),
                    "-c".into(),
                    "core.hooksPath=/dev/null".into(),
                    "-c".into(),
                    "core.fsmonitor=false".into(),
                    "-c".into(),
                    "credential.helper=".into(),
                    "-c".into(),
                    "http.followRedirects=false".into(),
                    "-c".into(),
                    "http.proxy=".into(),
                    "-c".into(),
                    "submodule.recurse=false".into(),
                    "-c".into(),
                    "filter.lfs.smudge=".into(),
                    "-c".into(),
                    "filter.lfs.process=".into(),
                    "-c".into(),
                    "filter.lfs.required=false".into(),
                    "fetch".into(),
                    "--no-tags".into(),
                    "--no-recurse-submodules".into(),
                    "--no-write-fetch-head".into(),
                    "--depth=1".into(),
                    origin.as_str().into(),
                    format!("+{}:{candidate}", manifest.source_sha),
                    format!("+{}:{trusted_base}", manifest.trusted_base_sha),
                ],
                4 * 1024,
                NetworkScope::Origin {
                    url: origin.as_str().into(),
                },
            ),
            git(
                vec![
                    git_dir.clone(),
                    "rev-parse".into(),
                    "--verify".into(),
                    "--end-of-options".into(),
                    format!("{candidate}^{{commit}}"),
                ],
                129,
                NetworkScope::None,
            ),
            git(
                vec![
                    git_dir.clone(),
                    "rev-parse".into(),
                    "--verify".into(),
                    "--end-of-options".into(),
                    format!("{candidate}^{{tree}}"),
                ],
                129,
                NetworkScope::None,
            ),
            git(
                vec![
                    git_dir.clone(),
                    "rev-parse".into(),
                    "--verify".into(),
                    "--end-of-options".into(),
                    format!("{trusted_base}^{{commit}}"),
                ],
                129,
                NetworkScope::None,
            ),
            git(
                vec![
                    git_dir.clone(),
                    "ls-tree".into(),
                    "-r".into(),
                    "-z".into(),
                    "-l".into(),
                    "--full-tree".into(),
                    candidate.into(),
                ],
                ls_tree_output_limit,
                NetworkScope::None,
            ),
            git(
                vec![
                    git_dir.clone(),
                    "show".into(),
                    format!("{trusted_base}:{}", manifest.workflow_path),
                ],
                policy.limits.max_blob_bytes,
                NetworkScope::None,
            ),
        ];
        Ok(Self {
            bare_repository,
            staging_tree,
            destination_tree,
            commands,
            expected_source_sha: manifest.source_sha.clone(),
            expected_tree_oid: manifest.tree_oid.clone(),
            expected_trusted_base_sha: manifest.trusted_base_sha.clone(),
            git_program: policy.git_program.clone(),
            git_dir_argument: git_dir,
            environment,
            deadline_millis,
            maximum_blob_bytes: policy.limits.max_blob_bytes,
        })
    }

    /// Verify the exact `rev-parse` outputs before any blob is materialized.
    pub(crate) fn verify_readbacks(
        &self,
        commit_stdout: &[u8],
        tree_stdout: &[u8],
        trusted_base_stdout: &[u8],
    ) -> Result<(), MaterializeError> {
        verify_single_readback("source_sha", &self.expected_source_sha, commit_stdout)?;
        verify_single_readback("tree_oid", &self.expected_tree_oid, tree_stdout)?;
        verify_single_readback(
            "trusted_base_sha",
            &self.expected_trusted_base_sha,
            trusted_base_stdout,
        )
    }

    pub(crate) fn blob_command(&self, object_id: &str) -> Result<CommandSpec, MaterializeError> {
        let current_dir = self.bare_repository.parent().ok_or_else(|| {
            MaterializeError::InvalidPolicy("bare repository lacks a workspace parent".into())
        })?;
        Ok(CommandSpec {
            program: self.git_program.clone(),
            arguments: vec![
                self.git_dir_argument.clone(),
                "cat-file".into(),
                "blob".into(),
                object_id.into(),
            ],
            current_dir: current_dir.to_path_buf(),
            clear_environment: true,
            environment: self.environment.clone(),
            required_uid: self
                .commands
                .first()
                .map(|command| command.required_uid)
                .ok_or_else(|| MaterializeError::InvalidPolicy("empty Git plan".into()))?,
            lease_id: self.commands[0].lease_id.clone(),
            cgroup_token: self.commands[0].cgroup_token.clone(),
            netns_token: self.commands[0].netns_token.clone(),
            lease_expires_at_unix_seconds: self.commands[0].lease_expires_at_unix_seconds,
            maximum_stdout_bytes: self.maximum_blob_bytes,
            maximum_stderr_bytes: 64 * 1024,
            deadline_millis: self.deadline_millis,
            network: NetworkScope::None,
            maximum_network_bytes: 0,
        })
    }
}

fn policy_digest(
    git_program: &Path,
    git_exec_path: &Path,
    origins: &BTreeMap<String, Url>,
    limits: &MaterializationLimits,
) -> Result<Sha256Digest, MaterializeError> {
    let mut hasher = Sha256::new();
    hasher.update(b"buzz-ci-materializer-policy-v1\0");
    for value in [git_program, git_exec_path] {
        let value = value
            .to_str()
            .ok_or_else(|| MaterializeError::InvalidPolicy("policy paths must be UTF-8".into()))?;
        hash_field(&mut hasher, value.as_bytes());
    }
    for (coordinate, origin) in origins {
        hash_field(&mut hasher, coordinate.as_bytes());
        hash_field(&mut hasher, origin.as_str().as_bytes());
    }
    hasher.update(limits.max_wire_bytes.to_be_bytes());
    hasher.update(limits.max_blob_bytes.to_be_bytes());
    hasher.update(limits.max_checkout_bytes.to_be_bytes());
    hasher.update(limits.max_entries.to_be_bytes());
    hasher.update(limits.max_path_bytes.to_be_bytes());
    hasher.update(limits.max_depth.to_be_bytes());
    hasher.update(limits.deadline_seconds.to_be_bytes());
    Sha256Digest::parse(hex::encode(hasher.finalize()))
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn verify_single_readback(
    field: &'static str,
    expected: &str,
    stdout: &[u8],
) -> Result<(), MaterializeError> {
    if stdout.len() > 129 {
        return Err(MaterializeError::ResourceLimit(format!(
            "{field} readback bytes"
        )));
    }
    let actual = std::str::from_utf8(stdout)
        .map_err(|_| MaterializeError::InvalidManifest(format!("{field} readback is not UTF-8")))?;
    let actual = actual.strip_suffix('\n').unwrap_or(actual);
    if actual.contains(['\r', '\n']) || actual != expected {
        return Err(MaterializeError::DigestMismatch {
            field,
            expected: expected.into(),
            actual: actual.into(),
        });
    }
    Ok(())
}

fn hardened_environment(policy: &RootOwnedPolicy) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("PATH".into(), "/usr/bin:/bin".into()),
        (
            "GIT_EXEC_PATH".into(),
            policy.git_exec_path.display().to_string(),
        ),
        // The backend fchdirs to the pinned workspace before exec. Cwd survives
        // exec even when the workspace descriptor is CLOEXEC; a procfd HOME
        // would not.
        ("HOME".into(), "/proc/self/cwd/home".into()),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ("GIT_ASKPASS".into(), "/bin/false".into()),
        ("SSH_ASKPASS".into(), "/bin/false".into()),
        ("GIT_LFS_SKIP_SMUDGE".into(), "1".into()),
    ])
}

fn validate_absolute_file_path(name: &str, value: &Path) -> Result<(), MaterializeError> {
    if !value.is_absolute()
        || value
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(MaterializeError::InvalidPolicy(format!(
            "{name} must be an absolute path without parent traversal"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sha256Digest;
    use buzz_ci_isolation_contract::{
        AttemptLeaseBinding, BrokerObjectHandle, CgroupHandle, EngineKind, IsolationProfile,
        NetnsHandle, NetworkPolicy, Phase1ValidationContext, PrincipalUids, QuotaBackend,
        QuotaHandle, ResourceLimits, RuntimeEndpointIdentity, WorkspaceHandle,
    };
    use std::os::unix::fs::PermissionsExt;

    fn manifest() -> MaterializationManifest {
        MaterializationManifest {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            source_sha: "a".repeat(40),
            job_id: "linux".into(),
            attempt: 1,
            repo_coordinate: format!("30617:{}:buzz", "e".repeat(64)),
            workflow_id: "required-ci".into(),
            lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            tree_oid: "b".repeat(40),
            trusted_base_sha: "c".repeat(40),
            workflow_path: ".github/workflows/ci.yml".into(),
            workflow_sha256: Sha256Digest::parse("d".repeat(64)).unwrap(),
            checkout_sha256: Sha256Digest::parse("e".repeat(64)).unwrap(),
            inputs_sha256: Sha256Digest::parse("f".repeat(64)).unwrap(),
            policy_sha256: Sha256Digest::parse("1".repeat(64)).unwrap(),
        }
    }

    fn policy() -> RootOwnedPolicy {
        RootOwnedPolicy::new(
            "/usr/bin/git".into(),
            "/usr/libexec/git-core".into(),
            BTreeMap::from([(
                format!("30617:{}:buzz", "e".repeat(64)),
                Url::parse("https://relay.example/git/owner/repo").unwrap(),
            )]),
            MaterializationLimits {
                max_wire_bytes: 1_000_000,
                max_blob_bytes: 100_000,
                max_checkout_bytes: 500_000,
                max_entries: 100,
                max_path_bytes: 200,
                max_depth: 20,
                deadline_seconds: 60,
            },
        )
        .unwrap()
    }

    fn manifest_for(policy: &RootOwnedPolicy) -> MaterializationManifest {
        let mut manifest = manifest();
        manifest.policy_sha256 = policy.digest().clone();
        manifest
    }

    #[test]
    fn slot_requires_the_validated_workspace_capability() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("attempt");
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::symlink_metadata(&workspace).unwrap();
        let uid = metadata.uid();
        let token = |byte: char| byte.to_string().repeat(64);
        let limits = ResourceLimits {
            cpu_weight: 100,
            mem_max_bytes: 1024 * 1024,
            pids_max: 32,
            io_weight: 100,
        };
        let binding = AttemptLeaseBinding {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            target_repo_a: format!("30617:{}:buzz", "e".repeat(64)),
            source_sha: "a".repeat(40),
            base_oid: "c".repeat(40),
            workflow_id: "required-ci".into(),
            workflow_digest: "d".repeat(64),
            job_id: "linux".into(),
            attempt: 1,
            lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            expires_at_unix_seconds: 1_060,
            principals: PrincipalUids {
                materializer: uid,
                executor: uid.saturating_add(1),
                runtime: uid.saturating_add(2),
            },
            workspace: WorkspaceHandle {
                path: workspace.display().to_string(),
                object: BrokerObjectHandle {
                    token: token('1'),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
                owner_uid: uid,
                quota_token: token('5'),
            },
            runtime_endpoint: RuntimeEndpointIdentity::InheritedFd {
                token: token('2'),
                owner_uid: uid.saturating_add(2),
            },
            cgroup: CgroupHandle {
                object: BrokerObjectHandle {
                    token: token('3'),
                    device: metadata.dev().saturating_add(1),
                    inode: metadata.ino().saturating_add(1),
                },
                limits: limits.clone(),
            },
            netns: NetnsHandle {
                object: BrokerObjectHandle {
                    token: token('4'),
                    device: metadata.dev().saturating_add(2),
                    inode: metadata.ino().saturating_add(2),
                },
                name: "buzzci-run-1".into(),
            },
            quota: QuotaHandle {
                token: token('5'),
                backend: QuotaBackend::BoundedFilesystem,
                quota_id: "quota-1".into(),
                hard_bytes: 1024 * 1024,
            },
            isolation_profile: IsolationProfile {
                image_digest: format!("sha256:{}", "b".repeat(64)),
                engine_kind: EngineKind::Podman,
                engine_version: "5.8.4".into(),
                arch: "x86_64".into(),
                limits,
                network_policy: NetworkPolicy::None,
                service_requirements: Vec::new(),
                netns: "buzzci-run-1".into(),
            },
        };
        let lease = binding
            .validate_phase1(&Phase1ValidationContext {
                now_unix_seconds: 1_000,
                max_expiry_horizon_seconds: 300,
                forbidden_host_uids: &[],
                expected_engine_version: "5.8.4",
                expected_arch: "x86_64",
            })
            .unwrap();

        let slot = MaterializationSlot::from_lease(lease.clone(), File::open(&workspace).unwrap())
            .unwrap();
        assert!(slot.verify_manifest(&manifest()).is_ok());
        let mut mismatches = Vec::new();
        let mut request = manifest();
        request.request_event_id = "1".repeat(64);
        mismatches.push(request);
        let mut repo = manifest();
        repo.repo_coordinate = format!("30617:{}:other", "e".repeat(64));
        mismatches.push(repo);
        let mut base = manifest();
        base.trusted_base_sha = "1".repeat(40);
        mismatches.push(base);
        let mut workflow = manifest();
        workflow.workflow_id = "other".into();
        mismatches.push(workflow);
        let mut workflow_digest = manifest();
        workflow_digest.workflow_sha256 = Sha256Digest::parse("1".repeat(64)).unwrap();
        mismatches.push(workflow_digest);
        let mut lease_id = manifest();
        lease_id.lease_id = "01ARZ3NDEKTSV4RRFFQ69G5FAA".into();
        mismatches.push(lease_id);
        assert!(mismatches
            .iter()
            .all(|manifest| slot.verify_manifest(manifest).is_err()));
        let mut wrong = lease.into_binding();
        wrong.workspace.object.inode = wrong.workspace.object.inode.saturating_add(9);
        let wrong = wrong
            .validate_phase1(&Phase1ValidationContext {
                now_unix_seconds: 1_000,
                max_expiry_horizon_seconds: 300,
                forbidden_host_uids: &[],
                expected_engine_version: "5.8.4",
                expected_arch: "x86_64",
            })
            .unwrap();
        assert!(MaterializationSlot::from_lease(wrong, File::open(&workspace).unwrap()).is_err());
    }

    #[test]
    fn plan_clears_environment_and_never_checks_out() {
        let slot = MaterializationSlot::for_test("/var/lib/buzz-ci/slot/stage".into(), 990);
        let policy = policy();
        let plan = MaterializationPlan::build(&manifest_for(&policy), &policy, &slot).unwrap();
        assert!(plan
            .commands
            .iter()
            .all(|command| command.clear_environment));
        let joined = plan
            .commands
            .iter()
            .flat_map(|command| &command.arguments)
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        for forbidden_command in ["clone", "checkout", "archive", "submodule", "lfs"] {
            assert!(
                !plan.commands.iter().any(|command| command
                    .arguments
                    .iter()
                    .any(|argument| argument == forbidden_command)),
                "plan invokes forbidden command {forbidden_command}: {joined}"
            );
        }
        assert!(joined.contains("--no-recurse-submodules"));
        assert_eq!(plan.commands[1].environment["GIT_CONFIG_NOSYSTEM"], "1");
        assert!(plan
            .verify_readbacks(
                format!("{}\n", "a".repeat(40)).as_bytes(),
                format!("{}\n", "b".repeat(40)).as_bytes(),
                format!("{}\n", "c".repeat(40)).as_bytes()
            )
            .is_ok());
        assert!(plan
            .verify_readbacks(
                format!("{}\n", "f".repeat(40)).as_bytes(),
                format!("{}\n", "b".repeat(40)).as_bytes(),
                format!("{}\n", "c".repeat(40)).as_bytes()
            )
            .is_err());
    }

    #[test]
    fn request_cannot_choose_a_url() {
        let mut manifest = manifest();
        manifest.repo_coordinate = "https://attacker.example/repo".into();
        let slot = MaterializationSlot::for_test("/var/lib/buzz-ci/slot/stage".into(), 990);
        let policy = policy();
        manifest.policy_sha256 = policy.digest().clone();
        assert!(MaterializationPlan::build(&manifest, &policy, &slot).is_err());
    }
}
