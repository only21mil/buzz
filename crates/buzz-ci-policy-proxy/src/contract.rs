use serde::{Deserialize, Serialize};

use buzz_ci_isolation_contract::{PHASE1_SECCOMP_PROFILE_DIGEST, PHASE1_SECCOMP_PROFILE_PATH};
use std::{collections::BTreeSet, path::Component};

use crate::ProxyError;

const RESERVED_ENVIRONMENT: [&str; 3] = ["BUZZ_CI_RUN_ID", "BUZZ_CI_SHA", "BUZZ_CI_ATTEMPT"];
const FORBIDDEN_ENVIRONMENT: [&str; 8] = [
    "BUZZ_PRIVATE_KEY",
    "BUZZ_AUTH_TAG",
    "NOSTR_PRIVATE_KEY",
    "GITHUB_TOKEN",
    "SSH_AUTH_SOCK",
    "DOCKER_HOST",
    "CONTAINER_HOST",
    "XDG_RUNTIME_DIR",
];

/// Runtime implementation frozen by the signed isolation profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    /// Rootless Podman through its Docker-compatible API.
    Podman,
}

/// Root-owned execution network policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No configured network interface and no runtime fetches.
    None,
    /// Reserved for a later separately reviewed selective-egress lane.
    Allowlist,
}

/// Hard cgroup/container limits bound into the signed manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationLimits {
    /// CPU quota in microseconds per 100,000 microsecond period.
    pub cpu_quota_micros: u64,
    /// Hard memory ceiling.
    pub memory_max_bytes: u64,
    /// Swap ceiling. Phase 1 requires zero.
    pub memory_swap_max_bytes: u64,
    /// Hard PID ceiling.
    pub pids_max: u64,
    /// Shared-memory ceiling.
    pub shm_size_bytes: u64,
    /// Attempt disk ceiling.
    pub disk_max_bytes: u64,
    /// Wall-clock deadline.
    pub timeout_seconds: u64,
}

impl IsolationLimits {
    fn validate(&self) -> Result<(), ProxyError> {
        if self.memory_swap_max_bytes != 0 {
            return Err(ProxyError::InvalidManifest(
                "Phase 1 requires memory_swap_max_bytes=0".into(),
            ));
        }
        if [
            self.cpu_quota_micros,
            self.memory_max_bytes,
            self.pids_max,
            self.shm_size_bytes,
            self.disk_max_bytes,
            self.timeout_seconds,
        ]
        .contains(&0)
        {
            return Err(ProxyError::InvalidManifest(
                "all isolation limits except swap must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

/// A single exact broker-enumerated bind mount.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedMount {
    /// Broker-owned source path.
    pub source: String,
    /// Exact container destination.
    pub destination: String,
    /// Phase 1 requires read-only source mounts.
    pub read_only: bool,
}

/// Hermes v1.1 `isolation_profile`, expanded by the lease lane.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationProfile {
    /// Digest-pinned act runner image (`sha256:<64 lowercase hex>`).
    pub image_digest: String,
    /// Fixed engine implementation.
    pub engine_kind: EngineKind,
    /// Exact qualified engine version.
    pub engine_version: String,
    /// Exact qualified architecture.
    pub arch: String,
    /// Broker-provisioned content-addressed seccomp profile path.
    pub seccomp_profile_path: String,
    /// SHA-256 digest of the broker-provisioned seccomp profile bytes.
    pub seccomp_profile_digest: String,
    /// Resource ceilings.
    pub limits: IsolationLimits,
    /// Root-owned execution network policy.
    pub network_policy: NetworkPolicy,
    /// Phase 1 requires no service containers.
    pub service_requirements: Vec<String>,
    /// Root-owned attempt network namespace identifier.
    pub netns: String,
}

impl IsolationProfile {
    fn validate(&self) -> Result<(), ProxyError> {
        validate_digest("image_digest", &self.image_digest)?;
        if self.engine_version.is_empty() || self.arch.is_empty() || self.netns.is_empty() {
            return Err(ProxyError::InvalidManifest(
                "engine_version, arch, and netns are required".into(),
            ));
        }
        if self.seccomp_profile_path != PHASE1_SECCOMP_PROFILE_PATH
            || self.seccomp_profile_digest != PHASE1_SECCOMP_PROFILE_DIGEST
        {
            return Err(ProxyError::InvalidManifest(
                "seccomp profile does not match the Phase-1 content-addressed profile".into(),
            ));
        }
        if self.network_policy != NetworkPolicy::None {
            return Err(ProxyError::InvalidManifest(
                "Phase 1 accepts network_policy=none only".into(),
            ));
        }
        if !self.service_requirements.is_empty() {
            return Err(ProxyError::InvalidManifest(
                "Phase 1 refuses service containers".into(),
            ));
        }
        self.limits.validate()
    }
}

/// One manifest-bound class of Docker exec-create request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecExpectation {
    /// Exact non-empty argument vector.
    pub argv: Vec<String>,
    /// Exact non-secret caller environment before proxy identity injection.
    #[serde(default)]
    pub environment: Vec<String>,
    /// Exact numeric non-root UID:GID.
    pub user: String,
    /// Exact canonical absolute working directory.
    pub working_dir: String,
    /// Whether the executor may send stdin bytes after hijack.
    #[serde(default)]
    pub attach_stdin: bool,
    /// Whether stdout is attached.
    #[serde(default)]
    pub attach_stdout: bool,
    /// Whether stderr is attached.
    #[serde(default)]
    pub attach_stderr: bool,
    /// Whether Docker multiplexing is disabled for a TTY stream.
    #[serde(default)]
    pub tty: bool,
}

/// Immutable policy installed by the trusted broker for one attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifest {
    /// Frozen policy schema. Phase 1 accepts version 1 only.
    pub schema_version: u16,
    /// Exact accepted kind-46100 request event ID.
    pub request_event_id: String,
    /// Hermes `run` field.
    pub run_id: String,
    /// Exact NIP-33 repository coordinate from the accepted request.
    pub target_repo_a: String,
    /// Hermes `c` tip: full exact commit.
    pub sha: String,
    /// Trusted base commit that owns the workflow bytes.
    pub base_oid: String,
    /// Exact static workflow identifier.
    pub workflow_id: String,
    /// SHA-256 of the trusted-base workflow bytes.
    pub workflow_digest: String,
    /// Hermes `job` field.
    pub job_id: String,
    /// Hermes attempt number.
    pub attempt: u32,
    /// Broker-issued per-job isolation lease identifier.
    pub lease_id: String,
    /// Digest of the complete signed job manifest.
    pub manifest_digest: String,
    /// Runtime isolation profile.
    pub isolation_profile: IsolationProfile,
    /// Numeric non-root UID:GID used inside job containers.
    pub container_user: String,
    /// Exact broker-enumerated mounts.
    pub mounts: Vec<AllowedMount>,
    /// Exact non-secret environment names the executor may provide.
    ///
    /// An empty list is the secure default: only proxy-injected attempt
    /// identity variables reach the container.
    #[serde(default)]
    pub allowed_environment: Vec<String>,
    /// Exact exec-create classes derived from the signed job manifest.
    ///
    /// An empty list keeps exec creation closed.
    #[serde(default)]
    pub expected_execs: Vec<ExecExpectation>,
}

impl PolicyManifest {
    /// Validate the immutable manifest before the proxy becomes ready.
    pub fn validate(&self) -> Result<(), ProxyError> {
        if self.schema_version != 1 {
            return Err(ProxyError::InvalidManifest(
                "only schema_version 1 is accepted".into(),
            ));
        }
        for (name, value) in [
            ("request_event_id", self.request_event_id.as_str()),
            ("run_id", self.run_id.as_str()),
            ("target_repo_a", self.target_repo_a.as_str()),
            ("workflow_id", self.workflow_id.as_str()),
            ("job_id", self.job_id.as_str()),
            ("lease_id", self.lease_id.as_str()),
        ] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(ProxyError::InvalidManifest(format!(
                    "{name} is empty, too long, or contains controls"
                )));
            }
        }
        validate_object_id(&self.sha)?;
        validate_object_id(&self.base_oid)?;
        if self.sha.len() != self.base_oid.len() {
            return Err(ProxyError::InvalidManifest(
                "tip and base object IDs must use the same width".into(),
            ));
        }
        validate_protocol_digest("workflow_digest", &self.workflow_digest)?;
        validate_digest("manifest_digest", &self.manifest_digest)?;
        if self.attempt == 0 {
            return Err(ProxyError::InvalidManifest(
                "attempt must be at least 1".into(),
            ));
        }
        let parts = self.container_user.split(':').collect::<Vec<_>>();
        if parts.len() != 2
            || parts.iter().any(|part| {
                part.parse::<u32>()
                    .map_or(true, |value| value == 0 || value == 1000)
            })
        {
            return Err(ProxyError::InvalidManifest(
                "container_user must be a dedicated numeric non-root UID:GID".into(),
            ));
        }
        if self.mounts.iter().any(|mount| {
            !mount.read_only
                || !mount.source.starts_with("/var/lib/buzz-ci/")
                || !is_normal_absolute_path(&mount.source)
                || !is_normal_absolute_path(&mount.destination)
                || mount
                    .source
                    .chars()
                    .any(|character| matches!(character, ':' | '\\' | '\n' | '\r' | '\0'))
                || mount
                    .destination
                    .chars()
                    .any(|character| matches!(character, ':' | '\\' | '\n' | '\r' | '\0'))
                || is_socket_path(&mount.source)
                || is_socket_path(&mount.destination)
        }) {
            return Err(ProxyError::InvalidManifest(
                "mounts must be read-only, broker-rooted, canonical, and socket-name-free".into(),
            ));
        }
        let mut destinations = BTreeSet::new();
        if self
            .mounts
            .iter()
            .any(|mount| !destinations.insert(mount.destination.as_str()))
        {
            return Err(ProxyError::InvalidManifest(
                "mount destinations must be unique".into(),
            ));
        }
        let mut environment = BTreeSet::new();
        if self
            .allowed_environment
            .iter()
            .any(|name| !is_environment_name(name) || !environment.insert(name.as_str()))
        {
            return Err(ProxyError::InvalidManifest(
                "allowed_environment contains an invalid or duplicate name".into(),
            ));
        }
        if self.expected_execs.len() > 4096 {
            return Err(ProxyError::InvalidManifest(
                "expected_execs exceeds the manifest limit".into(),
            ));
        }
        for expectation in &self.expected_execs {
            if expectation.argv.is_empty()
                || expectation.argv.len() > 256
                || expectation
                    .argv
                    .iter()
                    .any(|value| value.len() > 8192 || value.bytes().any(|byte| byte == 0))
                || expectation.user != self.container_user
                || !is_normal_absolute_path(&expectation.working_dir)
                || !self.mounts.iter().any(|mount| {
                    std::path::Path::new(&expectation.working_dir).starts_with(&mount.destination)
                })
            {
                return Err(ProxyError::InvalidManifest(
                    "expected exec argv, user, or working directory is invalid".into(),
                ));
            }
            let mut names = BTreeSet::new();
            if expectation.environment.len() > 256
                || expectation.environment.iter().any(|entry| {
                    let Some((name, _)) = entry.split_once('=') else {
                        return true;
                    };
                    entry.len() > 8192
                        || entry.bytes().any(|byte| byte == 0)
                        || !is_environment_name(name)
                        || RESERVED_ENVIRONMENT.contains(&name)
                        || FORBIDDEN_ENVIRONMENT.contains(&name)
                        || !self
                            .allowed_environment
                            .iter()
                            .any(|allowed| allowed == name)
                        || !names.insert(name)
                })
            {
                return Err(ProxyError::InvalidManifest(
                    "expected exec environment is invalid, secret-bearing, or not allowlisted"
                        .into(),
                ));
            }
        }
        self.isolation_profile.validate()
    }
}

fn is_normal_absolute_path(value: &str) -> bool {
    let mut components = std::path::Path::new(value).components();
    matches!(components.next(), Some(Component::RootDir))
        && components.all(|component| matches!(component, Component::Normal(_)))
}

pub(crate) fn is_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && value.len() <= 128
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

pub(crate) fn validate_digest(name: &str, value: &str) -> Result<(), ProxyError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ProxyError::InvalidManifest(format!(
            "{name} must use sha256: digest form"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProxyError::InvalidManifest(format!(
            "{name} is not a canonical SHA-256 digest"
        )));
    }
    Ok(())
}

fn validate_protocol_digest(name: &str, value: &str) -> Result<(), ProxyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProxyError::InvalidManifest(format!(
            "{name} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_object_id(value: &str) -> Result<(), ProxyError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProxyError::InvalidManifest(
            "sha must be a full lowercase SHA-1 or SHA-256 object ID".into(),
        ));
    }
    Ok(())
}

pub(crate) fn is_socket_path(value: &str) -> bool {
    matches!(
        value,
        "/var/run/docker.sock" | "/run/docker.sock" | "/run/podman/podman.sock"
    ) || (value.starts_with("/run/user/") && value.ends_with("/podman/podman.sock"))
        || value.ends_with("policy-proxy.sock")
}
