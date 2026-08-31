//! Strict, secret-free configuration for dormant and capacity-one operation.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde::{de, Deserialize, Deserializer};
use thiserror::Error;

use buzz_ci_controld::keyholder::{KeyholderClientConfig, KeyholderSelectorBindings};
use buzz_ci_controld::runner_client::UnixRunnerConnectorConfig;
use buzz_ci_controld::{ACCEPTANCE_BINDING_PATH, RUNNER_CONTROL_SOCKET_PATH};

const CONFIG_MODE: u32 = 0o600;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const SCHEMA_VERSION: u32 = 2;
const MAX_POLL_INTERVAL_MILLIS: u64 = 60_000;
const MAX_RUNNER_TRANSPORT_ATTEMPTS: u32 = 8;

/// Validated local service configuration. Capacity zero contains no active
/// endpoints. Capacity one contains every public provider binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonConfig {
    capacity: u32,
    store_root: PathBuf,
    acceptance_binding: Option<PathBuf>,
    active: Option<ActiveConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveConfig {
    pub(crate) relay_url: String,
    pub(crate) relay_http_origin: String,
    pub(crate) channel_id: String,
    pub(crate) poll_interval_millis: u64,
    pub(crate) runner: UnixRunnerConnectorConfig,
    pub(crate) runner_transport_attempts: u32,
    pub(crate) lane_manifest_digest: String,
    pub(crate) lane_epoch: u64,
    pub(crate) audience_digest: String,
    pub(crate) isolation_profile_digest: String,
    pub(crate) workflow_id: String,
    pub(crate) workflow_digest: String,
    pub(crate) jobs: Vec<StaticJobConfig>,
    pub(crate) keyholder: KeyholderClientConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct StaticJobConfig {
    pub(crate) job_id: String,
    pub(crate) name: String,
    pub(crate) required: bool,
    pub(crate) skip_policy: buzz_core::ci::CiSkipPolicy,
    pub(crate) selected_job_instance: String,
    pub(crate) also_reruns: Vec<String>,
    pub(crate) artifacts: Vec<StaticArtifactConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct StaticArtifactConfig {
    pub(crate) artifact_id: String,
    pub(crate) name: String,
    pub(crate) media_type: String,
    pub(crate) relative_name: String,
    pub(crate) max_bytes: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDaemonConfig {
    schema_version: u32,
    capacity: u32,
    store_root: PathBuf,
    acceptance_binding: Option<PathBuf>,
    relay_url: Option<String>,
    relay_http_origin: Option<String>,
    channel_id: Option<String>,
    poll_interval_millis: Option<u64>,
    runner_socket: Option<PathBuf>,
    runner_uid: Option<u32>,
    runner_gid: Option<u32>,
    runner_connect_timeout_millis: Option<u64>,
    runner_io_timeout_millis: Option<u64>,
    runner_transport_attempts: Option<u32>,
    lane_manifest_digest: Option<String>,
    lane_epoch: Option<u64>,
    audience_digest: Option<String>,
    isolation_profile_digest: Option<String>,
    workflow_id: Option<String>,
    workflow_digest: Option<String>,
    jobs: Option<Vec<StaticJobConfig>>,
    keyholder_socket: Option<PathBuf>,
    keyholder_uid: Option<u32>,
    keyholder_gid: Option<u32>,
    keyholder_selectors: Option<KeyholderSelectorBindings>,
    keyholder_timeout_millis: Option<u64>,
    keyholder_transport_attempts: Option<u32>,
}

impl<'de> Deserialize<'de> for DaemonConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawDaemonConfig::deserialize(deserializer)?;
        Self::from_raw(raw).map_err(de::Error::custom)
    }
}

impl DaemonConfig {
    /// Load an exact regular file without following a final symlink.
    #[cfg(target_os = "linux")]
    pub(crate) fn load(path: &Path, expected_owner_uid: u32) -> Result<Self, ConfigError> {
        use nix::fcntl::{open, OFlag};
        use nix::sys::stat::Mode;

        validate_absolute_path(path)?;
        let before = fs::symlink_metadata(path).map_err(|_| ConfigError::Unavailable)?;
        validate_metadata(&before, expected_owner_uid)?;
        if fs::canonicalize(path).map_err(|_| ConfigError::Unavailable)? != path {
            return Err(ConfigError::InsecureMetadata);
        }
        if before.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Oversized);
        }

        let descriptor = open(
            path,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ConfigError::Unavailable)?;
        let file = File::from(descriptor);
        let opened = file.metadata().map_err(|_| ConfigError::Unavailable)?;
        validate_metadata(&opened, expected_owner_uid)?;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(ConfigError::InsecureMetadata);
        }

        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigError::Unavailable)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::Oversized);
        }
        let raw: RawDaemonConfig =
            serde_json::from_slice(&bytes).map_err(|_| ConfigError::InvalidSyntax)?;
        Self::from_raw(raw)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn load(_path: &Path, _expected_owner_uid: u32) -> Result<Self, ConfigError> {
        Err(ConfigError::UnsupportedPlatform)
    }

    fn from_raw(mut raw: RawDaemonConfig) -> Result<Self, ConfigError> {
        if raw.schema_version != SCHEMA_VERSION {
            return Err(ConfigError::InvalidSchema);
        }
        validate_absolute_path(&raw.store_root)?;
        let any_active = raw.relay_url.is_some()
            || raw.relay_http_origin.is_some()
            || raw.channel_id.is_some()
            || raw.poll_interval_millis.is_some()
            || raw.runner_socket.is_some()
            || raw.runner_uid.is_some()
            || raw.runner_gid.is_some()
            || raw.runner_connect_timeout_millis.is_some()
            || raw.runner_io_timeout_millis.is_some()
            || raw.runner_transport_attempts.is_some()
            || raw.lane_manifest_digest.is_some()
            || raw.lane_epoch.is_some()
            || raw.audience_digest.is_some()
            || raw.isolation_profile_digest.is_some()
            || raw.workflow_id.is_some()
            || raw.workflow_digest.is_some()
            || raw.jobs.is_some()
            || raw.keyholder_socket.is_some()
            || raw.keyholder_uid.is_some()
            || raw.keyholder_gid.is_some()
            || raw.keyholder_selectors.is_some()
            || raw.keyholder_timeout_millis.is_some()
            || raw.keyholder_transport_attempts.is_some();
        let acceptance_binding = raw.acceptance_binding.take();
        if acceptance_binding.as_deref() != Some(Path::new(ACCEPTANCE_BINDING_PATH)) {
            return Err(ConfigError::InvalidSchema);
        }
        let active = match raw.capacity {
            0 if !any_active => None,
            1 => {
                if acceptance_binding.is_none() {
                    return Err(ConfigError::InvalidSchema);
                }
                let relay_url = raw.relay_url.take().ok_or(ConfigError::InvalidSchema)?;
                let relay_http_origin = raw
                    .relay_http_origin
                    .take()
                    .ok_or(ConfigError::InvalidSchema)?;
                validate_relay_pair(&relay_url, &relay_http_origin)?;
                let channel_id = raw.channel_id.take().ok_or(ConfigError::InvalidSchema)?;
                if uuid::Uuid::parse_str(&channel_id).is_err() {
                    return Err(ConfigError::InvalidSchema);
                }
                let poll_interval_millis = raw
                    .poll_interval_millis
                    .take()
                    .filter(|value| (1..=MAX_POLL_INTERVAL_MILLIS).contains(value))
                    .ok_or(ConfigError::InvalidSchema)?;
                let runner = UnixRunnerConnectorConfig {
                    socket_path: raw.runner_socket.take().ok_or(ConfigError::InvalidSchema)?,
                    runner_uid: raw.runner_uid.take().ok_or(ConfigError::InvalidSchema)?,
                    runner_gid: raw.runner_gid.take().ok_or(ConfigError::InvalidSchema)?,
                    connect_timeout_millis: raw
                        .runner_connect_timeout_millis
                        .take()
                        .ok_or(ConfigError::InvalidSchema)?,
                    io_timeout_millis: raw
                        .runner_io_timeout_millis
                        .take()
                        .ok_or(ConfigError::InvalidSchema)?,
                };
                if runner.socket_path != Path::new(RUNNER_CONTROL_SOCKET_PATH) {
                    return Err(ConfigError::InvalidSchema);
                }
                runner.validate().map_err(|_| ConfigError::InvalidSchema)?;
                let runner_transport_attempts = raw
                    .runner_transport_attempts
                    .take()
                    .filter(|value| (1..=MAX_RUNNER_TRANSPORT_ATTEMPTS).contains(value))
                    .ok_or(ConfigError::InvalidSchema)?;
                for digest in [
                    raw.lane_manifest_digest.as_deref(),
                    raw.audience_digest.as_deref(),
                    raw.isolation_profile_digest.as_deref(),
                    raw.workflow_digest.as_deref(),
                ] {
                    if !digest.is_some_and(|value| is_lower_hex(value, 64)) {
                        return Err(ConfigError::InvalidSchema);
                    }
                }
                let lane_epoch = raw
                    .lane_epoch
                    .take()
                    .filter(|value| *value > 0)
                    .ok_or(ConfigError::InvalidSchema)?;
                let workflow_id = raw.workflow_id.take().ok_or(ConfigError::InvalidSchema)?;
                let jobs = raw.jobs.take().ok_or(ConfigError::InvalidSchema)?;
                validate_static_jobs(&workflow_id, &jobs)?;
                let keyholder = KeyholderClientConfig {
                    keyholder_socket: raw
                        .keyholder_socket
                        .take()
                        .ok_or(ConfigError::InvalidSchema)?,
                    keyholder_uid: raw.keyholder_uid.take().ok_or(ConfigError::InvalidSchema)?,
                    keyholder_gid: raw.keyholder_gid.take().ok_or(ConfigError::InvalidSchema)?,
                    keyholder_selectors: raw
                        .keyholder_selectors
                        .take()
                        .ok_or(ConfigError::InvalidSchema)?,
                    keyholder_timeout_millis: raw
                        .keyholder_timeout_millis
                        .take()
                        .ok_or(ConfigError::InvalidSchema)?,
                    keyholder_transport_attempts: raw
                        .keyholder_transport_attempts
                        .take()
                        .ok_or(ConfigError::InvalidSchema)?,
                };
                keyholder
                    .validate()
                    .map_err(|_| ConfigError::InvalidSchema)?;
                Some(ActiveConfig {
                    relay_url,
                    relay_http_origin,
                    channel_id,
                    poll_interval_millis,
                    runner,
                    runner_transport_attempts,
                    lane_manifest_digest: raw.lane_manifest_digest.take().unwrap(),
                    lane_epoch,
                    audience_digest: raw.audience_digest.take().unwrap(),
                    isolation_profile_digest: raw.isolation_profile_digest.take().unwrap(),
                    workflow_id,
                    workflow_digest: raw.workflow_digest.take().unwrap(),
                    jobs,
                    keyholder,
                })
            }
            _ => return Err(ConfigError::InvalidSchema),
        };
        Ok(Self {
            capacity: raw.capacity,
            store_root: raw.store_root,
            acceptance_binding,
            active,
        })
    }

    pub(crate) fn store_root(&self) -> &Path {
        &self.store_root
    }

    pub(crate) const fn capacity(&self) -> u32 {
        self.capacity
    }

    pub(crate) fn acceptance_binding(&self) -> Option<&Path> {
        self.acceptance_binding.as_deref()
    }

    pub(crate) const fn active(&self) -> Option<&ActiveConfig> {
        self.active.as_ref()
    }
}

/// Startup-safe errors which never include configuration contents or paths.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ConfigError {
    #[cfg(not(target_os = "linux"))]
    #[error("controld is supported only on Linux")]
    UnsupportedPlatform,
    #[error("controld configuration path is invalid")]
    InvalidPath,
    #[error("controld configuration is unavailable")]
    Unavailable,
    #[error("controld configuration metadata is insecure")]
    InsecureMetadata,
    #[error("controld configuration exceeds the byte limit")]
    Oversized,
    #[error("controld configuration syntax is invalid")]
    InvalidSyntax,
    #[error("controld configuration schema is unsupported")]
    InvalidSchema,
}

fn validate_relay_pair(relay_url: &str, http_origin: &str) -> Result<(), ConfigError> {
    let relay = url::Url::parse(relay_url).map_err(|_| ConfigError::InvalidSchema)?;
    let origin = url::Url::parse(http_origin).map_err(|_| ConfigError::InvalidSchema)?;
    if relay.scheme() != "wss"
        || relay.host_str().is_none()
        || !relay.username().is_empty()
        || relay.password().is_some()
        || relay.path() != "/"
        || relay.query().is_some()
        || relay.fragment().is_some()
        || origin.scheme() != "https"
        || origin.host_str() != relay.host_str()
        || origin.port_or_known_default() != relay.port_or_known_default()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(ConfigError::InvalidSchema);
    }
    Ok(())
}

fn validate_static_jobs(workflow_id: &str, jobs: &[StaticJobConfig]) -> Result<(), ConfigError> {
    let mut ids = std::collections::BTreeSet::new();
    if workflow_id.is_empty()
        || jobs.len() != 1
        || jobs.iter().any(|job| {
            job.job_id.is_empty()
                || job.name.is_empty()
                || job.selected_job_instance.is_empty()
                || !ids.insert(job.job_id.as_str())
                || job.also_reruns.iter().any(|value| value.is_empty())
                || job.artifacts.len() != 1
                || job.artifacts.iter().any(|artifact| {
                    !valid_artifact_name(&artifact.artifact_id)
                        || !valid_artifact_name(&artifact.name)
                        || !valid_artifact_name(&artifact.relative_name)
                        || artifact.max_bytes == 0
                        || artifact.max_bytes > 32 * 1024
                        || !artifact.media_type.contains('/')
                        || artifact.media_type.len() > 64
                        || !artifact.media_type.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'/' | b'+' | b'.' | b'-')
                        })
                })
        })
    {
        return Err(ConfigError::InvalidSchema);
    }
    Ok(())
}

fn valid_artifact_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_absolute_path(path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(ConfigError::InvalidPath);
    }
    Ok(())
}

fn validate_metadata(metadata: &fs::Metadata, expected_owner_uid: u32) -> Result<(), ConfigError> {
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o7777 != CONFIG_MODE
        || metadata.uid() != expected_owner_uid
        || metadata.nlink() != 1
    {
        return Err(ConfigError::InsecureMetadata);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use buzz_ci_keyholder::KEYHOLDER_SOCKET_PATH;

    use super::*;

    fn fixture(json: &str) -> (TempDir, PathBuf, u32) {
        let root = tempfile::tempdir().expect("temporary directory");
        let config_path = root.path().join("controld.json");
        fs::write(&config_path, json).expect("write fixture");
        fs::set_permissions(&config_path, fs::Permissions::from_mode(CONFIG_MODE))
            .expect("secure fixture mode");
        let owner_uid = fs::metadata(&config_path).expect("fixture metadata").uid();
        (root, config_path, owner_uid)
    }

    #[test]
    fn loads_exact_capacity_zero_configuration() {
        let store = tempfile::tempdir().expect("store directory");
        let json = format!(
            r#"{{"schema_version":2,"capacity":0,"store_root":"{}","acceptance_binding":"{}"}}"#,
            store.path().display(),
            ACCEPTANCE_BINDING_PATH,
        );
        let (_root, path, owner_uid) = fixture(&json);

        let config = DaemonConfig::load(&path, owner_uid).expect("valid configuration");

        assert_eq!(config.capacity(), 0);
        assert_eq!(config.store_root(), store.path());
    }

    #[test]
    fn loads_exact_capacity_one_public_provider_bindings() {
        let store = tempfile::tempdir().expect("store directory");
        let json = format!(
            r#"{{
                "schema_version":2,
                "capacity":1,
                "store_root":"{}",
                "acceptance_binding":"/var/lib/buzzci/activation-controller/controld-acceptance-v2.json",
                "relay_url":"wss://relay.example.test",
                "relay_http_origin":"https://relay.example.test",
                "channel_id":"123e4567-e89b-12d3-a456-426614174099",
                "poll_interval_millis":100,
                "runner_socket":"/run/buzzci/runner-control.sock",
                "runner_uid":1003,
                "runner_gid":1004,
                "runner_connect_timeout_millis":500,
                "runner_io_timeout_millis":1000,
                "runner_transport_attempts":2,
                "lane_manifest_digest":"{digest}",
                "lane_epoch":7,
                "audience_digest":"{digest}",
                "isolation_profile_digest":"{digest}",
                "workflow_id":"native-ci",
                "workflow_digest":"{digest}",
                "jobs":[{{
                    "job_id":"test",
                    "name":"test",
                    "required":true,
                    "skip_policy":"forbid",
                    "selected_job_instance":"test",
                    "also_reruns":[],
                    "artifacts":[{{
                        "artifact_id":"result",
                        "name":"result.json",
                        "media_type":"application/json",
                        "relative_name":"result.json",
                        "max_bytes":32768
                    }}]
                }}],
                "keyholder_socket":"/run/buzzci/keyholder.sock",
                "keyholder_uid":1001,
                "keyholder_gid":1002,
                "keyholder_selectors":{{
                    "ci_event":{{"public_key":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","generation":1}},
                    "nip98":{{"public_key":"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5","generation":2}},
                    "manifest":{{"public_key":"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9","generation":3}}
                }},
                "keyholder_timeout_millis":500,
                "keyholder_transport_attempts":2
            }}"#,
            store.path().display(),
            digest = "11".repeat(32),
        );
        let (_root, path, owner_uid) = fixture(&json);

        assert!(!json.contains("scenario_sha256"));
        assert!(!json.contains("activation_package_digest"));

        let config = DaemonConfig::load(&path, owner_uid).expect("active configuration");
        let active = config.active().expect("active binding");
        assert_eq!(config.capacity(), 1);
        assert_eq!(
            config.acceptance_binding(),
            Some(Path::new(ACCEPTANCE_BINDING_PATH))
        );
        assert_eq!(active.relay_url, "wss://relay.example.test");
        assert_eq!(
            active.runner.socket_path,
            Path::new(RUNNER_CONTROL_SOCKET_PATH)
        );
        assert_eq!(
            active.keyholder.keyholder_socket,
            PathBuf::from(KEYHOLDER_SOCKET_PATH)
        );
        assert_eq!(active.keyholder.keyholder_selectors.nip98.generation, 2);

        let cyclic = json.replacen(
            "\"keyholder_transport_attempts\":2",
            &format!(
                "\"keyholder_transport_attempts\":2,\"acceptance\":{{\"scenario_sha256\":\"{}\"}}",
                "11".repeat(32)
            ),
            1,
        );
        let (_root, path, owner_uid) = fixture(&cyclic);
        assert_eq!(
            DaemonConfig::load(&path, owner_uid),
            Err(ConfigError::InvalidSyntax)
        );
    }

    #[test]
    fn capacity_zero_accepts_only_the_fixed_post_freeze_acceptance_binding() {
        let store = tempfile::tempdir().expect("store directory");
        let missing = format!(
            r#"{{"schema_version":2,"capacity":0,"store_root":"{}"}}"#,
            store.path().display()
        );
        let (_root, path, owner_uid) = fixture(&missing);
        assert_eq!(
            DaemonConfig::load(&path, owner_uid),
            Err(ConfigError::InvalidSchema)
        );

        let valid = format!(
            r#"{{"schema_version":2,"capacity":0,"store_root":"{}","acceptance_binding":"{}"}}"#,
            store.path().display(),
            ACCEPTANCE_BINDING_PATH
        );
        let (_root, path, owner_uid) = fixture(&valid);
        let config = DaemonConfig::load(&path, owner_uid).expect("staged-zero configuration");
        assert_eq!(
            config.acceptance_binding(),
            Some(Path::new(ACCEPTANCE_BINDING_PATH))
        );

        let invalid = format!(
            r#"{{"schema_version":2,"capacity":0,"store_root":"{}","acceptance_binding":"/var/lib/buzzci/controld/acceptance.json"}}"#,
            store.path().display()
        );
        let (_root, path, owner_uid) = fixture(&invalid);
        assert_eq!(
            DaemonConfig::load(&path, owner_uid),
            Err(ConfigError::InvalidSchema)
        );
    }

    #[test]
    fn capacity_modes_reject_partial_or_cross_mode_provider_fields() {
        let store = tempfile::tempdir().expect("store directory");
        for json in [
            format!(
                r#"{{"schema_version":2,"capacity":1,"store_root":"{}"}}"#,
                store.path().display()
            ),
            format!(
                r#"{{"schema_version":2,"capacity":0,"store_root":"{}","keyholder_socket":"/run/buzzci/keyholder.sock"}}"#,
                store.path().display()
            ),
        ] {
            let (_root, path, owner_uid) = fixture(&json);
            assert_eq!(
                DaemonConfig::load(&path, owner_uid),
                Err(ConfigError::InvalidSchema)
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_and_insecure_mode() {
        let store = tempfile::tempdir().expect("store directory");
        let json = format!(
            r#"{{"schema_version":2,"capacity":0,"store_root":"{}","acceptance_binding":"{}","secret_path":"/forbidden"}}"#,
            store.path().display(),
            ACCEPTANCE_BINDING_PATH,
        );
        let (_root, path, owner_uid) = fixture(&json);
        assert_eq!(
            DaemonConfig::load(&path, owner_uid),
            Err(ConfigError::InvalidSyntax)
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("change fixture mode");
        assert_eq!(
            DaemonConfig::load(&path, owner_uid),
            Err(ConfigError::InsecureMetadata)
        );
    }
}
