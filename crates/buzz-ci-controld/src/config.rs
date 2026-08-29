//! Strict, secret-free configuration for the capacity-zero daemon.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde::{de, Deserialize, Deserializer};
use thiserror::Error;

use buzz_ci_controld::keyholder::{KeyholderClientConfig, KeyholderSelectorBindings};
use buzz_ci_controld::RUNNER_CONTROL_SOCKET_PATH;

const CONFIG_MODE: u32 = 0o600;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const SCHEMA_VERSION: u32 = 1;

/// Validated local service configuration. Capacity zero contains no active
/// endpoints. Capacity one contains every public provider binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonConfig {
    capacity: u32,
    store_root: PathBuf,
    active: Option<ActiveConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveConfig {
    pub(crate) relay_url: String,
    pub(crate) runner_socket: PathBuf,
    pub(crate) keyholder: KeyholderClientConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDaemonConfig {
    schema_version: u32,
    capacity: u32,
    store_root: PathBuf,
    relay_url: Option<String>,
    runner_socket: Option<PathBuf>,
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

    fn from_raw(raw: RawDaemonConfig) -> Result<Self, ConfigError> {
        if raw.schema_version != SCHEMA_VERSION {
            return Err(ConfigError::InvalidSchema);
        }
        validate_absolute_path(&raw.store_root)?;
        let active_fields = (
            raw.relay_url,
            raw.runner_socket,
            raw.keyholder_socket,
            raw.keyholder_uid,
            raw.keyholder_gid,
            raw.keyholder_selectors,
            raw.keyholder_timeout_millis,
            raw.keyholder_transport_attempts,
        );
        let active = match (raw.capacity, active_fields) {
            (0, (None, None, None, None, None, None, None, None)) => None,
            (
                1,
                (
                    Some(relay_url),
                    Some(runner_socket),
                    Some(keyholder_socket),
                    Some(keyholder_uid),
                    Some(keyholder_gid),
                    Some(keyholder_selectors),
                    Some(keyholder_timeout_millis),
                    Some(keyholder_transport_attempts),
                ),
            ) => {
                validate_relay_url(&relay_url)?;
                if runner_socket != Path::new(RUNNER_CONTROL_SOCKET_PATH) {
                    return Err(ConfigError::InvalidSchema);
                }
                let keyholder = KeyholderClientConfig {
                    keyholder_socket,
                    keyholder_uid,
                    keyholder_gid,
                    keyholder_selectors,
                    keyholder_timeout_millis,
                    keyholder_transport_attempts,
                };
                keyholder
                    .validate()
                    .map_err(|_| ConfigError::InvalidSchema)?;
                Some(ActiveConfig {
                    relay_url,
                    runner_socket,
                    keyholder,
                })
            }
            _ => return Err(ConfigError::InvalidSchema),
        };
        Ok(Self {
            capacity: raw.capacity,
            store_root: raw.store_root,
            active,
        })
    }

    pub(crate) fn store_root(&self) -> &Path {
        &self.store_root
    }

    pub(crate) const fn capacity(&self) -> u32 {
        self.capacity
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

fn validate_relay_url(value: &str) -> Result<(), ConfigError> {
    let parsed = url::Url::parse(value).map_err(|_| ConfigError::InvalidSchema)?;
    if parsed.scheme() != "wss"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::InvalidSchema);
    }
    Ok(())
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
            r#"{{"schema_version":1,"capacity":0,"store_root":"{}"}}"#,
            store.path().display()
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
                "schema_version":1,
                "capacity":1,
                "store_root":"{}",
                "relay_url":"wss://relay.example.test",
                "runner_socket":"/run/buzzci/runner-control.sock",
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
            store.path().display()
        );
        let (_root, path, owner_uid) = fixture(&json);

        let config = DaemonConfig::load(&path, owner_uid).expect("active configuration");
        let active = config.active().expect("active binding");
        assert_eq!(config.capacity(), 1);
        assert_eq!(active.relay_url, "wss://relay.example.test");
        assert_eq!(active.runner_socket, Path::new(RUNNER_CONTROL_SOCKET_PATH));
        assert_eq!(
            active.keyholder.keyholder_socket,
            PathBuf::from(KEYHOLDER_SOCKET_PATH)
        );
        assert_eq!(active.keyholder.keyholder_selectors.nip98.generation, 2);
    }

    #[test]
    fn capacity_modes_reject_partial_or_cross_mode_provider_fields() {
        let store = tempfile::tempdir().expect("store directory");
        for json in [
            format!(
                r#"{{"schema_version":1,"capacity":1,"store_root":"{}"}}"#,
                store.path().display()
            ),
            format!(
                r#"{{"schema_version":1,"capacity":0,"store_root":"{}","keyholder_socket":"/run/buzzci/keyholder.sock"}}"#,
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
            r#"{{"schema_version":1,"capacity":0,"store_root":"{}","secret_path":"/forbidden"}}"#,
            store.path().display()
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
