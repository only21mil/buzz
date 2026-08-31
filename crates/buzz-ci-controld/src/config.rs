//! Strict, secret-free configuration for the capacity-zero daemon.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

const CONFIG_MODE: u32 = 0o600;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const SCHEMA_VERSION: u32 = 1;
pub(crate) const ACCEPTANCE_BINDING: &str =
    "/var/lib/buzzci/activation-controller/controld-acceptance-v1.json";

/// Validated local-only service configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonConfig {
    schema_version: u32,
    capacity: u32,
    store_root: PathBuf,
    acceptance_binding: PathBuf,
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
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|_| ConfigError::InvalidSyntax)?;
        config.validate()?;
        Ok(config)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn load(_path: &Path, _expected_owner_uid: u32) -> Result<Self, ConfigError> {
        Err(ConfigError::UnsupportedPlatform)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ConfigError::InvalidSchema);
        }
        validate_absolute_path(&self.store_root)?;
        validate_absolute_path(&self.acceptance_binding)?;
        if self.acceptance_binding != Path::new(ACCEPTANCE_BINDING) {
            return Err(ConfigError::InvalidAcceptanceBinding);
        }
        if self.capacity != 0 {
            return Err(ConfigError::ProvidersUnavailable);
        }
        Ok(())
    }

    pub(crate) fn store_root(&self) -> &Path {
        &self.store_root
    }

    pub(crate) const fn capacity(&self) -> u32 {
        self.capacity
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
    #[error("capacity above zero requires production provider and keyholder wiring")]
    ProvidersUnavailable,
    #[error("controld acceptance binding path is unsupported")]
    InvalidAcceptanceBinding,
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
            r#"{{"schema_version":1,"capacity":0,"store_root":"{}","acceptance_binding":"{}"}}"#,
            store.path().display(),
            ACCEPTANCE_BINDING
        );
        let (_root, path, owner_uid) = fixture(&json);

        let config = DaemonConfig::load(&path, owner_uid).expect("valid configuration");

        assert_eq!(config.capacity(), 0);
        assert_eq!(config.store_root(), store.path());
    }

    #[test]
    fn rejects_capacity_one_until_providers_are_wired() {
        let store = tempfile::tempdir().expect("store directory");
        let json = format!(
            r#"{{"schema_version":1,"capacity":1,"store_root":"{}","acceptance_binding":"{}"}}"#,
            store.path().display(),
            ACCEPTANCE_BINDING
        );
        let (_root, path, owner_uid) = fixture(&json);

        assert_eq!(
            DaemonConfig::load(&path, owner_uid),
            Err(ConfigError::ProvidersUnavailable)
        );
    }

    #[test]
    fn rejects_noncanonical_acceptance_binding() {
        let store = tempfile::tempdir().expect("store directory");
        let json = format!(
            r#"{{"schema_version":1,"capacity":0,"store_root":"{}","acceptance_binding":"/var/lib/buzzci/other.json"}}"#,
            store.path().display()
        );
        let (_root, path, owner_uid) = fixture(&json);

        assert_eq!(
            DaemonConfig::load(&path, owner_uid),
            Err(ConfigError::InvalidAcceptanceBinding)
        );
    }

    #[test]
    fn rejects_unknown_fields_and_insecure_mode() {
        let store = tempfile::tempdir().expect("store directory");
        let json = format!(
            r#"{{"schema_version":1,"capacity":0,"store_root":"{}","acceptance_binding":"{}","relay_url":"https://example.invalid"}}"#,
            store.path().display(),
            ACCEPTANCE_BINDING
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
