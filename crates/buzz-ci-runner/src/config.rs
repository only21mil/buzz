//! Secure loading for runner-owned configuration.
//!
//! The reviewed version-1 contract supplies only the peer UID. Socket and
//! output paths remain fixed crate constants and cannot be selected here.

use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

const CONFIG_MODE: u32 = 0o600;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;

/// Contract-independent runner configuration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    /// Configuration schema. Version 1 is the only accepted value.
    pub schema_version: u32,
    /// Dedicated controld account accepted by `SO_PEERCRED`.
    pub controld_uid: u32,
}

/// Fail-closed configuration loading failures.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("runner configuration is unavailable")]
    Unavailable(#[source] io::Error),
    #[error("runner configuration must be a mode-0600 regular file")]
    InsecureFile,
    #[error("runner configuration changed while it was opened")]
    ReplacedFile,
    #[error("runner configuration exceeds the byte limit")]
    Oversized,
    #[error("runner configuration is invalid JSON")]
    InvalidJson(#[source] serde_json::Error),
    #[error("runner configuration schema is unsupported")]
    UnsupportedSchema,
    #[error("runner controld UID must be nonzero")]
    InvalidPeerUid,
}

impl RunnerConfig {
    /// Load a bounded JSON file after checking its type, mode, and stable inode.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let before = fs::symlink_metadata(path).map_err(ConfigError::Unavailable)?;
        if !before.file_type().is_file()
            || before.permissions().mode() & 0o7777 != CONFIG_MODE
            || before.nlink() != 1
        {
            return Err(ConfigError::InsecureFile);
        }

        let file = File::open(path).map_err(ConfigError::Unavailable)?;
        let opened = file.metadata().map_err(ConfigError::Unavailable)?;
        if !opened.is_file()
            || opened.permissions().mode() & 0o7777 != CONFIG_MODE
            || opened.nlink() != 1
        {
            return Err(ConfigError::InsecureFile);
        }
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(ConfigError::ReplacedFile);
        }
        if opened.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Oversized);
        }

        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(ConfigError::Unavailable)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::Oversized);
        }
        let config: Self = serde_json::from_slice(&bytes).map_err(ConfigError::InvalidJson)?;
        if config.schema_version != 1 {
            return Err(ConfigError::UnsupportedSchema);
        }
        if config.controld_uid == 0 {
            return Err(ConfigError::InvalidPeerUid);
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use tempfile::tempdir;

    use super::*;

    fn write_config(path: &Path, contents: &[u8], mode: u32) {
        fs::write(path, contents).expect("write fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
    }

    #[test]
    fn loads_exact_mode_0600_version_one_config() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("runner.json");
        write_config(&path, br#"{"schema_version":1,"controld_uid":962}"#, 0o600);

        assert_eq!(
            RunnerConfig::load(&path).expect("valid config"),
            RunnerConfig {
                schema_version: 1,
                controld_uid: 962,
            }
        );
    }

    #[test]
    fn rejects_broad_mode_symlink_and_unknown_fields() {
        let directory = tempdir().expect("tempdir");
        let broad = directory.path().join("broad.json");
        write_config(&broad, br#"{"schema_version":1,"controld_uid":962}"#, 0o640);
        assert!(matches!(
            RunnerConfig::load(&broad),
            Err(ConfigError::InsecureFile)
        ));

        let target = directory.path().join("target.json");
        let linked = directory.path().join("linked.json");
        write_config(
            &target,
            br#"{"schema_version":1,"controld_uid":962}"#,
            0o600,
        );
        symlink(&target, &linked).expect("create fixture symlink");
        assert!(matches!(
            RunnerConfig::load(&linked),
            Err(ConfigError::InsecureFile)
        ));

        let unknown = directory.path().join("unknown.json");
        write_config(
            &unknown,
            br#"{"schema_version":1,"controld_uid":962,"runner_socket":"unfrozen"}"#,
            0o600,
        );
        assert!(matches!(
            RunnerConfig::load(&unknown),
            Err(ConfigError::InvalidJson(_))
        ));

        let root = directory.path().join("root.json");
        write_config(&root, br#"{"schema_version":1,"controld_uid":0}"#, 0o600);
        assert!(matches!(
            RunnerConfig::load(&root),
            Err(ConfigError::InvalidPeerUid)
        ));
    }
}
