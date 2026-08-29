//! Secure loading for runner-owned configuration.
//!
//! The version-1 contract supplies only the peer UID. Legacy host composition
//! is rejected so production cannot fall back from broker v2 to local execution.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use serde::Deserialize;
use thiserror::Error;

const CONFIG_MODE: u32 = 0o600;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;

/// Contract-independent runner configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    /// Configuration schema. Version 1 is the only accepted value.
    pub schema_version: u32,
    /// Dedicated controld account accepted by `SO_PEERCRED`.
    pub controld_uid: u32,
}

/// Test-only shape retained for the closed legacy host unit tests. Production
/// configuration cannot deserialize this shape and the binary cannot compose it.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerHostConfig {
    pub owner_pubkey: String,
    pub manifest_verification_key: String,
    pub relay_signer: String,
    pub broker_socket: PathBuf,
    pub broker_uid: u32,
    pub executor_program: PathBuf,
    pub evidence_directory: PathBuf,
    pub journal_directory: PathBuf,
    pub max_argv_items: usize,
    pub max_argv_bytes: usize,
    pub max_environment_items: usize,
    pub max_environment_bytes: usize,
    pub max_output_bytes: usize,
}

/// Fail-closed configuration loading failures.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("runner configuration is unavailable")]
    Unavailable(#[source] io::Error),
    #[error("runner configuration must be a mode-0600 regular file")]
    InsecureFile,
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
    /// Load a bounded JSON file descriptor-relative without following its final link.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let parent = path.parent().ok_or(ConfigError::InsecureFile)?;
        let name = path.file_name().ok_or(ConfigError::InsecureFile)?;
        let directory = File::open(parent).map_err(ConfigError::Unavailable)?;
        let opened: OwnedFd = nix::fcntl::openat(
            &directory,
            Path::new(name),
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_CLOEXEC
                | nix::fcntl::OFlag::O_NOFOLLOW,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|error| {
            if error == nix::errno::Errno::ELOOP {
                ConfigError::InsecureFile
            } else {
                ConfigError::Unavailable(error.into())
            }
        })?;
        let file = File::from(opened);
        let opened = file.metadata().map_err(ConfigError::Unavailable)?;
        if !opened.is_file()
            || opened.permissions().mode() & 0o7777 != CONFIG_MODE
            || opened.nlink() != 1
            || opened.uid() != nix::unistd::Uid::effective().as_raw()
        {
            return Err(ConfigError::InsecureFile);
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

pub(crate) fn validate_private_directory(path: &Path) -> Result<(), ()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
    {
        return Err(());
    }
    Ok(())
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
    fn legacy_host_composition_is_rejected() {
        let directory = tempdir().expect("tempdir");
        let complete = directory.path().join("complete.json");
        let value = serde_json::json!({
            "schema_version": 1,
            "controld_uid": 962,
            "host": {
                "owner_pubkey": "11".repeat(32),
                "manifest_verification_key": "22".repeat(32),
                "relay_signer": "33".repeat(32),
                "broker_socket": "/run/buzzci/execd.sock",
                "broker_uid": 0,
                "executor_program": "/usr/bin/buzz-ci-executor",
                "evidence_directory": "/var/lib/buzz-ci-runner/evidence",
                "journal_directory": "/var/lib/buzz-ci-runner/journal",
                "max_argv_items": 32,
                "max_argv_bytes": 8192,
                "max_environment_items": 32,
                "max_environment_bytes": 8192,
                "max_output_bytes": 1048576
            }
        });
        write_config(&complete, &serde_json::to_vec(&value).unwrap(), 0o600);
        assert!(matches!(
            RunnerConfig::load(&complete),
            Err(ConfigError::InvalidJson(_))
        ));

        let partial = directory.path().join("partial.json");
        write_config(
            &partial,
            br#"{"schema_version":1,"controld_uid":962,"host":{"owner_pubkey":"11"}}"#,
            0o600,
        );
        assert!(matches!(
            RunnerConfig::load(&partial),
            Err(ConfigError::InvalidJson(_))
        ));
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
