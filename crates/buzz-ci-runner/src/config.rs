//! Secure loading for runner-owned configuration.
//!
//! The version-1 contract always supplies the peer UID. A complete optional
//! host block selects the reviewed concrete adapters; omission stays closed.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

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
    /// Complete concrete host composition. Omission keeps the runner closed.
    #[serde(default)]
    pub host: Option<RunnerHostConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
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
    #[error("runner host configuration is invalid")]
    InvalidHost,
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
        if config.host.as_ref().is_some_and(|host| !host.is_valid()) {
            return Err(ConfigError::InvalidHost);
        }
        Ok(config)
    }
}

impl RunnerHostConfig {
    fn is_valid(&self) -> bool {
        is_lower_hex(&self.owner_pubkey, 64)
            && is_lower_hex(&self.manifest_verification_key, 64)
            && is_lower_hex(&self.relay_signer, 64)
            && self.broker_uid != 0
            && self.broker_socket.is_absolute()
            && self.executor_program.is_absolute()
            && self.evidence_directory.is_absolute()
            && self.journal_directory.is_absolute()
            && (1..=256).contains(&self.max_argv_items)
            && (1..=65_536).contains(&self.max_argv_bytes)
            && (1..=256).contains(&self.max_environment_items)
            && (1..=65_536).contains(&self.max_environment_bytes)
            && (1..=16_777_216).contains(&self.max_output_bytes)
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
                host: None,
            }
        );
    }

    #[test]
    fn host_composition_is_all_or_nothing() {
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
                "broker_uid": 963,
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
        assert!(RunnerConfig::load(&complete).unwrap().host.is_some());

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
