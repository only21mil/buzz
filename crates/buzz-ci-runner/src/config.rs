//! Secure loading for runner-owned configuration.
//!
//! Configuration selects either a closed listener or the broker-v2 proxy.
//! Legacy host composition is rejected so production cannot fall back from
//! broker v2 to local execution.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

const CONFIG_MODE: u32 = 0o600;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_TIMEOUT_MILLIS: u64 = 30_000;
const MAX_TRANSPORT_ATTEMPTS: u8 = 5;
const MAX_RETRY_DELAY_MILLIS: u64 = 5_000;

/// Fixed production execd endpoint. The runner never accepts an endpoint from
/// controld request bytes.
pub const EXECD_SOCKET_PATH: &str = "/run/buzzci/execd.sock";
/// Fixed durable replay map owned by the unprivileged runner account.
pub const V2_REPLAY_JOURNAL_PATH: &str = "/var/lib/buzzci/runner/v2-replay.json";

/// Contract-independent runner configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct RunnerConfig {
    /// Configuration schema. Version 2 is the only accepted value.
    pub schema_version: u32,
    /// Dedicated controld account accepted by `SO_PEERCRED`.
    pub controld_uid: u32,
    /// Dedicated controld primary group accepted by `SO_PEERCRED`.
    pub controld_gid: u32,
    #[serde(flatten)]
    pub mode: RunnerMode,
}

/// Strict production mode. Dormant stays closed; v2 proxy has no legacy host
/// or executable configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerMode {
    Dormant,
    V2Proxy {
        execd_socket: PathBuf,
        execd_uid: u32,
        execd_gid: u32,
        replay_journal: PathBuf,
        connect_timeout_millis: u64,
        io_timeout_millis: u64,
        transport_attempts: u8,
        retry_delay_millis: u64,
        lane_manifest_digest: String,
        lane_epoch: u64,
        admission_key_generation: u64,
        isolation_profile_digest: String,
        audience_digest: String,
    },
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
    #[error("runner configuration contains unknown fields")]
    UnknownFields,
    #[error("runner controld UID must be nonzero")]
    InvalidPeerUid,
    #[error("runner controld GID must be nonzero")]
    InvalidPeerGid,
    #[error("runner v2 proxy configuration is invalid")]
    InvalidV2Proxy,
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
        validate_config_fields(&bytes)?;
        let config: Self = serde_json::from_slice(&bytes).map_err(ConfigError::InvalidJson)?;
        if config.schema_version != 2 {
            return Err(ConfigError::UnsupportedSchema);
        }
        if config.controld_uid == 0 {
            return Err(ConfigError::InvalidPeerUid);
        }
        if config.controld_gid == 0 {
            return Err(ConfigError::InvalidPeerGid);
        }
        if let RunnerMode::V2Proxy {
            execd_socket,
            execd_uid,
            execd_gid,
            replay_journal,
            connect_timeout_millis,
            io_timeout_millis,
            transport_attempts,
            retry_delay_millis,
            lane_manifest_digest,
            lane_epoch,
            admission_key_generation,
            isolation_profile_digest,
            audience_digest,
        } = &config.mode
        {
            if execd_socket != Path::new(EXECD_SOCKET_PATH)
                || *execd_uid != 0
                || *execd_gid != 0
                || replay_journal != Path::new(V2_REPLAY_JOURNAL_PATH)
                || !(1..=MAX_TIMEOUT_MILLIS).contains(connect_timeout_millis)
                || !(1..=MAX_TIMEOUT_MILLIS).contains(io_timeout_millis)
                || !(1..=MAX_TRANSPORT_ATTEMPTS).contains(transport_attempts)
                || *retry_delay_millis > MAX_RETRY_DELAY_MILLIS
                || !digest(lane_manifest_digest)
                || *lane_epoch == 0
                || *admission_key_generation == 0
                || !digest(isolation_profile_digest)
                || !digest(audience_digest)
            {
                return Err(ConfigError::InvalidV2Proxy);
            }
        }
        Ok(config)
    }
}

fn validate_config_fields(bytes: &[u8]) -> Result<(), ConfigError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(ConfigError::InvalidJson)?;
    let object = value.as_object().ok_or(ConfigError::UnknownFields)?;
    let expected: &[&str] = match object.get("mode").and_then(serde_json::Value::as_str) {
        Some("dormant") => &["schema_version", "controld_uid", "controld_gid", "mode"],
        Some("v2_proxy") => &[
            "schema_version",
            "controld_uid",
            "controld_gid",
            "mode",
            "execd_socket",
            "execd_uid",
            "execd_gid",
            "replay_journal",
            "connect_timeout_millis",
            "io_timeout_millis",
            "transport_attempts",
            "retry_delay_millis",
            "lane_manifest_digest",
            "lane_epoch",
            "admission_key_generation",
            "isolation_profile_digest",
            "audience_digest",
        ],
        _ => return Ok(()),
    };
    if object.len() != expected.len() || object.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err(ConfigError::UnknownFields);
    }
    Ok(())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value != "0".repeat(64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
    fn loads_exact_mode_0600_dormant_config() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("runner.json");
        write_config(
            &path,
            br#"{"schema_version":2,"controld_uid":962,"controld_gid":963,"mode":"dormant"}"#,
            0o600,
        );

        assert_eq!(
            RunnerConfig::load(&path).expect("valid config"),
            RunnerConfig {
                schema_version: 2,
                controld_uid: 962,
                controld_gid: 963,
                mode: RunnerMode::Dormant,
            }
        );
    }

    #[test]
    fn loads_only_fixed_v2_proxy_coordinates() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("runner.json");
        let value = serde_json::json!({
            "schema_version": 2,
            "controld_uid": 962,
            "controld_gid": 963,
            "mode": "v2_proxy",
            "execd_socket": EXECD_SOCKET_PATH,
            "execd_uid": 0,
            "execd_gid": 0,
            "replay_journal": V2_REPLAY_JOURNAL_PATH,
            "connect_timeout_millis": 1000,
            "io_timeout_millis": 5000,
            "transport_attempts": 3,
            "retry_delay_millis": 100,
            "lane_manifest_digest": "11".repeat(32),
            "lane_epoch": 4,
            "admission_key_generation": 9,
            "isolation_profile_digest": "22".repeat(32),
            "audience_digest": "33".repeat(32),
        });
        write_config(&path, &serde_json::to_vec(&value).unwrap(), 0o600);
        assert!(matches!(
            RunnerConfig::load(&path).expect("valid proxy config").mode,
            RunnerMode::V2Proxy { .. }
        ));

        let mut drifted = value;
        drifted["execd_socket"] = serde_json::json!("/tmp/execd.sock");
        write_config(
            &directory.path().join("drifted.json"),
            &serde_json::to_vec(&drifted).unwrap(),
            0o600,
        );
        assert!(matches!(
            RunnerConfig::load(&directory.path().join("drifted.json")),
            Err(ConfigError::InvalidV2Proxy)
        ));
    }

    #[test]
    fn legacy_host_composition_is_rejected() {
        let directory = tempdir().expect("tempdir");
        let complete = directory.path().join("complete.json");
        let value = serde_json::json!({
            "schema_version": 2,
            "controld_uid": 962,
            "controld_gid": 963,
            "mode": "dormant",
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
            Err(ConfigError::UnknownFields)
        ));

        let partial = directory.path().join("partial.json");
        write_config(
            &partial,
            br#"{"schema_version":2,"controld_uid":962,"controld_gid":963,"mode":"dormant","host":{"owner_pubkey":"11"}}"#,
            0o600,
        );
        assert!(matches!(
            RunnerConfig::load(&partial),
            Err(ConfigError::UnknownFields)
        ));
    }

    #[test]
    fn rejects_broad_mode_symlink_and_unknown_fields() {
        let directory = tempdir().expect("tempdir");
        let broad = directory.path().join("broad.json");
        write_config(
            &broad,
            br#"{"schema_version":2,"controld_uid":962,"controld_gid":963,"mode":"dormant"}"#,
            0o640,
        );
        assert!(matches!(
            RunnerConfig::load(&broad),
            Err(ConfigError::InsecureFile)
        ));

        let target = directory.path().join("target.json");
        let linked = directory.path().join("linked.json");
        write_config(
            &target,
            br#"{"schema_version":2,"controld_uid":962,"controld_gid":963,"mode":"dormant"}"#,
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
            br#"{"schema_version":2,"controld_uid":962,"controld_gid":963,"mode":"dormant","runner_socket":"unfrozen"}"#,
            0o600,
        );
        assert!(matches!(
            RunnerConfig::load(&unknown),
            Err(ConfigError::UnknownFields)
        ));

        let root = directory.path().join("root.json");
        write_config(
            &root,
            br#"{"schema_version":2,"controld_uid":0,"controld_gid":963,"mode":"dormant"}"#,
            0o600,
        );
        assert!(matches!(
            RunnerConfig::load(&root),
            Err(ConfigError::InvalidPeerUid)
        ));
    }
}
