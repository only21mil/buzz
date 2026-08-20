//! Root-owned configuration published for acceptance runners.

use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evidence::{atomic_publish, PublicationError, ROOT_READ_ONLY_FILE_MODE};

pub const HARNESS_KEYS: [&str; 8] = [
    "BUZZ_CI_EXECD_SOCKET",
    "BUZZ_CI_BROKER_UNIT",
    "BUZZ_CI_LEASE_STATE_ROOT",
    "BUZZ_CI_RUNNER_CTL",
    "BUZZ_CI_FIXTURE_REPO",
    "BUZZ_CI_HARNESS_SIGNER",
    "BUZZ_CI_GRAPH_REDUCER",
    "BUZZ_CI_GRAPH_FIXTURE_DIR",
];
pub const HARNESS_ENV_PATH: &str = "/etc/buzzci/harness.env";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessConfig {
    pub execd_socket: PathBuf,
    pub broker_unit: String,
    pub lease_state_root: PathBuf,
    pub runner_entrypoint: PathBuf,
    pub fixture_repo: String,
    /// Lowercase 32-byte public signer key. Secret signing material is never
    /// accepted by this configuration model.
    pub harness_signer: String,
    pub graph_reducer: PathBuf,
    pub graph_fixture_dir: PathBuf,
}

#[derive(Debug, Error)]
pub enum HarnessError {
    #[error("harness paths must be absolute and contain no control characters")]
    InvalidPath,
    #[error("broker unit is not a safe systemd unit name")]
    InvalidUnit,
    #[error("fixture repository coordinate is empty, oversized, or unsafe")]
    InvalidFixtureRepo,
    #[error("harness signer must be a lowercase 32-byte public key")]
    InvalidSigner,
    #[error(transparent)]
    Publication(#[from] PublicationError),
}

impl HarnessConfig {
    pub fn validate(&self) -> Result<(), HarnessError> {
        for path in [
            &self.execd_socket,
            &self.lease_state_root,
            &self.runner_entrypoint,
            &self.graph_reducer,
            &self.graph_fixture_dir,
        ] {
            if !safe_absolute_path(path) {
                return Err(HarnessError::InvalidPath);
            }
        }
        if !self.broker_unit.ends_with(".service")
            || self.broker_unit.is_empty()
            || !self.broker_unit.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@')
            })
        {
            return Err(HarnessError::InvalidUnit);
        }
        if !safe_fixture_repo(&self.fixture_repo) {
            return Err(HarnessError::InvalidFixtureRepo);
        }
        if self.harness_signer.len() != 64
            || !self
                .harness_signer
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(HarnessError::InvalidSigner);
        }
        Ok(())
    }

    pub fn encode_env(&self) -> Result<Vec<u8>, HarnessError> {
        self.validate()?;
        let values = [
            path_text(&self.execd_socket)?.to_owned(),
            self.broker_unit.clone(),
            path_text(&self.lease_state_root)?.to_owned(),
            path_text(&self.runner_entrypoint)?.to_owned(),
            self.fixture_repo.clone(),
            self.harness_signer.clone(),
            path_text(&self.graph_reducer)?.to_owned(),
            path_text(&self.graph_fixture_dir)?.to_owned(),
        ];
        let mut output = String::new();
        for (key, value) in HARNESS_KEYS.into_iter().zip(values) {
            writeln!(&mut output, "{key}={value}").expect("writing to String cannot fail");
        }
        Ok(output.into_bytes())
    }

    /// Publish the runner seam to its compiled root-owned path. The broker
    /// binary does not call this during zero-capacity startup.
    pub fn publish(&self) -> Result<(), HarnessError> {
        self.publish_destination(Path::new(HARNESS_ENV_PATH))
    }

    fn publish_destination(&self, destination: &Path) -> Result<(), HarnessError> {
        atomic_publish(destination, &self.encode_env()?, ROOT_READ_ONLY_FILE_MODE)?;
        Ok(())
    }

    #[cfg(test)]
    fn publish_to(&self, destination: &Path) -> Result<(), HarnessError> {
        self.publish_destination(destination)
    }
}

fn path_text(path: &Path) -> Result<&str, HarnessError> {
    path.to_str().ok_or(HarnessError::InvalidPath)
}

fn safe_fixture_repo(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.chars().any(|character| {
            character.is_whitespace() || character.is_control() || character == '='
        })
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        && path
            .to_str()
            .is_some_and(|value| !value.bytes().any(|byte| byte <= b' ' || byte == b'='))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn config(root: &Path) -> HarnessConfig {
        HarnessConfig {
            execd_socket: root.join("execd.sock"),
            broker_unit: "buzz-ci-execd.service".to_owned(),
            lease_state_root: root.join("leases"),
            runner_entrypoint: root.join("bin/runner"),
            fixture_repo: "only21mil/buzz-ci-fixtures".to_owned(),
            harness_signer: "11".repeat(32),
            graph_reducer: root.join("bin/reducer"),
            graph_fixture_dir: root.join("fixtures"),
        }
    }

    #[test]
    fn publishes_exact_keys_as_non_writable_file() {
        let root = crate::evidence::tests::temp_root("harness");
        let destination = root.join("harness.env");
        config(&root).publish_to(&destination).unwrap();
        assert_eq!(HARNESS_ENV_PATH, "/etc/buzzci/harness.env");
        let text = std::fs::read_to_string(&destination).unwrap();
        assert!(text.contains("BUZZ_CI_FIXTURE_REPO=only21mil/buzz-ci-fixtures\n"));
        assert_eq!(text.lines().count(), HARNESS_KEYS.len());
        for key in HARNESS_KEYS {
            assert_eq!(
                text.lines()
                    .filter(|line| line.starts_with(&format!("{key}=")))
                    .count(),
                1
            );
        }
        assert_eq!(
            std::fs::metadata(destination).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }

    #[test]
    fn rejects_injection_and_relative_paths() {
        let root = crate::evidence::tests::temp_root("invalid-harness");
        let mut value = config(&root);
        value.broker_unit = "broker.service\nEVIL=1".to_owned();
        assert!(matches!(value.validate(), Err(HarnessError::InvalidUnit)));
        value = config(&root);
        value.runner_entrypoint = PathBuf::from("relative");
        assert!(matches!(value.validate(), Err(HarnessError::InvalidPath)));
        value = config(&root);
        value.harness_signer = format!("{}\nEVIL", "11".repeat(32));
        assert!(matches!(value.validate(), Err(HarnessError::InvalidSigner)));
    }

    #[test]
    fn accepts_repo_coordinates_and_rejects_fixture_injection() {
        let root = crate::evidence::tests::temp_root("fixture-coordinate");
        let mut value = config(&root);
        value.validate().unwrap();
        value.fixture_repo = format!("nostr:30617:{}:buzz-ci-fixtures", "22".repeat(32));
        let encoded = String::from_utf8(value.encode_env().unwrap()).unwrap();
        assert!(encoded.contains(&format!("BUZZ_CI_FIXTURE_REPO={}\n", value.fixture_repo)));

        for invalid in ["", " ", "repo name", "repo\nname", "repo=name"] {
            value.fixture_repo = invalid.to_owned();
            assert!(matches!(
                value.validate(),
                Err(HarnessError::InvalidFixtureRepo)
            ));
        }
    }
}
