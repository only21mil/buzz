//! Canonical post-freeze acceptance authority shared by keyholder and controld.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path};

use buzz_ci_acceptance_ctl::acceptance::{AdmissionState, FixtureSpec, Operation};
use buzz_ci_acceptance_ctl::production::{
    expected_adapter_operation_id, AdapterRequest, ControlReadback, ADAPTER_REQUEST_SCHEMA,
};
use nostr::secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AcceptanceSigningPolicy, CanonicalPayload, PublicIdentity};

/// Fixed root-owned receipt read independently by keyholder and controld.
pub const ACCEPTANCE_BINDING_PATH: &str =
    "/var/lib/buzzci/activation-controller/controld-acceptance-v1.json";
/// Exact receipt schema.
pub const ACCEPTANCE_BINDING_SCHEMA: &str = "buzz-ci-activation-acceptance-binding/v1";
const ACCEPTANCE_BINDING_MODE: u32 = 0o444;
const ACCEPTANCE_BINDING_PARENT_MODE: u32 = 0o711;
const MAX_ACCEPTANCE_BINDING_BYTES: u64 = 256 * 1024;

/// Public identity encoded in canonical receipt JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceReceiptIdentity {
    pub public_key: String,
    pub generation: u64,
}

/// Exact four-template authority for one activation scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceReceiptPolicy {
    pub actor: AcceptanceReceiptIdentity,
    pub scenario_sha256: String,
    pub run_event: serde_json::Value,
    pub grant_event: serde_json::Value,
    pub rerun_event: serde_json::Value,
    pub tombstone_event: serde_json::Value,
}

/// Root-authored binding created only after package and scenario freeze.
/// Field declaration order is the canonical compact JSON order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceBindingReceipt {
    pub schema_version: String,
    pub activation_id: String,
    pub activation_package_digest: String,
    pub scenario_sha256: String,
    pub peer_uid: u32,
    pub peer_gid: u32,
    pub timeout_millis: u64,
    pub fixture: FixtureSpec,
    pub acceptance: AcceptanceReceiptPolicy,
}

impl AcceptanceBindingReceipt {
    /// Load the fixed canonical root-owned receipt without following links or
    /// accepting an inode replacement during the read.
    #[cfg(target_os = "linux")]
    pub fn load(path: &Path) -> Result<Self, ReceiptError> {
        Self::load_checked(path, 0, 0, true)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load(_path: &Path) -> Result<Self, ReceiptError> {
        Err(ReceiptError::Unavailable)
    }

    #[cfg(target_os = "linux")]
    fn load_checked(
        path: &Path,
        expected_uid: u32,
        expected_gid: u32,
        require_fixed_path: bool,
    ) -> Result<Self, ReceiptError> {
        use nix::fcntl::{open, OFlag};
        use nix::sys::stat::Mode;
        use std::os::unix::fs::MetadataExt;

        if (require_fixed_path && path != Path::new(ACCEPTANCE_BINDING_PATH))
            || !normalized_absolute(path)
        {
            return Err(ReceiptError::Invalid);
        }
        let parent = path.parent().ok_or(ReceiptError::Invalid)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(|_| ReceiptError::Unavailable)?;
        if fs::canonicalize(parent).map_err(|_| ReceiptError::Invalid)? != parent
            || !parent_metadata.file_type().is_dir()
            || parent_metadata.uid() != expected_uid
            || parent_metadata.gid() != expected_gid
            || parent_metadata.mode() & 0o7777 != ACCEPTANCE_BINDING_PARENT_MODE
        {
            return Err(ReceiptError::Invalid);
        }
        let before = fs::symlink_metadata(path).map_err(|_| ReceiptError::Unavailable)?;
        validate_metadata(&before, expected_uid, expected_gid)?;
        if fs::canonicalize(path).map_err(|_| ReceiptError::Invalid)? != path
            || before.len() == 0
            || before.len() > MAX_ACCEPTANCE_BINDING_BYTES
        {
            return Err(ReceiptError::Invalid);
        }
        let descriptor = open(
            path,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ReceiptError::Unavailable)?;
        let file = File::from(descriptor);
        let opened = file.metadata().map_err(|_| ReceiptError::Unavailable)?;
        validate_metadata(&opened, expected_uid, expected_gid)?;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(ReceiptError::Invalid);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take(MAX_ACCEPTANCE_BINDING_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ReceiptError::Unavailable)?;
        if bytes.len() as u64 != opened.len() || bytes.len() as u64 > MAX_ACCEPTANCE_BINDING_BYTES {
            return Err(ReceiptError::Invalid);
        }
        let receipt: Self = serde_json::from_slice(&bytes).map_err(|_| ReceiptError::Invalid)?;
        receipt.signing_policy()?;
        if serde_json::to_vec(&receipt).map_err(|_| ReceiptError::Invalid)? != bytes {
            return Err(ReceiptError::Invalid);
        }
        Ok(receipt)
    }

    /// Validate all fixture and signing bindings and construct the existing
    /// closed signing policy used by operations 5 and 6.
    pub fn signing_policy(&self) -> Result<AcceptanceSigningPolicy, ReceiptError> {
        if self.schema_version != ACCEPTANCE_BINDING_SCHEMA
            || self.activation_id != self.fixture.activation_id
            || self.activation_package_digest != self.fixture.activation_package_digest
            || self.scenario_sha256 != self.acceptance.scenario_sha256
            || decode_hex(&self.activation_package_digest, 32).is_none()
            || decode_hex(&self.fixture.integrated_candidate_sha, 20).is_none()
            || decode_hex(&self.scenario_sha256, 32).is_none()
            || self.peer_uid == 0
            || self.peer_gid == 0
            || self.timeout_millis == 0
            || self.timeout_millis > 300_000
        {
            return Err(ReceiptError::Invalid);
        }
        validate_fixture(self)?;
        let actor = self.acceptance.actor.identity()?;
        if self.acceptance.actor.public_key != self.fixture.approved_by {
            return Err(ReceiptError::Invalid);
        }
        let payload = |value: &serde_json::Value| {
            CanonicalPayload::new(serde_json::to_vec(value).map_err(|_| ReceiptError::Invalid)?)
                .map_err(|_| ReceiptError::Invalid)
        };
        let scenario_sha256: [u8; 32] = decode_hex(&self.scenario_sha256, 32)
            .ok_or(ReceiptError::Invalid)?
            .try_into()
            .map_err(|_| ReceiptError::Invalid)?;
        let policy = AcceptanceSigningPolicy::new(
            actor,
            scenario_sha256,
            [
                payload(&self.acceptance.run_event)?,
                payload(&self.acceptance.grant_event)?,
                payload(&self.acceptance.rerun_event)?,
                payload(&self.acceptance.tombstone_event)?,
            ],
        )
        .map_err(|_| ReceiptError::Invalid)?;
        if hex::encode(policy.event_ids()[1]) != self.fixture.grant_event_id {
            return Err(ReceiptError::Invalid);
        }
        Ok(policy)
    }
}

impl AcceptanceReceiptIdentity {
    fn identity(&self) -> Result<PublicIdentity, ReceiptError> {
        let bytes = decode_hex(&self.public_key, 32).ok_or(ReceiptError::Invalid)?;
        let public_key: [u8; 32] = bytes.try_into().map_err(|_| ReceiptError::Invalid)?;
        XOnlyPublicKey::from_slice(&public_key).map_err(|_| ReceiptError::Invalid)?;
        if self.generation == 0 {
            return Err(ReceiptError::Invalid);
        }
        Ok(PublicIdentity {
            public_key,
            generation: self.generation,
        })
    }
}

fn validate_fixture(receipt: &AcceptanceBindingReceipt) -> Result<(), ReceiptError> {
    let mut probe = AdapterRequest {
        schema_version: ADAPTER_REQUEST_SCHEMA.to_owned(),
        sequence: 1,
        operation: Operation::ObserveInitial,
        scenario_sha256: receipt.scenario_sha256.clone(),
        operation_id: String::new(),
        fixture: receipt.fixture.clone(),
        attempt_id: None,
        expected_controller_generation: None,
        expected_runner_generation: None,
        host: ControlReadback {
            activation_id: receipt.activation_id.clone(),
            activation_package_digest: receipt.activation_package_digest.clone(),
            integrated_candidate_sha: receipt.fixture.integrated_candidate_sha.clone(),
            capacity: 0,
            admission: AdmissionState::Closed,
            controller_generation: receipt.fixture.controller_generation,
            runner_generation: receipt.fixture.runner_generation,
        },
    };
    probe.operation_id =
        expected_adapter_operation_id(&probe).map_err(|_| ReceiptError::Invalid)?;
    probe.validate().map_err(|_| ReceiptError::Invalid)
}

fn decode_hex(value: &str, bytes: usize) -> Option<Vec<u8>> {
    (value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| hex::decode(value).ok())
    .flatten()
    .filter(|decoded| decoded.iter().any(|byte| *byte != 0))
}

#[cfg(target_os = "linux")]
fn validate_metadata(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), ReceiptError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o7777 != ACCEPTANCE_BINDING_MODE
    {
        return Err(ReceiptError::Invalid);
    }
    Ok(())
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

/// Public receipt failures intentionally omit file paths and parse details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReceiptError {
    #[error("acceptance binding receipt is unavailable")]
    Unavailable,
    #[error("acceptance binding receipt is invalid")]
    Invalid,
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use buzz_ci_acceptance_ctl::acceptance::{EvidenceObject, FixtureSpec};
    use buzz_core::ci::{request_tags, CiRequestEnvelope};
    use sha2::{Digest, Sha256};

    use super::*;

    fn receipt() -> AcceptanceBindingReceipt {
        let source_templates = crate::service::tests::acceptance_templates();
        let mut events: Vec<serde_json::Value> = source_templates
            .iter()
            .map(|payload| serde_json::from_slice(payload.as_bytes()).expect("event"))
            .collect();
        let actor = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13".to_owned();
        let channel = "123e4567-e89b-12d3-a456-426614174099";
        for index in [0, 2] {
            events[index][1] = serde_json::Value::String(actor.clone());
            let mut request: CiRequestEnvelope =
                serde_json::from_str(events[index][5].as_str().expect("request content"))
                    .expect("request");
            request.actor = actor.clone();
            events[index][4] =
                serde_json::to_value(request_tags(channel, &request).expect("request tags"))
                    .expect("tags");
            events[index][5] = serde_json::Value::String(
                serde_json::to_string(&request).expect("request content"),
            );
        }
        events[1][1] = serde_json::Value::String(actor.clone());
        events[3][1] = serde_json::Value::String(actor.clone());
        let rerun_bytes = serde_json::to_vec(&events[2]).expect("rerun bytes");
        events[3][4] = serde_json::json!([["e", hex::encode(Sha256::digest(rerun_bytes))]]);
        let grant_event_id = hex::encode(Sha256::digest(
            serde_json::to_vec(&events[1]).expect("grant"),
        ));
        AcceptanceBindingReceipt {
            schema_version: ACCEPTANCE_BINDING_SCHEMA.to_owned(),
            activation_id: "activation-1".to_owned(),
            activation_package_digest: "12".repeat(32),
            scenario_sha256: "09".repeat(32),
            peer_uid: 1201,
            peer_gid: 1201,
            timeout_millis: 1_000,
            fixture: FixtureSpec {
                integrated_candidate_sha: "11".repeat(20),
                activation_id: "activation-1".to_owned(),
                activation_package_digest: "12".repeat(32),
                run_id: "13".repeat(16),
                job_id: "test".to_owned(),
                request_digest: "14".repeat(32),
                manifest_digest: "15".repeat(32),
                source_oid: "16".repeat(20),
                approval_id: "17".repeat(16),
                grant_event_id,
                grant_digest: "19".repeat(32),
                approved_by: actor.clone(),
                export_subject: "1b".repeat(32),
                export_authorization_digest: "1c".repeat(32),
                controller_generation: 7,
                runner_generation: 9,
                expected_log: EvidenceObject {
                    name: "job.log".to_owned(),
                    sha256: "1d".repeat(32),
                    bytes: 1,
                },
                expected_artifacts: vec![EvidenceObject {
                    name: "result.json".to_owned(),
                    sha256: "1e".repeat(32),
                    bytes: 1,
                }],
            },
            acceptance: AcceptanceReceiptPolicy {
                actor: AcceptanceReceiptIdentity {
                    public_key: actor,
                    generation: 10,
                },
                scenario_sha256: "09".repeat(32),
                run_event: events[0].clone(),
                grant_event: events[1].clone(),
                rerun_event: events[2].clone(),
                tombstone_event: events[3].clone(),
            },
        }
    }

    fn materialize(receipt: &AcceptanceBindingReceipt) -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(
            root.path(),
            fs::Permissions::from_mode(ACCEPTANCE_BINDING_PARENT_MODE),
        )
        .expect("parent mode");
        let path = root.path().join("receipt.json");
        fs::write(
            &path,
            serde_json::to_vec(receipt).expect("canonical receipt"),
        )
        .expect("receipt");
        fs::set_permissions(&path, fs::Permissions::from_mode(ACCEPTANCE_BINDING_MODE))
            .expect("receipt mode");
        (root, path)
    }

    fn load_test(path: &Path) -> Result<AcceptanceBindingReceipt, ReceiptError> {
        let parent = fs::metadata(path.parent().expect("parent")).expect("parent metadata");
        AcceptanceBindingReceipt::load_checked(path, parent.uid(), parent.gid(), false)
    }

    #[test]
    fn canonical_receipt_binds_fixture_actor_scenario_and_four_event_ids() {
        let expected = receipt();
        let (_root, path) = materialize(&expected);
        let loaded = load_test(&path).expect("receipt");
        let policy = loaded.signing_policy().expect("policy");
        assert_eq!(loaded, expected);
        assert_eq!(policy.actor().generation, 10);
        assert_eq!(policy.scenario_sha256(), [9; 32]);
        assert_eq!(
            hex::encode(policy.event_ids()[1]),
            loaded.fixture.grant_event_id
        );
    }

    #[test]
    fn missing_links_loose_modes_and_noncanonical_bytes_fail_closed() {
        let expected = receipt();
        let (root, path) = materialize(&expected);
        let missing = root.path().join("missing.json");
        assert_eq!(load_test(&missing), Err(ReceiptError::Unavailable));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loose mode");
        assert_eq!(load_test(&path), Err(ReceiptError::Invalid));
        fs::set_permissions(&path, fs::Permissions::from_mode(ACCEPTANCE_BINDING_MODE))
            .expect("exact mode");

        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).expect("loose parent");
        assert_eq!(load_test(&path), Err(ReceiptError::Invalid));
        fs::set_permissions(
            root.path(),
            fs::Permissions::from_mode(ACCEPTANCE_BINDING_PARENT_MODE),
        )
        .expect("exact parent");

        let link = root.path().join("receipt-link.json");
        std::os::unix::fs::symlink(&path, &link).expect("link");
        assert_eq!(load_test(&link), Err(ReceiptError::Invalid));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("write mode");
        let mut bytes = serde_json::to_vec(&expected).expect("canonical receipt");
        bytes.push(b'\n');
        fs::write(&path, bytes).expect("noncanonical receipt");
        fs::set_permissions(&path, fs::Permissions::from_mode(ACCEPTANCE_BINDING_MODE))
            .expect("exact mode");
        assert_eq!(load_test(&path), Err(ReceiptError::Invalid));
    }

    #[test]
    fn tamper_and_restart_reload_drift_are_rejected() {
        let expected = receipt();
        let (_root, path) = materialize(&expected);
        assert!(load_test(&path).is_ok());

        let mut drifted = expected.clone();
        drifted.acceptance.scenario_sha256 = "0a".repeat(32);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("write mode");
        fs::write(
            &path,
            serde_json::to_vec(&drifted).expect("drifted receipt"),
        )
        .expect("drifted receipt");
        fs::set_permissions(&path, fs::Permissions::from_mode(ACCEPTANCE_BINDING_MODE))
            .expect("exact mode");
        assert_eq!(load_test(&path), Err(ReceiptError::Invalid));

        drifted.acceptance.scenario_sha256 = drifted.scenario_sha256.clone();
        drifted.acceptance.actor.generation += 1;
        drifted.fixture.grant_event_id = "20".repeat(32);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("write mode");
        fs::write(
            &path,
            serde_json::to_vec(&drifted).expect("drifted receipt"),
        )
        .expect("drifted receipt");
        fs::set_permissions(&path, fs::Permissions::from_mode(ACCEPTANCE_BINDING_MODE))
            .expect("exact mode");
        assert_eq!(load_test(&path), Err(ReceiptError::Invalid));
    }
}
