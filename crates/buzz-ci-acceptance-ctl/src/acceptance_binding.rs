//! Canonical post-freeze acceptance binding shared by controld and keyholder.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path};

use buzz_core::ci::{request_tags, CiRequestEnvelope, CiRequestType};
use buzz_core::kind::{KIND_CI_GRANT, KIND_CI_REQUEST, KIND_DELETION};
use nostr::secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::acceptance::{EvidenceObject, FixtureSpec};

/// Fixed root-owned receipt read independently by keyholder and controld.
pub const ACCEPTANCE_BINDING_PATH: &str =
    "/var/lib/buzzci/activation-controller/controld-acceptance-v1.json";
/// Exact receipt schema. This is distinct from the capacity-one acceptance receipt v2.
pub const ACCEPTANCE_BINDING_SCHEMA: &str = "buzz-ci-activation-acceptance-binding/v1";
/// Required mode of the root-owned receipt.
pub const ACCEPTANCE_BINDING_MODE: u32 = 0o444;
/// Required mode of the immediate root-owned receipt directory.
pub const ACCEPTANCE_BINDING_PARENT_MODE: u32 = 0o711;
/// Maximum accepted receipt size.
pub const MAX_ACCEPTANCE_BINDING_BYTES: u64 = 256 * 1024;
const MAX_ACCEPTANCE_EVENT_BYTES: usize = 48 * 1024;
const MAX_ACCEPTANCE_GRANT_WINDOW_SECONDS: i64 = 3_600;

/// Public acceptance actor encoded in canonical receipt JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceActorBinding {
    pub public_key: String,
    pub generation: u64,
}

/// Exact four-template authority for one activation scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceAuthorityBinding {
    pub actor: AcceptanceActorBinding,
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
    pub acceptance: AcceptanceAuthorityBinding,
}

/// Validated identities and event IDs derived from one canonical receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedAcceptanceBinding {
    actor_public_key: [u8; 32],
    actor_generation: u64,
    scenario_sha256: [u8; 32],
    event_ids: [[u8; 32]; 4],
    granted_ci_signer: [u8; 32],
}

impl ValidatedAcceptanceBinding {
    /// Return the dedicated acceptance actor public key.
    pub const fn actor_public_key(&self) -> [u8; 32] {
        self.actor_public_key
    }

    /// Return the dedicated acceptance actor generation.
    pub const fn actor_generation(&self) -> u64 {
        self.actor_generation
    }

    /// Return the exact activation scenario digest.
    pub const fn scenario_sha256(&self) -> [u8; 32] {
        self.scenario_sha256
    }

    /// Return event IDs in Run, Grant, Rerun, Tombstone order.
    pub const fn event_ids(&self) -> [[u8; 32]; 4] {
        self.event_ids
    }

    /// Return the CI signer authorized by the grant template.
    pub const fn granted_ci_signer(&self) -> [u8; 32] {
        self.granted_ci_signer
    }
}

impl AcceptanceBindingReceipt {
    /// Load the fixed canonical root-owned receipt without following links or
    /// accepting an inode replacement during the read.
    #[cfg(target_os = "linux")]
    pub fn load(path: &Path) -> Result<Self, AcceptanceBindingError> {
        Self::load_checked(path, 0, 0, true)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load(_path: &Path) -> Result<Self, AcceptanceBindingError> {
        Err(AcceptanceBindingError::Unavailable)
    }

    /// Parse and validate the exact compact receipt bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AcceptanceBindingError> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_ACCEPTANCE_BINDING_BYTES {
            return Err(AcceptanceBindingError::Invalid);
        }
        let receipt: Self =
            serde_json::from_slice(bytes).map_err(|_| AcceptanceBindingError::Invalid)?;
        receipt.validate()?;
        if serde_json::to_vec(&receipt).map_err(|_| AcceptanceBindingError::Invalid)? != bytes {
            return Err(AcceptanceBindingError::Invalid);
        }
        Ok(receipt)
    }

    /// Validate the package, fixture, peer, actor, generation, scenario, and
    /// exact Run/Grant/Rerun/Tombstone event bindings.
    pub fn validate(&self) -> Result<ValidatedAcceptanceBinding, AcceptanceBindingError> {
        if self.schema_version != ACCEPTANCE_BINDING_SCHEMA
            || !valid_name(&self.activation_id, 128)
            || self.scenario_sha256 != self.acceptance.scenario_sha256
            || decode_hex::<32>(&self.activation_package_digest).is_none()
            || !matches!(self.fixture.integrated_candidate_sha.len(), 40 | 64)
            || !lower_hex_nonzero(&self.fixture.integrated_candidate_sha)
            || self.peer_uid == 0
            || self.peer_gid == 0
            || self.timeout_millis == 0
            || self.timeout_millis > 300_000
            || self.acceptance.actor.generation == 0
        {
            return Err(AcceptanceBindingError::Invalid);
        }

        let actor_public_key = decode_hex::<32>(&self.acceptance.actor.public_key)
            .ok_or(AcceptanceBindingError::Invalid)?;
        XOnlyPublicKey::from_slice(&actor_public_key)
            .map_err(|_| AcceptanceBindingError::Invalid)?;
        let scenario_sha256 =
            decode_hex::<32>(&self.scenario_sha256).ok_or(AcceptanceBindingError::Invalid)?;
        validate_fixture(self)?;

        let event_bytes = self.event_bytes()?;
        let event_refs = event_bytes.each_ref().map(Vec::as_slice);
        let templates = validate_acceptance_event_templates(actor_public_key, event_refs)?;
        if self.fixture.request_digest != hex::encode(templates.event_ids[0])
            || self.fixture.grant_digest != hex::encode(templates.event_ids[1])
            || self.fixture.approved_by != self.acceptance.actor.public_key
        {
            return Err(AcceptanceBindingError::Invalid);
        }

        Ok(ValidatedAcceptanceBinding {
            actor_public_key,
            actor_generation: self.acceptance.actor.generation,
            scenario_sha256,
            event_ids: templates.event_ids,
            granted_ci_signer: templates.granted_ci_signer,
        })
    }

    fn event_bytes(&self) -> Result<[Vec<u8>; 4], AcceptanceBindingError> {
        [
            &self.acceptance.run_event,
            &self.acceptance.grant_event,
            &self.acceptance.rerun_event,
            &self.acceptance.tombstone_event,
        ]
        .map(|event| serde_json::to_vec(event).map_err(|_| AcceptanceBindingError::Invalid))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| AcceptanceBindingError::Invalid)
    }

    #[cfg(target_os = "linux")]
    fn load_checked(
        path: &Path,
        expected_uid: u32,
        expected_gid: u32,
        require_fixed_path: bool,
    ) -> Result<Self, AcceptanceBindingError> {
        use nix::fcntl::{open, OFlag};
        use nix::sys::stat::Mode;
        use std::os::unix::fs::MetadataExt;

        if (require_fixed_path && path != Path::new(ACCEPTANCE_BINDING_PATH))
            || !normalized_absolute(path)
        {
            return Err(AcceptanceBindingError::Invalid);
        }
        let parent = path.parent().ok_or(AcceptanceBindingError::Invalid)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(|_| AcceptanceBindingError::Unavailable)?;
        if fs::canonicalize(parent).map_err(|_| AcceptanceBindingError::Invalid)? != parent
            || !parent_metadata.file_type().is_dir()
            || parent_metadata.uid() != expected_uid
            || parent_metadata.gid() != expected_gid
            || parent_metadata.mode() & 0o7777 != ACCEPTANCE_BINDING_PARENT_MODE
        {
            return Err(AcceptanceBindingError::Invalid);
        }
        let before = fs::symlink_metadata(path).map_err(|_| AcceptanceBindingError::Unavailable)?;
        validate_metadata(&before, expected_uid, expected_gid)?;
        if fs::canonicalize(path).map_err(|_| AcceptanceBindingError::Invalid)? != path
            || before.len() == 0
            || before.len() > MAX_ACCEPTANCE_BINDING_BYTES
        {
            return Err(AcceptanceBindingError::Invalid);
        }
        let descriptor = open(
            path,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| AcceptanceBindingError::Unavailable)?;
        let file = File::from(descriptor);
        let opened = file
            .metadata()
            .map_err(|_| AcceptanceBindingError::Unavailable)?;
        validate_metadata(&opened, expected_uid, expected_gid)?;
        if (before.dev(), before.ino(), before.len()) != (opened.dev(), opened.ino(), opened.len())
        {
            return Err(AcceptanceBindingError::Invalid);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take(MAX_ACCEPTANCE_BINDING_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AcceptanceBindingError::Unavailable)?;
        if bytes.len() as u64 != opened.len() {
            return Err(AcceptanceBindingError::Invalid);
        }
        Self::from_canonical_bytes(&bytes)
    }

    #[cfg(all(test, target_os = "linux"))]
    fn load_test_path(
        path: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, AcceptanceBindingError> {
        Self::load_checked(path, expected_uid, expected_gid, false)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedEventTemplates {
    event_ids: [[u8; 32]; 4],
    granted_ci_signer: [u8; 32],
}

/// Validate the exact Run/Grant/Rerun/Tombstone event template set.
pub fn validate_acceptance_event_templates(
    actor: [u8; 32],
    templates: [&[u8]; 4],
) -> Result<ValidatedAcceptanceEvents, AcceptanceBindingError> {
    if actor == [0; 32]
        || templates
            .iter()
            .any(|template| template.is_empty() || template.len() > MAX_ACCEPTANCE_EVENT_BYTES)
    {
        return Err(AcceptanceBindingError::Invalid);
    }
    let validated = validate_event_templates(actor, templates)?;
    Ok(ValidatedAcceptanceEvents {
        event_ids: validated.event_ids,
        granted_ci_signer: validated.granted_ci_signer,
    })
}

/// Validated IDs and grant signer derived from four event templates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedAcceptanceEvents {
    event_ids: [[u8; 32]; 4],
    granted_ci_signer: [u8; 32],
}

impl ValidatedAcceptanceEvents {
    /// Return event IDs in Run, Grant, Rerun, Tombstone order.
    pub const fn event_ids(&self) -> [[u8; 32]; 4] {
        self.event_ids
    }

    /// Return the CI signer authorized by the grant event.
    pub const fn granted_ci_signer(&self) -> [u8; 32] {
        self.granted_ci_signer
    }
}

fn validate_event_templates(
    actor: [u8; 32],
    templates: [&[u8]; 4],
) -> Result<ValidatedEventTemplates, AcceptanceBindingError> {
    let values = templates
        .into_iter()
        .zip([
            KIND_CI_REQUEST,
            KIND_CI_GRANT,
            KIND_CI_REQUEST,
            KIND_DELETION,
        ])
        .map(|(template, kind)| validate_event(template, actor, kind))
        .collect::<Result<Vec<_>, _>>()?;
    let run = request_from_template(&values[0], CiRequestType::Run)?;
    let rerun = request_from_template(&values[2], CiRequestType::Rerun)?;
    let run_tags = values[0][4]
        .as_array()
        .ok_or(AcceptanceBindingError::Invalid)?;
    let channel = exact_channel(run_tags)?;
    validate_request_template(run_tags, channel, &run)?;
    validate_request_template(
        values[2][4]
            .as_array()
            .ok_or(AcceptanceBindingError::Invalid)?,
        channel,
        &rerun,
    )?;
    if run.target_repo_a != rerun.target_repo_a
        || run.pr_root_event_id != rerun.pr_root_event_id
        || run.pr_update_event_id != rerun.pr_update_event_id
        || run.source_clone_url != rerun.source_clone_url
        || run.immutable_source_ref != rerun.immutable_source_ref
        || run.tip_oid != rerun.tip_oid
        || run.source_branch != rerun.source_branch
        || run.base_ref != rerun.base_ref
        || run.base_oid != rerun.base_oid
        || run.workflow_id != rerun.workflow_id
        || run.workflow_digest != rerun.workflow_digest
        || run.run_id != rerun.run_id
        || run.actor != rerun.actor
        || run.actor != hex::encode(actor)
        || rerun.parent_run_id.as_deref() != Some(run.run_id.as_str())
        || rerun.parent_attempt != Some(1)
        || rerun.attempt != 2
        || rerun.job_ids.len() != 1
    {
        return Err(AcceptanceBindingError::Invalid);
    }
    let granted_ci_signer = validate_grant_template(&values[1], channel, &run.target_repo_a)?;
    let event_ids: [[u8; 32]; 4] = templates.map(|template| Sha256::digest(template).into());
    validate_tombstone_template(&values[3], event_ids[2])?;
    if event_ids.contains(&[0; 32]) || event_ids.iter().collect::<HashSet<_>>().len() != 4 {
        return Err(AcceptanceBindingError::Invalid);
    }
    Ok(ValidatedEventTemplates {
        event_ids,
        granted_ci_signer,
    })
}

fn validate_event(
    bytes: &[u8],
    actor: [u8; 32],
    expected_kind: u32,
) -> Result<serde_json::Value, AcceptanceBindingError> {
    let value = validate_canonical_json(bytes)?;
    let fields = value.as_array().ok_or(AcceptanceBindingError::Invalid)?;
    if fields.len() != 6
        || fields[0].as_u64() != Some(0)
        || fields[1].as_str() != Some(hex::encode(actor).as_str())
        || fields[2].as_u64().is_none()
        || fields[3].as_u64() != Some(u64::from(expected_kind))
        || !fields[4].is_array()
        || fields[5].as_str().is_none()
    {
        return Err(AcceptanceBindingError::Invalid);
    }
    let tags = fields[4]
        .as_array()
        .ok_or(AcceptanceBindingError::Invalid)?;
    if tags.iter().any(|tag| {
        tag.as_array()
            .is_none_or(|values| values.is_empty() || values.iter().any(|value| !value.is_string()))
    }) {
        return Err(AcceptanceBindingError::Invalid);
    }
    Ok(value)
}

fn request_from_template(
    value: &serde_json::Value,
    request_type: CiRequestType,
) -> Result<CiRequestEnvelope, AcceptanceBindingError> {
    let content = value[5].as_str().ok_or(AcceptanceBindingError::Invalid)?;
    let envelope: CiRequestEnvelope =
        serde_json::from_str(content).map_err(|_| AcceptanceBindingError::Invalid)?;
    envelope
        .validate()
        .map_err(|_| AcceptanceBindingError::Invalid)?;
    if envelope.request_type != request_type {
        return Err(AcceptanceBindingError::Invalid);
    }
    Ok(envelope)
}

fn exact_channel(tags: &[serde_json::Value]) -> Result<&str, AcceptanceBindingError> {
    let channels = tags
        .iter()
        .filter_map(|tag| {
            let fields = tag.as_array()?;
            (fields.first()?.as_str()? == "h")
                .then(|| fields.get(1)?.as_str())
                .flatten()
        })
        .collect::<Vec<_>>();
    match channels.as_slice() {
        [channel]
            if Uuid::parse_str(channel)
                .is_ok_and(|value| value.hyphenated().to_string() == *channel) =>
        {
            Ok(channel)
        }
        _ => Err(AcceptanceBindingError::Invalid),
    }
}

fn validate_request_template(
    tags: &[serde_json::Value],
    channel: &str,
    envelope: &CiRequestEnvelope,
) -> Result<(), AcceptanceBindingError> {
    let expected = request_tags(channel, envelope).map_err(|_| AcceptanceBindingError::Invalid)?;
    let expected = serde_json::to_value(expected).map_err(|_| AcceptanceBindingError::Invalid)?;
    (expected == serde_json::Value::Array(tags.to_vec()))
        .then_some(())
        .ok_or(AcceptanceBindingError::Invalid)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceGrant {
    schema_version: u32,
    target_repo_a: String,
    signer_pubkey: String,
    valid_from: serde_json::Value,
    #[serde(default)]
    valid_until: Option<serde_json::Value>,
}

fn validate_grant_template(
    value: &serde_json::Value,
    channel: &str,
    target_repo_a: &str,
) -> Result<[u8; 32], AcceptanceBindingError> {
    let content = value[5].as_str().ok_or(AcceptanceBindingError::Invalid)?;
    let grant: AcceptanceGrant =
        serde_json::from_str(content).map_err(|_| AcceptanceBindingError::Invalid)?;
    let tags = value[4].as_array().ok_or(AcceptanceBindingError::Invalid)?;
    let valid_from = grant
        .valid_from
        .as_i64()
        .ok_or(AcceptanceBindingError::Invalid)?;
    let valid_until = grant
        .valid_until
        .as_ref()
        .map(|value| value.as_i64().ok_or(AcceptanceBindingError::Invalid))
        .transpose()?;
    let created_at = i64::try_from(value[2].as_u64().ok_or(AcceptanceBindingError::Invalid)?)
        .map_err(|_| AcceptanceBindingError::Invalid)?;
    if grant.schema_version != 1
        || grant.target_repo_a != target_repo_a
        || decode_hex::<32>(&grant.signer_pubkey).is_none()
        || valid_from != created_at
        || !matches!(
            valid_until,
            Some(until)
                if until > valid_from
                    && until.saturating_sub(valid_from) <= MAX_ACCEPTANCE_GRANT_WINDOW_SECONDS
        )
        || serde_json::Value::Array(tags.to_vec()) != serde_json::json!([["h", channel]])
    {
        return Err(AcceptanceBindingError::Invalid);
    }
    decode_hex::<32>(&grant.signer_pubkey).ok_or(AcceptanceBindingError::Invalid)
}

fn validate_tombstone_template(
    value: &serde_json::Value,
    rerun_event_id: [u8; 32],
) -> Result<(), AcceptanceBindingError> {
    let tags = value[4].as_array().ok_or(AcceptanceBindingError::Invalid)?;
    if value[5].as_str() != Some("")
        || serde_json::Value::Array(tags.to_vec())
            != serde_json::json!([["e", hex::encode(rerun_event_id)]])
    {
        return Err(AcceptanceBindingError::Invalid);
    }
    Ok(())
}

fn validate_fixture(receipt: &AcceptanceBindingReceipt) -> Result<(), AcceptanceBindingError> {
    let fixture = &receipt.fixture;
    if !matches!(fixture.integrated_candidate_sha.len(), 40 | 64)
        || !lower_hex_nonzero(&fixture.integrated_candidate_sha)
        || !lower_hex_nonzero_len(&fixture.run_id, 32)
        || !lower_hex_nonzero_len(&fixture.approval_id, 32)
        || !matches!(fixture.source_oid.len(), 40 | 64)
        || !lower_hex_nonzero(&fixture.source_oid)
        || [
            &fixture.request_digest,
            &fixture.manifest_digest,
            &fixture.grant_digest,
            &fixture.approved_by,
            &fixture.export_subject,
            &fixture.export_authorization_digest,
        ]
        .into_iter()
        .any(|value| !lower_hex_nonzero_len(value, 64))
        || !valid_evidence(&fixture.expected_log)
        || fixture.expected_artifacts.is_empty()
        || fixture
            .expected_artifacts
            .iter()
            .any(|item| !valid_evidence(item))
    {
        return Err(AcceptanceBindingError::Invalid);
    }
    let names = fixture
        .expected_artifacts
        .iter()
        .map(|item| item.name.as_str())
        .collect::<HashSet<_>>();
    if names.len() != fixture.expected_artifacts.len()
        || names.contains(fixture.expected_log.name.as_str())
    {
        return Err(AcceptanceBindingError::Invalid);
    }
    Ok(())
}

fn valid_evidence(value: &EvidenceObject) -> bool {
    !value.name.is_empty()
        && value.name.len() <= 255
        && !value.name.contains('/')
        && value.bytes > 0
        && lower_hex_nonzero_len(&value.sha256, 64)
}

fn lower_hex_nonzero_len(value: &str, len: usize) -> bool {
    value.len() == len && lower_hex_nonzero(value)
}

fn valid_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_canonical_json(bytes: &[u8]) -> Result<serde_json::Value, AcceptanceBindingError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| AcceptanceBindingError::Invalid)?;
    let mut canonical = Vec::with_capacity(bytes.len());
    append_canonical_json(&value, &mut canonical)?;
    if canonical != bytes {
        return Err(AcceptanceBindingError::Invalid);
    }
    Ok(value)
}

fn append_canonical_json(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), AcceptanceBindingError> {
    match value {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {
            serde_json::to_writer(output, value).map_err(|_| AcceptanceBindingError::Invalid)?;
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                append_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|_| AcceptanceBindingError::Invalid)?;
                output.push(b':');
                append_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    (value.len() == N * 2 && lower_hex_nonzero(value))
        .then(|| hex::decode(value).ok())
        .flatten()
        .and_then(|decoded| decoded.try_into().ok())
}

fn lower_hex_nonzero(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(target_os = "linux")]
fn validate_metadata(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), AcceptanceBindingError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o7777 != ACCEPTANCE_BINDING_MODE
    {
        return Err(AcceptanceBindingError::Invalid);
    }
    Ok(())
}

/// Public receipt failures intentionally omit file paths and parse details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcceptanceBindingError {
    #[error("acceptance binding receipt is unavailable")]
    Unavailable,
    #[error("acceptance binding receipt is invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;
    use crate::acceptance_binding_test_support::{
        acceptance_binding_mutation_corpus, canonical_acceptance_binding,
    };

    #[test]
    fn canonical_receipt_derives_all_four_ids() {
        let receipt = canonical_acceptance_binding();
        let bytes = serde_json::to_vec(&receipt).expect("receipt bytes");
        let parsed = AcceptanceBindingReceipt::from_canonical_bytes(&bytes).expect("receipt");
        let validated = parsed.validate().expect("validated");
        assert_eq!(validated.actor_generation(), 10);
        assert_eq!(validated.scenario_sha256(), [9; 32]);
        assert_eq!(
            hex::encode(validated.event_ids()[0]),
            receipt.fixture.request_digest
        );
        assert_eq!(
            hex::encode(validated.event_ids()[1]),
            receipt.fixture.grant_digest
        );
        for mutation in acceptance_binding_mutation_corpus() {
            assert_eq!(
                AcceptanceBindingReceipt::from_canonical_bytes(&mutation.bytes),
                Err(AcceptanceBindingError::Invalid),
                "mutation {}",
                mutation.name
            );
        }
    }

    #[test]
    fn secure_loader_rejects_wrong_path_modes_links_and_owners() {
        let expected = canonical_acceptance_binding();
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(
            root.path(),
            fs::Permissions::from_mode(ACCEPTANCE_BINDING_PARENT_MODE),
        )
        .expect("parent mode");
        let path = root.path().join("receipt.json");
        fs::write(&path, serde_json::to_vec(&expected).expect("receipt")).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(ACCEPTANCE_BINDING_MODE))
            .expect("receipt mode");
        let parent = fs::metadata(root.path()).expect("parent metadata");
        assert!(
            AcceptanceBindingReceipt::load_test_path(&path, parent.uid(), parent.gid()).is_ok()
        );
        assert_eq!(
            AcceptanceBindingReceipt::load(&path),
            Err(AcceptanceBindingError::Invalid)
        );
        assert_eq!(
            AcceptanceBindingReceipt::load_test_path(
                &path,
                parent.uid().saturating_add(1),
                parent.gid()
            ),
            Err(AcceptanceBindingError::Invalid)
        );

        let hard_link = root.path().join("receipt-hard-link.json");
        fs::hard_link(&path, &hard_link).expect("hard link");
        assert_eq!(
            AcceptanceBindingReceipt::load_test_path(&path, parent.uid(), parent.gid()),
            Err(AcceptanceBindingError::Invalid)
        );
        fs::remove_file(hard_link).expect("remove hard link");

        let symbolic_link = root.path().join("receipt-symbolic-link.json");
        std::os::unix::fs::symlink(&path, &symbolic_link).expect("symbolic link");
        assert_eq!(
            AcceptanceBindingReceipt::load_test_path(&symbolic_link, parent.uid(), parent.gid()),
            Err(AcceptanceBindingError::Invalid)
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loose mode");
        assert_eq!(
            AcceptanceBindingReceipt::load_test_path(&path, parent.uid(), parent.gid()),
            Err(AcceptanceBindingError::Invalid)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(ACCEPTANCE_BINDING_MODE))
            .expect("receipt mode");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).expect("parent mode");
        assert_eq!(
            AcceptanceBindingReceipt::load_test_path(&path, parent.uid(), parent.gid()),
            Err(AcceptanceBindingError::Invalid)
        );
    }
}
