//! Durable storage planning for Buzz-native CI logs and artifacts.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// CI evidence remains readable for thirty days after its request expires.
pub const CI_EVIDENCE_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
/// A compact tombstone remains for seven more days after the blob is removed.
pub const CI_EVIDENCE_TOMBSTONE_SECONDS: u64 = 7 * 24 * 60 * 60;

const RECEIPT_SCHEMA_VERSION: u32 = 1;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Immutable identity of one CI log or artifact upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiEvidenceBinding {
    /// Host-derived community UUID.
    pub community_id: String,
    /// Repository address from the accepted request.
    pub target_repo_a: String,
    /// Exact workflow identifier from the accepted request.
    pub workflow_id: String,
    /// Exact source tip object ID.
    pub tip_oid: String,
    /// Accepted request event ID for this attempt.
    pub request_event_id: String,
    /// Stable run UUID.
    pub run_id: String,
    /// Static workflow job identifier.
    pub job_id: String,
    /// One-based attempt number.
    pub attempt: u32,
    /// Artifact identifier, or `None` for a job log.
    pub object_id: Option<String>,
    /// SHA-256 of the scrubbed durable bytes.
    pub sha256: String,
    /// Length of the durable bytes.
    pub byte_length: u64,
    /// Expiry from the signed request, used as the deterministic retention anchor.
    pub request_expires_at: u64,
}

impl CiEvidenceBinding {
    /// Return the sole producer-to-uploader handoff root for this job attempt.
    pub fn handoff_root(&self) -> Result<String, CiEvidenceError> {
        Ok(format!("{}/handoff", self.attempt_root()?))
    }

    /// Return the immutable durable object key for this exact evidence binding.
    pub fn object_key(&self) -> Result<String, CiEvidenceError> {
        Ok(format!(
            "{}/durable/{}/{}",
            self.attempt_root()?,
            self.object_id.as_deref().unwrap_or("log"),
            self.sha256
        ))
    }

    /// Return the durable uploader-receipt key paired with the object.
    pub fn receipt_key(&self) -> Result<String, CiEvidenceError> {
        Ok(format!("{}.receipt.json", self.object_key()?))
    }

    fn validate(&self) -> Result<(), CiEvidenceError> {
        if !is_lower_hex(&self.request_event_id, 64)
            || uuid::Uuid::parse_str(&self.community_id).is_err()
            || uuid::Uuid::parse_str(&self.run_id).is_err()
            || !is_static_job_id(&self.job_id)
            || self.attempt == 0
            || !is_lower_hex(&self.sha256, 64)
            || self.byte_length > usize::MAX as u64
            || self.request_expires_at
                > MAX_SAFE_INTEGER - CI_EVIDENCE_RETENTION_SECONDS - CI_EVIDENCE_TOMBSTONE_SECONDS
            || self.target_repo_a.is_empty()
            || self.workflow_id.is_empty()
            || self.tip_oid.is_empty()
            || self
                .object_id
                .as_deref()
                .is_some_and(|value| !is_safe_component(value, 128))
        {
            return Err(CiEvidenceError::InvalidBinding);
        }
        Ok(())
    }

    fn scope_digest(&self) -> String {
        hex::encode(Sha256::digest(
            format!(
                "{}\0{}\0{}",
                self.target_repo_a, self.tip_oid, self.workflow_id
            )
            .as_bytes(),
        ))
    }

    fn attempt_root(&self) -> Result<String, CiEvidenceError> {
        self.validate()?;
        Ok(format!(
            "_ci/v2/{}/{}/{}/{}/{}/{}",
            self.community_id,
            self.scope_digest(),
            self.request_event_id,
            self.run_id,
            self.job_id,
            self.attempt
        ))
    }
}

/// Durable, deterministic acknowledgement of one completed uploader handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiEvidenceReceipt {
    /// Receipt schema version.
    pub schema_version: u32,
    /// Complete immutable evidence identity.
    pub binding: CiEvidenceBinding,
    /// Producer-owned root consumed by the uploader.
    pub handoff_root: String,
    /// Owner before the uploader accepts the handoff.
    pub handoff_owner: CiEvidenceOwner,
    /// Relay-owned immutable blob after the ownership transition.
    pub durable_object_key: String,
    /// Sole owner after this durable receipt exists.
    pub durable_owner: CiEvidenceOwner,
    /// Durable receipt object paired with the blob.
    pub receipt_key: String,
    /// Last Unix second at which the blob remains readable.
    pub retain_until: u64,
    /// Last Unix second at which the tombstone remains durable.
    pub tombstone_until: u64,
}

impl CiEvidenceReceipt {
    /// Return the required storage action at `now`.
    pub const fn retention_action(&self, now: u64) -> CiEvidenceRetentionAction {
        if now <= self.retain_until {
            CiEvidenceRetentionAction::Retain
        } else if now <= self.tombstone_until {
            CiEvidenceRetentionAction::Tombstone
        } else {
            CiEvidenceRetentionAction::Purge
        }
    }

    /// Validate a stored receipt against the expected deterministic receipt.
    pub fn validate_exact(&self, expected: &Self) -> Result<(), CiEvidenceError> {
        if self == expected {
            Ok(())
        } else {
            Err(CiEvidenceError::ReceiptConflict)
        }
    }

    /// Validate every deterministic field against an expected binding.
    pub fn validate_binding(
        &self,
        expected_binding: &CiEvidenceBinding,
    ) -> Result<(), CiEvidenceError> {
        let retain_until = expected_binding
            .request_expires_at
            .checked_add(CI_EVIDENCE_RETENTION_SECONDS)
            .ok_or(CiEvidenceError::RetentionOverflow)?;
        let tombstone_until = retain_until
            .checked_add(CI_EVIDENCE_TOMBSTONE_SECONDS)
            .ok_or(CiEvidenceError::RetentionOverflow)?;
        if self.schema_version != RECEIPT_SCHEMA_VERSION
            || &self.binding != expected_binding
            || self.handoff_root != expected_binding.handoff_root()?
            || self.handoff_owner != CiEvidenceOwner::Producer
            || self.durable_object_key != expected_binding.object_key()?
            || self.durable_owner != CiEvidenceOwner::Relay
            || self.receipt_key != expected_binding.receipt_key()?
            || self.retain_until != retain_until
            || self.tombstone_until != tombstone_until
        {
            return Err(CiEvidenceError::ReceiptConflict);
        }
        Ok(())
    }
}

/// Exclusive owner on either side of the uploader handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiEvidenceOwner {
    /// The job producer owns the attempt-scoped handoff root.
    Producer,
    /// The relay owns the immutable object and receipt after publication.
    Relay,
}

/// Storage action for the bounded evidence-retention window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiEvidenceRetentionAction {
    /// Keep the receipt and evidence blob.
    Retain,
    /// Remove the blob but retain the receipt as a non-readable tombstone.
    Tombstone,
    /// Remove the expired tombstone.
    Purge,
}

/// Bytes and receipt produced before the relay performs any durable write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCiEvidence {
    /// Scrubbed bytes whose digest matches the immutable binding.
    pub bytes: Vec<u8>,
    /// Deterministic uploader receipt.
    pub receipt: CiEvidenceReceipt,
    /// Whether the relay changed sensitive bytes during the scrub pass.
    pub scrubbed: bool,
    /// Canonical JSON bytes stored for the receipt.
    pub receipt_bytes: Vec<u8>,
    /// SHA-256 of `receipt_bytes`, used for exact readback.
    pub receipt_sha256: String,
}

/// Validate, scrub, and bind bytes before any durable write occurs.
pub fn prepare_ci_evidence(
    binding: CiEvidenceBinding,
    input: &[u8],
) -> Result<PreparedCiEvidence, CiEvidenceError> {
    binding.validate()?;
    if input.len() as u64 != binding.byte_length {
        return Err(CiEvidenceError::LengthMismatch);
    }

    let bytes = scrub_sensitive_assignments(input);
    let scrubbed = bytes != input;
    let digest = hex::encode(Sha256::digest(&bytes));
    if digest != binding.sha256 {
        return Err(CiEvidenceError::DigestMismatch);
    }

    let retain_until = binding
        .request_expires_at
        .checked_add(CI_EVIDENCE_RETENTION_SECONDS)
        .ok_or(CiEvidenceError::RetentionOverflow)?;
    let tombstone_until = retain_until
        .checked_add(CI_EVIDENCE_TOMBSTONE_SECONDS)
        .ok_or(CiEvidenceError::RetentionOverflow)?;
    let receipt = CiEvidenceReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        handoff_root: binding.handoff_root()?,
        handoff_owner: CiEvidenceOwner::Producer,
        durable_object_key: binding.object_key()?,
        durable_owner: CiEvidenceOwner::Relay,
        receipt_key: binding.receipt_key()?,
        binding,
        retain_until,
        tombstone_until,
    };
    let receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|error| CiEvidenceError::ReceiptEncoding(error.to_string()))?;
    let receipt_sha256 = hex::encode(Sha256::digest(&receipt_bytes));
    Ok(PreparedCiEvidence {
        bytes,
        receipt,
        scrubbed,
        receipt_bytes,
        receipt_sha256,
    })
}

/// Parse a durable receipt and require exact idempotent equality.
pub fn validate_ci_evidence_receipt(
    bytes: &[u8],
    expected: &CiEvidenceReceipt,
) -> Result<(), CiEvidenceError> {
    let stored: CiEvidenceReceipt =
        serde_json::from_slice(bytes).map_err(|_| CiEvidenceError::ReceiptConflict)?;
    stored.validate_exact(expected)
}

/// Parse a receipt and validate its immutable binding and retention window.
pub fn read_ci_evidence_receipt(
    bytes: &[u8],
    expected_binding: &CiEvidenceBinding,
) -> Result<CiEvidenceReceipt, CiEvidenceError> {
    let stored: CiEvidenceReceipt =
        serde_json::from_slice(bytes).map_err(|_| CiEvidenceError::ReceiptConflict)?;
    stored.validate_binding(expected_binding)?;
    Ok(stored)
}

/// Parse a listed receipt, validate all deterministic fields, and require the
/// listed key to equal the key derived from the embedded immutable binding.
pub fn read_listed_ci_evidence_receipt(
    bytes: &[u8],
    listed_key: &str,
) -> Result<CiEvidenceReceipt, CiEvidenceError> {
    let stored: CiEvidenceReceipt =
        serde_json::from_slice(bytes).map_err(|_| CiEvidenceError::ReceiptConflict)?;
    stored.validate_binding(&stored.binding)?;
    if stored.receipt_key != listed_key {
        return Err(CiEvidenceError::ReceiptConflict);
    }
    Ok(stored)
}

/// CI evidence lifecycle validation failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CiEvidenceError {
    /// One or more immutable coordinates are malformed.
    #[error("invalid CI evidence binding")]
    InvalidBinding,
    /// Input size differs from the bound durable size.
    #[error("CI evidence length mismatch")]
    LengthMismatch,
    /// Scrubbed bytes differ from the bound durable digest.
    #[error("CI evidence digest mismatch after scrub")]
    DigestMismatch,
    /// The deterministic retention window exceeded the supported integer range.
    #[error("CI evidence retention window overflow")]
    RetentionOverflow,
    /// Existing receipt is malformed or belongs to another binding.
    #[error("stored CI evidence receipt conflicts")]
    ReceiptConflict,
    /// Canonical receipt serialization failed.
    #[error("CI evidence receipt encoding failed: {0}")]
    ReceiptEncoding(String),
}

fn scrub_sensitive_assignments(input: &[u8]) -> Vec<u8> {
    let mut output = input.to_vec();
    let mut offset = 0;
    while offset < output.len() {
        let line_end = output[offset..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(output.len(), |index| offset + index);
        scrub_line(&mut output[offset..line_end]);
        offset = line_end.saturating_add(1);
    }
    output
}

fn scrub_line(line: &mut [u8]) {
    let Some(separator) = line.iter().position(|byte| matches!(byte, b'=' | b':')) else {
        return;
    };
    let key = line[..separator]
        .iter()
        .copied()
        .filter(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let sensitive = [
        b"authorization".as_slice(),
        b"api_key".as_slice(),
        b"access_token".as_slice(),
        b"auth_token".as_slice(),
        b"client_secret".as_slice(),
        b"password".as_slice(),
        b"private_key".as_slice(),
        b"secret".as_slice(),
        b"token".as_slice(),
    ];
    if !sensitive.iter().any(|candidate| key.ends_with(candidate)) {
        return;
    }
    for byte in &mut line[separator + 1..] {
        if !byte.is_ascii_whitespace() && !matches!(*byte, b'\'' | b'"') {
            *byte = b'*';
        }
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_static_job_id(value: &str) -> bool {
    value.len() <= 64
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_safe_component(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(bytes: &[u8]) -> CiEvidenceBinding {
        CiEvidenceBinding {
            community_id: "123e4567-e89b-12d3-a456-426614174099".to_owned(),
            target_repo_a: format!("30617:{}:buzz", "11".repeat(32)),
            workflow_id: "ci".to_owned(),
            tip_oid: "22".repeat(20),
            request_event_id: "33".repeat(32),
            run_id: "123e4567-e89b-12d3-a456-426614174011".to_owned(),
            job_id: "test_job".to_owned(),
            attempt: 2,
            object_id: Some("results".to_owned()),
            sha256: hex::encode(Sha256::digest(bytes)),
            byte_length: bytes.len() as u64,
            request_expires_at: 10_000,
        }
    }

    #[test]
    fn plan_binds_workflow_attempt_digest_and_single_handoff_root() {
        let bytes = b"safe output\n";
        let first = prepare_ci_evidence(binding(bytes), bytes).expect("plan");
        let replay = prepare_ci_evidence(binding(bytes), bytes).expect("replay");
        assert_eq!(first, replay, "receipt must be deterministic");
        assert!(first
            .receipt
            .handoff_root
            .ends_with("/123e4567-e89b-12d3-a456-426614174011/test_job/2/handoff"));
        assert!(first
            .receipt
            .durable_object_key
            .ends_with(&format!("/durable/results/{}", binding(bytes).sha256)));

        let mut other_attempt = binding(bytes);
        other_attempt.attempt = 3;
        let other = prepare_ci_evidence(other_attempt, bytes).expect("other attempt");
        assert_ne!(first.receipt.handoff_root, other.receipt.handoff_root);

        let mut other_workflow = binding(bytes);
        other_workflow.workflow_id = "release".to_owned();
        let other = prepare_ci_evidence(other_workflow, bytes).expect("other workflow");
        assert_ne!(first.receipt.handoff_root, other.receipt.handoff_root);
    }

    #[test]
    fn scrub_happens_before_digest_and_receipt_creation() {
        let raw = b"step=build\nAUTH_TOKEN=super-secret\n";
        let scrubbed = b"step=build\nAUTH_TOKEN=************\n";
        let planned = prepare_ci_evidence(binding(scrubbed), raw).expect("scrubbed plan");
        assert_eq!(planned.bytes, scrubbed);
        assert!(planned.scrubbed);

        let error = prepare_ci_evidence(binding(raw), raw).expect_err("raw digest must fail");
        assert_eq!(error, CiEvidenceError::DigestMismatch);
    }

    #[test]
    fn receipt_replay_is_exact_and_retention_is_bounded() {
        let bytes = b"artifact";
        let planned = prepare_ci_evidence(binding(bytes), bytes).expect("plan");
        validate_ci_evidence_receipt(&planned.receipt_bytes, &planned.receipt)
            .expect("exact receipt");
        assert_eq!(
            read_ci_evidence_receipt(&planned.receipt_bytes, &planned.receipt.binding)
                .expect("bound receipt"),
            planned.receipt
        );

        let mut drifted = planned.receipt.clone();
        drifted.binding.attempt = 1;
        assert_eq!(
            validate_ci_evidence_receipt(&planned.receipt_bytes, &drifted),
            Err(CiEvidenceError::ReceiptConflict)
        );
        assert_eq!(
            planned
                .receipt
                .retention_action(planned.receipt.retain_until),
            CiEvidenceRetentionAction::Retain
        );
        assert_eq!(
            planned
                .receipt
                .retention_action(planned.receipt.retain_until + 1),
            CiEvidenceRetentionAction::Tombstone
        );
        assert_eq!(
            planned
                .receipt
                .retention_action(planned.receipt.tombstone_until + 1),
            CiEvidenceRetentionAction::Purge
        );
    }

    #[test]
    fn listed_receipt_must_occupy_its_binding_derived_key() {
        let bytes = b"artifact";
        let planned = prepare_ci_evidence(binding(bytes), bytes).expect("plan");
        assert_eq!(
            read_listed_ci_evidence_receipt(&planned.receipt_bytes, &planned.receipt.receipt_key)
                .expect("bound listed receipt"),
            planned.receipt
        );
        assert_eq!(
            read_listed_ci_evidence_receipt(
                &planned.receipt_bytes,
                "_ci/v2/unrelated.receipt.json"
            ),
            Err(CiEvidenceError::ReceiptConflict)
        );
    }
}
