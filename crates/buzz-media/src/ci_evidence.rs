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

    let bytes = scrub_sensitive_content(input)?;
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

const REDACTED: &str = "[REDACTED]";
const SENSITIVE_KEYS: [&str; 14] = [
    "aws_secret_access_key",
    "buzz_s3_secret_key",
    "secret_access_key",
    "authorization",
    "client_secret",
    "secret",
    "access_token",
    "private_key",
    "private key",
    "auth_token",
    "password",
    "passwd",
    "api_key",
    "token",
];

/// Apply the relay's independent, idempotent secret gate. UTF-8 text and JSON
/// are the only evidence forms the upstream executor can seal. Anything else
/// cannot be proven safe and fails before an object key or receipt is written.
fn scrub_sensitive_content(input: &[u8]) -> Result<Vec<u8>, CiEvidenceError> {
    let text = std::str::from_utf8(input).map_err(|_| CiEvidenceError::InvalidBinding)?;
    if contains_disallowed_text_char(text) {
        return Err(CiEvidenceError::InvalidBinding);
    }

    let scrubbed = scrub_sensitive_content_once(text)?;
    let scrubbed_text =
        std::str::from_utf8(&scrubbed).map_err(|_| CiEvidenceError::InvalidBinding)?;
    if scrub_sensitive_content_once(scrubbed_text)? != scrubbed {
        return Err(CiEvidenceError::InvalidBinding);
    }
    Ok(scrubbed)
}

fn scrub_sensitive_content_once(text: &str) -> Result<Vec<u8>, CiEvidenceError> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let mut value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| CiEvidenceError::InvalidBinding)?;
        if scrub_json_value(&mut value)? {
            serde_json::to_vec(&value).map_err(|_| CiEvidenceError::InvalidBinding)
        } else {
            Ok(text.as_bytes().to_vec())
        }
    } else {
        Ok(scrub_text(text).into_bytes())
    }
}

fn scrub_json_value(value: &mut serde_json::Value) -> Result<bool, CiEvidenceError> {
    match value {
        serde_json::Value::Object(fields) => {
            let mut changed = scrub_evidence_document(fields)?;
            for (key, value) in fields {
                if contains_disallowed_text_char(key)
                    || contains_sensitive_assignment(key)
                    || contains_authorization_value(key)
                    || private_key_begin(key).is_some()
                {
                    return Err(CiEvidenceError::InvalidBinding);
                }
                if is_sensitive_key(key) {
                    if value.as_str() != Some(REDACTED) {
                        *value = serde_json::Value::String(REDACTED.to_owned());
                        changed = true;
                    }
                } else {
                    changed |= scrub_json_value(value)?;
                }
            }
            Ok(changed)
        }
        serde_json::Value::Array(items) => {
            let mut changed = false;
            for item in items {
                changed |= scrub_json_value(item)?;
            }
            Ok(changed)
        }
        serde_json::Value::String(text) => {
            if contains_disallowed_text_char(text) {
                return Err(CiEvidenceError::InvalidBinding);
            }
            let scrubbed = scrub_text(text);
            if scrubbed == *text {
                Ok(false)
            } else {
                *text = scrubbed;
                Ok(true)
            }
        }
        _ => Ok(false),
    }
}

fn contains_disallowed_text_char(text: &str) -> bool {
    text.contains('\0') || text.contains('\u{feff}')
}

fn scrub_evidence_document(
    fields: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<bool, CiEvidenceError> {
    let looks_like_evidence_document = fields.contains_key("schema_version")
        && fields.contains_key("execution_binding_digest")
        && ["output", "output_length", "output_sha256"]
            .iter()
            .any(|key| fields.contains_key(*key));
    if !looks_like_evidence_document {
        return Ok(false);
    }

    const EXPECTED_FIELDS: [&str; 6] = [
        "schema_version",
        "execution_binding_digest",
        "conclusion",
        "output_sha256",
        "output_length",
        "output",
    ];
    if fields.len() != EXPECTED_FIELDS.len()
        || !EXPECTED_FIELDS.iter().all(|key| fields.contains_key(*key))
        || fields
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        || !fields
            .get("execution_binding_digest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| is_lower_hex(digest, 64))
        || !fields
            .get("conclusion")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|conclusion| {
                matches!(
                    conclusion,
                    "none"
                        | "success"
                        | "failure"
                        | "cancelled"
                        | "timed_out"
                        | "infrastructure_failure"
                )
            })
    {
        return Err(CiEvidenceError::InvalidBinding);
    }

    let output = fields
        .get("output")
        .and_then(serde_json::Value::as_str)
        .ok_or(CiEvidenceError::InvalidBinding)?;
    let output_length = fields
        .get("output_length")
        .and_then(serde_json::Value::as_u64)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(CiEvidenceError::InvalidBinding)?;
    let output_sha256 = fields
        .get("output_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or(CiEvidenceError::InvalidBinding)?;
    if output.len() != output_length
        || output_sha256 != hex::encode(Sha256::digest(output.as_bytes()))
    {
        return Err(CiEvidenceError::InvalidBinding);
    }

    let scrubbed = scrub_text(output);
    if scrubbed == output {
        return Ok(false);
    }
    fields.insert("output_length".to_owned(), scrubbed.len().into());
    fields.insert(
        "output_sha256".to_owned(),
        hex::encode(Sha256::digest(scrubbed.as_bytes())).into(),
    );
    fields.insert("output".to_owned(), scrubbed.into());
    Ok(true)
}

fn scrub_text(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut pem_end: Option<String> = None;

    for segment in text.split_inclusive('\n') {
        let (line, newline) = segment
            .strip_suffix('\n')
            .map_or((segment, ""), |line| (line, "\n"));
        let (line, carriage_return) = line
            .strip_suffix('\r')
            .map_or((line, ""), |line| (line, "\r"));

        if let Some(expected_end) = pem_end.as_deref() {
            if let Some(end) = find_ascii_case_insensitive(line, expected_end) {
                let suffix = &line[end + expected_end.len()..];
                if !suffix.is_empty() {
                    output.push_str(&scrub_text_line(suffix));
                    output.push_str(carriage_return);
                    output.push_str(newline);
                }
                pem_end = None;
            }
            continue;
        }

        if let Some((begin, expected_end)) = private_key_begin(line) {
            output.push_str(&scrub_text_line(&line[..begin]));
            output.push_str(REDACTED);
            let marker_end = begin + private_key_begin_marker_len(&line[begin..]);
            if let Some(relative_end) =
                find_ascii_case_insensitive(&line[marker_end..], &expected_end)
            {
                let suffix = &line[marker_end + relative_end + expected_end.len()..];
                output.push_str(&scrub_text_line(suffix));
            } else {
                pem_end = Some(expected_end);
            }
            output.push_str(carriage_return);
            output.push_str(newline);
            continue;
        }

        output.push_str(&scrub_text_line(line));
        output.push_str(carriage_return);
        output.push_str(newline);
    }
    output
}

fn scrub_text_line(line: &str) -> String {
    if let Some(value_start) = authorization_value_start(line) {
        return replace_sensitive_tail(line, value_start);
    }
    if let Some(value_start) = sensitive_assignment_value_start(line) {
        return replace_sensitive_tail(line, value_start);
    }
    line.to_owned()
}

fn replace_sensitive_tail(line: &str, value_start: usize) -> String {
    if line[value_start..].trim() == REDACTED {
        return line.to_owned();
    }
    let mut output = String::with_capacity(value_start + REDACTED.len());
    output.push_str(&line[..value_start]);
    output.push_str(REDACTED);
    output
}

fn authorization_value_start(line: &str) -> Option<usize> {
    find_key_value_start(line, "authorization").and_then(|value_start| {
        let value = &line[value_start..];
        (starts_ascii_word(value, "bearer") || starts_ascii_word(value, "basic"))
            .then_some(value_start)
    })
}

fn sensitive_assignment_value_start(line: &str) -> Option<usize> {
    SENSITIVE_KEYS
        .iter()
        .filter(|key| **key != "authorization")
        .filter_map(|key| find_key_value_start(line, key))
        .min()
}

fn find_key_value_start(line: &str, key: &str) -> Option<usize> {
    let mut offset = 0;
    while let Some(found) = find_ascii_case_insensitive(&line[offset..], key) {
        let start = offset + found;
        let before_ok = start == 0 || !line.as_bytes()[start - 1].is_ascii_alphanumeric();
        let mut after = start + key.len();
        let after_ok = after == line.len() || !is_key_byte(line.as_bytes()[after]);
        if before_ok && after_ok {
            after += line[after..]
                .bytes()
                .take_while(u8::is_ascii_whitespace)
                .count();
            if matches!(line.as_bytes().get(after), Some(b'=') | Some(b':')) {
                after += 1;
                after += line[after..]
                    .bytes()
                    .take_while(u8::is_ascii_whitespace)
                    .count();
                return Some(after);
            }
        }
        offset = start + key.len();
    }
    None
}

fn contains_sensitive_assignment(text: &str) -> bool {
    sensitive_assignment_value_start(text).is_some()
}

fn contains_authorization_value(text: &str) -> bool {
    authorization_value_start(text).is_some()
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    SENSITIVE_KEYS.iter().any(|candidate| {
        let candidate = normalize_key(candidate);
        normalized == candidate || normalized.ends_with(&format!("_{candidate}"))
    })
}

fn normalize_key(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len());
    let mut separator = false;
    for byte in key.bytes() {
        if byte.is_ascii_alphanumeric() {
            if separator && !normalized.is_empty() {
                normalized.push('_');
            }
            normalized.push(char::from(byte.to_ascii_lowercase()));
            separator = false;
        } else {
            separator = true;
        }
    }
    normalized
}

fn private_key_begin(line: &str) -> Option<(usize, String)> {
    const PREFIX: &str = "-----begin ";
    let begin = find_ascii_case_insensitive(line, PREFIX)?;
    let label_start = begin + PREFIX.len();
    let label_end = line[label_start..].find("-----")? + label_start;
    let label = &line[label_start..label_end];
    if !label.to_ascii_lowercase().ends_with("private key") {
        return None;
    }
    Some((
        begin,
        format!("-----end {}-----", label.to_ascii_lowercase()),
    ))
}

fn private_key_begin_marker_len(text: &str) -> usize {
    const PREFIX_LEN: usize = "-----begin ".len();
    text[PREFIX_LEN..]
        .find("-----")
        .map_or(text.len(), |end| PREFIX_LEN + end + 5)
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn starts_ascii_word(value: &str, word: &str) -> bool {
    value
        .as_bytes()
        .get(..word.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(word.as_bytes()))
        && value
            .as_bytes()
            .get(word.len())
            .is_some_and(u8::is_ascii_whitespace)
}

const fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
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
        let raw = b"step=build\nAUTH_TOKEN=1234567890\n";
        let scrubbed = b"step=build\nAUTH_TOKEN=[REDACTED]\n";
        let planned = prepare_ci_evidence(binding(scrubbed), raw).expect("scrubbed plan");
        assert_eq!(planned.bytes, scrubbed);
        assert!(planned.scrubbed);

        let error = prepare_ci_evidence(binding(raw), raw).expect_err("raw digest must fail");
        assert_eq!(error, CiEvidenceError::DigestMismatch);
    }

    #[test]
    fn secondary_scrub_matches_the_shared_case_insensitive_assignment_corpus() {
        let raw = concat!(
            "safe before\n",
            "aws_secret_access_key=first\n",
            "prefix BUZZ_S3_SECRET_KEY : second\n",
            "Access_Token=third\n",
            "API_KEY=fourth\n",
            "PASSWORD=fifth\n",
            "passwd=sixth\n",
            "client_secret=seventh\n",
            "private key=eighth\n",
            "suffix token=ninth\n",
            "DATABASE_PASSWORD=tenth\n",
            "safe after\n",
        );
        let expected = concat!(
            "safe before\n",
            "aws_secret_access_key=[REDACTED]\n",
            "prefix BUZZ_S3_SECRET_KEY : [REDACTED]\n",
            "Access_Token=[REDACTED]\n",
            "API_KEY=[REDACTED]\n",
            "PASSWORD=[REDACTED]\n",
            "passwd=[REDACTED]\n",
            "client_secret=[REDACTED]\n",
            "private key=[REDACTED]\n",
            "suffix token=[REDACTED]\n",
            "DATABASE_PASSWORD=[REDACTED]\n",
            "safe after\n",
        );
        assert_eq!(
            scrub_sensitive_content(raw.as_bytes()).expect("scrub assignment corpus"),
            expected.as_bytes()
        );
    }

    #[test]
    fn secondary_scrub_handles_authorization_and_private_key_blocks() {
        let raw = concat!(
            "request Authorization: Bearer raw-token\n",
            "proxy authorization: basic dXNlcjpwYXNz\r\n",
            "before\n",
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "raw key material\n",
            "-----END RSA PRIVATE KEY-----\n",
            "after\n",
            "-----begin private key-----\n",
            "unterminated key material",
        );
        let expected = concat!(
            "request Authorization: [REDACTED]\n",
            "proxy authorization: [REDACTED]\r\n",
            "before\n",
            "[REDACTED]\n",
            "after\n",
            "[REDACTED]\n",
        );
        assert_eq!(
            scrub_sensitive_content(raw.as_bytes()).expect("scrub authorization and PEM"),
            expected.as_bytes()
        );
    }

    #[test]
    fn secondary_scrub_walks_every_json_field_array_and_nested_object() {
        let raw = br#"{
  "safe": "keep formatting when safe",
  "nested": {
    "AWS_SECRET_ACCESS_KEY": "raw-one",
    "items": ["safe", "authorization: Bearer raw-two", {"password": "raw-three"}]
  }
}"#;
        let scrubbed = scrub_sensitive_content(raw).expect("scrub structured evidence");
        let value: serde_json::Value = serde_json::from_slice(&scrubbed).expect("scrubbed JSON");
        assert_eq!(value["safe"], "keep formatting when safe");
        assert_eq!(value["nested"]["AWS_SECRET_ACCESS_KEY"], REDACTED);
        assert_eq!(value["nested"]["items"][0], "safe");
        assert_eq!(value["nested"]["items"][1], "authorization: [REDACTED]");
        assert_eq!(value["nested"]["items"][2]["password"], REDACTED);
        assert!(!String::from_utf8(scrubbed).expect("UTF-8").contains("raw-"));
    }

    #[test]
    fn secondary_scrub_inspects_the_evidence_document_output_field() {
        let output = "build ok\nBUZZ_S3_SECRET_KEY=raw\n";
        let raw = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "execution_binding_digest": "aa".repeat(32),
            "conclusion": "success",
            "output_sha256": hex::encode(Sha256::digest(output.as_bytes())),
            "output_length": output.len(),
            "output": output,
        }))
        .expect("EvidenceDocument bytes");
        let scrubbed = scrub_sensitive_content(&raw).expect("scrub EvidenceDocument");
        let value: serde_json::Value = serde_json::from_slice(&scrubbed).expect("document JSON");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["conclusion"], "success");
        assert_eq!(value["output"], "build ok\nBUZZ_S3_SECRET_KEY=[REDACTED]\n");
        let scrubbed_output = value["output"].as_str().expect("scrubbed output");
        assert_eq!(value["output_length"], scrubbed_output.len());
        assert_eq!(
            value["output_sha256"],
            hex::encode(Sha256::digest(scrubbed_output.as_bytes()))
        );
        assert!(!scrubbed.windows(3).any(|window| window == b"raw"));
    }

    #[test]
    fn safe_text_and_structured_evidence_remain_byte_exact() {
        for safe in [
            b"plain test output\nsha256=0123456789abcdef\n".as_slice(),
            b"basic compile mode\nauthorization: digest abc123\n".as_slice(),
            br#"{ "output": "compiled 12 targets", "sha256": "abc123" }
"#,
        ] {
            assert_eq!(
                scrub_sensitive_content(safe).expect("safe evidence"),
                safe,
                "safe evidence bytes must not be normalized"
            );
        }
    }

    #[test]
    fn unprovable_or_malformed_structured_content_fails_closed() {
        assert_eq!(
            scrub_sensitive_content(b"\xff\xfe"),
            Err(CiEvidenceError::InvalidBinding)
        );
        assert_eq!(
            scrub_sensitive_content(b"safe\0hidden"),
            Err(CiEvidenceError::InvalidBinding)
        );
        assert_eq!(
            scrub_sensitive_content("\u{feff}{\"safe\":true}".as_bytes()),
            Err(CiEvidenceError::InvalidBinding)
        );
        assert_eq!(
            scrub_sensitive_content(br#"{"token":"unterminated}"#),
            Err(CiEvidenceError::InvalidBinding)
        );
        assert_eq!(
            scrub_sensitive_content(br#"{"safe":"value","token=raw":"key"}"#),
            Err(CiEvidenceError::InvalidBinding),
            "secret-bearing JSON keys cannot be rewritten without changing identity"
        );
        assert_eq!(
            scrub_sensitive_content(br#"{"schema_version":1,"execution_binding_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","conclusion":"success","output_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_length":4,"output":"safe"}"#),
            Err(CiEvidenceError::InvalidBinding),
            "EvidenceDocument integrity fields must bind the pre-scrub output"
        );
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
