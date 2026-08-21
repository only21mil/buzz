use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::MaterializeError;

/// A lowercase SHA-256 digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Parse one exact lowercase SHA-256 digest.
    pub fn parse(value: impl Into<String>) -> Result<Self, MaterializeError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MaterializeError::InvalidManifest(
                "SHA-256 digests must be 64 lowercase hexadecimal characters".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Return the canonical lowercase hexadecimal value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_sha256_bytes(bytes: [u8; 32]) -> Self {
        Self(hex::encode(bytes))
    }
}

/// Resource ceilings that the broker must enforce around the materializer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationLimits {
    /// Maximum fetched bytes.
    pub max_wire_bytes: u64,
    /// Maximum bytes in any one Git blob.
    pub max_blob_bytes: u64,
    /// Maximum bytes in the published tree.
    pub max_checkout_bytes: u64,
    /// Maximum number of regular files.
    pub max_entries: u32,
    /// Maximum UTF-8 bytes in a relative path.
    pub max_path_bytes: u32,
    /// Maximum path component depth.
    pub max_depth: u16,
    /// Wall-clock deadline for the complete phase.
    pub deadline_seconds: u64,
}

impl MaterializationLimits {
    pub(crate) fn validate(&self) -> Result<(), MaterializeError> {
        let values = [
            ("max_wire_bytes", self.max_wire_bytes),
            ("max_blob_bytes", self.max_blob_bytes),
            ("max_checkout_bytes", self.max_checkout_bytes),
            ("deadline_seconds", self.deadline_seconds),
        ];
        if let Some((name, _)) = values.into_iter().find(|(_, value)| *value == 0) {
            return Err(MaterializeError::InvalidPolicy(format!(
                "{name} must be non-zero"
            )));
        }
        if self.max_entries == 0 || self.max_path_bytes == 0 || self.max_depth == 0 {
            return Err(MaterializeError::InvalidPolicy(
                "entry, path, and depth limits must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

/// Signed, fixed-schema inputs required to materialize one accepted commit.
///
/// The repository value is an opaque coordinate. It is not a URL: the broker
/// maps it to a root-owned origin allowlist after signature/authorization
/// validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationManifest {
    /// Frozen schema version. Phase 1 accepts version 1 only.
    pub schema_version: u16,
    /// Exact accepted kind-46100 request event ID.
    pub request_event_id: String,
    /// Hermes protocol `run` field.
    pub run_id: String,
    /// Hermes protocol `c` tag: exact full commit object ID.
    pub source_sha: String,
    /// Hermes protocol `job` field.
    pub job_id: String,
    /// Hermes protocol attempt number.
    pub attempt: u32,
    /// Exact NIP-33 repository coordinate, resolved through root-owned policy.
    pub repo_coordinate: String,
    /// Exact static workflow identifier from the accepted request.
    pub workflow_id: String,
    /// Broker-issued per-job isolation lease identifier.
    pub lease_id: String,
    /// Expected Git tree object ID.
    pub tree_oid: String,
    /// Trusted base commit that owns the workflow bytes.
    pub trusted_base_sha: String,
    /// Normalized relative workflow path inside the trusted base tree.
    pub workflow_path: String,
    /// Digest of the trusted workflow bytes.
    pub workflow_sha256: Sha256Digest,
    /// Canonical digest of the published source tree.
    pub checkout_sha256: Sha256Digest,
    /// Digest of canonical, broker-supplied non-secret job inputs.
    pub inputs_sha256: Sha256Digest,
    /// Digest of the root-owned materialization policy.
    pub policy_sha256: Sha256Digest,
}

impl MaterializationManifest {
    pub(crate) fn validate(&self) -> Result<(), MaterializeError> {
        if self.schema_version != 1 {
            return Err(MaterializeError::InvalidManifest(
                "only schema_version 1 is accepted".into(),
            ));
        }
        for (name, value) in [
            ("workflow_id", self.workflow_id.as_str()),
            ("lease_id", self.lease_id.as_str()),
        ] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(MaterializeError::InvalidManifest(format!(
                    "{name} is empty, too long, or contains control characters"
                )));
            }
        }
        validate_lower_hex("request_event_id", &self.request_event_id, 64)?;
        Uuid::parse_str(&self.run_id)
            .map_err(|_| MaterializeError::InvalidManifest("run_id must be a UUID".into()))?;
        validate_job_id(&self.job_id)?;
        validate_repository_coordinate(&self.repo_coordinate)?;
        if self.attempt == 0 {
            return Err(MaterializeError::InvalidManifest(
                "attempt must be at least 1".into(),
            ));
        }
        validate_object_id("source_sha", &self.source_sha)?;
        validate_object_id("tree_oid", &self.tree_oid)?;
        validate_object_id("trusted_base_sha", &self.trusted_base_sha)?;
        if self.source_sha.len() != self.trusted_base_sha.len() {
            return Err(MaterializeError::InvalidManifest(
                "tip and base object IDs must use the same width".into(),
            ));
        }
        validate_relative_path(&self.workflow_path)?;
        Ok(())
    }
}

/// Evidence emitted after atomic publication succeeds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationReceipt {
    /// Exact accepted kind-46100 request event ID.
    pub(crate) request_event_id: String,
    /// Run identity.
    pub(crate) run_id: String,
    /// Exact NIP-33 repository coordinate.
    pub(crate) repo_coordinate: String,
    /// Exact accepted commit.
    pub(crate) source_sha: String,
    /// Trusted base commit that supplied the workflow bytes.
    pub(crate) trusted_base_sha: String,
    /// Exact static workflow identifier.
    pub(crate) workflow_id: String,
    /// Exact observed tree object ID.
    pub(crate) tree_oid: String,
    /// Exact trusted-base workflow blob object ID.
    pub(crate) workflow_blob_oid: String,
    /// Job identity.
    pub(crate) job_id: String,
    /// Attempt number.
    pub(crate) attempt: u32,
    /// Broker-issued per-job isolation lease identifier.
    pub(crate) lease_id: String,
    /// Canonical digest of published source bytes.
    pub(crate) checkout_sha256: Sha256Digest,
    /// Digest of trusted workflow bytes.
    pub(crate) workflow_sha256: Sha256Digest,
    /// Digest of canonical inputs.
    pub(crate) inputs_sha256: Sha256Digest,
    /// Digest of root-owned policy.
    pub(crate) policy_sha256: Sha256Digest,
    /// Number of published regular files.
    pub(crate) files: u32,
    /// Number of published file bytes.
    pub(crate) bytes: u64,
}

impl MaterializationReceipt {
    pub fn request_event_id(&self) -> &str {
        &self.request_event_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn repo_coordinate(&self) -> &str {
        &self.repo_coordinate
    }

    pub fn source_sha(&self) -> &str {
        &self.source_sha
    }

    pub fn tree_oid(&self) -> &str {
        &self.tree_oid
    }

    pub fn workflow_blob_oid(&self) -> &str {
        &self.workflow_blob_oid
    }

    pub fn trusted_base_sha(&self) -> &str {
        &self.trusted_base_sha
    }

    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub fn checkout_sha256(&self) -> &Sha256Digest {
        &self.checkout_sha256
    }

    pub fn workflow_sha256(&self) -> &Sha256Digest {
        &self.workflow_sha256
    }

    pub fn inputs_sha256(&self) -> &Sha256Digest {
        &self.inputs_sha256
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    pub fn files(&self) -> u32 {
        self.files
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

fn validate_lower_hex(name: &str, value: &str, length: usize) -> Result<(), MaterializeError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MaterializeError::InvalidManifest(format!(
            "{name} must be lowercase hexadecimal with the required width"
        )));
    }
    Ok(())
}

fn validate_job_id(value: &str) -> Result<(), MaterializeError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(MaterializeError::InvalidManifest(
            "job_id does not match the protocol static job grammar".into(),
        ));
    }
    Ok(())
}

fn validate_repository_coordinate(value: &str) -> Result<(), MaterializeError> {
    let mut parts = value.splitn(3, ':');
    if parts.next() != Some("30617") {
        return Err(MaterializeError::InvalidManifest(
            "repo_coordinate must use repository kind 30617".into(),
        ));
    }
    validate_lower_hex(
        "repo_coordinate owner",
        parts.next().unwrap_or_default(),
        64,
    )?;
    if parts.next().is_none_or(str::is_empty) {
        return Err(MaterializeError::InvalidManifest(
            "repo_coordinate d-tag must be non-empty".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_object_id(name: &str, value: &str) -> Result<(), MaterializeError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MaterializeError::InvalidManifest(format!(
            "{name} must be a full lowercase SHA-1 or SHA-256 object ID"
        )));
    }
    Ok(())
}

pub(crate) fn validate_relative_path(value: &str) -> Result<(), MaterializeError> {
    let path = std::path::Path::new(value);
    if value.is_empty() || path.is_absolute() || value.contains(['\\', ':']) {
        return Err(MaterializeError::InvalidManifest(
            "workflow_path must be a non-empty slash-separated relative path".into(),
        ));
    }
    for component in path.components() {
        match component {
            std::path::Component::Normal(component)
                if component != ".git" && component != "." && component != ".." => {}
            _ => {
                return Err(MaterializeError::InvalidManifest(
                    "workflow_path contains a forbidden component".into(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_parser_is_canonical() {
        assert!(Sha256Digest::parse("a".repeat(64)).is_ok());
        assert!(Sha256Digest::parse("A".repeat(64)).is_err());
        assert!(Sha256Digest::parse("a".repeat(63)).is_err());
    }

    #[test]
    fn path_parser_rejects_escape_and_git_alias() {
        for value in ["../ci.yml", "/ci.yml", ".git/config", "a\\b"] {
            assert!(validate_relative_path(value).is_err(), "accepted {value}");
        }
        assert!(validate_relative_path(".github/workflows/ci.yml").is_ok());
    }
}
