//! Exact, root-staged native evidence read authority. This grants no publication
//! or execution authority and never enables the acceptance fixture actor.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::ServiceError;

/// One artifact authorized by its exact identifier and immutable content digest.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeEvidenceArtifact {
    /// Artifact identifier within the bound job attempt.
    pub artifact_id: String,
    /// Lowercase SHA-256 of the authorized bytes.
    pub sha256: String,
}

/// A bounded read window for one root-authorized completed job attempt.
/// Root derives the digests from the verified immutable completion bundle.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeEvidencePolicy {
    /// Inclusive start of read authority, independent of workload admission.
    pub not_before: u64,
    /// Exclusive expiry, at most fifteen minutes after `not_before`.
    pub expires_at: u64,
    /// Exact accepted request event ID.
    pub request_event_id: String,
    /// Canonical hyphenated run UUID.
    pub run_id: String,
    /// Exact selected job.
    pub job_id: String,
    /// Exact nonzero attempt.
    pub attempt: u32,
    /// SHA-256 of the reviewed root authority used to validate completion.
    pub authority_sha256: String,
    /// SHA-256 of the immutable completion bundle manifest.
    pub bundle_sha256: String,
    /// Lowercase SHA-256 of the exact published log bytes.
    pub log_sha256: String,
    /// Exact artifact objects, bounded to sixteen and unique by identifier.
    pub artifacts: Vec<NativeEvidenceArtifact>,
}

impl NativeEvidencePolicy {
    /// Validate the complete typed binding and its canonical object paths.
    pub fn validate(&self) -> Result<(), ServiceError> {
        let hex = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && s != "0".repeat(64)
        };
        if self.not_before == 0
            || self.expires_at <= self.not_before
            || self.expires_at - self.not_before > 900
            || self.artifacts.is_empty()
            || self.artifacts.len() > 16
            || !hex(&self.request_event_id)
            || !hex(&self.log_sha256)
            || self.artifacts.iter().any(|a| !hex(&a.sha256))
            || !hex(&self.authority_sha256)
            || !hex(&self.bundle_sha256)
        {
            return Err(ServiceError::InvalidRequest);
        }
        let mut ids = BTreeSet::new();
        if self.artifacts.iter().any(|a| !ids.insert(&a.artifact_id))
            || self
                .paths()
                .iter()
                .any(|p| !crate::service::canonical_evidence_get_path(p))
        {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(())
    }

    /// Exact paths; URL origin is separately pinned by the signing policy.
    pub fn paths(&self) -> BTreeSet<String> {
        let binding = format!(
            "{}/{}/{}/{}",
            self.request_event_id, self.run_id, self.job_id, self.attempt
        );
        let mut paths = BTreeSet::from([format!("/ci/logs/{binding}/{}", self.log_sha256)]);
        paths.extend(
            self.artifacts
                .iter()
                .map(|a| format!("/ci/artifacts/{binding}/{}/{}", a.artifact_id, a.sha256)),
        );
        paths
    }

    pub(crate) fn permits(&self, path: &str, now: u64) -> bool {
        self.not_before <= now && now < self.expires_at && self.paths().contains(path)
    }
}
