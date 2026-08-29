//! Typed, zero-I/O envelopes for Buzz-native CI events.

use crate::kind::{
    KIND_CI_ARTIFACT_REFERENCE, KIND_CI_EVIDENCE_FINALIZED, KIND_CI_JOB_STATUS,
    KIND_CI_LOG_REFERENCE, KIND_CI_REQUEST, KIND_CI_RUN_STATUS, KIND_CI_TEARDOWN_ATTESTATION,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use nostr::Tag;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

/// Current CI envelope schema version.
pub const CI_SCHEMA_VERSION: u32 = 1;
/// Largest integer represented exactly by JavaScript consumers.
pub const CI_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// SHA-256 of `BUZZ_CI_PROTOCOL_CONTRACT.md` v1.4 implemented by this module.
pub const CI_PROTOCOL_CONTRACT_SHA256: &str =
    "ac335626526aba0a0c429e6fbbe387600155d539f456075375cb6f11fb0a18d1";

/// Validation failure for a CI envelope.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid CI envelope: {0}")]
pub struct CiValidationError(pub &'static str);

/// CI request operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiRequestType {
    /// Start a new run.
    Run,
    /// Rerun exactly one failed job.
    Rerun,
}

/// Closed job lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiJobState {
    /// Accepted and waiting to start.
    Queued,
    /// Currently executing.
    Running,
    /// Completed successfully.
    Success,
    /// Completed with a code/test failure.
    Failure,
    /// Cancelled before completion.
    Cancelled,
    /// Exceeded its allowed runtime.
    TimedOut,
    /// Deliberately skipped under signed policy.
    Skipped,
}

impl CiJobState {
    /// Return whether a transition is permitted by the frozen state machine.
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::Running | Self::Cancelled)
                | (
                    Self::Running,
                    Self::Success
                        | Self::Failure
                        | Self::Cancelled
                        | Self::TimedOut
                        | Self::Skipped
                )
        )
    }

    /// Return whether this state is terminal.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }
}

/// Closed run lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiRunState {
    /// Accepted and waiting to start.
    Queued,
    /// At least one job is executing.
    Running,
    /// All required work completed successfully.
    Success,
    /// Required code/test work failed.
    Failure,
    /// Cancelled before completion.
    Cancelled,
    /// Exceeded its allowed runtime.
    TimedOut,
    /// Infrastructure or evidence integrity failed.
    InfrastructureFailure,
}

impl CiRunState {
    /// Return whether a transition is permitted by the frozen state machine.
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Queued,
                Self::Running | Self::Cancelled | Self::InfrastructureFailure
            ) | (
                Self::Running,
                Self::Success
                    | Self::Failure
                    | Self::Cancelled
                    | Self::TimedOut
                    | Self::InfrastructureFailure
            )
        )
    }

    /// Return whether this state is terminal.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }
}

/// Closed policy for interpreting a skipped job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiSkipPolicy {
    /// A skipped required job makes the verdict red.
    Forbid,
    /// A skipped required job may be terminal-good.
    Allow,
}

/// Request content for kind 46100.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiRequestEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Run or rerun operation.
    pub request_type: CiRequestType,
    /// NIP-33 repository coordinate.
    pub target_repo_a: String,
    /// Root pull-request event ID.
    pub pr_root_event_id: String,
    /// Effective pull-request update event ID, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr_update_event_id: Option<String>,
    /// Authorized source clone URL.
    pub source_clone_url: String,
    /// Advertised immutable source ref.
    pub immutable_source_ref: String,
    /// Exact source tip object ID.
    pub tip_oid: String,
    /// Source branch name.
    pub source_branch: String,
    /// Trusted base ref.
    pub base_ref: String,
    /// Trusted base object ID.
    pub base_oid: String,
    /// Static workflow identifier.
    pub workflow_id: String,
    /// SHA-256 of trusted-base workflow bytes.
    pub workflow_digest: String,
    /// Selected static job identifiers.
    pub job_ids: Vec<String>,
    /// Stable run UUID.
    pub run_id: String,
    /// One-based attempt number.
    pub attempt: u32,
    /// Parent attempt for a rerun.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_attempt: Option<u32>,
    /// Parent run identifier for a rerun.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_run_id: Option<String>,
    /// Effective PR source event ID.
    pub trigger_event_id: String,
    /// Requesting signer pubkey.
    pub actor: String,
    /// Requested timeout in seconds.
    pub timeout_seconds: u64,
    /// Actor/repository-scoped idempotency key.
    pub idempotency_key: String,
    /// Request issue time in Unix seconds.
    pub issued_at: u64,
    /// Request expiry time in Unix seconds.
    pub expires_at: u64,
}

impl CiRequestEnvelope {
    /// Validate request-local schema and lineage invariants.
    pub fn validate(&self) -> Result<(), CiValidationError> {
        validate_common(
            self.schema_version,
            &self.run_id,
            &self.tip_oid,
            &self.workflow_digest,
        )?;
        validate_hex(&self.pr_root_event_id, 64, "invalid PR root event ID")?;
        if let Some(id) = &self.pr_update_event_id {
            validate_hex(id, 64, "invalid PR update event ID")?;
        }
        validate_hex(&self.base_oid, self.tip_oid.len(), "invalid base OID")?;
        validate_hex(&self.trigger_event_id, 64, "invalid trigger event ID")?;
        validate_hex(&self.actor, 64, "invalid actor pubkey")?;
        validate_repository_coordinate(&self.target_repo_a)?;
        validate_non_empty(&self.workflow_id, "workflow ID must be non-empty")?;
        validate_non_empty(
            &self.immutable_source_ref,
            "immutable source ref must be non-empty",
        )?;
        validate_non_empty(&self.source_branch, "source branch must be non-empty")?;
        validate_non_empty(&self.base_ref, "base ref must be non-empty")?;
        validate_clone_url(&self.source_clone_url)?;
        validate_job_ids(&self.job_ids, "request jobs must be non-empty and unique")?;
        let expected_trigger = self
            .pr_update_event_id
            .as_deref()
            .unwrap_or(self.pr_root_event_id.as_str());
        if self.trigger_event_id != expected_trigger {
            return Err(CiValidationError(
                "trigger event must equal effective PR event",
            ));
        }
        validate_safe_integer(self.timeout_seconds, "timeout exceeds safe integer")?;
        validate_safe_integer(self.issued_at, "issued_at exceeds safe integer")?;
        validate_safe_integer(self.expires_at, "expires_at exceeds safe integer")?;
        if self.timeout_seconds == 0 || self.expires_at <= self.issued_at {
            return Err(CiValidationError("invalid timeout or expiry"));
        }
        if self.idempotency_key.is_empty() {
            return Err(CiValidationError("idempotency key must be non-empty"));
        }
        match self.request_type {
            CiRequestType::Run => {
                if self.attempt != 1
                    || self.parent_attempt.is_some()
                    || self.parent_run_id.is_some()
                {
                    return Err(CiValidationError("run must be attempt one without parent"));
                }
            }
            CiRequestType::Rerun => {
                if self.attempt <= 1 || self.job_ids.len() != 1 {
                    return Err(CiValidationError(
                        "rerun must select one job after attempt one",
                    ));
                }
                let parent_attempt = self
                    .parent_attempt
                    .ok_or(CiValidationError("rerun requires parent attempt"))?;
                if parent_attempt == 0 || self.attempt != parent_attempt.saturating_add(1) {
                    return Err(CiValidationError(
                        "rerun attempt must follow parent contiguously",
                    ));
                }
                if self.parent_run_id.as_deref() != Some(self.run_id.as_str()) {
                    return Err(CiValidationError("rerun parent run must equal run ID"));
                }
            }
        }
        Ok(())
    }
}

/// Run-status content for kind 46101.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiRunStatusEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Request event being acknowledged.
    pub request_event_id: String,
    /// Stable run UUID.
    pub run_id: String,
    /// Workflow identifier.
    pub workflow_id: String,
    /// Repository coordinate.
    pub target_repo_a: String,
    /// Exact source tip object ID.
    pub tip_oid: String,
    /// Trusted base object ID.
    pub base_oid: String,
    /// Attempt number.
    pub attempt: u32,
    /// Monotonic stream sequence.
    pub sequence: u64,
    /// Closed run state.
    pub state: CiRunState,
    /// Optional closed-form conclusion text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conclusion: Option<String>,
    /// Optional infrastructure or state reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Start time in Unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    /// Finish time in Unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
    /// Static jobs in the run.
    pub job_ids: Vec<String>,
    /// Authorized status signer pubkey.
    pub relay_signer: String,
}

impl CiRunStatusEnvelope {
    /// Validate run-status shape and sequence invariants.
    pub fn validate(&self) -> Result<(), CiValidationError> {
        validate_status_common(
            self.schema_version,
            &self.request_event_id,
            &self.run_id,
            &self.tip_oid,
            &self.base_oid,
            self.attempt,
            self.sequence,
            &self.relay_signer,
        )?;
        validate_repository_coordinate(&self.target_repo_a)?;
        validate_non_empty(&self.workflow_id, "workflow ID must be non-empty")?;
        validate_job_ids(
            &self.job_ids,
            "run status jobs must be non-empty and unique",
        )?;
        validate_times(self.state.is_terminal(), self.started_at, self.finished_at)
    }
}

/// Job-status content for kind 46102.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiJobStatusEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Request event being acknowledged.
    pub request_event_id: String,
    /// Stable run UUID.
    pub run_id: String,
    /// Workflow identifier.
    pub workflow_id: String,
    /// Repository coordinate.
    pub target_repo_a: String,
    /// Exact source tip object ID.
    pub tip_oid: String,
    /// Trusted base object ID.
    pub base_oid: String,
    /// Static job identifier.
    pub job_id: String,
    /// Human-readable job name.
    pub name: String,
    /// Attempt number.
    pub attempt: u32,
    /// Parent attempt for a rerun.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_attempt: Option<u32>,
    /// Monotonic stream sequence.
    pub sequence: u64,
    /// Closed job state.
    pub state: CiJobState,
    /// Optional conclusion text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conclusion: Option<String>,
    /// Optional failure or state reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the signed manifest requires the job.
    pub required: bool,
    /// Closed signed skip policy.
    pub skip_policy: CiSkipPolicy,
    /// Canonical selected matrix instance.
    pub selected_job_instance: String,
    /// Broker-computed dependency reruns.
    pub also_reruns: Vec<String>,
    /// Start time in Unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    /// Finish time in Unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
    /// Finalized log event ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_ref: Option<String>,
    /// Finalized artifact event IDs.
    pub artifact_refs: Vec<String>,
    /// Authorized status signer pubkey.
    pub relay_signer: String,
}

impl CiJobStatusEnvelope {
    /// Validate job-status shape and sequence invariants.
    pub fn validate(&self) -> Result<(), CiValidationError> {
        validate_status_common(
            self.schema_version,
            &self.request_event_id,
            &self.run_id,
            &self.tip_oid,
            &self.base_oid,
            self.attempt,
            self.sequence,
            &self.relay_signer,
        )?;
        validate_repository_coordinate(&self.target_repo_a)?;
        validate_non_empty(&self.workflow_id, "workflow ID must be non-empty")?;
        validate_job_id(&self.job_id)?;
        if self.name.is_empty() || self.selected_job_instance.is_empty() {
            return Err(CiValidationError("job identity must be non-empty"));
        }
        match (self.attempt, self.parent_attempt) {
            (1, None) => {}
            (1, Some(_)) => return Err(CiValidationError("attempt one forbids parent")),
            (_, Some(parent)) if parent >= 1 && self.attempt == parent.saturating_add(1) => {}
            _ => {
                return Err(CiValidationError(
                    "later attempts require contiguous parent",
                ))
            }
        }
        validate_fanout(&self.also_reruns, &self.job_id)?;
        if let Some(log_ref) = &self.log_ref {
            validate_hex(log_ref, 64, "invalid log reference event ID")?;
        }
        validate_unique_event_ids(
            &self.artifact_refs,
            "invalid or duplicate artifact reference",
        )?;
        validate_times(self.state.is_terminal(), self.started_at, self.finished_at)
    }
}

/// Log-reference content for kind 46103.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiLogReferenceEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Request event ID.
    pub request_event_id: String,
    /// Stable run UUID.
    pub run_id: String,
    /// Workflow identifier.
    pub workflow_id: String,
    /// Repository coordinate.
    pub target_repo_a: String,
    /// Exact source tip object ID.
    pub tip_oid: String,
    /// Static job identifier.
    pub job_id: String,
    /// Attempt number.
    pub attempt: u32,
    /// SHA-256 of decoded scrubbed bytes.
    pub log_sha256: String,
    /// Decoded scrubbed byte length.
    pub byte_length: u64,
    /// Maximum permitted decoded byte length.
    pub cap_bytes: u64,
    /// Whether evidence was truncated.
    pub truncated: bool,
    /// Authenticated same-relay log URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Canonical padded RFC 4648 base64 log bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline: Option<String>,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Authorized evidence signer pubkey.
    pub relay_signer: String,
}

impl CiLogReferenceEnvelope {
    /// Validate shape, boundedness, and inline bytes when present.
    pub fn validate(&self) -> Result<(), CiValidationError> {
        validate_reference_common(
            self.schema_version,
            &self.request_event_id,
            &self.run_id,
            &self.tip_oid,
            &self.job_id,
            self.attempt,
            &self.log_sha256,
            &self.relay_signer,
        )?;
        validate_repository_coordinate(&self.target_repo_a)?;
        validate_non_empty(&self.workflow_id, "workflow ID must be non-empty")?;
        validate_safe_integer(self.byte_length, "log byte length exceeds safe integer")?;
        validate_safe_integer(self.cap_bytes, "log cap exceeds safe integer")?;
        validate_safe_integer(self.created_at, "log timestamp exceeds safe integer")?;
        if self.url.is_some() == self.inline.is_some() {
            return Err(CiValidationError("exactly one log location is required"));
        }
        if self.truncated || self.byte_length > self.cap_bytes {
            return Err(CiValidationError(
                "truncated or oversized log is not durable evidence",
            ));
        }
        if let Some(inline) = &self.inline {
            let max_encoded = self
                .cap_bytes
                .div_ceil(3)
                .checked_mul(4)
                .ok_or(CiValidationError("inline log encoded bound overflow"))?;
            if inline.len() as u64 > max_encoded {
                return Err(CiValidationError("inline log exceeds encoded bound"));
            }
            let bytes = BASE64_STANDARD
                .decode(inline)
                .map_err(|_| CiValidationError("inline log is not canonical base64"))?;
            if BASE64_STANDARD.encode(&bytes) != *inline {
                return Err(CiValidationError("inline log is not canonical base64"));
            }
            if bytes.len() as u64 != self.byte_length {
                return Err(CiValidationError("inline log byte length mismatch"));
            }
            let digest = hex::encode(Sha256::digest(&bytes));
            if digest != self.log_sha256 {
                return Err(CiValidationError("inline log digest mismatch"));
            }
        }
        Ok(())
    }

    /// Validate an external URL against the active relay and frozen path binding.
    pub fn validate_url_for_relay(&self, relay_url: &str) -> Result<(), CiValidationError> {
        self.validate()?;
        let raw = self
            .url
            .as_deref()
            .ok_or(CiValidationError("log reference is not URL-backed"))?;
        let mut expected_origin =
            Url::parse(relay_url).map_err(|_| CiValidationError("invalid active relay URL"))?;
        let http_scheme = match expected_origin.scheme() {
            "wss" => "https",
            "ws" => "http",
            "https" => "https",
            "http" => "http",
            _ => {
                return Err(CiValidationError(
                    "active relay must use http, https, ws, or wss",
                ));
            }
        };
        expected_origin
            .set_scheme(http_scheme)
            .map_err(|_| CiValidationError("invalid active relay URL"))?;
        let candidate = Url::parse(raw).map_err(|_| CiValidationError("invalid log URL"))?;
        if !candidate.username().is_empty()
            || candidate.password().is_some()
            || candidate.query().is_some()
            || candidate.fragment().is_some()
        {
            return Err(CiValidationError("log URL has forbidden components"));
        }
        if candidate.scheme() != expected_origin.scheme()
            || candidate.host_str() != expected_origin.host_str()
            || candidate.port_or_known_default() != expected_origin.port_or_known_default()
        {
            return Err(CiValidationError("log URL is off relay origin"));
        }
        let expected_path = format!(
            "/ci/logs/{}/{}/{}/{}/{}",
            self.request_event_id, self.run_id, self.job_id, self.attempt, self.log_sha256
        );
        if candidate.path() != expected_path {
            return Err(CiValidationError(
                "log URL path does not bind evidence identity",
            ));
        }
        Ok(())
    }
}

/// Artifact-reference content for kind 46104.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiArtifactReferenceEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Request event ID.
    pub request_event_id: String,
    /// Stable run UUID.
    pub run_id: String,
    /// Workflow identifier.
    pub workflow_id: String,
    /// Repository coordinate.
    pub target_repo_a: String,
    /// Exact source tip object ID.
    pub tip_oid: String,
    /// Static job identifier.
    pub job_id: String,
    /// Attempt number.
    pub attempt: u32,
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Human-readable artifact name.
    pub name: String,
    /// Artifact media type.
    pub media_type: String,
    /// SHA-256 of durable artifact bytes.
    pub sha256: String,
    /// Artifact byte length.
    pub byte_length: u64,
    /// Authenticated artifact URL.
    pub url: String,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Authorized evidence signer pubkey.
    pub relay_signer: String,
}

impl CiArtifactReferenceEnvelope {
    /// Validate artifact-reference shape.
    pub fn validate(&self) -> Result<(), CiValidationError> {
        validate_reference_common(
            self.schema_version,
            &self.request_event_id,
            &self.run_id,
            &self.tip_oid,
            &self.job_id,
            self.attempt,
            &self.sha256,
            &self.relay_signer,
        )?;
        validate_repository_coordinate(&self.target_repo_a)?;
        validate_non_empty(&self.workflow_id, "workflow ID must be non-empty")?;
        validate_safe_integer(
            self.byte_length,
            "artifact byte length exceeds safe integer",
        )?;
        validate_safe_integer(self.created_at, "artifact timestamp exceeds safe integer")?;
        if self.artifact_id.is_empty()
            || self.name.is_empty()
            || self.media_type.is_empty()
            || self.url.is_empty()
        {
            return Err(CiValidationError("artifact fields must be non-empty"));
        }
        Ok(())
    }
}

/// One selected job attempt whose durable evidence has been finalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiFinalizedJobAttempt {
    /// Static job identifier.
    pub job_id: String,
    /// Selected one-based job attempt.
    pub attempt: u32,
    /// Finalized log-reference event ID.
    pub log_ref: String,
    /// Finalized artifact-reference event IDs.
    pub artifact_refs: Vec<String>,
}

/// Evidence-finalized fact for kind 46105.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiEvidenceFinalizedEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Request event ID.
    pub request_event_id: String,
    /// Stable run UUID.
    pub run_id: String,
    /// Workflow identifier.
    pub workflow_id: String,
    /// Repository coordinate.
    pub target_repo_a: String,
    /// Exact source tip object ID.
    pub tip_oid: String,
    /// Top-level selected attempt.
    pub attempt: u32,
    /// Every selected required job attempt, exactly once.
    pub finalized_job_attempts: Vec<CiFinalizedJobAttempt>,
    /// Finalization time in Unix seconds.
    pub finalized_at: u64,
    /// Authorized evidence signer pubkey.
    pub relay_signer: String,
}

impl CiEvidenceFinalizedEnvelope {
    /// Validate the context-free evidence-finalized fact shape.
    pub fn validate(&self) -> Result<(), CiValidationError> {
        validate_fact_common(
            self.schema_version,
            &self.request_event_id,
            &self.run_id,
            &self.workflow_id,
            &self.target_repo_a,
            &self.tip_oid,
            self.attempt,
            self.finalized_at,
            &self.relay_signer,
        )?;
        if self.finalized_job_attempts.is_empty() {
            return Err(CiValidationError("evidence fact requires finalized jobs"));
        }
        let mut jobs = HashSet::new();
        let mut event_ids = HashSet::new();
        for job in &self.finalized_job_attempts {
            validate_job_id(&job.job_id)?;
            if job.attempt == 0 || !jobs.insert(job.job_id.as_str()) {
                return Err(CiValidationError("invalid or duplicate finalized job"));
            }
            validate_hex(&job.log_ref, 64, "invalid finalized log reference")?;
            if !event_ids.insert(job.log_ref.as_str()) {
                return Err(CiValidationError("duplicate finalized evidence reference"));
            }
            validate_unique_event_ids(
                &job.artifact_refs,
                "invalid or duplicate finalized artifact reference",
            )?;
            if job
                .artifact_refs
                .iter()
                .any(|event_id| !event_ids.insert(event_id.as_str()))
            {
                return Err(CiValidationError("duplicate finalized evidence reference"));
            }
        }
        Ok(())
    }
}

/// One selected job attempt and its dedicated isolation lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiTeardownLease {
    /// Static job identifier.
    pub job_id: String,
    /// Selected one-based job attempt.
    pub attempt: u32,
    /// Job-attempt-scoped isolation lease identifier.
    pub lease_id: String,
}

/// Lease-empty teardown fact for kind 46106.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiTeardownAttestationEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Request event ID.
    pub request_event_id: String,
    /// Stable run UUID.
    pub run_id: String,
    /// Workflow identifier.
    pub workflow_id: String,
    /// Repository coordinate.
    pub target_repo_a: String,
    /// Exact source tip object ID.
    pub tip_oid: String,
    /// Trusted base object ID.
    pub base_oid: String,
    /// SHA-256 of trusted-base workflow bytes.
    pub workflow_digest: String,
    /// Maximum selected job attempt.
    pub attempt: u32,
    /// Every selected job attempt and its isolation lease, in canonical order.
    pub leases: Vec<CiTeardownLease>,
    /// Must be true: every listed lease is proven empty.
    pub lease_empty: bool,
    /// Teardown proof time in Unix seconds.
    pub teardown_at: u64,
    /// Authorized control-plane signer pubkey.
    pub relay_signer: String,
}

impl CiTeardownAttestationEnvelope {
    /// Validate the context-free lease-empty teardown fact shape.
    pub fn validate(&self) -> Result<(), CiValidationError> {
        validate_fact_common(
            self.schema_version,
            &self.request_event_id,
            &self.run_id,
            &self.workflow_id,
            &self.target_repo_a,
            &self.tip_oid,
            self.attempt,
            self.teardown_at,
            &self.relay_signer,
        )?;
        validate_hex(
            &self.base_oid,
            self.tip_oid.len(),
            "invalid teardown base OID",
        )?;
        validate_hex(
            &self.workflow_digest,
            64,
            "invalid teardown workflow digest",
        )?;
        if self.leases.is_empty() || !self.lease_empty {
            return Err(CiValidationError(
                "teardown must prove a non-empty lease set empty",
            ));
        }
        let mut job_attempts = HashSet::new();
        let mut lease_ids = HashSet::new();
        let mut previous: Option<(&str, u32, &str)> = None;
        for lease in &self.leases {
            validate_job_id(&lease.job_id)?;
            if lease.attempt == 0 || lease.lease_id.is_empty() {
                return Err(CiValidationError("invalid teardown lease tuple"));
            }
            if !job_attempts.insert((lease.job_id.as_str(), lease.attempt)) {
                return Err(CiValidationError("duplicate teardown job attempt"));
            }
            if !lease_ids.insert(lease.lease_id.as_str()) {
                return Err(CiValidationError("duplicate teardown lease ID"));
            }
            let current = (
                lease.job_id.as_str(),
                lease.attempt,
                lease.lease_id.as_str(),
            );
            if previous.is_some_and(|prior| prior >= current) {
                return Err(CiValidationError(
                    "teardown leases are not canonically sorted",
                ));
            }
            previous = Some(current);
        }
        if self.attempt
            != self
                .leases
                .iter()
                .map(|lease| lease.attempt)
                .max()
                .unwrap_or(0)
        {
            return Err(CiValidationError(
                "teardown attempt must equal maximum selected job attempt",
            ));
        }
        Ok(())
    }

    /// Bind this fact to the accepted request and the reducer's selected job-attempt graph.
    pub fn validate_context(
        &self,
        request_event_id: &str,
        request: &CiRequestEnvelope,
        selected_job_attempts: &[(String, u32)],
    ) -> Result<(), CiValidationError> {
        self.validate()?;
        request.validate()?;
        if self.request_event_id != request_event_id
            || self.run_id != request.run_id
            || self.workflow_id != request.workflow_id
            || self.workflow_digest != request.workflow_digest
            || self.target_repo_a != request.target_repo_a
            || self.tip_oid != request.tip_oid
            || self.base_oid != request.base_oid
        {
            return Err(CiValidationError(
                "teardown provenance does not match accepted request",
            ));
        }
        validate_hex(request_event_id, 64, "invalid accepted request event ID")?;
        if selected_job_attempts.is_empty() {
            return Err(CiValidationError("selected job-attempt graph is empty"));
        }
        let selected: HashSet<(&str, u32)> = selected_job_attempts
            .iter()
            .map(|(job_id, attempt)| (job_id.as_str(), *attempt))
            .collect();
        let selected_job_ids: HashSet<&str> = selected_job_attempts
            .iter()
            .map(|(job_id, _)| job_id.as_str())
            .collect();
        if selected.len() != selected_job_attempts.len()
            || selected_job_ids.len() != selected_job_attempts.len()
            || selected
                .iter()
                .any(|(job_id, attempt)| *attempt == 0 || validate_job_id(job_id).is_err())
        {
            return Err(CiValidationError("invalid selected job-attempt graph"));
        }
        let attested: HashSet<(&str, u32)> = self
            .leases
            .iter()
            .map(|lease| (lease.job_id.as_str(), lease.attempt))
            .collect();
        if attested != selected {
            return Err(CiValidationError(
                "teardown leases do not exactly match selected job attempts",
            ));
        }
        Ok(())
    }
}

/// A signature-verified, kind-bound CI event envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedCiEnvelope {
    /// Kind 46100 request authored by its actor.
    Request(CiRequestEnvelope),
    /// Kind 46101 run status authored by an authorized control-plane signer.
    RunStatus(CiRunStatusEnvelope),
    /// Kind 46102 job status authored by an authorized control-plane signer.
    JobStatus(CiJobStatusEnvelope),
    /// Kind 46103 log reference authored by an authorized control-plane signer.
    LogReference(CiLogReferenceEnvelope),
    /// Kind 46104 artifact reference authored by an authorized control-plane signer.
    ArtifactReference(CiArtifactReferenceEnvelope),
    /// Kind 46105 evidence-finalized fact.
    EvidenceFinalized(CiEvidenceFinalizedEnvelope),
    /// Kind 46106 lease-empty teardown fact.
    TeardownAttestation(CiTeardownAttestationEnvelope),
}

/// Verify a signed CI event, bind its kind to the exact envelope and tags, and enforce signer trust.
pub fn validate_signed_ci_event(
    event: &nostr::Event,
    channel_id: &str,
    authorized_status_signers: &HashSet<String>,
) -> Result<ValidatedCiEnvelope, CiValidationError> {
    event
        .verify()
        .map_err(|_| CiValidationError("invalid CI event ID or signature"))?;
    let signer = event.pubkey.to_hex();
    let tags: Vec<Tag> = event.tags.iter().cloned().collect();
    match event.kind.as_u16() as u32 {
        KIND_CI_REQUEST => {
            let envelope: CiRequestEnvelope = serde_json::from_str(&event.content)
                .map_err(|_| CiValidationError("invalid CI request content"))?;
            envelope.validate()?;
            if envelope.actor != signer {
                return Err(CiValidationError(
                    "request actor does not match event signer",
                ));
            }
            validate_request_tags(&tags, channel_id, &envelope)?;
            Ok(ValidatedCiEnvelope::Request(envelope))
        }
        KIND_CI_RUN_STATUS => {
            let envelope: CiRunStatusEnvelope = serde_json::from_str(&event.content)
                .map_err(|_| CiValidationError("invalid CI run status content"))?;
            validate_status_signer(&signer, &envelope.relay_signer, authorized_status_signers)?;
            validate_run_status_tags(&tags, channel_id, &envelope)?;
            Ok(ValidatedCiEnvelope::RunStatus(envelope))
        }
        KIND_CI_JOB_STATUS => {
            let envelope: CiJobStatusEnvelope = serde_json::from_str(&event.content)
                .map_err(|_| CiValidationError("invalid CI job status content"))?;
            validate_status_signer(&signer, &envelope.relay_signer, authorized_status_signers)?;
            validate_job_status_tags(&tags, channel_id, &envelope)?;
            Ok(ValidatedCiEnvelope::JobStatus(envelope))
        }
        KIND_CI_LOG_REFERENCE => {
            let envelope: CiLogReferenceEnvelope = serde_json::from_str(&event.content)
                .map_err(|_| CiValidationError("invalid CI log reference content"))?;
            validate_status_signer(&signer, &envelope.relay_signer, authorized_status_signers)?;
            validate_log_reference_tags(&tags, channel_id, &envelope)?;
            Ok(ValidatedCiEnvelope::LogReference(envelope))
        }
        KIND_CI_ARTIFACT_REFERENCE => {
            let envelope: CiArtifactReferenceEnvelope = serde_json::from_str(&event.content)
                .map_err(|_| CiValidationError("invalid CI artifact reference content"))?;
            validate_status_signer(&signer, &envelope.relay_signer, authorized_status_signers)?;
            validate_artifact_reference_tags(&tags, channel_id, &envelope)?;
            Ok(ValidatedCiEnvelope::ArtifactReference(envelope))
        }
        KIND_CI_EVIDENCE_FINALIZED => {
            let envelope: CiEvidenceFinalizedEnvelope = serde_json::from_str(&event.content)
                .map_err(|_| CiValidationError("invalid CI evidence-finalized content"))?;
            validate_status_signer(&signer, &envelope.relay_signer, authorized_status_signers)?;
            validate_evidence_finalized_tags(&tags, channel_id, &envelope)?;
            Ok(ValidatedCiEnvelope::EvidenceFinalized(envelope))
        }
        KIND_CI_TEARDOWN_ATTESTATION => {
            let envelope: CiTeardownAttestationEnvelope = serde_json::from_str(&event.content)
                .map_err(|_| CiValidationError("invalid CI teardown attestation content"))?;
            validate_status_signer(&signer, &envelope.relay_signer, authorized_status_signers)?;
            validate_teardown_attestation_tags(&tags, channel_id, &envelope)?;
            Ok(ValidatedCiEnvelope::TeardownAttestation(envelope))
        }
        _ => Err(CiValidationError("event kind is not a CI envelope kind")),
    }
}

/// Build the required index tags for a kind 46100 request.
pub fn request_tags(
    channel_id: &str,
    envelope: &CiRequestEnvelope,
) -> Result<Vec<Tag>, CiValidationError> {
    envelope.validate()?;
    build_tags(channel_id, TagFields::request(envelope))
}

/// Validate required index tags against a kind 46100 request.
pub fn validate_request_tags(
    tags: &[Tag],
    channel_id: &str,
    envelope: &CiRequestEnvelope,
) -> Result<(), CiValidationError> {
    envelope.validate()?;
    validate_tags(tags, channel_id, TagFields::request(envelope))
}

/// Build the required index tags for a kind 46101 run status.
pub fn run_status_tags(
    channel_id: &str,
    envelope: &CiRunStatusEnvelope,
) -> Result<Vec<Tag>, CiValidationError> {
    envelope.validate()?;
    build_tags(channel_id, TagFields::run_status(envelope))
}

/// Validate required index tags against a kind 46101 run status.
pub fn validate_run_status_tags(
    tags: &[Tag],
    channel_id: &str,
    envelope: &CiRunStatusEnvelope,
) -> Result<(), CiValidationError> {
    envelope.validate()?;
    validate_tags(tags, channel_id, TagFields::run_status(envelope))
}

/// Build the required index tags for a kind 46102 job status.
pub fn job_status_tags(
    channel_id: &str,
    envelope: &CiJobStatusEnvelope,
) -> Result<Vec<Tag>, CiValidationError> {
    envelope.validate()?;
    build_tags(channel_id, TagFields::job_status(envelope))
}

/// Validate required index tags against a kind 46102 job status.
pub fn validate_job_status_tags(
    tags: &[Tag],
    channel_id: &str,
    envelope: &CiJobStatusEnvelope,
) -> Result<(), CiValidationError> {
    envelope.validate()?;
    validate_tags(tags, channel_id, TagFields::job_status(envelope))
}

/// Build the required index tags for a kind 46103 log reference.
pub fn log_reference_tags(
    channel_id: &str,
    envelope: &CiLogReferenceEnvelope,
) -> Result<Vec<Tag>, CiValidationError> {
    envelope.validate()?;
    build_tags(channel_id, TagFields::log_reference(envelope))
}

/// Validate required index tags against a kind 46103 log reference.
pub fn validate_log_reference_tags(
    tags: &[Tag],
    channel_id: &str,
    envelope: &CiLogReferenceEnvelope,
) -> Result<(), CiValidationError> {
    envelope.validate()?;
    validate_tags(tags, channel_id, TagFields::log_reference(envelope))
}

/// Build the required index tags for a kind 46104 artifact reference.
pub fn artifact_reference_tags(
    channel_id: &str,
    envelope: &CiArtifactReferenceEnvelope,
) -> Result<Vec<Tag>, CiValidationError> {
    envelope.validate()?;
    build_tags(channel_id, TagFields::artifact_reference(envelope))
}

/// Validate required index tags against a kind 46104 artifact reference.
pub fn validate_artifact_reference_tags(
    tags: &[Tag],
    channel_id: &str,
    envelope: &CiArtifactReferenceEnvelope,
) -> Result<(), CiValidationError> {
    envelope.validate()?;
    validate_tags(tags, channel_id, TagFields::artifact_reference(envelope))
}

/// Build the required index tags for a kind 46105 evidence-finalized fact.
pub fn evidence_finalized_tags(
    channel_id: &str,
    envelope: &CiEvidenceFinalizedEnvelope,
) -> Result<Vec<Tag>, CiValidationError> {
    envelope.validate()?;
    build_tags(channel_id, TagFields::evidence_finalized(envelope))
}

/// Validate required index tags against a kind 46105 evidence-finalized fact.
pub fn validate_evidence_finalized_tags(
    tags: &[Tag],
    channel_id: &str,
    envelope: &CiEvidenceFinalizedEnvelope,
) -> Result<(), CiValidationError> {
    envelope.validate()?;
    validate_tags(tags, channel_id, TagFields::evidence_finalized(envelope))
}

/// Build the required index tags for a kind 46106 teardown attestation.
pub fn teardown_attestation_tags(
    channel_id: &str,
    envelope: &CiTeardownAttestationEnvelope,
) -> Result<Vec<Tag>, CiValidationError> {
    envelope.validate()?;
    build_tags(channel_id, TagFields::teardown_attestation(envelope))
}

/// Validate required index tags against a kind 46106 teardown attestation.
pub fn validate_teardown_attestation_tags(
    tags: &[Tag],
    channel_id: &str,
    envelope: &CiTeardownAttestationEnvelope,
) -> Result<(), CiValidationError> {
    envelope.validate()?;
    validate_tags(tags, channel_id, TagFields::teardown_attestation(envelope))
}

struct TagFields<'a> {
    target_repo_a: &'a str,
    run_id: &'a str,
    workflow_id: &'a str,
    tip_oid: &'a str,
    attempt: u32,
    job_id: Option<&'a str>,
    request_event_id: Option<&'a str>,
    digest: Option<&'a str>,
}

impl<'a> TagFields<'a> {
    fn request(envelope: &'a CiRequestEnvelope) -> Self {
        Self {
            target_repo_a: &envelope.target_repo_a,
            run_id: &envelope.run_id,
            workflow_id: &envelope.workflow_id,
            tip_oid: &envelope.tip_oid,
            attempt: envelope.attempt,
            job_id: None,
            request_event_id: None,
            digest: None,
        }
    }

    fn run_status(envelope: &'a CiRunStatusEnvelope) -> Self {
        Self {
            target_repo_a: &envelope.target_repo_a,
            run_id: &envelope.run_id,
            workflow_id: &envelope.workflow_id,
            tip_oid: &envelope.tip_oid,
            attempt: envelope.attempt,
            job_id: None,
            request_event_id: Some(&envelope.request_event_id),
            digest: None,
        }
    }

    fn evidence_finalized(envelope: &'a CiEvidenceFinalizedEnvelope) -> Self {
        Self {
            target_repo_a: &envelope.target_repo_a,
            run_id: &envelope.run_id,
            workflow_id: &envelope.workflow_id,
            tip_oid: &envelope.tip_oid,
            attempt: envelope.attempt,
            job_id: None,
            request_event_id: Some(&envelope.request_event_id),
            digest: None,
        }
    }

    fn teardown_attestation(envelope: &'a CiTeardownAttestationEnvelope) -> Self {
        Self {
            target_repo_a: &envelope.target_repo_a,
            run_id: &envelope.run_id,
            workflow_id: &envelope.workflow_id,
            tip_oid: &envelope.tip_oid,
            attempt: envelope.attempt,
            job_id: None,
            request_event_id: Some(&envelope.request_event_id),
            digest: None,
        }
    }

    fn job_status(envelope: &'a CiJobStatusEnvelope) -> Self {
        Self {
            target_repo_a: &envelope.target_repo_a,
            run_id: &envelope.run_id,
            workflow_id: &envelope.workflow_id,
            tip_oid: &envelope.tip_oid,
            attempt: envelope.attempt,
            job_id: Some(&envelope.job_id),
            request_event_id: Some(&envelope.request_event_id),
            digest: None,
        }
    }

    fn log_reference(envelope: &'a CiLogReferenceEnvelope) -> Self {
        Self {
            target_repo_a: &envelope.target_repo_a,
            run_id: &envelope.run_id,
            workflow_id: &envelope.workflow_id,
            tip_oid: &envelope.tip_oid,
            attempt: envelope.attempt,
            job_id: Some(&envelope.job_id),
            request_event_id: Some(&envelope.request_event_id),
            digest: Some(&envelope.log_sha256),
        }
    }

    fn artifact_reference(envelope: &'a CiArtifactReferenceEnvelope) -> Self {
        Self {
            target_repo_a: &envelope.target_repo_a,
            run_id: &envelope.run_id,
            workflow_id: &envelope.workflow_id,
            tip_oid: &envelope.tip_oid,
            attempt: envelope.attempt,
            job_id: Some(&envelope.job_id),
            request_event_id: Some(&envelope.request_event_id),
            digest: Some(&envelope.sha256),
        }
    }
}

fn build_tags(channel_id: &str, fields: TagFields<'_>) -> Result<Vec<Tag>, CiValidationError> {
    Uuid::parse_str(channel_id).map_err(|_| CiValidationError("invalid channel UUID"))?;
    let attempt = fields.attempt.to_string();
    let mut raw = vec![
        vec!["h", channel_id],
        vec!["a", fields.target_repo_a],
        vec!["run", fields.run_id],
        vec!["workflow", fields.workflow_id],
        vec!["c", fields.tip_oid],
        vec!["attempt", &attempt],
    ];
    if let Some(job_id) = fields.job_id {
        raw.push(vec!["job", job_id]);
    }
    if let Some(request_event_id) = fields.request_event_id {
        raw.push(vec!["e", request_event_id, "", "request"]);
    }
    if let Some(digest) = fields.digest {
        raw.push(vec!["x", digest]);
    }
    raw.into_iter()
        .map(|parts| Tag::parse(parts).map_err(|_| CiValidationError("failed to build CI tag")))
        .collect()
}

fn validate_tags(
    tags: &[Tag],
    channel_id: &str,
    fields: TagFields<'_>,
) -> Result<(), CiValidationError> {
    let expected = build_tags(channel_id, fields)?;
    let expected_names: HashSet<&str> = expected
        .iter()
        .filter_map(|tag| tag.as_slice().first().map(|part| part.as_str()))
        .collect();
    const RESERVED: &[&str] = &["h", "a", "run", "workflow", "c", "attempt", "job", "e", "x"];
    for tag in tags {
        let Some(name) = tag.as_slice().first().map(|part| part.as_str()) else {
            continue;
        };
        if RESERVED.contains(&name) && !expected_names.contains(name) {
            return Err(CiValidationError("forbidden reserved CI tag"));
        }
    }
    for expected_tag in expected {
        let expected_parts = expected_tag.as_slice();
        let name = expected_parts[0].as_str();
        let matching: Vec<&Tag> = tags
            .iter()
            .filter(|tag| {
                tag.as_slice()
                    .first()
                    .is_some_and(|part| part.as_str() == name)
            })
            .collect();
        if matching.len() != 1 {
            return Err(CiValidationError("required CI tag must occur exactly once"));
        }
        let actual = matching[0].as_slice();
        if actual.len() != expected_parts.len()
            || !actual
                .iter()
                .zip(expected_parts.iter())
                .all(|(left, right)| left.as_str() == right.as_str())
        {
            return Err(CiValidationError("CI tag does not match envelope"));
        }
    }
    Ok(())
}

fn validate_common(
    schema_version: u32,
    run_id: &str,
    tip_oid: &str,
    workflow_digest: &str,
) -> Result<(), CiValidationError> {
    if schema_version != CI_SCHEMA_VERSION {
        return Err(CiValidationError("unsupported schema version"));
    }
    Uuid::parse_str(run_id).map_err(|_| CiValidationError("invalid run UUID"))?;
    if !matches!(tip_oid.len(), 40 | 64) {
        return Err(CiValidationError("invalid tip OID length"));
    }
    validate_hex(tip_oid, tip_oid.len(), "invalid tip OID")?;
    validate_hex(workflow_digest, 64, "invalid workflow digest")
}

#[allow(clippy::too_many_arguments)]
fn validate_status_common(
    schema_version: u32,
    request_event_id: &str,
    run_id: &str,
    tip_oid: &str,
    base_oid: &str,
    attempt: u32,
    sequence: u64,
    relay_signer: &str,
) -> Result<(), CiValidationError> {
    if schema_version != CI_SCHEMA_VERSION {
        return Err(CiValidationError("unsupported schema version"));
    }
    Uuid::parse_str(run_id).map_err(|_| CiValidationError("invalid run UUID"))?;
    validate_git_oid(tip_oid, "invalid tip object ID")?;
    validate_hex(request_event_id, 64, "invalid request event ID")?;
    validate_hex(base_oid, tip_oid.len(), "invalid base OID")?;
    validate_hex(relay_signer, 64, "invalid relay signer")?;
    if attempt == 0 || sequence == 0 {
        return Err(CiValidationError("attempt and sequence begin at one"));
    }
    validate_safe_integer(sequence, "sequence exceeds safe integer")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_reference_common(
    schema_version: u32,
    request_event_id: &str,
    run_id: &str,
    tip_oid: &str,
    job_id: &str,
    attempt: u32,
    digest: &str,
    relay_signer: &str,
) -> Result<(), CiValidationError> {
    validate_common(schema_version, run_id, tip_oid, digest)?;
    validate_hex(request_event_id, 64, "invalid request event ID")?;
    validate_hex(relay_signer, 64, "invalid relay signer")?;
    validate_job_id(job_id)?;
    if attempt == 0 {
        return Err(CiValidationError("attempt is required"));
    }
    Ok(())
}

fn validate_times(
    terminal: bool,
    started_at: Option<u64>,
    finished_at: Option<u64>,
) -> Result<(), CiValidationError> {
    if terminal != finished_at.is_some() {
        return Err(CiValidationError("finished_at must match terminal state"));
    }
    if let Some(started) = started_at {
        validate_safe_integer(started, "started_at exceeds safe integer")?;
    }
    if let Some(finished) = finished_at {
        validate_safe_integer(finished, "finished_at exceeds safe integer")?;
    }
    if matches!((started_at, finished_at), (Some(started), Some(finished)) if finished < started) {
        return Err(CiValidationError("finished_at precedes started_at"));
    }
    Ok(())
}

fn validate_repository_coordinate(value: &str) -> Result<(), CiValidationError> {
    let mut parts = value.splitn(3, ':');
    if parts.next() != Some("30617") {
        return Err(CiValidationError("invalid repository coordinate kind"));
    }
    let owner = parts
        .next()
        .ok_or(CiValidationError("invalid repository coordinate"))?;
    validate_hex(owner, 64, "invalid repository coordinate owner")?;
    let repo_id = parts
        .next()
        .ok_or(CiValidationError("invalid repository coordinate"))?;
    validate_non_empty(repo_id, "repository d-tag must be non-empty")
}

fn validate_clone_url(value: &str) -> Result<(), CiValidationError> {
    let url = Url::parse(value).map_err(|_| CiValidationError("invalid source clone URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CiValidationError("unsafe source clone URL"));
    }
    Ok(())
}

fn validate_non_empty(value: &str, message: &'static str) -> Result<(), CiValidationError> {
    if value.is_empty() {
        return Err(CiValidationError(message));
    }
    Ok(())
}

fn validate_job_id(value: &str) -> Result<(), CiValidationError> {
    if value.len() > 64 {
        return Err(CiValidationError("invalid static job ID"));
    }
    let mut bytes = value.bytes();
    if !matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CiValidationError("invalid static job ID"));
    }
    Ok(())
}

fn validate_git_oid(value: &str, message: &'static str) -> Result<(), CiValidationError> {
    if !matches!(value.len(), 40 | 64) {
        return Err(CiValidationError(message));
    }
    validate_hex(value, value.len(), message)
}

fn validate_job_ids(values: &[String], message: &'static str) -> Result<(), CiValidationError> {
    if values.is_empty() || values.iter().any(|value| validate_job_id(value).is_err()) {
        return Err(CiValidationError(message));
    }
    let unique: HashSet<&str> = values.iter().map(String::as_str).collect();
    if unique.len() != values.len() {
        return Err(CiValidationError(message));
    }
    Ok(())
}

fn validate_fanout(values: &[String], selected: &str) -> Result<(), CiValidationError> {
    if values.iter().any(|value| value == selected) {
        return Err(CiValidationError("rerun fan-out contains selected job"));
    }
    if values.is_empty() {
        return Ok(());
    }
    validate_job_ids(values, "rerun fan-out must contain unique static job IDs")
}

fn validate_unique_event_ids(
    values: &[String],
    message: &'static str,
) -> Result<(), CiValidationError> {
    if values
        .iter()
        .any(|value| validate_hex(value, 64, message).is_err())
    {
        return Err(CiValidationError(message));
    }
    let unique: HashSet<&str> = values.iter().map(String::as_str).collect();
    if unique.len() != values.len() {
        return Err(CiValidationError(message));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_fact_common(
    schema_version: u32,
    request_event_id: &str,
    run_id: &str,
    workflow_id: &str,
    target_repo_a: &str,
    tip_oid: &str,
    attempt: u32,
    timestamp: u64,
    relay_signer: &str,
) -> Result<(), CiValidationError> {
    if schema_version != CI_SCHEMA_VERSION {
        return Err(CiValidationError("unsupported schema version"));
    }
    Uuid::parse_str(run_id).map_err(|_| CiValidationError("invalid run UUID"))?;
    validate_git_oid(tip_oid, "invalid tip object ID")?;
    validate_hex(request_event_id, 64, "invalid request event ID")?;
    validate_non_empty(workflow_id, "workflow ID is required")?;
    validate_repository_coordinate(target_repo_a)?;
    validate_hex(relay_signer, 64, "invalid relay signer")?;
    if attempt == 0 {
        return Err(CiValidationError("fact attempt must be one-based"));
    }
    validate_safe_integer(timestamp, "fact timestamp exceeds JavaScript safe integer")
}

fn validate_safe_integer(value: u64, message: &'static str) -> Result<(), CiValidationError> {
    if value > CI_MAX_SAFE_INTEGER {
        return Err(CiValidationError(message));
    }
    Ok(())
}

fn validate_status_signer(
    event_signer: &str,
    envelope_signer: &str,
    authorized_status_signers: &HashSet<String>,
) -> Result<(), CiValidationError> {
    if event_signer != envelope_signer {
        return Err(CiValidationError(
            "status signer does not match event signer",
        ));
    }
    if !authorized_status_signers.contains(event_signer) {
        return Err(CiValidationError("unauthorized CI status signer"));
    }
    Ok(())
}

fn validate_hex(value: &str, len: usize, message: &'static str) -> Result<(), CiValidationError> {
    if value.len() != len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CiValidationError(message));
    }
    Ok(())
}
