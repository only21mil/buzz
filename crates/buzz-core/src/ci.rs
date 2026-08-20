//! Typed, zero-I/O envelopes for Buzz-native CI events.

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
/// SHA-256 of `BUZZ_CI_PROTOCOL_CONTRACT.md` v1.2 implemented by this module.
pub const CI_PROTOCOL_CONTRACT_SHA256: &str =
    "50bb013fe1af573a000ba8c47eb9d0a42be69ab2dde2a5a0b1c12afe81e501fe";

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
    pub parent_attempt: Option<u32>,
    /// Parent run identifier for a rerun.
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
        if self.job_ids.is_empty() || self.job_ids.iter().any(|id| id.is_empty()) {
            return Err(CiValidationError("job IDs must be non-empty"));
        }
        let unique: HashSet<&str> = self.job_ids.iter().map(String::as_str).collect();
        if unique.len() != self.job_ids.len() {
            return Err(CiValidationError("job IDs must be unique"));
        }
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
                if parent_attempt >= self.attempt {
                    return Err(CiValidationError("rerun parent attempt must be earlier"));
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
    pub conclusion: Option<String>,
    /// Optional infrastructure or state reason.
    pub reason: Option<String>,
    /// Start time in Unix seconds.
    pub started_at: Option<u64>,
    /// Finish time in Unix seconds.
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
        if self.job_ids.is_empty() {
            return Err(CiValidationError("run status requires jobs"));
        }
        validate_terminal_time(self.state.is_terminal(), self.finished_at)
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
    pub parent_attempt: Option<u32>,
    /// Monotonic stream sequence.
    pub sequence: u64,
    /// Closed job state.
    pub state: CiJobState,
    /// Optional conclusion text.
    pub conclusion: Option<String>,
    /// Optional failure or state reason.
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
    pub started_at: Option<u64>,
    /// Finish time in Unix seconds.
    pub finished_at: Option<u64>,
    /// Finalized log event ID.
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
        if self.job_id.is_empty() || self.name.is_empty() || self.selected_job_instance.is_empty() {
            return Err(CiValidationError("job identity must be non-empty"));
        }
        if let Some(parent) = self.parent_attempt {
            if parent >= self.attempt {
                return Err(CiValidationError("parent attempt must be earlier"));
            }
        }
        validate_terminal_time(self.state.is_terminal(), self.finished_at)
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
    pub url: Option<String>,
    /// Canonical padded RFC 4648 base64 log bytes.
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
        if self.url.is_some() == self.inline.is_some() {
            return Err(CiValidationError("exactly one log location is required"));
        }
        if self.truncated || self.byte_length > self.cap_bytes {
            return Err(CiValidationError(
                "truncated or oversized log is not durable evidence",
            ));
        }
        if let Some(inline) = &self.inline {
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
            _ => return Err(CiValidationError("active relay must use ws or wss")),
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
    validate_common(schema_version, run_id, tip_oid, &"0".repeat(64))?;
    validate_hex(request_event_id, 64, "invalid request event ID")?;
    validate_hex(base_oid, tip_oid.len(), "invalid base OID")?;
    validate_hex(relay_signer, 64, "invalid relay signer")?;
    if attempt == 0 || sequence == 0 {
        return Err(CiValidationError("attempt and sequence begin at one"));
    }
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
    if job_id.is_empty() || attempt == 0 {
        return Err(CiValidationError("job ID and attempt are required"));
    }
    Ok(())
}

fn validate_terminal_time(
    terminal: bool,
    finished_at: Option<u64>,
) -> Result<(), CiValidationError> {
    if terminal != finished_at.is_some() {
        return Err(CiValidationError("finished_at must match terminal state"));
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
