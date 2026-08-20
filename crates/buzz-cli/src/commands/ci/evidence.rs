//! Pure selection and evidence checks for `buzz ci logs` and `buzz ci rerun`.
//!
//! This module deliberately performs no network I/O and publishes no events.
//! Callers must verify event signatures, tags, channel scope, and signer
//! authorization before passing envelopes here. The functions below re-check
//! envelope and cross-event bindings before producing output or write plans.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use buzz_core::ci::{
    CiJobState, CiJobStatusEnvelope, CiLogReferenceEnvelope, CiRequestEnvelope, CiRequestType,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

/// CI envelope/CLI protocol implemented by these checks.
pub const CI_PROTOCOL_VERSION: &str = "1.4";
/// Relay/API attempt-selection protocol implemented by these checks.
pub const CI_RELAY_API_VERSION: &str = "1.1";

/// A validated kind-46103 envelope paired with its verified event ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableLogEvent {
    /// Verified Nostr event ID.
    pub event_id: String,
    /// Individually validated log-reference content.
    pub envelope: CiLogReferenceEnvelope,
}

/// Refusal raised before logs are exposed or a rerun is published.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvidenceError {
    /// An input envelope fails its frozen schema checks.
    #[error("invalid CI envelope: {0}")]
    InvalidEnvelope(String),
    /// An event does not bind to the verified request's immutable identity.
    #[error("CI event does not bind to the verified request: {0}")]
    RequestMismatch(&'static str),
    /// No status stream exists for the requested job or attempt.
    #[error("unknown job attempt: {job_id} attempt {attempt:?}")]
    UnknownAttempt {
        /// Requested job.
        job_id: String,
        /// Explicit attempt, or `None` for greatest-known selection.
        attempt: Option<u32>,
    },
    /// The status stream is incomplete, duplicated, or illegally ordered.
    #[error("invalid job status lineage: {0}")]
    InvalidLineage(&'static str),
    /// The selected job attempt has not reached a terminal state.
    #[error("job_not_terminal: {job_id} attempt {attempt} is {state:?}")]
    JobNotTerminal {
        /// Selected job.
        job_id: String,
        /// Selected attempt.
        attempt: u32,
        /// Current state.
        state: CiJobState,
    },
    /// Rerun requires a failed selected parent.
    #[error("job_not_failed: {job_id} attempt {attempt} is {state:?}")]
    JobNotFailed {
        /// Selected job.
        job_id: String,
        /// Selected attempt.
        attempt: u32,
        /// Terminal non-failure state.
        state: CiJobState,
    },
    /// The terminal job has no durable log reference.
    #[error("durable log missing for {job_id} attempt {attempt}")]
    DurableLogMissing {
        /// Selected job.
        job_id: String,
        /// Selected attempt.
        attempt: u32,
    },
    /// The referenced log event is missing, duplicated, or identity-mismatched.
    #[error("invalid durable log reference: {0}")]
    InvalidLogReference(&'static str),
    /// A URL-backed log does not satisfy the same-relay retrieval contract.
    #[error("unsafe log retrieval: {0}")]
    UnsafeRetrieval(&'static str),
    /// Retrieved bytes do not match the signed durable reference.
    #[error("log evidence mismatch: {0}")]
    EvidenceMismatch(&'static str),
    /// The broker's configured attempt limit would be exceeded.
    #[error("attempt_limit: {job_id} limit {limit}")]
    AttemptLimit {
        /// Selected job.
        job_id: String,
        /// Configured maximum attempt.
        limit: u32,
    },
    /// A queued rerun acknowledgment does not bind to the derived request.
    #[error("invalid rerun acknowledgment: {0}")]
    InvalidRerunAck(&'static str),
}

/// Default JSON result for `buzz ci logs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogsResult {
    /// Stable run identifier.
    pub run_id: String,
    /// Immutable source tip.
    pub sha: String,
    /// Selected static job identifier.
    pub job_id: String,
    /// Selected job attempt.
    pub attempt: u32,
    /// SHA-256 of the scrubbed decoded bytes.
    pub log_sha256: String,
    /// Decoded byte size.
    pub size: u64,
    /// Signed decoded-byte cap.
    pub cap_bytes: u64,
    /// Signed truncation marker; successful selections are always false.
    pub truncated: bool,
    /// Signed location, either a same-relay URL or canonical inline base64.
    pub url_or_inline: String,
}

/// A same-relay authenticated GET that the network layer may execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFetchPlan {
    url: String,
    cap_bytes: u64,
    byte_length: u64,
    log_sha256: String,
}

impl LogFetchPlan {
    /// Exact signed URL. The caller must authenticate this request.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Maximum accepted response bytes. Clients should enforce this while buffering.
    pub const fn cap_bytes(&self) -> u64 {
        self.cap_bytes
    }

    /// Required redirect policy. This is always zero.
    pub const fn maximum_redirects(&self) -> u8 {
        0
    }

    /// Whether retrieval requires repository-channel authentication.
    pub const fn requires_authentication(&self) -> bool {
        true
    }
}

/// Network-layer facts and complete buffered body for a URL log retrieval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferedLogResponse {
    /// URL originally requested by the client.
    pub requested_url: String,
    /// Final URL reported by the HTTP client.
    pub final_url: String,
    /// Number of followed redirects.
    pub redirects_followed: u32,
    /// Whether repository-channel authentication was attached.
    pub authenticated: bool,
    /// Declared response length, when present.
    pub content_length: Option<u64>,
    /// Complete bounded response body.
    pub body: Vec<u8>,
}

/// Scrubbed bytes proven against the signed durable log reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRawLog(Vec<u8>);

impl VerifiedRawLog {
    /// Bytes safe to write to stdout only after this type has been constructed.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Transfer ownership to the output layer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Fully selected log plus its already-validated evidence location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedLog {
    result: LogsResult,
    source: SelectedLogSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SelectedLogSource {
    Inline(VerifiedRawLog),
    Url(LogFetchPlan),
}

impl SelectedLog {
    /// JSON metadata for default (non-raw) output.
    pub fn result(&self) -> &LogsResult {
        &self.result
    }

    /// Return inline bytes only after canonical base64, cap, length, hash, and
    /// truncation checks have all succeeded.
    pub fn inline_raw(&self) -> Option<&VerifiedRawLog> {
        match &self.source {
            SelectedLogSource::Inline(bytes) => Some(bytes),
            SelectedLogSource::Url(_) => None,
        }
    }

    /// Return the constrained authenticated retrieval plan for a URL log.
    pub fn fetch_plan(&self) -> Option<&LogFetchPlan> {
        match &self.source {
            SelectedLogSource::Url(plan) => Some(plan),
            SelectedLogSource::Inline(_) => None,
        }
    }
}

/// Select and verify the log reference for one job attempt.
///
/// Omitted `attempt` means the greatest known attempt, even when an older
/// attempt is the latest one carrying a log. The selected latest status must
/// be terminal and point to exactly one supplied durable log event.
pub fn select_log(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    statuses: &[CiJobStatusEnvelope],
    log_events: &[DurableLogEvent],
    relay_url: &str,
    job_id: &str,
    attempt: Option<u32>,
) -> Result<SelectedLog, EvidenceError> {
    validate_request_context(request_event_id, request)?;
    let status = select_job_attempt(request_event_id, request, statuses, job_id, attempt)?;
    if !status.state.is_terminal() {
        return Err(EvidenceError::JobNotTerminal {
            job_id: job_id.to_owned(),
            attempt: status.attempt,
            state: status.state,
        });
    }

    let log_ref = status
        .log_ref
        .as_deref()
        .ok_or_else(|| EvidenceError::DurableLogMissing {
            job_id: job_id.to_owned(),
            attempt: status.attempt,
        })?;
    let mut matches = log_events.iter().filter(|event| event.event_id == log_ref);
    let log_event = matches.next().ok_or(EvidenceError::InvalidLogReference(
        "referenced event is unavailable",
    ))?;
    if matches.next().is_some() {
        return Err(EvidenceError::InvalidLogReference(
            "referenced event is duplicated",
        ));
    }
    validate_log_binding(request_event_id, request, &status, log_event)?;

    let envelope = &log_event.envelope;
    let (url_or_inline, source) = if let Some(inline) = &envelope.inline {
        // `validate_log_binding` called `validate`, so allocation/decode occurs
        // only after the encoded-size bound and canonical form have passed.
        let bytes = BASE64_STANDARD
            .decode(inline)
            .map_err(|_| EvidenceError::EvidenceMismatch("invalid inline base64"))?;
        (
            inline.clone(),
            SelectedLogSource::Inline(VerifiedRawLog(bytes)),
        )
    } else {
        envelope
            .validate_url_for_relay(relay_url)
            .map_err(|error| EvidenceError::InvalidEnvelope(error.to_string()))?;
        let url = envelope
            .url
            .clone()
            .ok_or(EvidenceError::InvalidLogReference("log has no location"))?;
        (
            url.clone(),
            SelectedLogSource::Url(LogFetchPlan {
                url,
                cap_bytes: envelope.cap_bytes,
                byte_length: envelope.byte_length,
                log_sha256: envelope.log_sha256.clone(),
            }),
        )
    };

    Ok(SelectedLog {
        result: LogsResult {
            run_id: request.run_id.clone(),
            sha: request.tip_oid.clone(),
            job_id: job_id.to_owned(),
            attempt: status.attempt,
            log_sha256: envelope.log_sha256.clone(),
            size: envelope.byte_length,
            cap_bytes: envelope.cap_bytes,
            truncated: envelope.truncated,
            url_or_inline,
        },
        source,
    })
}

/// Verify a complete authenticated URL response before exposing any raw bytes.
pub fn verify_fetched_log(
    plan: &LogFetchPlan,
    response: BufferedLogResponse,
) -> Result<VerifiedRawLog, EvidenceError> {
    if !response.authenticated {
        return Err(EvidenceError::UnsafeRetrieval(
            "request was not authenticated",
        ));
    }
    if response.redirects_followed != 0 {
        return Err(EvidenceError::UnsafeRetrieval("redirects are forbidden"));
    }
    if response.requested_url != plan.url || response.final_url != plan.url {
        return Err(EvidenceError::UnsafeRetrieval(
            "requested or final URL changed",
        ));
    }
    if response
        .content_length
        .is_some_and(|length| length > plan.cap_bytes)
    {
        return Err(EvidenceError::EvidenceMismatch(
            "declared response exceeds signed cap",
        ));
    }
    let actual_length = u64::try_from(response.body.len())
        .map_err(|_| EvidenceError::EvidenceMismatch("response length overflow"))?;
    if actual_length > plan.cap_bytes {
        return Err(EvidenceError::EvidenceMismatch(
            "response exceeds signed cap",
        ));
    }
    if response
        .content_length
        .is_some_and(|length| length != actual_length)
    {
        return Err(EvidenceError::EvidenceMismatch(
            "declared response length mismatch",
        ));
    }
    if actual_length != plan.byte_length {
        return Err(EvidenceError::EvidenceMismatch(
            "decoded response length mismatch",
        ));
    }
    if hex::encode(Sha256::digest(&response.body)) != plan.log_sha256 {
        return Err(EvidenceError::EvidenceMismatch("response digest mismatch"));
    }
    Ok(VerifiedRawLog(response.body))
}

/// Inputs that may change when deriving a rerun request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RerunParameters {
    /// Requesting signer pubkey.
    pub actor: String,
    /// Requested job timeout.
    pub timeout_seconds: u64,
    /// New request issue time.
    pub issued_at: u64,
    /// New request expiry time.
    pub expires_at: u64,
    /// Broker policy maximum attempt.
    pub max_attempts: u32,
}

/// Pure write plan for a single-job rerun request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RerunPlan {
    /// Kind-46100 content for the caller to sign and publish.
    pub request: CiRequestEnvelope,
    /// Failed parent status selected from the greatest known attempt.
    pub selected_parent: CiJobStatusEnvelope,
}

/// Derive a legal single-job rerun without publishing it.
pub fn derive_rerun_plan(
    original_request_event_id: &str,
    original_request: &CiRequestEnvelope,
    statuses: &[CiJobStatusEnvelope],
    job_id: &str,
    parameters: RerunParameters,
) -> Result<RerunPlan, EvidenceError> {
    validate_request_context(original_request_event_id, original_request)?;
    let parent = select_job_attempt(
        original_request_event_id,
        original_request,
        statuses,
        job_id,
        None,
    )?;
    if !parent.state.is_terminal() {
        return Err(EvidenceError::JobNotTerminal {
            job_id: job_id.to_owned(),
            attempt: parent.attempt,
            state: parent.state,
        });
    }
    if parent.state != CiJobState::Failure {
        return Err(EvidenceError::JobNotFailed {
            job_id: job_id.to_owned(),
            attempt: parent.attempt,
            state: parent.state,
        });
    }
    let next_attempt = parent
        .attempt
        .checked_add(1)
        .ok_or(EvidenceError::AttemptLimit {
            job_id: job_id.to_owned(),
            limit: parameters.max_attempts,
        })?;
    if next_attempt > parameters.max_attempts {
        return Err(EvidenceError::AttemptLimit {
            job_id: job_id.to_owned(),
            limit: parameters.max_attempts,
        });
    }

    let request = CiRequestEnvelope {
        schema_version: original_request.schema_version,
        request_type: CiRequestType::Rerun,
        target_repo_a: original_request.target_repo_a.clone(),
        pr_root_event_id: original_request.pr_root_event_id.clone(),
        pr_update_event_id: original_request.pr_update_event_id.clone(),
        source_clone_url: original_request.source_clone_url.clone(),
        immutable_source_ref: original_request.immutable_source_ref.clone(),
        tip_oid: original_request.tip_oid.clone(),
        source_branch: original_request.source_branch.clone(),
        base_ref: original_request.base_ref.clone(),
        base_oid: original_request.base_oid.clone(),
        workflow_id: original_request.workflow_id.clone(),
        workflow_digest: original_request.workflow_digest.clone(),
        job_ids: vec![job_id.to_owned()],
        run_id: original_request.run_id.clone(),
        attempt: next_attempt,
        parent_attempt: Some(parent.attempt),
        parent_run_id: Some(original_request.run_id.clone()),
        trigger_event_id: original_request.trigger_event_id.clone(),
        actor: parameters.actor,
        timeout_seconds: parameters.timeout_seconds,
        idempotency_key: Uuid::now_v7().to_string(),
        issued_at: parameters.issued_at,
        expires_at: parameters.expires_at,
    };
    request
        .validate()
        .map_err(|error| EvidenceError::InvalidEnvelope(error.to_string()))?;
    if request.idempotency_key == original_request.idempotency_key {
        return Err(EvidenceError::InvalidLineage(
            "rerun idempotency key was not refreshed",
        ));
    }
    Ok(RerunPlan {
        request,
        selected_parent: parent,
    })
}

/// Validated authoritative broker fan-out from the queued rerun acknowledgment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RerunResult {
    /// Stable run identifier.
    pub run_id: String,
    /// Immutable source tip.
    pub sha: String,
    /// Explicitly selected job.
    pub job_id: String,
    /// New contiguous attempt.
    pub attempt: u32,
    /// Frozen acknowledgment state.
    pub state: &'static str,
    /// Selected failed parent attempt.
    pub parent_attempt: u32,
    /// Broker-signed dependency fan-out.
    pub also_reruns: Vec<String>,
}

/// Validate the broker's authoritative queued acknowledgment for a rerun.
pub fn validate_rerun_ack(
    plan: &RerunPlan,
    rerun_request_event_id: &str,
    acknowledgment: &CiJobStatusEnvelope,
) -> Result<RerunResult, EvidenceError> {
    validate_event_id(rerun_request_event_id)?;
    acknowledgment
        .validate()
        .map_err(|error| EvidenceError::InvalidEnvelope(error.to_string()))?;
    if acknowledgment.request_event_id != rerun_request_event_id {
        return Err(EvidenceError::InvalidRerunAck("request event ID mismatch"));
    }
    let request = &plan.request;
    let selected_job = &request.job_ids[0];
    if acknowledgment.run_id != request.run_id
        || acknowledgment.workflow_id != request.workflow_id
        || acknowledgment.target_repo_a != request.target_repo_a
        || acknowledgment.tip_oid != request.tip_oid
        || acknowledgment.base_oid != request.base_oid
        || acknowledgment.job_id != *selected_job
        || acknowledgment.attempt != request.attempt
        || acknowledgment.parent_attempt != request.parent_attempt
    {
        return Err(EvidenceError::InvalidRerunAck(
            "immutable identity or lineage mismatch",
        ));
    }
    if acknowledgment.sequence != 1 {
        return Err(EvidenceError::InvalidRerunAck(
            "queued acknowledgment must be sequence one",
        ));
    }
    if acknowledgment.state != CiJobState::Queued {
        return Err(EvidenceError::InvalidRerunAck(
            "acknowledgment must be queued",
        ));
    }
    Ok(RerunResult {
        run_id: request.run_id.clone(),
        sha: request.tip_oid.clone(),
        job_id: selected_job.clone(),
        attempt: request.attempt,
        state: "queued",
        parent_attempt: plan.selected_parent.attempt,
        also_reruns: acknowledgment.also_reruns.clone(),
    })
}

fn validate_request_context(
    request_event_id: &str,
    request: &CiRequestEnvelope,
) -> Result<(), EvidenceError> {
    validate_event_id(request_event_id)?;
    request
        .validate()
        .map_err(|error| EvidenceError::InvalidEnvelope(error.to_string()))
}

fn validate_event_id(event_id: &str) -> Result<(), EvidenceError> {
    if event_id.len() == 64
        && event_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(EvidenceError::RequestMismatch("invalid request event ID"))
    }
}

fn select_job_attempt(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    statuses: &[CiJobStatusEnvelope],
    job_id: &str,
    requested_attempt: Option<u32>,
) -> Result<CiJobStatusEnvelope, EvidenceError> {
    if !request.job_ids.iter().any(|candidate| candidate == job_id) {
        return Err(EvidenceError::UnknownAttempt {
            job_id: job_id.to_owned(),
            attempt: requested_attempt,
        });
    }
    let mut attempts: BTreeMap<u32, Vec<&CiJobStatusEnvelope>> = BTreeMap::new();
    for status in statuses.iter().filter(|status| status.job_id == job_id) {
        status
            .validate()
            .map_err(|error| EvidenceError::InvalidEnvelope(error.to_string()))?;
        validate_status_binding(request_event_id, request, status)?;
        attempts.entry(status.attempt).or_default().push(status);
    }
    if attempts.is_empty() {
        return Err(EvidenceError::UnknownAttempt {
            job_id: job_id.to_owned(),
            attempt: requested_attempt,
        });
    }

    let mut expected_attempt = 1u32;
    let mut latest_by_attempt = BTreeMap::new();
    for (attempt, stream) in &mut attempts {
        if *attempt != expected_attempt {
            return Err(EvidenceError::InvalidLineage(
                "job attempts are not contiguous from one",
            ));
        }
        let expected_parent = attempt.checked_sub(1).filter(|_| *attempt > 1);
        if stream
            .iter()
            .any(|status| status.parent_attempt != expected_parent)
        {
            return Err(EvidenceError::InvalidLineage(
                "attempt does not name its contiguous parent",
            ));
        }
        stream.sort_by_key(|status| status.sequence);
        let mut expected_sequence = 1u64;
        let mut previous_state: Option<CiJobState> = None;
        for status in stream.iter() {
            if status.sequence != expected_sequence {
                return Err(EvidenceError::InvalidLineage(
                    "job status sequence is duplicated or has a gap",
                ));
            }
            if let Some(previous) = previous_state {
                if !previous.can_transition_to(status.state) {
                    return Err(EvidenceError::InvalidLineage(
                        "job status transition is illegal",
                    ));
                }
            } else if status.state != CiJobState::Queued {
                return Err(EvidenceError::InvalidLineage(
                    "job status sequence must begin queued",
                ));
            }
            previous_state = Some(status.state);
            expected_sequence =
                expected_sequence
                    .checked_add(1)
                    .ok_or(EvidenceError::InvalidLineage(
                        "job status sequence overflow",
                    ))?;
        }
        latest_by_attempt.insert(
            *attempt,
            (*stream.last().expect("non-empty stream")).clone(),
        );
        expected_attempt = expected_attempt
            .checked_add(1)
            .ok_or(EvidenceError::InvalidLineage("job attempt overflow"))?;
    }

    let selected_attempt = requested_attempt.unwrap_or_else(|| {
        *latest_by_attempt
            .last_key_value()
            .expect("non-empty attempt map")
            .0
    });
    latest_by_attempt
        .remove(&selected_attempt)
        .ok_or_else(|| EvidenceError::UnknownAttempt {
            job_id: job_id.to_owned(),
            attempt: requested_attempt,
        })
}

fn validate_status_binding(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    status: &CiJobStatusEnvelope,
) -> Result<(), EvidenceError> {
    if status.request_event_id != request_event_id {
        return Err(EvidenceError::RequestMismatch("request event ID mismatch"));
    }
    if status.run_id != request.run_id {
        return Err(EvidenceError::RequestMismatch("run ID mismatch"));
    }
    if status.workflow_id != request.workflow_id {
        return Err(EvidenceError::RequestMismatch("workflow ID mismatch"));
    }
    if status.target_repo_a != request.target_repo_a {
        return Err(EvidenceError::RequestMismatch("repository mismatch"));
    }
    if status.tip_oid != request.tip_oid || status.base_oid != request.base_oid {
        return Err(EvidenceError::RequestMismatch("source tuple mismatch"));
    }
    Ok(())
}

fn validate_log_binding(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    status: &CiJobStatusEnvelope,
    log_event: &DurableLogEvent,
) -> Result<(), EvidenceError> {
    if log_event.event_id.len() != 64
        || !log_event
            .event_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EvidenceError::InvalidLogReference("invalid log event ID"));
    }
    let log = &log_event.envelope;
    log.validate()
        .map_err(|error| EvidenceError::InvalidEnvelope(error.to_string()))?;
    if log.request_event_id != request_event_id
        || log.run_id != request.run_id
        || log.workflow_id != request.workflow_id
        || log.target_repo_a != request.target_repo_a
        || log.tip_oid != request.tip_oid
        || log.job_id != status.job_id
        || log.attempt != status.attempt
    {
        return Err(EvidenceError::InvalidLogReference(
            "log identity does not match selected attempt",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::ci::{CiSkipPolicy, CI_SCHEMA_VERSION};

    const REQUEST_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LOG_EVENT_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SIGNER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const ACTOR: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const TIP: &str = "1111111111111111111111111111111111111111";
    const BASE: &str = "2222222222222222222222222222222222222222";
    const WORKFLOW_DIGEST: &str =
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const RELAY: &str = "wss://relay.example";

    fn request() -> CiRequestEnvelope {
        CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{ACTOR}:buzz"),
            pr_root_event_id: "f".repeat(64),
            pr_update_event_id: None,
            source_clone_url: "https://example.com/buzz.git".into(),
            immutable_source_ref: "refs/buzz/requests/one".into(),
            tip_oid: TIP.into(),
            source_branch: "feature".into(),
            base_ref: "refs/heads/main".into(),
            base_oid: BASE.into(),
            workflow_id: "required_ci".into(),
            workflow_digest: WORKFLOW_DIGEST.into(),
            job_ids: vec!["unit".into(), "package".into()],
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "f".repeat(64),
            actor: ACTOR.into(),
            timeout_seconds: 600,
            idempotency_key: "original-key".into(),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_600,
        }
    }

    fn status(job_id: &str, attempt: u32, sequence: u64, state: CiJobState) -> CiJobStatusEnvelope {
        CiJobStatusEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: REQUEST_ID.into(),
            run_id: request().run_id,
            workflow_id: "required_ci".into(),
            target_repo_a: format!("30617:{ACTOR}:buzz"),
            tip_oid: TIP.into(),
            base_oid: BASE.into(),
            job_id: job_id.into(),
            name: job_id.into(),
            attempt,
            parent_attempt: attempt.checked_sub(1).filter(|_| attempt > 1),
            sequence,
            state,
            conclusion: None,
            reason: None,
            required: true,
            skip_policy: CiSkipPolicy::Forbid,
            selected_job_instance: job_id.into(),
            also_reruns: Vec::new(),
            started_at: (sequence >= 2).then_some(1_700_000_001),
            finished_at: state.is_terminal().then_some(1_700_000_002),
            log_ref: None,
            artifact_refs: Vec::new(),
            relay_signer: SIGNER.into(),
        }
    }

    fn terminal_status(job_id: &str, attempt: u32, state: CiJobState) -> Vec<CiJobStatusEnvelope> {
        vec![
            status(job_id, attempt, 1, CiJobState::Queued),
            status(job_id, attempt, 2, CiJobState::Running),
            status(job_id, attempt, 3, state),
        ]
    }

    fn log_event(job_id: &str, attempt: u32, bytes: &[u8]) -> DurableLogEvent {
        let inline = BASE64_STANDARD.encode(bytes);
        DurableLogEvent {
            event_id: LOG_EVENT_ID.into(),
            envelope: CiLogReferenceEnvelope {
                schema_version: CI_SCHEMA_VERSION,
                request_event_id: REQUEST_ID.into(),
                run_id: request().run_id,
                workflow_id: "required_ci".into(),
                target_repo_a: format!("30617:{ACTOR}:buzz"),
                tip_oid: TIP.into(),
                job_id: job_id.into(),
                attempt,
                log_sha256: hex::encode(Sha256::digest(bytes)),
                byte_length: bytes.len() as u64,
                cap_bytes: 1024,
                truncated: false,
                url: None,
                inline: Some(inline),
                created_at: 1_700_000_003,
                relay_signer: SIGNER.into(),
            },
        }
    }

    fn attach_log(statuses: &mut [CiJobStatusEnvelope]) {
        statuses.last_mut().expect("terminal status").log_ref = Some(LOG_EVENT_ID.into());
    }

    fn parameters(max_attempts: u32) -> RerunParameters {
        RerunParameters {
            actor: ACTOR.into(),
            timeout_seconds: 600,
            issued_at: 1_700_001_000,
            expires_at: 1_700_001_600,
            max_attempts,
        }
    }

    #[test]
    fn omitted_attempt_refuses_stale_older_log() {
        let mut statuses = terminal_status("unit", 1, CiJobState::Failure);
        attach_log(&mut statuses);
        statuses.push(status("unit", 2, 1, CiJobState::Queued));
        statuses.push(status("unit", 2, 2, CiJobState::Running));
        let result = select_log(
            REQUEST_ID,
            &request(),
            &statuses,
            &[log_event("unit", 1, b"old")],
            RELAY,
            "unit",
            None,
        );
        assert!(matches!(
            result,
            Err(EvidenceError::JobNotTerminal { attempt: 2, .. })
        ));
    }

    #[test]
    fn omitted_attempt_refuses_terminal_latest_attempt_without_log() {
        let mut statuses = terminal_status("unit", 1, CiJobState::Failure);
        attach_log(&mut statuses);
        statuses.extend(terminal_status("unit", 2, CiJobState::Success));
        let result = select_log(
            REQUEST_ID,
            &request(),
            &statuses,
            &[log_event("unit", 1, b"old")],
            RELAY,
            "unit",
            None,
        );
        assert!(matches!(
            result,
            Err(EvidenceError::DurableLogMissing { attempt: 2, .. })
        ));
    }

    #[test]
    fn explicit_attempt_selects_exact_older_log() {
        let mut statuses = terminal_status("unit", 1, CiJobState::Failure);
        attach_log(&mut statuses);
        statuses.push(status("unit", 2, 1, CiJobState::Queued));
        let selected = select_log(
            REQUEST_ID,
            &request(),
            &statuses,
            &[log_event("unit", 1, b"old")],
            RELAY,
            "unit",
            Some(1),
        )
        .expect("select explicit attempt");
        assert_eq!(selected.result().attempt, 1);
        assert_eq!(selected.inline_raw().unwrap().as_bytes(), b"old");
    }

    #[test]
    fn inline_requires_canonical_base64_size_hash_cap_and_no_truncation() {
        let mut statuses = terminal_status("unit", 1, CiJobState::Success);
        attach_log(&mut statuses);
        let valid = log_event("unit", 1, b"hello");
        assert!(select_log(
            REQUEST_ID,
            &request(),
            &statuses,
            std::slice::from_ref(&valid),
            RELAY,
            "unit",
            None
        )
        .is_ok());

        let mut cases = Vec::new();
        let mut noncanonical = valid.clone();
        noncanonical.envelope.inline = Some("aGVsbG8".into());
        cases.push(noncanonical);
        let mut wrong_size = valid.clone();
        wrong_size.envelope.byte_length = 4;
        cases.push(wrong_size);
        let mut wrong_hash = valid.clone();
        wrong_hash.envelope.log_sha256 = "0".repeat(64);
        cases.push(wrong_hash);
        let mut over_cap = valid.clone();
        over_cap.envelope.cap_bytes = 4;
        cases.push(over_cap);
        let mut truncated = valid;
        truncated.envelope.truncated = true;
        cases.push(truncated);

        for event in cases {
            assert!(select_log(
                REQUEST_ID,
                &request(),
                &statuses,
                &[event],
                RELAY,
                "unit",
                None
            )
            .is_err());
        }
    }

    #[test]
    fn url_rejects_bad_origin_path_query_and_redirected_response() {
        let mut statuses = terminal_status("unit", 1, CiJobState::Success);
        attach_log(&mut statuses);
        let bytes = b"hello";
        let hash = hex::encode(Sha256::digest(bytes));
        let valid_url = format!(
            "https://relay.example/ci/logs/{}/{}/unit/1/{}",
            REQUEST_ID,
            request().run_id,
            hash
        );
        let mut valid = log_event("unit", 1, bytes);
        valid.envelope.inline = None;
        valid.envelope.url = Some(valid_url.clone());

        for bad in [
            valid_url.replace("relay.example", "evil.example"),
            valid_url.replace("/ci/logs/", "/ci/log/"),
            format!("{valid_url}?download=1"),
        ] {
            let mut event = valid.clone();
            event.envelope.url = Some(bad);
            assert!(select_log(
                REQUEST_ID,
                &request(),
                &statuses,
                &[event],
                RELAY,
                "unit",
                None
            )
            .is_err());
        }

        let selected = select_log(
            REQUEST_ID,
            &request(),
            &statuses,
            &[valid],
            RELAY,
            "unit",
            None,
        )
        .unwrap();
        let plan = selected.fetch_plan().unwrap();
        let response = BufferedLogResponse {
            requested_url: valid_url.clone(),
            final_url: valid_url,
            redirects_followed: 1,
            authenticated: true,
            content_length: Some(bytes.len() as u64),
            body: bytes.to_vec(),
        };
        assert!(matches!(
            verify_fetched_log(plan, response.clone()),
            Err(EvidenceError::UnsafeRetrieval("redirects are forbidden"))
        ));
        let verified = verify_fetched_log(
            plan,
            BufferedLogResponse {
                redirects_followed: 0,
                ..response
            },
        )
        .expect("verify same-relay response");
        assert_eq!(verified.as_bytes(), bytes);
    }

    #[test]
    fn rerun_rejects_nonfailed_terminal_parent() {
        let statuses = terminal_status("unit", 1, CiJobState::Success);
        assert!(matches!(
            derive_rerun_plan(REQUEST_ID, &request(), &statuses, "unit", parameters(3)),
            Err(EvidenceError::JobNotFailed { .. })
        ));
    }

    #[test]
    fn rerun_uses_contiguous_selected_lineage_and_immutable_tuple() {
        let statuses = terminal_status("unit", 1, CiJobState::Failure);
        let plan =
            derive_rerun_plan(REQUEST_ID, &request(), &statuses, "unit", parameters(3)).unwrap();
        assert_eq!(plan.request.attempt, 2);
        assert_eq!(plan.request.parent_attempt, Some(1));
        assert_eq!(plan.request.parent_run_id, Some(request().run_id));
        assert_eq!(plan.request.job_ids, ["unit"]);
        assert_eq!(plan.request.target_repo_a, request().target_repo_a);
        assert_eq!(plan.request.pr_root_event_id, request().pr_root_event_id);
        assert_eq!(plan.request.source_clone_url, request().source_clone_url);
        assert_eq!(
            plan.request.immutable_source_ref,
            request().immutable_source_ref
        );
        assert_eq!(plan.request.tip_oid, request().tip_oid);
        assert_eq!(plan.request.base_oid, request().base_oid);
        assert_eq!(plan.request.workflow_digest, request().workflow_digest);
        assert_ne!(plan.request.idempotency_key, request().idempotency_key);
        assert_eq!(
            Uuid::parse_str(&plan.request.idempotency_key)
                .unwrap()
                .get_version(),
            Some(uuid::Version::SortRand)
        );
        let second =
            derive_rerun_plan(REQUEST_ID, &request(), &statuses, "unit", parameters(3)).unwrap();
        assert_ne!(plan.request.idempotency_key, second.request.idempotency_key);
    }

    #[test]
    fn rerun_refuses_noncontiguous_attempt_history() {
        let statuses = terminal_status("unit", 2, CiJobState::Failure);
        assert!(matches!(
            derive_rerun_plan(REQUEST_ID, &request(), &statuses, "unit", parameters(3)),
            Err(EvidenceError::InvalidLineage(_))
        ));
    }

    #[test]
    fn queued_ack_returns_explicit_signed_fanout() {
        let statuses = terminal_status("unit", 1, CiJobState::Failure);
        let plan =
            derive_rerun_plan(REQUEST_ID, &request(), &statuses, "unit", parameters(3)).unwrap();
        let rerun_event_id = "9".repeat(64);
        let mut ack = status("unit", 2, 1, CiJobState::Queued);
        ack.request_event_id = rerun_event_id.clone();
        ack.also_reruns = vec!["package".into()];
        let result = validate_rerun_ack(&plan, &rerun_event_id, &ack).unwrap();
        assert_eq!(result.also_reruns, ["package"]);

        ack.also_reruns.push("unit".into());
        assert!(validate_rerun_ack(&plan, &rerun_event_id, &ack).is_err());
    }

    #[test]
    fn rerun_honors_max_attempts() {
        let statuses = terminal_status("unit", 1, CiJobState::Failure);
        assert!(matches!(
            derive_rerun_plan(REQUEST_ID, &request(), &statuses, "unit", parameters(1)),
            Err(EvidenceError::AttemptLimit { limit: 1, .. })
        ));
    }
}
