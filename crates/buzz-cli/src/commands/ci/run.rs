//! `buzz ci run` preflight, request publication, and queued acknowledgment.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use buzz_core::ci::{
    request_tags, validate_signed_ci_event, CiRequestEnvelope, CiRequestType, CiRunState,
    CiSkipPolicy, ValidatedCiEnvelope, CI_MAX_SAFE_INTEGER, CI_SCHEMA_VERSION,
};
use buzz_core::kind::{KIND_CI_REQUEST, KIND_CI_RUN_STATUS};
use nostr::{Event, EventBuilder, Kind, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::{Uuid, Version};

use crate::client::BuzzClient;
use crate::error::CliError;

const PREFLIGHT_PATH: &str = "/ci/preflight";
const ACK_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Arguments carried by the frozen `buzz ci run` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunArgs {
    /// Repository owner pubkey.
    pub repo_owner: String,
    /// Repository NIP-33 d-tag.
    pub repo_id: String,
    /// Exact full source object ID.
    pub sha: String,
    /// Optional workflow ID or digest selector.
    pub workflow: Option<String>,
    /// Optional explicit static job selection.
    pub jobs: Option<Vec<String>>,
}

/// Trusted repository and acknowledgment inputs supplied by owner configuration.
///
/// This input is deliberately separate from preflight. Relay responses cannot
/// choose the channel or add a signer to this set.
#[derive(Debug, Clone)]
pub struct RunTrustedContext {
    /// Repository's owner-configured channel binding.
    pub channel_id: String,
    /// Non-empty owner-configured status/control-plane signer set.
    pub status_signers: HashSet<String>,
}

/// Successful `buzz ci run` output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunQueuedOutput {
    /// Fresh UUIDv7 run identifier.
    pub run_id: String,
    /// Exact requested source object ID.
    pub sha: String,
    /// Independently verified workflow digest.
    pub workflow_digest: String,
    /// Selected static jobs.
    pub jobs: Vec<RunQueuedJob>,
    /// Initial attempt number.
    pub attempt: u32,
    /// Broker-acknowledged state.
    pub state: CiRunState,
}

/// Static job identity returned by `buzz ci run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunQueuedJob {
    /// Static job ID.
    pub job_id: String,
    /// Human-readable workflow job name.
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PreflightRequest {
    target_repo_a: String,
    requested_tip_oid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow_selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_job_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PreflightResponse {
    target_repo_a: String,
    pr_root_event_id: String,
    pr_update_event_id: Option<String>,
    trigger_event_id: String,
    source_clone_url: String,
    immutable_source_ref: String,
    tip_oid: String,
    source_branch: String,
    base_ref: String,
    base_oid: String,
    workflow_id: String,
    workflow_path: String,
    workflow_digest: String,
    canonical_workflow_base64: String,
    jobs: Vec<PreflightJob>,
    selected_job_ids: Vec<String>,
    policy: PreflightPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PreflightJob {
    job_id: String,
    name: String,
    required: bool,
    skip_policy: CiSkipPolicy,
    needs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PreflightPolicy {
    min_timeout_seconds: u64,
    max_timeout_seconds: u64,
    max_expiry_seconds: u64,
    acknowledgement_timeout_seconds: u64,
    max_attempts: u64,
}

#[derive(Debug, Clone)]
struct ValidatedPreflight {
    response: PreflightResponse,
    selected_jobs: Vec<RunQueuedJob>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunIdentity {
    run_id: String,
    idempotency_key: String,
    issued_at: u64,
}

#[derive(Debug, Deserialize)]
struct SubmitResponse {
    event_id: String,
    accepted: bool,
    #[serde(default)]
    message: String,
}

/// Resolve, preflight, sign, publish, and wait for an authorized queued acknowledgment.
///
/// The administrative signer set must come from owner configuration. The relay
/// API contract intentionally does not define that configuration source yet,
/// so callers must inject it explicitly.
pub async fn execute_run(
    client: &BuzzClient,
    args: &RunArgs,
    trusted: &RunTrustedContext,
) -> Result<RunQueuedOutput, CliError> {
    validate_trusted_context(trusted)?;
    validate_run_args(args)?;

    let target_repo_a = format!("30617:{}:{}", args.repo_owner, args.repo_id);
    let request = PreflightRequest {
        target_repo_a: target_repo_a.clone(),
        requested_tip_oid: args.sha.clone(),
        workflow_selector: args.workflow.clone(),
        requested_job_ids: args.jobs.clone(),
    };
    let request_binding = serde_json::to_string(&request).map_err(|error| {
        CliError::Other(format!("preflight request serialization failed: {error}"))
    })?;
    let response: PreflightResponse = client
        .post_authed_json(PREFLIGHT_PATH, &request)
        .await
        .map_err(|source| CliError::CiPreflight {
            request: request_binding,
            source: Box::new(match source {
                CliError::Relay { status: 404, ref body } if body.is_empty() => CliError::Other(
                    "relay returned an empty HTTP 404 for /ci/preflight; the endpoint may be unavailable"
                        .into(),
                ),
                other => other,
            }),
        })?;
    let preflight = validate_preflight(response, &request, client.relay_url())?;

    let identity = fresh_run_identity()?;
    let (event, envelope) = build_run_event(client, &trusted.channel_id, &preflight, identity)?;
    let request_event_id = event.id.to_hex();
    let raw_submit = client.submit_event(event).await?;
    validate_submit_response(&raw_submit, &request_event_id)?;

    wait_for_queued_acknowledgement(
        client,
        &trusted.channel_id,
        &request_event_id,
        &envelope,
        &preflight.selected_jobs,
        &trusted.status_signers,
        Duration::from_secs(preflight.response.policy.acknowledgement_timeout_seconds),
    )
    .await
}

/// Run the command and print its sole success object.
pub async fn cmd_run(
    client: &BuzzClient,
    args: &RunArgs,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    let output = execute_run(client, args, trusted).await?;
    let json = serde_json::to_string(&output)
        .map_err(|error| CliError::Other(format!("failed to serialize run output: {error}")))?;
    println!("{json}");
    Ok(())
}

fn validate_trusted_context(trusted: &RunTrustedContext) -> Result<(), CliError> {
    let channel = Uuid::parse_str(&trusted.channel_id)
        .map_err(|_| CliError::Auth("CI channel binding is not a UUID".into()))?;
    if channel.to_string() != trusted.channel_id {
        return Err(CliError::Auth("CI channel binding is not canonical".into()));
    }
    if trusted.status_signers.is_empty() {
        return Err(CliError::Auth(
            "CI acknowledgment signer configuration is empty".into(),
        ));
    }
    if trusted
        .status_signers
        .iter()
        .any(|signer| !is_lower_hex(signer, 64))
    {
        return Err(CliError::Auth(
            "CI acknowledgment signer configuration contains an invalid pubkey".into(),
        ));
    }
    Ok(())
}

fn validate_run_args(args: &RunArgs) -> Result<(), CliError> {
    if !is_lower_hex(&args.repo_owner, 64) {
        return Err(CliError::Usage(
            "--repo-owner must be 64 lowercase hex characters".into(),
        ));
    }
    crate::validate::validate_repo_id(&args.repo_id)?;
    validate_git_oid(&args.sha, "--sha")?;
    if let Some(selector) = &args.workflow {
        validate_nonempty_text(selector, "--workflow")?;
    }
    if args.jobs.as_ref().is_some_and(Vec::is_empty) {
        return Err(CliError::Usage(
            "--jobs must contain at least one static job ID".into(),
        ));
    }
    if let Some(jobs) = &args.jobs {
        validate_unique_job_ids(jobs, "--jobs")?;
    }
    Ok(())
}

fn validate_preflight(
    response: PreflightResponse,
    request: &PreflightRequest,
    relay_url: &str,
) -> Result<ValidatedPreflight, CliError> {
    if response.target_repo_a != request.target_repo_a {
        return Err(preflight_error("repository binding mismatch"));
    }
    if response.tip_oid != request.requested_tip_oid {
        return Err(CliError::Usage(format!(
            "{{\"error\":\"sha_mismatch\",\"requested\":\"{}\",\"resolved\":\"{}\"}}",
            request.requested_tip_oid, response.tip_oid
        )));
    }
    validate_git_oid(&response.tip_oid, "preflight tip_oid")?;
    validate_git_oid(&response.base_oid, "preflight base_oid")?;
    if response.base_oid.len() != response.tip_oid.len() {
        return Err(preflight_error("tip and base object ID widths differ"));
    }
    validate_lower_hex(&response.pr_root_event_id, 64, "preflight PR root event ID")?;
    if let Some(update) = &response.pr_update_event_id {
        validate_lower_hex(update, 64, "preflight PR update event ID")?;
    }
    validate_lower_hex(&response.trigger_event_id, 64, "preflight trigger event ID")?;
    let expected_trigger = response
        .pr_update_event_id
        .as_deref()
        .unwrap_or(response.pr_root_event_id.as_str());
    if response.trigger_event_id != expected_trigger {
        return Err(preflight_error(
            "trigger event does not equal the effective PR event",
        ));
    }

    validate_clone_url_for_relay(&response.source_clone_url, relay_url)?;
    validate_git_ref(&response.immutable_source_ref, "immutable source ref")?;
    validate_nonempty_text(&response.source_branch, "source branch")?;
    validate_nonempty_text(&response.base_ref, "base ref")?;
    validate_nonempty_text(&response.workflow_path, "workflow path")?;
    validate_workflow_path(&response.workflow_path)?;
    validate_nonempty_text(&response.workflow_id, "workflow_id")?;
    validate_lower_hex(&response.workflow_digest, 64, "workflow digest")?;
    if let Some(selector) = &request.workflow_selector {
        let matches = if is_lower_hex(selector, 64) {
            selector == &response.workflow_digest
        } else {
            selector == &response.workflow_id
        };
        if !matches {
            return Err(preflight_error("workflow selector binding mismatch"));
        }
    }

    let workflow_bytes = BASE64_STANDARD
        .decode(response.canonical_workflow_base64.as_bytes())
        .map_err(|_| preflight_error("workflow bytes are not canonical base64"))?;
    if BASE64_STANDARD.encode(&workflow_bytes) != response.canonical_workflow_base64 {
        return Err(preflight_error("workflow bytes are not canonical base64"));
    }
    if hex::encode(Sha256::digest(&workflow_bytes)) != response.workflow_digest {
        return Err(preflight_error("workflow digest mismatch"));
    }

    validate_policy(&response.policy)?;
    let selected_jobs = validate_jobs(&response, request.requested_job_ids.as_deref())?;
    Ok(ValidatedPreflight {
        response,
        selected_jobs,
    })
}

fn validate_jobs(
    response: &PreflightResponse,
    requested: Option<&[String]>,
) -> Result<Vec<RunQueuedJob>, CliError> {
    if response.jobs.is_empty() {
        return Err(preflight_error("workflow job set is empty"));
    }
    let all_ids: Vec<String> = response.jobs.iter().map(|job| job.job_id.clone()).collect();
    validate_unique_job_ids(&all_ids, "preflight jobs")?;
    let by_id: HashMap<&str, &PreflightJob> = response
        .jobs
        .iter()
        .map(|job| (job.job_id.as_str(), job))
        .collect();
    for job in &response.jobs {
        let _signed_job_policy = (job.required, job.skip_policy);
        validate_nonempty_text(&job.name, "preflight job name")?;
        let mut needs = HashSet::new();
        for need in &job.needs {
            validate_job_id(need, "preflight job dependency")?;
            if need == &job.job_id || !by_id.contains_key(need.as_str()) || !needs.insert(need) {
                return Err(preflight_error("invalid preflight job dependency graph"));
            }
        }
    }
    validate_unique_job_ids(&response.selected_job_ids, "selected jobs")?;
    if response
        .selected_job_ids
        .iter()
        .any(|job_id| !by_id.contains_key(job_id.as_str()))
    {
        return Err(preflight_error("selected job is not in the workflow"));
    }
    match requested {
        Some(requested) if requested != response.selected_job_ids.as_slice() => {
            return Err(preflight_error("selected jobs differ from --jobs"));
        }
        None if all_ids != response.selected_job_ids => {
            return Err(preflight_error(
                "omitted --jobs did not resolve to the complete workflow job set",
            ));
        }
        _ => {}
    }
    response
        .selected_job_ids
        .iter()
        .map(|job_id| {
            let job = by_id
                .get(job_id.as_str())
                .ok_or_else(|| preflight_error("selected job is not in the workflow"))?;
            Ok(RunQueuedJob {
                job_id: job.job_id.clone(),
                name: job.name.clone(),
            })
        })
        .collect()
}

fn validate_policy(policy: &PreflightPolicy) -> Result<(), CliError> {
    let values = [
        policy.min_timeout_seconds,
        policy.max_timeout_seconds,
        policy.max_expiry_seconds,
        policy.acknowledgement_timeout_seconds,
        policy.max_attempts,
    ];
    if values
        .iter()
        .any(|value| *value == 0 || *value > CI_MAX_SAFE_INTEGER)
        || policy.max_attempts > u64::from(u32::MAX)
        || policy.min_timeout_seconds > policy.max_timeout_seconds
    {
        return Err(preflight_error("invalid preflight policy bounds"));
    }
    Ok(())
}

fn fresh_run_identity() -> Result<RunIdentity, CliError> {
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::Other("system clock precedes Unix epoch".into()))?
        .as_secs();
    if issued_at > CI_MAX_SAFE_INTEGER {
        return Err(CliError::Other(
            "system time exceeds JSON safe integer".into(),
        ));
    }
    Ok(RunIdentity {
        run_id: Uuid::now_v7().to_string(),
        idempotency_key: Uuid::now_v7().to_string(),
        issued_at,
    })
}

fn build_run_event(
    client: &BuzzClient,
    channel_id: &str,
    preflight: &ValidatedPreflight,
    identity: RunIdentity,
) -> Result<(Event, CiRequestEnvelope), CliError> {
    validate_uuid_v7(&identity.run_id, "run_id")?;
    validate_uuid_v7(&identity.idempotency_key, "idempotency_key")?;
    let expires_at = identity
        .issued_at
        .checked_add(preflight.response.policy.max_expiry_seconds)
        .filter(|value| *value <= CI_MAX_SAFE_INTEGER)
        .ok_or_else(|| preflight_error("request expiry exceeds safe integer"))?;
    let actor = client.keys().public_key().to_hex();
    let response = &preflight.response;
    let envelope = CiRequestEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_type: CiRequestType::Run,
        target_repo_a: response.target_repo_a.clone(),
        pr_root_event_id: response.pr_root_event_id.clone(),
        pr_update_event_id: response.pr_update_event_id.clone(),
        source_clone_url: response.source_clone_url.clone(),
        immutable_source_ref: response.immutable_source_ref.clone(),
        tip_oid: response.tip_oid.clone(),
        source_branch: response.source_branch.clone(),
        base_ref: response.base_ref.clone(),
        base_oid: response.base_oid.clone(),
        workflow_id: response.workflow_id.clone(),
        workflow_digest: response.workflow_digest.clone(),
        job_ids: response.selected_job_ids.clone(),
        run_id: identity.run_id,
        attempt: 1,
        parent_attempt: None,
        parent_run_id: None,
        trigger_event_id: response.trigger_event_id.clone(),
        actor,
        timeout_seconds: response.policy.min_timeout_seconds,
        idempotency_key: identity.idempotency_key,
        issued_at: identity.issued_at,
        expires_at,
    };
    envelope
        .validate()
        .map_err(|error| preflight_error(&error.to_string()))?;
    let content = serde_json::to_string(&envelope)
        .map_err(|error| CliError::Other(format!("failed to serialize CI request: {error}")))?;
    let tags =
        request_tags(channel_id, &envelope).map_err(|error| CliError::Other(error.to_string()))?;
    let event = client.sign_event(
        EventBuilder::new(Kind::Custom(KIND_CI_REQUEST as u16), content)
            .tags(tags)
            .custom_created_at(Timestamp::from(envelope.issued_at)),
    )?;
    Ok((event, envelope))
}

fn validate_submit_response(raw: &str, request_event_id: &str) -> Result<(), CliError> {
    let response: SubmitResponse = serde_json::from_str(raw)
        .map_err(|error| CliError::Other(format!("invalid event submission response: {error}")))?;
    if !response.accepted || response.event_id != request_event_id {
        return Err(CliError::Relay {
            status: 400,
            body: if response.message.is_empty() {
                "relay did not accept the exact CI request event".into()
            } else {
                response.message
            },
        });
    }
    Ok(())
}

async fn wait_for_queued_acknowledgement(
    client: &BuzzClient,
    channel_id: &str,
    request_event_id: &str,
    request: &CiRequestEnvelope,
    selected_jobs: &[RunQueuedJob],
    authorized_signers: &HashSet<String>,
    timeout: Duration,
) -> Result<RunQueuedOutput, CliError> {
    let poll = async {
        loop {
            let filter = serde_json::json!({
                "kinds": [KIND_CI_RUN_STATUS],
                "#e": [request_event_id],
                "#h": [channel_id],
            });
            let raw = client.query(&filter).await?;
            let values: Vec<serde_json::Value> = serde_json::from_str(&raw).map_err(|error| {
                CliError::Other(format!("invalid CI acknowledgment query response: {error}"))
            })?;
            if let Some(output) = evaluate_run_acknowledgements(
                &values,
                channel_id,
                request_event_id,
                request,
                selected_jobs,
                authorized_signers,
            )? {
                return Ok(output);
            }
            tokio::time::sleep(ACK_POLL_INTERVAL).await;
        }
    };
    tokio::time::timeout(timeout, poll).await.map_err(|_| {
        CliError::Other("timed out waiting for authorized queued acknowledgment".into())
    })?
}

fn evaluate_run_acknowledgements(
    values: &[serde_json::Value],
    channel_id: &str,
    request_event_id: &str,
    request: &CiRequestEnvelope,
    selected_jobs: &[RunQueuedJob],
    authorized_signers: &HashSet<String>,
) -> Result<Option<RunQueuedOutput>, CliError> {
    let mut event_ids = HashSet::new();
    let mut acknowledgment = None;
    for value in values {
        let event: Event = serde_json::from_value(value.clone()).map_err(|error| {
            CliError::Other(format!("invalid CI acknowledgment event: {error}"))
        })?;
        if !event_ids.insert(event.id) {
            continue;
        }
        let envelope = match validate_signed_ci_event(&event, channel_id, authorized_signers)
            .map_err(|error| CliError::Other(error.to_string()))?
        {
            ValidatedCiEnvelope::RunStatus(envelope) => envelope,
            _ => return Err(CliError::Other("unexpected CI acknowledgment kind".into())),
        };
        if envelope.request_event_id != request_event_id
            || envelope.run_id != request.run_id
            || envelope.workflow_id != request.workflow_id
            || envelope.target_repo_a != request.target_repo_a
            || envelope.tip_oid != request.tip_oid
            || envelope.base_oid != request.base_oid
            || envelope.job_ids != request.job_ids
            || envelope.attempt != 1
            || envelope.sequence != 1
            || envelope.state != CiRunState::Queued
        {
            return Err(CliError::Other(
                "CI acknowledgment does not match the signed request".into(),
            ));
        }
        if acknowledgment.replace(envelope).is_some() {
            return Err(CliError::Other(
                "CI queued acknowledgment sequence is equivocated".into(),
            ));
        }
    }
    Ok(acknowledgment.map(|_| RunQueuedOutput {
        run_id: request.run_id.clone(),
        sha: request.tip_oid.clone(),
        workflow_digest: request.workflow_digest.clone(),
        jobs: selected_jobs.to_vec(),
        attempt: 1,
        state: CiRunState::Queued,
    }))
}

fn validate_clone_url_for_relay(value: &str, relay_url: &str) -> Result<(), CliError> {
    let source = Url::parse(value).map_err(|_| preflight_error("invalid source clone URL"))?;
    let relay = Url::parse(relay_url).map_err(|_| CliError::Other("invalid relay URL".into()))?;
    if !matches!(source.scheme(), "http" | "https")
        || source.host_str().is_none()
        || !source.username().is_empty()
        || source.password().is_some()
        || source.query().is_some()
        || source.fragment().is_some()
    {
        return Err(preflight_error("unsafe source clone URL"));
    }
    if source.scheme() == "http"
        && (relay.scheme() != "http"
            || source.host_str() != relay.host_str()
            || source.port_or_known_default() != relay.port_or_known_default())
    {
        return Err(preflight_error(
            "plaintext source clone URL must use the active relay origin",
        ));
    }
    Ok(())
}

fn validate_workflow_path(path: &str) -> Result<(), CliError> {
    if path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(preflight_error("unsafe workflow path"));
    }
    Ok(())
}

fn validate_git_ref(value: &str, field: &str) -> Result<(), CliError> {
    validate_nonempty_text(value, field)?;
    if !value.starts_with("refs/")
        || value.ends_with('/')
        || value.contains("..")
        || value.contains("@{")
        || value.bytes().any(|byte| {
            byte <= b' ' || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
        || value
            .split('/')
            .any(|part| part.is_empty() || part.starts_with('.') || part.ends_with(".lock"))
    {
        return Err(preflight_error("invalid immutable source ref"));
    }
    Ok(())
}

fn validate_uuid_v7(value: &str, field: &str) -> Result<(), CliError> {
    let uuid =
        Uuid::parse_str(value).map_err(|_| CliError::Other(format!("{field} is not a UUID")))?;
    if uuid.get_version() != Some(Version::SortRand) || uuid.to_string() != value {
        return Err(CliError::Other(format!(
            "{field} is not a canonical UUIDv7"
        )));
    }
    Ok(())
}

fn validate_unique_job_ids(values: &[String], field: &str) -> Result<(), CliError> {
    if values.is_empty() {
        return Err(preflight_error("selected job set is empty"));
    }
    let mut unique = HashSet::new();
    for value in values {
        validate_job_id(value, field)?;
        if !unique.insert(value) {
            return Err(preflight_error("job IDs must be unique"));
        }
    }
    Ok(())
}

fn validate_job_id(value: &str, field: &str) -> Result<(), CliError> {
    if value.len() > 64 {
        return Err(CliError::Usage(format!(
            "{field} must start with [A-Za-z_], use [A-Za-z0-9_-], and contain 1 to 64 bytes"
        )));
    }
    let mut bytes = value.bytes();
    if !matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CliError::Usage(format!(
            "{field} must start with [A-Za-z_], use [A-Za-z0-9_-], and contain 1 to 64 bytes"
        )));
    }
    Ok(())
}

fn validate_git_oid(value: &str, field: &str) -> Result<(), CliError> {
    if !matches!(value.len(), 40 | 64) || !is_lower_hex(value, value.len()) {
        return Err(CliError::Usage(format!(
            "{field} must be a full lowercase SHA-1 or SHA-256 object ID"
        )));
    }
    Ok(())
}

fn validate_lower_hex(value: &str, len: usize, field: &str) -> Result<(), CliError> {
    if !is_lower_hex(value, len) {
        return Err(preflight_error(&format!("invalid {field}")));
    }
    Ok(())
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_nonempty_text(value: &str, field: &str) -> Result<(), CliError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(preflight_error(&format!("{field} must be non-empty text")));
    }
    Ok(())
}

fn preflight_error(message: &str) -> CliError {
    CliError::Usage(format!("invalid CI preflight response: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::ci::{run_status_tags, CiRunStatusEnvelope};
    use nostr::Keys;

    const CHANNEL: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const RUN_ID: &str = "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45";
    const IDEMPOTENCY_KEY: &str = "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd46";

    fn keys() -> Keys {
        Keys::parse("0101010101010101010101010101010101010101010101010101010101010101").unwrap()
    }

    fn args() -> RunArgs {
        RunArgs {
            repo_owner: keys().public_key().to_hex(),
            repo_id: "buzz".into(),
            sha: "a".repeat(40),
            workflow: None,
            jobs: None,
        }
    }

    fn preflight() -> PreflightResponse {
        let workflow = b"name: CI\njobs:\n  test:\n    runs-on: ubuntu-latest\n";
        PreflightResponse {
            target_repo_a: format!("30617:{}:buzz", keys().public_key().to_hex()),
            pr_root_event_id: "b".repeat(64),
            pr_update_event_id: Some("c".repeat(64)),
            trigger_event_id: "c".repeat(64),
            source_clone_url: "https://relay.example/git/source/buzz".into(),
            immutable_source_ref: format!("refs/nostr/{}", "b".repeat(64)),
            tip_oid: "a".repeat(40),
            source_branch: "feature/ci".into(),
            base_ref: "refs/heads/main".into(),
            base_oid: "d".repeat(40),
            workflow_id: "ci".into(),
            workflow_path: ".github/workflows/ci.yml".into(),
            workflow_digest: hex::encode(Sha256::digest(workflow)),
            canonical_workflow_base64: BASE64_STANDARD.encode(workflow),
            jobs: vec![PreflightJob {
                job_id: "test".into(),
                name: "Test".into(),
                required: true,
                skip_policy: CiSkipPolicy::Forbid,
                needs: vec![],
            }],
            selected_job_ids: vec!["test".into()],
            policy: PreflightPolicy {
                min_timeout_seconds: 60,
                max_timeout_seconds: 600,
                max_expiry_seconds: 120,
                acknowledgement_timeout_seconds: 10,
                max_attempts: 5,
            },
        }
    }

    fn preflight_request() -> PreflightRequest {
        let args = args();
        PreflightRequest {
            target_repo_a: format!("30617:{}:buzz", args.repo_owner),
            requested_tip_oid: args.sha,
            workflow_selector: None,
            requested_job_ids: None,
        }
    }

    fn client() -> BuzzClient {
        BuzzClient::new("https://relay.example".into(), keys(), None, None).unwrap()
    }

    fn built_request() -> (Event, CiRequestEnvelope, Vec<RunQueuedJob>) {
        let validated =
            validate_preflight(preflight(), &preflight_request(), "https://relay.example").unwrap();
        let jobs = validated.selected_jobs.clone();
        let (event, envelope) = build_run_event(
            &client(),
            CHANNEL,
            &validated,
            RunIdentity {
                run_id: RUN_ID.into(),
                idempotency_key: IDEMPOTENCY_KEY.into(),
                issued_at: 1_800_000_000,
            },
        )
        .unwrap();
        (event, envelope, jobs)
    }

    #[test]
    fn validates_and_hashes_untrusted_preflight() {
        let validated =
            validate_preflight(preflight(), &preflight_request(), "https://relay.example").unwrap();
        assert_eq!(validated.selected_jobs[0].job_id, "test");
    }

    #[test]
    fn static_job_id_grammar_accepts_hyphens_and_rejects_unsafe_forms() {
        let max = format!("a{}", "-".repeat(63));
        for value in ["a", "_", "A-0_x", "desktop-smoke-e2e", max.as_str()] {
            assert!(validate_job_id(value, "job").is_ok(), "rejected {value:?}");
        }

        let too_long = format!("a{}", "-".repeat(64));
        for value in [
            "",
            "0job",
            "-job",
            "job.name",
            "job/name",
            "job:name",
            "job name",
            "é",
            too_long.as_str(),
        ] {
            assert!(validate_job_id(value, "job").is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn rejects_preflight_binding_and_workflow_failures() {
        let request = preflight_request();
        let mut response = preflight();
        response.target_repo_a = format!("30617:{}:other", keys().public_key().to_hex());
        assert!(validate_preflight(response, &request, "https://relay.example").is_err());

        let mut response = preflight();
        response.tip_oid = "e".repeat(40);
        assert!(validate_preflight(response, &request, "https://relay.example").is_err());

        let mut response = preflight();
        response.trigger_event_id = response.pr_root_event_id.clone();
        assert!(validate_preflight(response, &request, "https://relay.example").is_err());

        let mut response = preflight();
        response.canonical_workflow_base64.push('=');
        assert!(validate_preflight(response, &request, "https://relay.example").is_err());

        let mut response = preflight();
        response.workflow_digest = "f".repeat(64);
        assert!(validate_preflight(response, &request, "https://relay.example").is_err());
    }

    #[test]
    fn rejects_unsafe_clone_and_job_selection() {
        let request = preflight_request();
        let mut response = preflight();
        response.source_clone_url = "https://token@relay.example/git/source/buzz".into();
        assert!(validate_preflight(response, &request, "https://relay.example").is_err());

        let mut response = preflight();
        response.selected_job_ids.push("test".into());
        assert!(validate_preflight(response, &request, "https://relay.example").is_err());

        let mut response = preflight();
        response.policy.min_timeout_seconds = 601;
        assert!(validate_preflight(response, &request, "https://relay.example").is_err());
    }

    #[test]
    fn builds_deterministic_kind_46100_request() {
        let (event, envelope, _) = built_request();
        assert_eq!(event.kind.as_u16() as u32, KIND_CI_REQUEST);
        assert_eq!(event.created_at.as_secs(), envelope.issued_at);
        assert_eq!(envelope.actor, keys().public_key().to_hex());
        assert_eq!(envelope.timeout_seconds, 60);
        assert_eq!(envelope.expires_at, 1_800_000_120);
        assert_eq!(envelope.run_id, RUN_ID);
        assert_eq!(envelope.idempotency_key, IDEMPOTENCY_KEY);
        assert_eq!(
            serde_json::from_str::<CiRequestEnvelope>(&event.content).unwrap(),
            envelope
        );
        let tag_names: Vec<_> = event
            .tags
            .iter()
            .map(|tag| tag.as_slice()[0].as_str())
            .collect();
        assert_eq!(tag_names, vec!["h", "a", "run", "workflow", "c", "attempt"]);
        event.verify().unwrap();
    }

    #[test]
    fn submission_must_accept_the_exact_request_event() {
        assert!(
            validate_submit_response(
                r#"{"event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","accepted":true}"#,
                &"a".repeat(64),
            )
            .is_ok()
        );
        assert!(
            validate_submit_response(
                r#"{"event_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","accepted":true}"#,
                &"a".repeat(64),
            )
            .is_err()
        );
        assert!(
            validate_submit_response(
                r#"{"event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","accepted":false,"message":"rejected"}"#,
                &"a".repeat(64),
            )
            .is_err()
        );
    }

    #[test]
    fn trusted_context_requires_canonical_channel_and_nonempty_signers() {
        let signer = "a".repeat(64);
        assert!(validate_trusted_context(&RunTrustedContext {
            channel_id: CHANNEL.into(),
            status_signers: HashSet::from([signer.clone()]),
        })
        .is_ok());
        assert!(validate_trusted_context(&RunTrustedContext {
            channel_id: CHANNEL.to_uppercase(),
            status_signers: HashSet::from([signer]),
        })
        .is_err());
        assert!(validate_trusted_context(&RunTrustedContext {
            channel_id: CHANNEL.into(),
            status_signers: HashSet::new(),
        })
        .is_err());
    }

    #[test]
    fn accepts_only_authorized_exact_queued_acknowledgement() {
        let (request_event, request, jobs) = built_request();
        let signer = Keys::generate();
        let signer_hex = signer.public_key().to_hex();
        let status = CiRunStatusEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_event.id.to_hex(),
            run_id: request.run_id.clone(),
            workflow_id: request.workflow_id.clone(),
            target_repo_a: request.target_repo_a.clone(),
            tip_oid: request.tip_oid.clone(),
            base_oid: request.base_oid.clone(),
            attempt: 1,
            sequence: 1,
            state: CiRunState::Queued,
            conclusion: None,
            reason: None,
            started_at: None,
            finished_at: None,
            job_ids: request.job_ids.clone(),
            relay_signer: signer_hex.clone(),
        };
        let tags = run_status_tags(CHANNEL, &status).unwrap();
        let event = EventBuilder::new(
            Kind::Custom(KIND_CI_RUN_STATUS as u16),
            serde_json::to_string(&status).unwrap(),
        )
        .tags(tags)
        .sign_with_keys(&signer)
        .unwrap();
        let values = vec![serde_json::to_value(event).unwrap()];
        let authority = HashSet::from([signer_hex]);
        let output = evaluate_run_acknowledgements(
            &values,
            CHANNEL,
            &request_event.id.to_hex(),
            &request,
            &jobs,
            &authority,
        )
        .unwrap()
        .unwrap();
        assert_eq!(output.state, CiRunState::Queued);
        assert_eq!(output.jobs, jobs);

        assert!(evaluate_run_acknowledgements(
            &values,
            CHANNEL,
            &request_event.id.to_hex(),
            &request,
            &jobs,
            &HashSet::new(),
        )
        .is_err());

        let mut wrong_sequence = status;
        wrong_sequence.sequence = 2;
        let event = EventBuilder::new(
            Kind::Custom(KIND_CI_RUN_STATUS as u16),
            serde_json::to_string(&wrong_sequence).unwrap(),
        )
        .tags(run_status_tags(CHANNEL, &wrong_sequence).unwrap())
        .sign_with_keys(&signer)
        .unwrap();
        assert!(evaluate_run_acknowledgements(
            &[serde_json::to_value(event).unwrap()],
            CHANNEL,
            &request_event.id.to_hex(),
            &request,
            &jobs,
            &authority,
        )
        .is_err());
    }

    #[test]
    fn fresh_run_identity_uses_uuid_v7() {
        let identity = fresh_run_identity().unwrap();
        validate_uuid_v7(&identity.run_id, "run_id").unwrap();
        validate_uuid_v7(&identity.idempotency_key, "idempotency_key").unwrap();
        assert_ne!(identity.run_id, identity.idempotency_key);
    }
}
