//! Relay-side CI selected-graph reduction.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use buzz_core::ci::{
    validate_signed_ci_event, CiJobState, CiJobStatusEnvelope, CiRequestEnvelope, CiRequestType,
    CiTeardownAttestationEnvelope, ValidatedCiEnvelope,
};
use nostr::Event;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An accepted kind-46100 request and its immutable event identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedCiRequest {
    /// Signed request event ID.
    pub event_id: String,
    /// Validated request envelope.
    pub envelope: CiRequestEnvelope,
}

/// Reducer input containing the signed events and signer authority needed for verification.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCiGraphInput {
    /// Repository channel UUID used to validate every event's `h` tag.
    pub channel_id: String,
    /// Non-empty owner-configured control-plane signer set.
    pub authorized_status_signers: HashSet<String>,
    /// Accepted kind-46100 request events for one run.
    pub request_events: Vec<Event>,
    /// Complete accepted kind-46102 history for that run.
    pub job_status_events: Vec<Event>,
}

/// Canonically sorted reducer output consumed by the runner and acceptance harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelectedCiGraph {
    /// Stable run identifier.
    pub run_id: String,
    /// Exact source tip object ID.
    pub tip_oid: String,
    /// Greatest selected attempt across all request jobs.
    pub attempt: u32,
    /// One tuple per accepted request job, sorted by job ID.
    pub selected_job_attempts: Vec<(String, u32)>,
}

/// Closed failures for selected-graph derivation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CiReducerError {
    /// No owner-authorized signer can validate status events.
    #[error("authorized CI signer set is empty")]
    EmptySignerSet,
    /// A signed event failed signature, tag, schema, or signer validation.
    #[error("invalid signed CI event: {0}")]
    InvalidSignedEvent(String),
    /// The reducer did not receive exactly one initial run request.
    #[error("selected graph requires exactly one initial run request")]
    InitialRequestCardinality,
    /// Two accepted requests reused an event identity.
    #[error("duplicate accepted request event ID")]
    DuplicateRequestEvent,
    /// A request failed its context-free contract.
    #[error("invalid accepted request")]
    InvalidRequest,
    /// A request or status changed immutable run coordinates.
    #[error("mixed immutable CI coordinates")]
    MixedCoordinates,
    /// A rerun selected a job outside the initial accepted request.
    #[error("rerun references an unknown request job")]
    UnknownJob,
    /// A request job has no accepted attempt-one history.
    #[error("request job is missing attempt-one history")]
    MissingInitialHistory,
    /// A status refers to no accepted request or to the wrong request attempt.
    #[error("job status has invalid request linkage")]
    InvalidRequestLinkage,
    /// A job stream contains duplicate, zero, or non-contiguous sequence numbers.
    #[error("job status sequence is duplicate, zero, or has a gap")]
    SequenceGap,
    /// A job stream changes signed manifest fields within one attempt.
    #[error("job status stream changes signed manifest fields")]
    ManifestMismatch,
    /// A job stream uses a transition outside the closed state table.
    #[error("illegal job state transition")]
    IllegalTransition,
    /// A rerun does not follow the selected parent attempt.
    #[error("rerun lineage is stale, ambiguous, or non-contiguous")]
    IllegalLineage,
    /// A rerun parent is not a terminal failure.
    #[error("rerun parent job is not failed")]
    ParentNotFailed,
    /// Signed fan-out and the accepted advanced histories differ.
    #[error("rerun fan-out does not exactly match advanced job histories")]
    FanoutMismatch,
    /// Accepted histories remain outside the request and signed rerun graph.
    #[error("job history is not selected by an accepted request")]
    UnselectedHistory,
    /// The teardown lease set differs from the independently selected graph.
    #[error("teardown leases do not exactly match selected job attempts")]
    TeardownGraphMismatch,
}

impl CiReducerError {
    /// Stable machine-readable error name.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptySignerSet => "empty_signer_set",
            Self::InvalidSignedEvent(_) => "invalid_signed_event",
            Self::InitialRequestCardinality => "initial_request_cardinality",
            Self::DuplicateRequestEvent => "duplicate_request_event",
            Self::InvalidRequest => "invalid_request",
            Self::MixedCoordinates => "mixed_coordinates",
            Self::UnknownJob => "unknown_job",
            Self::MissingInitialHistory => "missing_initial_history",
            Self::InvalidRequestLinkage => "invalid_request_linkage",
            Self::SequenceGap => "sequence_gap",
            Self::ManifestMismatch => "manifest_mismatch",
            Self::IllegalTransition => "illegal_transition",
            Self::IllegalLineage => "illegal_lineage",
            Self::ParentNotFailed => "parent_not_failed",
            Self::FanoutMismatch => "fanout_mismatch",
            Self::UnselectedHistory => "unselected_history",
            Self::TeardownGraphMismatch => "teardown_graph_mismatch",
        }
    }
}

#[derive(Debug, Clone)]
struct JobHistory {
    request_event_id: String,
    job_id: String,
    parent_attempt: Option<u32>,
    also_reruns: Vec<String>,
    terminal_state: CiJobState,
}

/// Verify signed request and job-status events, then derive the selected graph.
pub fn reduce_signed_ci_graph(
    input: &SignedCiGraphInput,
) -> Result<SelectedCiGraph, CiReducerError> {
    if input.authorized_status_signers.is_empty() {
        return Err(CiReducerError::EmptySignerSet);
    }

    let mut requests = Vec::with_capacity(input.request_events.len());
    for event in &input.request_events {
        let envelope =
            validate_signed_ci_event(event, &input.channel_id, &input.authorized_status_signers)
                .map_err(|error| CiReducerError::InvalidSignedEvent(error.to_string()))?;
        let ValidatedCiEnvelope::Request(envelope) = envelope else {
            return Err(CiReducerError::InvalidSignedEvent(
                "request input contains a non-request event".to_string(),
            ));
        };
        requests.push(AcceptedCiRequest {
            event_id: event.id.to_hex(),
            envelope,
        });
    }

    let mut statuses = Vec::with_capacity(input.job_status_events.len());
    for event in &input.job_status_events {
        let envelope =
            validate_signed_ci_event(event, &input.channel_id, &input.authorized_status_signers)
                .map_err(|error| CiReducerError::InvalidSignedEvent(error.to_string()))?;
        let ValidatedCiEnvelope::JobStatus(envelope) = envelope else {
            return Err(CiReducerError::InvalidSignedEvent(
                "job-status input contains a non-job-status event".to_string(),
            ));
        };
        statuses.push(envelope);
    }

    reduce_selected_job_attempts(&requests, &statuses)
}

/// Derive one selected attempt per initial request job from validated accepted envelopes.
pub fn reduce_selected_job_attempts(
    accepted_requests: &[AcceptedCiRequest],
    job_statuses: &[CiJobStatusEnvelope],
) -> Result<SelectedCiGraph, CiReducerError> {
    let mut request_ids = HashSet::new();
    for request in accepted_requests {
        request
            .envelope
            .validate()
            .map_err(|_| CiReducerError::InvalidRequest)?;
        if !request_ids.insert(request.event_id.as_str()) {
            return Err(CiReducerError::DuplicateRequestEvent);
        }
    }

    let initial_requests = accepted_requests
        .iter()
        .filter(|request| request.envelope.request_type == CiRequestType::Run)
        .collect::<Vec<_>>();
    if initial_requests.len() != 1 {
        return Err(CiReducerError::InitialRequestCardinality);
    }
    let initial = initial_requests[0];
    let initial_jobs = initial
        .envelope
        .job_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    let request_by_id = accepted_requests
        .iter()
        .map(|request| (request.event_id.as_str(), request))
        .collect::<HashMap<_, _>>();
    for request in accepted_requests {
        if !same_immutable_coordinates(&initial.envelope, &request.envelope) {
            return Err(CiReducerError::MixedCoordinates);
        }
        if request.envelope.request_type == CiRequestType::Rerun
            && !initial_jobs.contains(&request.envelope.job_ids[0])
        {
            return Err(CiReducerError::UnknownJob);
        }
    }

    let histories = build_histories(
        job_statuses,
        &request_by_id,
        &initial.envelope,
        &initial_jobs,
    )?;
    let mut selected = BTreeMap::new();
    let mut selected_states = BTreeMap::new();
    let mut consumed = HashSet::new();

    for job_id in &initial_jobs {
        let key = (initial.event_id.clone(), job_id.clone(), 1);
        let history = histories
            .get(&key)
            .ok_or(CiReducerError::MissingInitialHistory)?;
        selected.insert(job_id.clone(), 1);
        selected_states.insert(job_id.clone(), history.terminal_state);
        consumed.insert(key);
    }

    let mut pending = accepted_requests
        .iter()
        .filter(|request| request.envelope.request_type == CiRequestType::Rerun)
        .collect::<Vec<_>>();
    pending.sort_by(|left, right| left.event_id.cmp(&right.event_id));

    while !pending.is_empty() {
        let mut progressed = false;
        let mut index = 0;
        while index < pending.len() {
            let request = pending[index];
            let selected_job = &request.envelope.job_ids[0];
            let parent_attempt = request
                .envelope
                .parent_attempt
                .ok_or(CiReducerError::IllegalLineage)?;
            let current_attempt = selected
                .get(selected_job)
                .copied()
                .ok_or(CiReducerError::UnknownJob)?;
            if current_attempt < parent_attempt {
                index += 1;
                continue;
            }
            if current_attempt != parent_attempt
                || request.envelope.attempt != parent_attempt.saturating_add(1)
            {
                return Err(CiReducerError::IllegalLineage);
            }
            if selected_states.get(selected_job) != Some(&CiJobState::Failure) {
                return Err(CiReducerError::ParentNotFailed);
            }

            let selected_key = (
                request.event_id.clone(),
                selected_job.clone(),
                request.envelope.attempt,
            );
            let selected_history = histories
                .get(&selected_key)
                .ok_or(CiReducerError::FanoutMismatch)?;
            let mut advanced = BTreeSet::from([selected_job.clone()]);
            advanced.extend(selected_history.also_reruns.iter().cloned());
            if !advanced.is_subset(&initial_jobs) {
                return Err(CiReducerError::UnknownJob);
            }

            let linked = histories
                .values()
                .filter(|history| history.request_event_id == request.event_id)
                .map(|history| history.job_id.clone())
                .collect::<BTreeSet<_>>();
            if linked != advanced {
                return Err(CiReducerError::FanoutMismatch);
            }

            for job_id in &advanced {
                if selected.get(job_id).copied() != Some(parent_attempt) {
                    return Err(CiReducerError::IllegalLineage);
                }
                let key = (
                    request.event_id.clone(),
                    job_id.clone(),
                    request.envelope.attempt,
                );
                let history = histories.get(&key).ok_or(CiReducerError::FanoutMismatch)?;
                if history.parent_attempt != Some(parent_attempt) {
                    return Err(CiReducerError::IllegalLineage);
                }
                selected.insert(job_id.clone(), request.envelope.attempt);
                selected_states.insert(job_id.clone(), history.terminal_state);
                consumed.insert(key);
            }

            pending.remove(index);
            progressed = true;
        }
        if !progressed {
            return Err(CiReducerError::IllegalLineage);
        }
    }

    if consumed.len() != histories.len() {
        return Err(CiReducerError::UnselectedHistory);
    }

    let selected_job_attempts = selected.into_iter().collect::<Vec<_>>();
    let attempt = selected_job_attempts
        .iter()
        .map(|(_, attempt)| *attempt)
        .max()
        .ok_or(CiReducerError::MissingInitialHistory)?;
    Ok(SelectedCiGraph {
        run_id: initial.envelope.run_id.clone(),
        tip_oid: initial.envelope.tip_oid.clone(),
        attempt,
        selected_job_attempts,
    })
}

/// Validate kind 46106 against the independently reduced selected graph.
pub fn validate_teardown_selected_graph(
    accepted_requests: &[AcceptedCiRequest],
    job_statuses: &[CiJobStatusEnvelope],
    attestation: &CiTeardownAttestationEnvelope,
) -> Result<SelectedCiGraph, CiReducerError> {
    let graph = reduce_selected_job_attempts(accepted_requests, job_statuses)?;
    let initial = accepted_requests
        .iter()
        .find(|request| request.envelope.request_type == CiRequestType::Run)
        .ok_or(CiReducerError::InitialRequestCardinality)?;
    attestation
        .validate_context(
            &initial.event_id,
            &initial.envelope,
            &graph.selected_job_attempts,
        )
        .map_err(|_| CiReducerError::TeardownGraphMismatch)?;
    Ok(graph)
}

fn build_histories(
    statuses: &[CiJobStatusEnvelope],
    request_by_id: &HashMap<&str, &AcceptedCiRequest>,
    initial: &CiRequestEnvelope,
    initial_jobs: &BTreeSet<String>,
) -> Result<BTreeMap<(String, String, u32), JobHistory>, CiReducerError> {
    let mut grouped: BTreeMap<(String, String, u32), Vec<&CiJobStatusEnvelope>> = BTreeMap::new();
    for status in statuses {
        status.validate().map_err(|_| CiReducerError::SequenceGap)?;
        if !status_matches_request(status, initial) {
            return Err(CiReducerError::MixedCoordinates);
        }
        if !initial_jobs.contains(&status.job_id) {
            return Err(CiReducerError::UnknownJob);
        }
        let request = request_by_id
            .get(status.request_event_id.as_str())
            .ok_or(CiReducerError::InvalidRequestLinkage)?;
        if status.attempt != request.envelope.attempt {
            return Err(CiReducerError::InvalidRequestLinkage);
        }
        if request.envelope.request_type == CiRequestType::Run && status.parent_attempt.is_some() {
            return Err(CiReducerError::InvalidRequestLinkage);
        }
        grouped
            .entry((
                status.request_event_id.clone(),
                status.job_id.clone(),
                status.attempt,
            ))
            .or_default()
            .push(status);
    }

    let mut histories = BTreeMap::new();
    for (key, mut stream) in grouped {
        stream.sort_by_key(|status| status.sequence);
        for (index, status) in stream.iter().enumerate() {
            if status.sequence != index as u64 + 1 {
                return Err(CiReducerError::SequenceGap);
            }
            if index > 0 {
                let prior = stream[index - 1];
                if !same_manifest(prior, status) {
                    return Err(CiReducerError::ManifestMismatch);
                }
                if !allowed_transition(prior.state, status.state) {
                    return Err(CiReducerError::IllegalTransition);
                }
            }
        }
        let first = stream[0];
        let last = stream[stream.len() - 1];
        histories.insert(
            key,
            JobHistory {
                request_event_id: first.request_event_id.clone(),
                job_id: first.job_id.clone(),
                parent_attempt: first.parent_attempt,
                also_reruns: first.also_reruns.clone(),
                terminal_state: last.state,
            },
        );
    }
    Ok(histories)
}

fn same_immutable_coordinates(left: &CiRequestEnvelope, right: &CiRequestEnvelope) -> bool {
    left.run_id == right.run_id
        && left.target_repo_a == right.target_repo_a
        && left.pr_root_event_id == right.pr_root_event_id
        && left.pr_update_event_id == right.pr_update_event_id
        && left.source_clone_url == right.source_clone_url
        && left.immutable_source_ref == right.immutable_source_ref
        && left.tip_oid == right.tip_oid
        && left.source_branch == right.source_branch
        && left.base_ref == right.base_ref
        && left.base_oid == right.base_oid
        && left.workflow_id == right.workflow_id
        && left.workflow_digest == right.workflow_digest
        && left.trigger_event_id == right.trigger_event_id
}

fn status_matches_request(status: &CiJobStatusEnvelope, request: &CiRequestEnvelope) -> bool {
    status.run_id == request.run_id
        && status.workflow_id == request.workflow_id
        && status.target_repo_a == request.target_repo_a
        && status.tip_oid == request.tip_oid
        && status.base_oid == request.base_oid
}

fn same_manifest(left: &CiJobStatusEnvelope, right: &CiJobStatusEnvelope) -> bool {
    left.request_event_id == right.request_event_id
        && left.run_id == right.run_id
        && left.workflow_id == right.workflow_id
        && left.target_repo_a == right.target_repo_a
        && left.tip_oid == right.tip_oid
        && left.base_oid == right.base_oid
        && left.job_id == right.job_id
        && left.name == right.name
        && left.attempt == right.attempt
        && left.parent_attempt == right.parent_attempt
        && left.required == right.required
        && left.skip_policy == right.skip_policy
        && left.selected_job_instance == right.selected_job_instance
        && left.also_reruns == right.also_reruns
        && left.relay_signer == right.relay_signer
}

const fn allowed_transition(previous: CiJobState, next: CiJobState) -> bool {
    matches!(
        (previous, next),
        (
            CiJobState::Queued,
            CiJobState::Running | CiJobState::Cancelled
        ) | (
            CiJobState::Running,
            CiJobState::Success
                | CiJobState::Failure
                | CiJobState::Cancelled
                | CiJobState::TimedOut
                | CiJobState::Skipped
        )
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use buzz_core::ci::{
        job_status_tags, request_tags, CiJobState, CiJobStatusEnvelope, CiRequestEnvelope,
        CiRequestType, CiSkipPolicy, CiTeardownAttestationEnvelope, CiTeardownLease,
        CI_SCHEMA_VERSION,
    };
    use buzz_core::kind::{KIND_CI_JOB_STATUS, KIND_CI_REQUEST};
    use nostr::{EventBuilder, Keys, Kind};

    use super::{
        reduce_selected_job_attempts, reduce_signed_ci_graph, validate_teardown_selected_graph,
        AcceptedCiRequest, CiReducerError, SignedCiGraphInput,
    };

    fn request_event_id() -> String {
        "77".repeat(32)
    }

    fn run_request() -> CiRequestEnvelope {
        CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "11".repeat(32)),
            pr_root_event_id: "22".repeat(32),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/repo".to_string(),
            immutable_source_ref: "refs/nostr/source".to_string(),
            tip_oid: "33".repeat(20),
            source_branch: "feature".to_string(),
            base_ref: "refs/heads/main".to_string(),
            base_oid: "44".repeat(20),
            workflow_id: "ci".to_string(),
            workflow_digest: "55".repeat(32),
            job_ids: vec!["lint".to_string(), "test".to_string()],
            run_id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "22".repeat(32),
            actor: "66".repeat(32),
            timeout_seconds: 300,
            idempotency_key: "123e4567-e89b-12d3-a456-426614174001".to_string(),
            issued_at: 10,
            expires_at: 20,
        }
    }

    fn rerun_request(request: &CiRequestEnvelope, job_id: &str, attempt: u32) -> CiRequestEnvelope {
        let mut rerun = request.clone();
        rerun.request_type = CiRequestType::Rerun;
        rerun.job_ids = vec![job_id.to_string()];
        rerun.attempt = attempt;
        rerun.parent_attempt = Some(attempt - 1);
        rerun.parent_run_id = Some(rerun.run_id.clone());
        rerun.idempotency_key = format!("rerun-{job_id}-{attempt}");
        rerun
    }

    fn job_status(
        request: &CiRequestEnvelope,
        request_id: &str,
        job_id: &str,
        sequence: u64,
        state: CiJobState,
    ) -> CiJobStatusEnvelope {
        let terminal = state.is_terminal();
        CiJobStatusEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_id.to_string(),
            run_id: request.run_id.clone(),
            workflow_id: request.workflow_id.clone(),
            target_repo_a: request.target_repo_a.clone(),
            tip_oid: request.tip_oid.clone(),
            base_oid: request.base_oid.clone(),
            job_id: job_id.to_string(),
            name: job_id.to_string(),
            attempt: request.attempt,
            parent_attempt: request.parent_attempt,
            sequence,
            state,
            conclusion: terminal.then(|| match state {
                CiJobState::Failure => "failure".to_string(),
                _ => "success".to_string(),
            }),
            reason: None,
            required: true,
            skip_policy: CiSkipPolicy::Forbid,
            selected_job_instance: job_id.to_string(),
            also_reruns: Vec::new(),
            started_at: (sequence >= 2).then_some(11),
            finished_at: terminal.then_some(12),
            log_ref: terminal.then(|| "88".repeat(32)),
            artifact_refs: Vec::new(),
            relay_signer: "99".repeat(32),
        }
    }

    fn history(
        request: &CiRequestEnvelope,
        request_id: &str,
        job_id: &str,
        terminal: CiJobState,
    ) -> Vec<CiJobStatusEnvelope> {
        vec![
            job_status(request, request_id, job_id, 1, CiJobState::Queued),
            job_status(request, request_id, job_id, 2, CiJobState::Running),
            job_status(request, request_id, job_id, 3, terminal),
        ]
    }

    fn accepted(event_id: String, envelope: CiRequestEnvelope) -> AcceptedCiRequest {
        AcceptedCiRequest { event_id, envelope }
    }

    fn teardown(
        request: &CiRequestEnvelope,
        leases: Vec<CiTeardownLease>,
    ) -> CiTeardownAttestationEnvelope {
        CiTeardownAttestationEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: request_event_id(),
            run_id: request.run_id.clone(),
            workflow_id: request.workflow_id.clone(),
            target_repo_a: request.target_repo_a.clone(),
            tip_oid: request.tip_oid.clone(),
            base_oid: request.base_oid.clone(),
            workflow_digest: request.workflow_digest.clone(),
            attempt: leases.iter().map(|lease| lease.attempt).max().unwrap_or(0),
            leases,
            lease_empty: true,
            teardown_at: 13,
            relay_signer: "99".repeat(32),
        }
    }

    #[test]
    fn derives_sorted_attempt_one_graph() {
        let request = run_request();
        let statuses = history(&request, &request_event_id(), "lint", CiJobState::Success)
            .into_iter()
            .chain(history(
                &request,
                &request_event_id(),
                "test",
                CiJobState::Failure,
            ))
            .collect::<Vec<_>>();
        let graph =
            reduce_selected_job_attempts(&[accepted(request_event_id(), request)], &statuses)
                .expect("graph");
        assert_eq!(
            graph.selected_job_attempts,
            vec![("lint".to_string(), 1), ("test".to_string(), 1)]
        );
        assert_eq!(graph.attempt, 1);
    }

    #[test]
    fn signed_entrypoint_verifies_events_and_owner_signer_set() {
        let channel = "46bba699-8251-43c7-943e-66be58376585";
        let actor = Keys::generate();
        let control = Keys::generate();
        let mut request = run_request();
        request.actor = actor.public_key().to_hex();
        let request_event = EventBuilder::new(
            Kind::Custom(KIND_CI_REQUEST as u16),
            serde_json::to_string(&request).expect("serialize request"),
        )
        .tags(request_tags(channel, &request).expect("request tags"))
        .sign_with_keys(&actor)
        .expect("sign request");
        let request_id = request_event.id.to_hex();

        let status_events = ["lint", "test"]
            .into_iter()
            .flat_map(|job_id| {
                history(&request, &request_id, job_id, CiJobState::Success)
                    .into_iter()
                    .map(|mut status| {
                        status.relay_signer = control.public_key().to_hex();
                        EventBuilder::new(
                            Kind::Custom(KIND_CI_JOB_STATUS as u16),
                            serde_json::to_string(&status).expect("serialize status"),
                        )
                        .tags(job_status_tags(channel, &status).expect("status tags"))
                        .sign_with_keys(&control)
                        .expect("sign status")
                    })
            })
            .collect::<Vec<_>>();
        let mut input = SignedCiGraphInput {
            channel_id: channel.to_string(),
            authorized_status_signers: HashSet::from([control.public_key().to_hex()]),
            request_events: vec![request_event],
            job_status_events: status_events,
        };

        let graph = reduce_signed_ci_graph(&input).expect("signed graph");
        assert_eq!(
            graph.selected_job_attempts,
            vec![("lint".to_string(), 1), ("test".to_string(), 1)]
        );

        input.authorized_status_signers.clear();
        assert_eq!(
            reduce_signed_ci_graph(&input),
            Err(CiReducerError::EmptySignerSet)
        );
    }

    #[test]
    fn rerun_advances_selected_job_and_exact_signed_fanout() {
        let request = run_request();
        let rerun = rerun_request(&request, "test", 2);
        let rerun_id = "aa".repeat(32);
        let mut statuses = history(&request, &request_event_id(), "lint", CiJobState::Failure)
            .into_iter()
            .chain(history(
                &request,
                &request_event_id(),
                "test",
                CiJobState::Failure,
            ))
            .collect::<Vec<_>>();
        let mut test_rerun = history(&rerun, &rerun_id, "test", CiJobState::Success);
        for status in &mut test_rerun {
            status.also_reruns = vec!["lint".to_string()];
        }
        let mut lint_rerun = history(&rerun, &rerun_id, "lint", CiJobState::Success);
        for status in &mut lint_rerun {
            status.also_reruns = vec!["test".to_string()];
        }
        statuses.extend(test_rerun);
        statuses.extend(lint_rerun);

        let graph = reduce_selected_job_attempts(
            &[
                accepted(request_event_id(), request),
                accepted(rerun_id, rerun),
            ],
            &statuses,
        )
        .expect("rerun graph");
        assert_eq!(
            graph.selected_job_attempts,
            vec![("lint".to_string(), 2), ("test".to_string(), 2)]
        );
        assert_eq!(graph.attempt, 2);
    }

    #[test]
    fn sequence_gap_fails_closed() {
        let request = run_request();
        let mut statuses = history(&request, &request_event_id(), "lint", CiJobState::Success);
        statuses[1].sequence = 3;
        statuses.extend(history(
            &request,
            &request_event_id(),
            "test",
            CiJobState::Success,
        ));
        assert_eq!(
            reduce_selected_job_attempts(&[accepted(request_event_id(), request)], &statuses,),
            Err(CiReducerError::SequenceGap)
        );
    }

    #[test]
    fn stale_rerun_lineage_fails_closed() {
        let request = run_request();
        let rerun = rerun_request(&request, "test", 2);
        let competing = rerun_request(&request, "test", 2);
        let rerun_id = "aa".repeat(32);
        let competing_id = "bb".repeat(32);
        let mut statuses = history(&request, &request_event_id(), "lint", CiJobState::Success)
            .into_iter()
            .chain(history(
                &request,
                &request_event_id(),
                "test",
                CiJobState::Failure,
            ))
            .collect::<Vec<_>>();
        statuses.extend(history(&rerun, &rerun_id, "test", CiJobState::Failure));
        statuses.extend(history(
            &competing,
            &competing_id,
            "test",
            CiJobState::Success,
        ));
        assert_eq!(
            reduce_selected_job_attempts(
                &[
                    accepted(request_event_id(), request),
                    accepted(rerun_id, rerun),
                    accepted(competing_id, competing),
                ],
                &statuses,
            ),
            Err(CiReducerError::IllegalLineage)
        );
    }

    #[test]
    fn omitted_selected_lease_cannot_satisfy_teardown() {
        let request = run_request();
        let accepted = vec![accepted(request_event_id(), request.clone())];
        let statuses = history(&request, &request_event_id(), "lint", CiJobState::Success)
            .into_iter()
            .chain(history(
                &request,
                &request_event_id(),
                "test",
                CiJobState::Success,
            ))
            .collect::<Vec<_>>();
        let attestation = teardown(
            &request,
            vec![CiTeardownLease {
                job_id: "lint".to_string(),
                attempt: 1,
                lease_id: "lease-lint-1".to_string(),
            }],
        );

        assert_eq!(
            validate_teardown_selected_graph(&accepted, &statuses, &attestation),
            Err(CiReducerError::TeardownGraphMismatch)
        );
    }
}
