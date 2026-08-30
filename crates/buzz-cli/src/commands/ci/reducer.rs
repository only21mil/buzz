//! Pure reduction of validated Buzz CI envelopes into status and verdict state.
//!
//! Signature, tag, signer-set, and relay transport validation belong to the
//! caller. This module performs no I/O. It needs the accepted event ID and the
//! relay-assigned watch cursor because evidence facts name event IDs and the
//! terminal-success rule is defined by relay acceptance order.

use buzz_core::ci::{
    CiArtifactReferenceEnvelope, CiEvidenceFinalizedEnvelope, CiJobState, CiJobStatusEnvelope,
    CiLogReferenceEnvelope, CiRequestEnvelope, CiRunState, CiRunStatusEnvelope, CiSkipPolicy,
    CiTeardownAttestationEnvelope, ValidatedCiEnvelope,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use thiserror::Error;

/// A signature/tag-validated CI envelope with relay acceptance metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedCiEnvelope {
    /// Signed Nostr event ID.
    pub event_id: String,
    /// Durable, run-local relay acceptance order.
    pub watch_cursor: u64,
    /// Envelope returned by `validate_signed_ci_event`.
    pub envelope: ValidatedCiEnvelope,
}

/// Aggregate state shared by `status` and `verdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiReducedState {
    Pending,
    Green,
    Red,
    InfrastructureFailure,
}

/// One selected job attempt in the reduced status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiReducedJob {
    pub job_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<CiJobState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
    pub attempt: u32,
}

/// Deterministic state returned by the reducer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiReduction {
    pub run_id: String,
    pub sha: String,
    pub attempt: u32,
    pub state: CiReducedState,
    pub jobs: Vec<CiReducedJob>,
    pub jobs_terminal: usize,
    pub jobs_total: usize,
    pub required_failing: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A refusal that is separate from the reduced run state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CiReducerError {
    #[error("expected SHA {requested} does not match resolved SHA {resolved}")]
    ShaMismatch { requested: String, resolved: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JobPolicy {
    name: String,
    required: bool,
    skip_policy: CiSkipPolicy,
    selected_job_instance: String,
}

type RunEvent<'a> = (&'a AcceptedCiEnvelope, &'a CiRunStatusEnvelope);
type JobEvent<'a> = (&'a AcceptedCiEnvelope, &'a CiJobStatusEnvelope);

/// Reduce status without network access.
///
/// `fact_deadline_expired` lets the caller turn an otherwise reconcilable
/// missing fact or sequence gap into a terminal infrastructure failure.
pub fn reduce_status(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    events: &[AcceptedCiEnvelope],
    fact_deadline_expired: bool,
) -> CiReduction {
    match reduce_checked(request_event_id, request, events, fact_deadline_expired) {
        Ok(reduction) => reduction,
        Err(reason) => infrastructure_reduction(request, events, reason),
    }
}

/// Reduce a verdict after requiring byte-exact equality with the expected SHA.
pub fn reduce_verdict(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    events: &[AcceptedCiEnvelope],
    expected_sha: &str,
    fact_deadline_expired: bool,
) -> Result<CiReduction, CiReducerError> {
    if expected_sha != request.tip_oid {
        return Err(CiReducerError::ShaMismatch {
            requested: expected_sha.to_owned(),
            resolved: request.tip_oid.clone(),
        });
    }
    Ok(reduce_status(
        request_event_id,
        request,
        events,
        fact_deadline_expired,
    ))
}

/// Validate signatures' already-decoded immutable coordinates and stream history.
pub(super) fn validate_accepted_run(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    events: &[AcceptedCiEnvelope],
) -> Result<(), String> {
    reduce_checked(request_event_id, request, events, false).map(|_| ())
}

fn reduce_checked(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    events: &[AcceptedCiEnvelope],
    fact_deadline_expired: bool,
) -> Result<CiReduction, String> {
    request
        .validate()
        .map_err(|error| format!("invalid verified request: {error}"))?;
    validate_event_id(request_event_id)
        .map_err(|reason| format!("invalid accepted request identity: {reason}"))?;

    let request_jobs: HashSet<&str> = request.job_ids.iter().map(String::as_str).collect();
    let mut run_streams: BTreeMap<u32, Vec<RunEvent<'_>>> = BTreeMap::new();
    let mut job_streams: BTreeMap<(String, u32), Vec<JobEvent<'_>>> = BTreeMap::new();
    let mut logs: HashMap<&str, (&AcceptedCiEnvelope, &CiLogReferenceEnvelope)> = HashMap::new();
    let mut artifacts: HashMap<&str, (&AcceptedCiEnvelope, &CiArtifactReferenceEnvelope)> =
        HashMap::new();
    let mut evidence_facts: Vec<(&AcceptedCiEnvelope, &CiEvidenceFinalizedEnvelope)> = Vec::new();
    let mut teardown_facts: Vec<(&AcceptedCiEnvelope, &CiTeardownAttestationEnvelope)> = Vec::new();
    let mut seen_ids: HashMap<&str, &AcceptedCiEnvelope> = HashMap::new();
    let mut seen_cursors: HashMap<u64, &str> = HashMap::new();

    for event in events {
        validate_event_id(&event.event_id)?;
        if event.watch_cursor == 0 {
            return Err("CI event has zero watch cursor".into());
        }
        if let Some(previous) = seen_ids.get(event.event_id.as_str()) {
            if *previous == event {
                continue;
            }
            return Err(format!(
                "event ID {} has conflicting accepted contents",
                event.event_id
            ));
        }
        if let Some(previous_id) = seen_cursors.insert(event.watch_cursor, &event.event_id) {
            return Err(format!(
                "watch cursor {} is shared by events {} and {}",
                event.watch_cursor, previous_id, event.event_id
            ));
        }
        seen_ids.insert(&event.event_id, event);

        match &event.envelope {
            ValidatedCiEnvelope::Request(candidate) => {
                if event.event_id != request_event_id || candidate != request {
                    return Err("conflicting request appeared in the run event set".into());
                }
            }
            ValidatedCiEnvelope::RunStatus(status) => {
                status
                    .validate()
                    .map_err(|error| format!("invalid run status: {error}"))?;
                validate_run_coordinates(request_event_id, request, status)?;
                if !same_job_set(&request.job_ids, &status.job_ids) {
                    return Err("run status job set differs from the verified request".into());
                }
                run_streams
                    .entry(status.attempt)
                    .or_default()
                    .push((event, status));
            }
            ValidatedCiEnvelope::JobStatus(status) => {
                status
                    .validate()
                    .map_err(|error| format!("invalid job status: {error}"))?;
                validate_job_coordinates(request_event_id, request, status)?;
                if !request_jobs.contains(status.job_id.as_str()) {
                    return Err(format!("job status names unselected job {}", status.job_id));
                }
                job_streams
                    .entry((status.job_id.clone(), status.attempt))
                    .or_default()
                    .push((event, status));
            }
            ValidatedCiEnvelope::LogReference(reference) => {
                reference
                    .validate()
                    .map_err(|error| format!("invalid log reference: {error}"))?;
                validate_reference_coordinates(
                    request_event_id,
                    request,
                    &reference.request_event_id,
                    &reference.run_id,
                    &reference.workflow_id,
                    &reference.target_repo_a,
                    &reference.tip_oid,
                    &reference.job_id,
                )?;
                logs.insert(&event.event_id, (event, reference));
            }
            ValidatedCiEnvelope::ArtifactReference(reference) => {
                reference
                    .validate()
                    .map_err(|error| format!("invalid artifact reference: {error}"))?;
                validate_reference_coordinates(
                    request_event_id,
                    request,
                    &reference.request_event_id,
                    &reference.run_id,
                    &reference.workflow_id,
                    &reference.target_repo_a,
                    &reference.tip_oid,
                    &reference.job_id,
                )?;
                artifacts.insert(&event.event_id, (event, reference));
            }
            ValidatedCiEnvelope::EvidenceFinalized(fact) => {
                fact.validate()
                    .map_err(|error| format!("invalid evidence-finalized fact: {error}"))?;
                validate_fact_coordinates(
                    request_event_id,
                    request,
                    &fact.request_event_id,
                    &fact.run_id,
                    &fact.workflow_id,
                    &fact.target_repo_a,
                    &fact.tip_oid,
                )?;
                evidence_facts.push((event, fact));
            }
            ValidatedCiEnvelope::TeardownAttestation(fact) => {
                fact.validate()
                    .map_err(|error| format!("invalid teardown fact: {error}"))?;
                validate_fact_coordinates(
                    request_event_id,
                    request,
                    &fact.request_event_id,
                    &fact.run_id,
                    &fact.workflow_id,
                    &fact.target_repo_a,
                    &fact.tip_oid,
                )?;
                if fact.base_oid != request.base_oid
                    || fact.workflow_digest != request.workflow_digest
                {
                    return Err("teardown immutable coordinates differ from the request".into());
                }
                teardown_facts.push((event, fact));
            }
        }
    }

    let mut reconciliation_reasons = Vec::new();
    let mut latest_runs: BTreeMap<u32, RunEvent<'_>> = BTreeMap::new();
    for (attempt, stream) in &mut run_streams {
        match reduce_run_stream(stream)? {
            StreamReduction::Complete(latest) => {
                latest_runs.insert(*attempt, latest);
            }
            StreamReduction::Gap(latest) => {
                reconciliation_reasons.push(format!("run attempt {attempt} has a sequence gap"));
                latest_runs.insert(*attempt, latest);
            }
        }
    }

    let mut policies: HashMap<&str, JobPolicy> = HashMap::new();
    let mut latest_jobs: BTreeMap<(String, u32), JobEvent<'_>> = BTreeMap::new();
    for ((job_id, attempt), stream) in &mut job_streams {
        for (_, status) in stream.iter() {
            let policy = JobPolicy {
                name: status.name.clone(),
                required: status.required,
                skip_policy: status.skip_policy,
                selected_job_instance: status.selected_job_instance.clone(),
            };
            match policies.get(job_id.as_str()) {
                Some(previous) if previous != &policy => {
                    return Err(format!(
                        "signed policy changed across status history for job {job_id}"
                    ));
                }
                None => {
                    policies.insert(job_id, policy);
                }
                _ => {}
            }
        }
        match reduce_job_stream(stream)? {
            StreamReduction::Complete(latest) => {
                latest_jobs.insert((job_id.clone(), *attempt), latest);
            }
            StreamReduction::Gap(latest) => {
                reconciliation_reasons
                    .push(format!("job {job_id} attempt {attempt} has a sequence gap"));
                latest_jobs.insert((job_id.clone(), *attempt), latest);
            }
        }
    }

    let mut selected: BTreeMap<String, JobEvent<'_>> = BTreeMap::new();
    for job_id in &request.job_ids {
        let attempts: BTreeSet<u32> = latest_jobs
            .keys()
            .filter_map(|(candidate, attempt)| (candidate == job_id).then_some(*attempt))
            .collect();
        let Some(max_attempt) = attempts.last().copied() else {
            reconciliation_reasons.push(format!("job {job_id} has no accepted status"));
            continue;
        };
        for expected in 1..=max_attempt {
            if !attempts.contains(&expected) {
                reconciliation_reasons.push(format!("job {job_id} is missing attempt {expected}"));
            }
        }
        if let Some(latest) = latest_jobs.get(&(job_id.clone(), max_attempt)) {
            selected.insert(job_id.clone(), *latest);
        }
    }

    for ((job_id, attempt), (_, status)) in &latest_jobs {
        if *attempt == 1 {
            continue;
        }
        for rerun_job in &status.also_reruns {
            if !latest_jobs.contains_key(&(rerun_job.clone(), *attempt)) {
                reconciliation_reasons.push(format!(
                    "job {job_id} attempt {attempt} names missing fan-out job {rerun_job}"
                ));
            }
        }
    }

    let top_attempt = selected
        .values()
        .map(|(_, status)| status.attempt)
        .max()
        .unwrap_or(request.attempt.max(1));
    for expected in 1..=top_attempt {
        if !latest_runs.contains_key(&expected) {
            reconciliation_reasons.push(format!("run is missing attempt {expected}"));
        }
    }
    let current_run = latest_runs.get(&top_attempt).copied();
    let current_terminal = current_run.is_some_and(|(_, run)| run.state.is_terminal());

    let mut jobs = Vec::with_capacity(request.job_ids.len());
    let mut jobs_terminal = 0;
    let mut required_failing = Vec::new();
    for job_id in &request.job_ids {
        let status = selected.get(job_id).map(|(_, status)| *status);
        if status.is_some_and(|status| status.state.is_terminal()) {
            jobs_terminal += 1;
        }
        if let Some(status) = status {
            if status.required && required_job_failed(status) {
                required_failing.push(job_id.clone());
            }
        }
        jobs.push(CiReducedJob {
            job_id: job_id.clone(),
            name: status.map(|value| value.name.clone()),
            state: status.map(|value| value.state),
            required: status.map(|value| value.required),
            started_at: status.and_then(|value| value.started_at),
            finished_at: status.and_then(|value| value.finished_at),
            attempt: status.map_or(1, |value| value.attempt),
        });
    }

    let base = |state, reason| CiReduction {
        run_id: request.run_id.clone(),
        sha: request.tip_oid.clone(),
        attempt: top_attempt,
        state,
        jobs: jobs.clone(),
        jobs_terminal,
        jobs_total: request.job_ids.len(),
        required_failing: required_failing.clone(),
        reason,
    };

    if let Some((_, run)) = current_run {
        if run.state == CiRunState::InfrastructureFailure {
            return Ok(base(
                CiReducedState::InfrastructureFailure,
                Some(
                    run.reason
                        .clone()
                        .unwrap_or_else(|| "runner reported infrastructure failure".into()),
                ),
            ));
        }
    }

    if !reconciliation_reasons.is_empty() {
        let reason = reconciliation_reasons.join("; ");
        return Ok(if current_terminal || fact_deadline_expired {
            base(CiReducedState::InfrastructureFailure, Some(reason))
        } else {
            base(CiReducedState::Pending, Some(reason))
        });
    }

    let all_jobs_terminal = selected.len() == request.job_ids.len()
        && selected
            .values()
            .all(|(_, status)| status.state.is_terminal());
    if !required_failing.is_empty() {
        if current_run.is_some_and(|(_, run)| run.state == CiRunState::Success) {
            return Ok(base(
                CiReducedState::InfrastructureFailure,
                Some("terminal run success contradicts a required job failure".into()),
            ));
        }
        return Ok(base(CiReducedState::Red, None));
    }

    let Some((terminal_event, run)) = current_run else {
        return Ok(base(
            if fact_deadline_expired {
                CiReducedState::InfrastructureFailure
            } else {
                CiReducedState::Pending
            },
            fact_deadline_expired.then(|| "run status deadline expired".into()),
        ));
    };
    match run.state {
        CiRunState::Queued | CiRunState::Running => {
            return Ok(base(
                if fact_deadline_expired {
                    CiReducedState::InfrastructureFailure
                } else {
                    CiReducedState::Pending
                },
                fact_deadline_expired.then(|| "terminal fact deadline expired".into()),
            ));
        }
        CiRunState::Failure | CiRunState::Cancelled | CiRunState::TimedOut => {
            return Ok(base(CiReducedState::Red, None));
        }
        CiRunState::InfrastructureFailure => unreachable!("handled above"),
        CiRunState::Success => {}
    }

    if !all_jobs_terminal {
        return Ok(base(
            CiReducedState::InfrastructureFailure,
            Some("terminal run success is missing terminal job facts".into()),
        ));
    }
    if selected
        .values()
        .any(|(_, status)| status.required && !required_job_good(status))
    {
        return Ok(base(
            CiReducedState::InfrastructureFailure,
            Some("terminal run success has a non-good required job".into()),
        ));
    }

    let selected_graph: Vec<(String, u32)> = request
        .job_ids
        .iter()
        .map(|job_id| {
            let (_, status) = selected
                .get(job_id)
                .expect("all selected jobs checked above");
            (job_id.clone(), status.attempt)
        })
        .collect();
    let required_graph: BTreeMap<&str, u32> = selected
        .iter()
        .filter_map(|(job_id, (_, status))| {
            status.required.then_some((job_id.as_str(), status.attempt))
        })
        .collect();
    if required_graph.is_empty() {
        return Ok(base(
            CiReducedState::InfrastructureFailure,
            Some("successful run has no required job evidence set".into()),
        ));
    }

    let mut matching_evidence = Vec::new();
    let mut malformed_current_evidence = false;
    for (event, fact) in &evidence_facts {
        if fact.attempt != top_attempt {
            continue;
        }
        match evidence_matches(event, fact, &required_graph, &selected, &logs, &artifacts) {
            Ok(true) => matching_evidence.push(*event),
            Ok(false) | Err(_) => malformed_current_evidence = true,
        }
    }
    if matching_evidence.len() > 1 {
        return Ok(base(
            CiReducedState::InfrastructureFailure,
            Some("multiple evidence-finalized facts match the selected graph".into()),
        ));
    }

    let mut matching_teardown = Vec::new();
    let mut malformed_current_teardown = false;
    for (event, fact) in &teardown_facts {
        if fact.attempt != top_attempt {
            continue;
        }
        match fact.validate_context(request_event_id, request, &selected_graph) {
            Ok(()) => matching_teardown.push(*event),
            Err(_) => malformed_current_teardown = true,
        }
    }
    if matching_teardown.len() > 1 {
        return Ok(base(
            CiReducedState::InfrastructureFailure,
            Some("multiple teardown facts match the selected graph".into()),
        ));
    }

    let Some(evidence_event) = matching_evidence.first().copied() else {
        let reason = if malformed_current_evidence {
            "evidence-finalized fact does not link the selected durable evidence"
        } else {
            "terminal run success is missing evidence-finalized fact"
        };
        return Ok(base(
            CiReducedState::InfrastructureFailure,
            Some(reason.into()),
        ));
    };
    let Some(teardown_event) = matching_teardown.first().copied() else {
        let reason = if malformed_current_teardown {
            "teardown fact does not match the selected lease graph"
        } else {
            "terminal run success is missing teardown fact"
        };
        return Ok(base(
            CiReducedState::InfrastructureFailure,
            Some(reason.into()),
        ));
    };
    if evidence_event.watch_cursor >= terminal_event.watch_cursor
        || teardown_event.watch_cursor >= terminal_event.watch_cursor
    {
        return Ok(base(
            CiReducedState::InfrastructureFailure,
            Some("terminal run success was accepted before its terminal facts".into()),
        ));
    }

    Ok(base(CiReducedState::Green, None))
}

enum StreamReduction<T> {
    Complete(T),
    Gap(T),
}

fn reduce_run_stream<'a>(
    stream: &mut Vec<RunEvent<'a>>,
) -> Result<StreamReduction<RunEvent<'a>>, String> {
    stream.sort_by_key(|(_, status)| status.sequence);
    let mut gap = false;
    let mut expected = 1;
    let mut previous: Option<RunEvent<'a>> = None;
    for current in stream.iter().copied() {
        if current.1.sequence < expected {
            return Err(format!(
                "run attempt {} equivocates at sequence {}",
                current.1.attempt, current.1.sequence
            ));
        }
        if current.1.sequence > expected {
            gap = true;
        }
        if current.1.sequence == 1 && current.1.state != CiRunState::Queued {
            return Err(format!(
                "run attempt {} does not begin queued",
                current.1.attempt
            ));
        }
        if let Some(previous) = previous {
            if current.1.sequence == previous.1.sequence + 1 {
                if !previous.1.state.can_transition_to(current.1.state) {
                    return Err(format!(
                        "illegal run transition {:?} to {:?} at attempt {} sequence {}",
                        previous.1.state, current.1.state, current.1.attempt, current.1.sequence
                    ));
                }
                if current.0.watch_cursor <= previous.0.watch_cursor {
                    return Err("run sequence order contradicts relay acceptance order".into());
                }
            }
        }
        expected = current.1.sequence.saturating_add(1);
        previous = Some(current);
    }
    let latest = previous.ok_or_else(|| "empty run stream".to_string())?;
    Ok(if gap {
        StreamReduction::Gap(latest)
    } else {
        StreamReduction::Complete(latest)
    })
}

fn reduce_job_stream<'a>(
    stream: &mut Vec<JobEvent<'a>>,
) -> Result<StreamReduction<JobEvent<'a>>, String> {
    stream.sort_by_key(|(_, status)| status.sequence);
    let mut gap = false;
    let mut expected = 1;
    let mut previous: Option<JobEvent<'a>> = None;
    let mut fanout: Option<&[String]> = None;
    let mut parent_attempt = None;
    for current in stream.iter().copied() {
        if current.1.sequence < expected {
            return Err(format!(
                "job {} attempt {} equivocates at sequence {}",
                current.1.job_id, current.1.attempt, current.1.sequence
            ));
        }
        if current.1.sequence > expected {
            gap = true;
        }
        if current.1.sequence == 1 && current.1.state != CiJobState::Queued {
            return Err(format!(
                "job {} attempt {} does not begin queued",
                current.1.job_id, current.1.attempt
            ));
        }
        if fanout.is_some_and(|value| value != current.1.also_reruns.as_slice())
            || parent_attempt.is_some_and(|value| Some(value) != current.1.parent_attempt)
        {
            return Err(format!(
                "job {} attempt {} changed lineage metadata",
                current.1.job_id, current.1.attempt
            ));
        }
        fanout.get_or_insert(current.1.also_reruns.as_slice());
        if parent_attempt.is_none() {
            parent_attempt = current.1.parent_attempt;
        }
        if let Some(previous) = previous {
            if current.1.sequence == previous.1.sequence + 1 {
                if !previous.1.state.can_transition_to(current.1.state) {
                    return Err(format!(
                        "illegal job transition {:?} to {:?} for {} attempt {} sequence {}",
                        previous.1.state,
                        current.1.state,
                        current.1.job_id,
                        current.1.attempt,
                        current.1.sequence
                    ));
                }
                if current.0.watch_cursor <= previous.0.watch_cursor {
                    return Err("job sequence order contradicts relay acceptance order".into());
                }
            }
        }
        expected = current.1.sequence.saturating_add(1);
        previous = Some(current);
    }
    let latest = previous.ok_or_else(|| "empty job stream".to_string())?;
    Ok(if gap {
        StreamReduction::Gap(latest)
    } else {
        StreamReduction::Complete(latest)
    })
}

fn evidence_matches(
    fact_event: &AcceptedCiEnvelope,
    fact: &CiEvidenceFinalizedEnvelope,
    required_graph: &BTreeMap<&str, u32>,
    selected: &BTreeMap<String, JobEvent<'_>>,
    logs: &HashMap<&str, (&AcceptedCiEnvelope, &CiLogReferenceEnvelope)>,
    artifacts: &HashMap<&str, (&AcceptedCiEnvelope, &CiArtifactReferenceEnvelope)>,
) -> Result<bool, String> {
    let fact_graph: BTreeMap<&str, u32> = fact
        .finalized_job_attempts
        .iter()
        .map(|job| (job.job_id.as_str(), job.attempt))
        .collect();
    if &fact_graph != required_graph || fact_graph.len() != fact.finalized_job_attempts.len() {
        return Ok(false);
    }
    for finalized in &fact.finalized_job_attempts {
        let (_, status) = selected
            .get(&finalized.job_id)
            .ok_or_else(|| "finalized evidence names an unselected job".to_string())?;
        if status.attempt != finalized.attempt
            || status.log_ref.as_deref() != Some(finalized.log_ref.as_str())
            || !same_string_set(&status.artifact_refs, &finalized.artifact_refs)
        {
            return Err(format!(
                "job {} terminal status and finalized evidence disagree",
                finalized.job_id
            ));
        }
        let (log_event, log) = logs
            .get(finalized.log_ref.as_str())
            .ok_or_else(|| format!("missing finalized log event {}", finalized.log_ref))?;
        if log.job_id != finalized.job_id
            || log.attempt != finalized.attempt
            || log_event.watch_cursor >= fact_event.watch_cursor
            || log.created_at >= fact.finalized_at
        {
            return Err(format!(
                "finalized log for job {} is stale or out of order",
                finalized.job_id
            ));
        }
        for artifact_id in &finalized.artifact_refs {
            let (artifact_event, artifact) = artifacts
                .get(artifact_id.as_str())
                .ok_or_else(|| format!("missing finalized artifact event {artifact_id}"))?;
            if artifact.job_id != finalized.job_id
                || artifact.attempt != finalized.attempt
                || artifact_event.watch_cursor >= fact_event.watch_cursor
                || artifact.created_at >= fact.finalized_at
            {
                return Err(format!(
                    "finalized artifact for job {} is stale or out of order",
                    finalized.job_id
                ));
            }
        }
    }
    Ok(true)
}

fn required_job_good(status: &CiJobStatusEnvelope) -> bool {
    matches!(status.state, CiJobState::Success)
        || matches!(
            (status.state, status.skip_policy),
            (CiJobState::Skipped, CiSkipPolicy::Allow)
        )
}

fn required_job_failed(status: &CiJobStatusEnvelope) -> bool {
    status.required
        && (matches!(
            status.state,
            CiJobState::Failure | CiJobState::Cancelled | CiJobState::TimedOut
        ) || matches!(
            (status.state, status.skip_policy),
            (CiJobState::Skipped, CiSkipPolicy::Forbid)
        ))
}

fn validate_run_coordinates(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    status: &CiRunStatusEnvelope,
) -> Result<(), String> {
    if status.request_event_id != request_event_id
        || status.run_id != request.run_id
        || status.workflow_id != request.workflow_id
        || status.target_repo_a != request.target_repo_a
        || status.tip_oid != request.tip_oid
        || status.base_oid != request.base_oid
    {
        return Err("run status immutable coordinates differ from the request".into());
    }
    Ok(())
}

fn validate_job_coordinates(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    status: &CiJobStatusEnvelope,
) -> Result<(), String> {
    if status.request_event_id != request_event_id
        || status.run_id != request.run_id
        || status.workflow_id != request.workflow_id
        || status.target_repo_a != request.target_repo_a
        || status.tip_oid != request.tip_oid
        || status.base_oid != request.base_oid
    {
        return Err("job status immutable coordinates differ from the request".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_reference_coordinates(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    candidate_request_event_id: &str,
    run_id: &str,
    workflow_id: &str,
    target_repo_a: &str,
    tip_oid: &str,
    job_id: &str,
) -> Result<(), String> {
    validate_fact_coordinates(
        request_event_id,
        request,
        candidate_request_event_id,
        run_id,
        workflow_id,
        target_repo_a,
        tip_oid,
    )?;
    if !request.job_ids.iter().any(|candidate| candidate == job_id) {
        return Err(format!("evidence reference names unselected job {job_id}"));
    }
    Ok(())
}

fn validate_fact_coordinates(
    request_event_id: &str,
    request: &CiRequestEnvelope,
    candidate_request_event_id: &str,
    run_id: &str,
    workflow_id: &str,
    target_repo_a: &str,
    tip_oid: &str,
) -> Result<(), String> {
    if candidate_request_event_id != request_event_id
        || run_id != request.run_id
        || workflow_id != request.workflow_id
        || target_repo_a != request.target_repo_a
        || tip_oid != request.tip_oid
    {
        return Err("CI fact immutable coordinates differ from the request".into());
    }
    Ok(())
}

fn validate_event_id(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("invalid lowercase event ID {value}"));
    }
    Ok(())
}

fn same_job_set(left: &[String], right: &[String]) -> bool {
    left.len() == right.len()
        && left.iter().collect::<HashSet<_>>() == right.iter().collect::<HashSet<_>>()
}

fn same_string_set(left: &[String], right: &[String]) -> bool {
    same_job_set(left, right)
}

fn infrastructure_reduction(
    request: &CiRequestEnvelope,
    events: &[AcceptedCiEnvelope],
    reason: String,
) -> CiReduction {
    let attempt = events
        .iter()
        .filter_map(|event| match &event.envelope {
            ValidatedCiEnvelope::RunStatus(status) => Some(status.attempt),
            ValidatedCiEnvelope::JobStatus(status) => Some(status.attempt),
            ValidatedCiEnvelope::EvidenceFinalized(fact) => Some(fact.attempt),
            ValidatedCiEnvelope::TeardownAttestation(fact) => Some(fact.attempt),
            _ => None,
        })
        .max()
        .unwrap_or(request.attempt.max(1));
    CiReduction {
        run_id: request.run_id.clone(),
        sha: request.tip_oid.clone(),
        attempt,
        state: CiReducedState::InfrastructureFailure,
        jobs: request
            .job_ids
            .iter()
            .map(|job_id| CiReducedJob {
                job_id: job_id.clone(),
                name: None,
                state: None,
                required: None,
                started_at: None,
                finished_at: None,
                attempt: 1,
            })
            .collect(),
        jobs_terminal: 0,
        jobs_total: request.job_ids.len(),
        required_failing: Vec::new(),
        reason: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::ci::{CiFinalizedJobAttempt, CiRequestType, CiTeardownLease, CI_SCHEMA_VERSION};

    const REQUEST_ID: u64 = 1;

    fn id(value: u64) -> String {
        format!("{value:064x}")
    }

    fn request() -> CiRequestEnvelope {
        CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "a".repeat(64)),
            pr_root_event_id: "1".repeat(64),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/buzz.git".into(),
            immutable_source_ref: "refs/buzz/pr/1".into(),
            tip_oid: "b".repeat(40),
            source_branch: "feature".into(),
            base_ref: "refs/heads/main".into(),
            base_oid: "c".repeat(40),
            workflow_id: "required-ci".into(),
            workflow_digest: "e".repeat(64),
            job_ids: vec!["lint".into(), "unit".into()],
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "1".repeat(64),
            actor: "f".repeat(64),
            timeout_seconds: 600,
            idempotency_key: "idempotency".into(),
            issued_at: 1,
            expires_at: 601,
        }
    }

    fn accepted(event_id: u64, cursor: u64, envelope: ValidatedCiEnvelope) -> AcceptedCiEnvelope {
        AcceptedCiEnvelope {
            event_id: id(event_id),
            watch_cursor: cursor,
            envelope,
        }
    }

    fn run_status(attempt: u32, sequence: u64, state: CiRunState) -> CiRunStatusEnvelope {
        let request = request();
        CiRunStatusEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: id(REQUEST_ID),
            run_id: request.run_id,
            workflow_id: request.workflow_id,
            target_repo_a: request.target_repo_a,
            tip_oid: request.tip_oid,
            base_oid: request.base_oid,
            attempt,
            sequence,
            state,
            conclusion: state.is_terminal().then(|| format!("{state:?}")),
            reason: None,
            started_at: (state != CiRunState::Queued).then_some(10),
            finished_at: state.is_terminal().then_some(40),
            job_ids: vec!["lint".into(), "unit".into()],
            relay_signer: "d".repeat(64),
        }
    }

    fn job_status(
        job_id: &str,
        attempt: u32,
        sequence: u64,
        state: CiJobState,
        skip_policy: CiSkipPolicy,
        log_ref: Option<String>,
    ) -> CiJobStatusEnvelope {
        let request = request();
        CiJobStatusEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: id(REQUEST_ID),
            run_id: request.run_id,
            workflow_id: request.workflow_id,
            target_repo_a: request.target_repo_a,
            tip_oid: request.tip_oid,
            base_oid: request.base_oid,
            job_id: job_id.into(),
            name: job_id.into(),
            attempt,
            parent_attempt: (attempt > 1).then_some(attempt - 1),
            sequence,
            state,
            conclusion: state.is_terminal().then(|| format!("{state:?}")),
            reason: None,
            required: true,
            skip_policy,
            selected_job_instance: job_id.into(),
            also_reruns: Vec::new(),
            started_at: (state != CiJobState::Queued).then_some(10),
            finished_at: state.is_terminal().then_some(20),
            log_ref,
            artifact_refs: Vec::new(),
            relay_signer: "d".repeat(64),
        }
    }

    fn log_reference(job_id: &str, attempt: u32) -> CiLogReferenceEnvelope {
        let request = request();
        CiLogReferenceEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: id(REQUEST_ID),
            run_id: request.run_id,
            workflow_id: request.workflow_id,
            target_repo_a: request.target_repo_a,
            tip_oid: request.tip_oid,
            job_id: job_id.into(),
            attempt,
            log_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            byte_length: 0,
            cap_bytes: 1024,
            truncated: false,
            url: None,
            inline: Some(String::new()),
            created_at: 21,
            relay_signer: "d".repeat(64),
        }
    }

    fn green_events(
        unit_attempt: u32,
        unit_state: CiJobState,
        policy: CiSkipPolicy,
    ) -> Vec<AcceptedCiEnvelope> {
        let mut events = Vec::new();
        let mut cursor = 1;
        let mut event_id = 100;
        macro_rules! push {
            ($envelope:expr) => {{
                events.push(accepted(event_id, cursor, $envelope));
                event_id += 1;
                cursor += 1;
            }};
        }

        for attempt in 1..=unit_attempt {
            push!(ValidatedCiEnvelope::RunStatus(run_status(
                attempt,
                1,
                CiRunState::Queued,
            )));
            push!(ValidatedCiEnvelope::RunStatus(run_status(
                attempt,
                2,
                CiRunState::Running,
            )));
            if attempt < unit_attempt {
                push!(ValidatedCiEnvelope::RunStatus(run_status(
                    attempt,
                    3,
                    CiRunState::Failure,
                )));
            }
        }
        for job_id in ["lint", "unit"] {
            let max_attempt = if job_id == "unit" { unit_attempt } else { 1 };
            for attempt in 1..=max_attempt {
                push!(ValidatedCiEnvelope::JobStatus(job_status(
                    job_id,
                    attempt,
                    1,
                    CiJobState::Queued,
                    policy,
                    None,
                )));
                push!(ValidatedCiEnvelope::JobStatus(job_status(
                    job_id,
                    attempt,
                    2,
                    CiJobState::Running,
                    policy,
                    None,
                )));
                let terminal = if job_id == "unit" && attempt < max_attempt {
                    CiJobState::Failure
                } else if job_id == "unit" {
                    unit_state
                } else {
                    CiJobState::Success
                };
                let log_id = id(if job_id == "lint" {
                    20
                } else {
                    20 + attempt as u64
                });
                push!(ValidatedCiEnvelope::JobStatus(job_status(
                    job_id,
                    attempt,
                    3,
                    terminal,
                    policy,
                    terminal
                        .is_terminal()
                        .then_some(log_id)
                        .filter(|_| attempt == max_attempt),
                )));
            }
        }

        push!(ValidatedCiEnvelope::LogReference(log_reference("lint", 1)));
        events.last_mut().unwrap().event_id = id(20);
        push!(ValidatedCiEnvelope::LogReference(log_reference(
            "unit",
            unit_attempt,
        )));
        events.last_mut().unwrap().event_id = id(20 + unit_attempt as u64);

        let evidence = CiEvidenceFinalizedEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: id(REQUEST_ID),
            run_id: request().run_id,
            workflow_id: request().workflow_id,
            target_repo_a: request().target_repo_a,
            tip_oid: request().tip_oid,
            attempt: unit_attempt,
            finalized_job_attempts: vec![
                CiFinalizedJobAttempt {
                    job_id: "lint".into(),
                    attempt: 1,
                    log_ref: id(20),
                    artifact_refs: Vec::new(),
                },
                CiFinalizedJobAttempt {
                    job_id: "unit".into(),
                    attempt: unit_attempt,
                    log_ref: id(20 + unit_attempt as u64),
                    artifact_refs: Vec::new(),
                },
            ],
            finalized_at: 30,
            relay_signer: "d".repeat(64),
        };
        push!(ValidatedCiEnvelope::EvidenceFinalized(evidence));
        let teardown = CiTeardownAttestationEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_event_id: id(REQUEST_ID),
            run_id: request().run_id,
            workflow_id: request().workflow_id,
            target_repo_a: request().target_repo_a,
            tip_oid: request().tip_oid,
            base_oid: request().base_oid,
            workflow_digest: request().workflow_digest,
            attempt: unit_attempt,
            leases: vec![
                CiTeardownLease {
                    job_id: "lint".into(),
                    attempt: 1,
                    lease_id: "lease-lint".into(),
                },
                CiTeardownLease {
                    job_id: "unit".into(),
                    attempt: unit_attempt,
                    lease_id: format!("lease-unit-{unit_attempt}"),
                },
            ],
            lease_empty: true,
            teardown_at: 31,
            relay_signer: "d".repeat(64),
        };
        push!(ValidatedCiEnvelope::TeardownAttestation(teardown));
        push!(ValidatedCiEnvelope::RunStatus(run_status(
            unit_attempt,
            3,
            if unit_state == CiJobState::Skipped && policy == CiSkipPolicy::Forbid {
                CiRunState::Failure
            } else {
                CiRunState::Success
            },
        )));
        let _ = (event_id, cursor);
        events
    }

    fn reduce(events: &[AcceptedCiEnvelope]) -> CiReduction {
        reduce_status(&id(REQUEST_ID), &request(), events, false)
    }

    #[test]
    fn complete_success_is_green() {
        let result = reduce(&green_events(1, CiJobState::Success, CiSkipPolicy::Forbid));
        assert_eq!(result.state, CiReducedState::Green, "{result:?}");
        assert_eq!(result.jobs_terminal, 2);
        assert_eq!(result.attempt, 1);
    }

    #[test]
    fn required_code_failure_is_red() {
        let mut events = green_events(1, CiJobState::Failure, CiSkipPolicy::Forbid);
        events.retain(|event| {
            !matches!(
                event.envelope,
                ValidatedCiEnvelope::EvidenceFinalized(_)
                    | ValidatedCiEnvelope::TeardownAttestation(_)
            )
        });
        if let Some(ValidatedCiEnvelope::RunStatus(run)) =
            events.last_mut().map(|event| &mut event.envelope)
        {
            run.state = CiRunState::Failure;
            run.conclusion = Some("Failure".into());
        }
        let result = reduce(&events);
        assert_eq!(result.state, CiReducedState::Red);
        assert_eq!(result.required_failing, vec!["unit"]);
    }

    #[test]
    fn nonterminal_work_is_pending() {
        let mut events = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);
        events.retain(|event| {
            !matches!(
                event.envelope,
                ValidatedCiEnvelope::EvidenceFinalized(_)
                    | ValidatedCiEnvelope::TeardownAttestation(_)
            ) && !matches!(
                &event.envelope,
                ValidatedCiEnvelope::RunStatus(run) if run.state == CiRunState::Success
            )
        });
        assert_eq!(reduce(&events).state, CiReducedState::Pending);
    }

    #[test]
    fn skipped_required_job_obeys_signed_policy() {
        let allowed = reduce(&green_events(1, CiJobState::Skipped, CiSkipPolicy::Allow));
        assert_eq!(allowed.state, CiReducedState::Green);

        let forbidden = reduce(&green_events(1, CiJobState::Skipped, CiSkipPolicy::Forbid));
        assert_eq!(forbidden.state, CiReducedState::Red);
        assert_eq!(forbidden.required_failing, vec!["unit"]);
    }

    #[test]
    fn sequence_gap_is_pending_until_terminal_then_infrastructure_failure() {
        let mut events = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);
        events.retain(|event| {
            !matches!(
                &event.envelope,
                ValidatedCiEnvelope::JobStatus(job)
                    if job.job_id == "unit" && job.sequence == 2
            )
        });
        assert_eq!(reduce(&events).state, CiReducedState::InfrastructureFailure);

        events.retain(|event| {
            !matches!(
                &event.envelope,
                ValidatedCiEnvelope::RunStatus(run) if run.state == CiRunState::Success
            )
        });
        assert_eq!(reduce(&events).state, CiReducedState::Pending);
    }

    #[test]
    fn mixed_attempts_select_each_jobs_greatest_contiguous_attempt() {
        let result = reduce(&green_events(2, CiJobState::Success, CiSkipPolicy::Forbid));
        assert_eq!(result.state, CiReducedState::Green);
        assert_eq!(result.attempt, 2);
        assert_eq!(result.jobs[0].attempt, 1);
        assert_eq!(result.jobs[1].attempt, 2);
    }

    #[test]
    fn missing_or_stale_terminal_facts_fail_success_closed() {
        let mut missing = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);
        missing
            .retain(|event| !matches!(event.envelope, ValidatedCiEnvelope::EvidenceFinalized(_)));
        assert_eq!(
            reduce(&missing).state,
            CiReducedState::InfrastructureFailure
        );

        let mut stale = green_events(2, CiJobState::Success, CiSkipPolicy::Forbid);
        for event in &mut stale {
            if let ValidatedCiEnvelope::EvidenceFinalized(fact) = &mut event.envelope {
                fact.finalized_job_attempts[1].attempt = 1;
            }
        }
        assert_eq!(reduce(&stale).state, CiReducedState::InfrastructureFailure);
    }

    #[test]
    fn missing_or_extra_lease_never_satisfies_green() {
        let mut missing = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);
        for event in &mut missing {
            if let ValidatedCiEnvelope::TeardownAttestation(fact) = &mut event.envelope {
                fact.leases.pop();
            }
        }
        assert_eq!(
            reduce(&missing).state,
            CiReducedState::InfrastructureFailure
        );

        let mut extra = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);
        for event in &mut extra {
            if let ValidatedCiEnvelope::TeardownAttestation(fact) = &mut event.envelope {
                fact.leases.push(CiTeardownLease {
                    job_id: "unit_extra".into(),
                    attempt: 1,
                    lease_id: "lease-extra".into(),
                });
            }
        }
        assert_eq!(reduce(&extra).state, CiReducedState::InfrastructureFailure);
    }

    #[test]
    fn terminal_success_must_follow_both_terminal_facts() {
        let mut events = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);
        let terminal_cursor = events
            .iter()
            .find_map(|event| match &event.envelope {
                ValidatedCiEnvelope::RunStatus(run) if run.state == CiRunState::Success => {
                    Some(event.watch_cursor)
                }
                _ => None,
            })
            .unwrap();
        for event in &mut events {
            if matches!(event.envelope, ValidatedCiEnvelope::EvidenceFinalized(_)) {
                event.watch_cursor = terminal_cursor + 1;
            }
        }
        assert_eq!(reduce(&events).state, CiReducedState::InfrastructureFailure);
    }

    #[test]
    fn verdict_refuses_sha_mismatch_before_reduction() {
        let error =
            reduce_verdict(&id(REQUEST_ID), &request(), &[], &"a".repeat(40), false).unwrap_err();
        assert!(matches!(error, CiReducerError::ShaMismatch { .. }));
    }

    #[test]
    fn same_stream_sequence_with_different_events_is_equivocation() {
        let mut events = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);
        let original = events
            .iter()
            .find(|event| {
                matches!(
                    &event.envelope,
                    ValidatedCiEnvelope::RunStatus(run) if run.sequence == 1
                )
            })
            .unwrap()
            .clone();
        let mut conflicting = original;
        conflicting.event_id = id(999);
        conflicting.watch_cursor = 999;
        if let ValidatedCiEnvelope::RunStatus(run) = &mut conflicting.envelope {
            run.reason = Some("conflict".into());
        }
        events.push(conflicting);
        assert_eq!(reduce(&events).state, CiReducedState::InfrastructureFailure);
    }

    #[test]
    fn immutable_coordinate_mismatch_is_infrastructure_failure() {
        let mut events = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);
        if let ValidatedCiEnvelope::JobStatus(job) = &mut events[2].envelope {
            job.tip_oid = "a".repeat(40);
        }
        assert_eq!(reduce(&events).state, CiReducedState::InfrastructureFailure);
    }

    #[test]
    fn finalized_fact_must_link_existing_selected_log_event() {
        let mut events = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);
        events.retain(|event| event.event_id != id(20));
        assert_eq!(reduce(&events).state, CiReducedState::InfrastructureFailure);
    }

    #[test]
    fn accepted_run_validation_accepts_a_consistent_history() {
        let events = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);
        validate_accepted_run(&id(REQUEST_ID), &request(), &events)
            .expect("a consistent stream must validate");
    }

    #[test]
    fn accepted_run_validation_rejects_conflicting_requests_and_cursor_collisions() {
        let events = green_events(1, CiJobState::Success, CiSkipPolicy::Forbid);

        let mut conflicting = events.clone();
        conflicting.push(accepted(999, 999, ValidatedCiEnvelope::Request(request())));
        let reason = validate_accepted_run(&id(REQUEST_ID), &request(), &conflicting)
            .expect_err("a second request event must fail validation");
        assert!(reason.contains("conflicting request"));

        let mut colliding = events.clone();
        colliding.push(accepted(
            999,
            colliding[0].watch_cursor,
            ValidatedCiEnvelope::JobStatus(job_status(
                "lint",
                1,
                3,
                CiJobState::Success,
                CiSkipPolicy::Forbid,
                None,
            )),
        ));
        let reason = validate_accepted_run(&id(REQUEST_ID), &request(), &colliding)
            .expect_err("a shared watch cursor must fail validation");
        assert!(reason.contains("is shared by events"), "{reason}");
    }
}
