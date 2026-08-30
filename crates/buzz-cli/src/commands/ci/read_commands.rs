//! Read-side `buzz ci` subcommands: `status`, `verdict`, `logs`, and `watch`.
//! These commands share trusted-context resolution, relay I/O, and event
//! validation with [`super::dispatch`]; the shared helpers live there and are
//! re-exported here via `pub(super)` visibility.

use buzz_core::ci::ValidatedCiEnvelope;
use serde::Serialize;

use crate::client::BuzzClient;
use crate::commands::ci::evidence as ev;
use crate::commands::ci::reducer::{self as red, AcceptedCiEnvelope, CiReduction};
use crate::commands::ci::run::RunTrustedContext;
use crate::commands::ci::watch::{
    WatchAction, WatchEventState, WatchExit, WatchRecord, WatchScope, WatchStream,
};
use crate::error::CliError;

// ── Status ──

/// Frozen flat JSON output for `buzz ci status`.
#[derive(Debug, Serialize)]
struct StatusOutput {
    run_id: String,
    sha: String,
    attempt: u32,
    state: red::CiReducedState,
    jobs: Vec<red::CiReducedJob>,
}

pub(super) async fn cmd_status(
    client: &BuzzClient,
    run_id: &str,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    let snapshot = super::dispatch::fetch_ci_run_snapshot(client, run_id, trusted).await?;
    let reduction = red::reduce_status(
        &snapshot.request_event_id,
        &snapshot.request,
        &snapshot.accepted,
        false,
    );
    super::dispatch::print_json(&status_output(reduction))
}

// ── Verdict ──

pub(super) async fn cmd_verdict(
    client: &BuzzClient,
    run_id: &str,
    expect_sha: &str,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    let snapshot = super::dispatch::fetch_ci_run_snapshot(client, run_id, trusted).await?;
    match red::reduce_verdict(
        &snapshot.request_event_id,
        &snapshot.request,
        &snapshot.accepted,
        expect_sha,
        false,
    ) {
        Ok(reduction) => super::dispatch::print_json(&verdict_output(reduction)),
        Err(red::CiReducerError::ShaMismatch {
            requested,
            resolved,
        }) => Err(CliError::Usage(
            serde_json::to_string(&serde_json::json!({
                "error": "sha_mismatch",
                "requested": requested,
                "resolved": resolved,
            }))
            .map_err(|e| CliError::Other(format!("failed to serialize verdict error: {e}")))?,
        )),
    }
}

#[derive(Debug, Serialize)]
struct VerdictOutput {
    run_id: String,
    sha: String,
    attempt: u32,
    verdict: red::CiReducedState,
    jobs_terminal: usize,
    jobs_total: usize,
    required_failing: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

fn status_output(reduction: CiReduction) -> StatusOutput {
    StatusOutput {
        run_id: reduction.run_id,
        sha: reduction.sha,
        attempt: reduction.attempt,
        state: reduction.state,
        jobs: reduction.jobs,
    }
}

fn verdict_output(reduction: CiReduction) -> VerdictOutput {
    let reason = (reduction.state == red::CiReducedState::InfrastructureFailure)
        .then_some(reduction.reason)
        .flatten();
    VerdictOutput {
        run_id: reduction.run_id,
        sha: reduction.sha,
        attempt: reduction.attempt,
        verdict: reduction.state,
        jobs_terminal: reduction.jobs_terminal,
        jobs_total: reduction.jobs_total,
        required_failing: reduction.required_failing,
        reason,
    }
}

// ── Logs ──

/// JSON output for `buzz ci logs`.
#[derive(Debug, Serialize)]
struct LogsPendingOutput {
    run_id: String,
    state: String,
    message: String,
}

pub(super) async fn cmd_logs(
    client: &BuzzClient,
    run_id: &str,
    job: &str,
    attempt: Option<u32>,
    raw: bool,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    let snapshot = super::dispatch::fetch_ci_run_snapshot(client, run_id, trusted).await?;
    let request_event_id = snapshot.request_event_id;
    let request = snapshot.request;
    let accepted = snapshot.accepted;

    // Reduce to confirm we have terminal state.
    let reduction = red::reduce_status(&request_event_id, &request, &accepted, false);
    let is_terminal = matches!(
        reduction.state,
        red::CiReducedState::Green
            | red::CiReducedState::Red
            | red::CiReducedState::InfrastructureFailure
    );
    if !is_terminal {
        return super::dispatch::print_json(&LogsPendingOutput {
            run_id: run_id.to_owned(),
            state: "pending".into(),
            message: "run has not reached a terminal state; logs are not available yet".into(),
        });
    }

    // Collect job statuses and log events for the evidence module.
    let statuses: Vec<buzz_core::ci::CiJobStatusEnvelope> = accepted
        .iter()
        .filter_map(|e| match &e.envelope {
            ValidatedCiEnvelope::JobStatus(s) => Some(s.clone()),
            _ => None,
        })
        .collect();
    let log_events: Vec<ev::DurableLogEvent> = accepted
        .iter()
        .filter_map(|e| match &e.envelope {
            ValidatedCiEnvelope::LogReference(l) => Some(ev::DurableLogEvent {
                event_id: e.event_id.clone(),
                envelope: l.clone(),
            }),
            _ => None,
        })
        .collect();

    let selected = ev::select_log(
        &request_event_id,
        &request,
        &statuses,
        &log_events,
        client.relay_url(),
        job,
        attempt,
    )
    .map_err(|e| CliError::Other(format!("failed to select CI log: {e}")))?;

    if let Some(inline) = selected.inline_raw() {
        return output_log(inline.as_bytes(), raw, selected.result());
    }

    if let Some(plan) = selected.fetch_plan() {
        let fetched = client
            .get_authed_bytes_bounded(plan.url(), plan.cap_bytes())
            .await?;
        let response = ev::BufferedLogResponse {
            requested_url: plan.url().to_owned(),
            final_url: fetched.final_url,
            redirects_followed: 0,
            authenticated: true,
            content_length: fetched.content_length,
            body: fetched.body,
        };
        let verified = ev::verify_fetched_log(plan, response)
            .map_err(|e| CliError::Other(format!("CI log evidence mismatch: {e}")))?;
        output_log(verified.as_bytes(), raw, selected.result())
    } else {
        Err(CliError::Other(
            "internal error: selected log has neither inline nor URL source".into(),
        ))
    }
}

fn output_log(bytes: &[u8], raw: bool, result: &ev::LogsResult) -> Result<(), CliError> {
    if raw {
        use std::io::Write;
        std::io::stdout()
            .write_all(bytes)
            .map_err(|e| CliError::Other(format!("failed to write raw log: {e}")))?;
    } else {
        super::dispatch::print_json(result)?;
    }
    Ok(())
}

// ── Watch ──

/// JSON output for one emitted watch record.
#[derive(Debug, Serialize)]
struct WatchRecordOutput {
    run_id: String,
    sha: String,
    attempt: u32,
    watch_cursor: u64,
    event_id: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    timestamp: u64,
}

pub(super) async fn cmd_watch(
    client: &BuzzClient,
    run_id: &str,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    let request = super::dispatch::fetch_ci_run_request(client, run_id, trusted).await?;
    let replay_limit = std::num::NonZeroUsize::new(16)
        .ok_or_else(|| CliError::Other("CI watch replay limit is zero".into()))?;
    let mut stream = WatchStream::new(
        &request.request.run_id,
        &request.request.tip_oid,
        0,
        replay_limit,
    );
    let mut accepted_by_cursor = std::collections::BTreeMap::new();

    loop {
        let checkpoint = stream.last_fully_emitted_cursor();
        let page = match super::dispatch::fetch_ci_run_events_page(
            client, run_id, &request, trusted, checkpoint,
        )
        .await
        {
            Ok((page, _next_cursor)) => page,
            Err(error) if crate::error::is_retryable_error(&error) => {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        if page.is_empty() {
            if checkpoint == 0 {
                return Err(CliError::Other(
                    "CI run history omitted its immutable request".into(),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        for event in &page {
            match accepted_by_cursor.entry(event.watch_cursor) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(event.clone());
                }
                std::collections::btree_map::Entry::Occupied(entry) if entry.get() == event => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(CliError::Other(
                        "CI watch cursor was assigned conflicting events".into(),
                    ));
                }
            }
        }
        let accepted = accepted_by_cursor.values().cloned().collect::<Vec<_>>();
        super::dispatch::validate_ci_request_history(&request, &accepted)?;
        red::validate_accepted_run(&request.request_event_id, &request.request, &accepted)
            .map_err(|reason| CliError::Other(format!("invalid accepted CI history: {reason}")))?;

        for envelope in &page {
            let record = build_watch_record(envelope, &request.request)?;
            for action in stream.consume(record) {
                match action {
                    WatchAction::Emit(rec) => {
                        super::dispatch::print_json(&WatchRecordOutput {
                            run_id: rec.run_id,
                            sha: rec.sha,
                            attempt: rec.attempt,
                            watch_cursor: rec.watch_cursor,
                            event_id: rec.event_id,
                            scope: watch_scope_str(rec.scope).into(),
                            job_id: rec.job_id,
                            state: rec.state.map(watch_state_str).map(str::to_owned),
                            timestamp: rec.timestamp,
                        })?;
                    }
                    WatchAction::RequestReplay(_) => {}
                    WatchAction::Exit(exit) => match exit {
                        WatchExit::Terminal { .. } => return Ok(()),
                        WatchExit::InfrastructureFailure(failure) => {
                            return Err(CliError::Other(format!(
                                "CI watch infrastructure failure: {failure:?}"
                            )));
                        }
                    },
                }
            }
        }
        let _ = stream.replay_finished();
        if stream.last_fully_emitted_cursor() == checkpoint {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

fn watch_scope_str(s: WatchScope) -> &'static str {
    match s {
        WatchScope::Run => "run",
        WatchScope::Job => "job",
        WatchScope::Evidence => "evidence",
        WatchScope::Teardown => "teardown",
    }
}

fn watch_state_str(s: WatchEventState) -> &'static str {
    match s {
        WatchEventState::Queued => "queued",
        WatchEventState::Running => "running",
        WatchEventState::Success => "success",
        WatchEventState::Failure => "failure",
        WatchEventState::Cancelled => "cancelled",
        WatchEventState::TimedOut => "timed_out",
        WatchEventState::Skipped => "skipped",
        WatchEventState::InfrastructureFailure => "infrastructure_failure",
    }
}

/// Build a `WatchRecord` from an accepted CI envelope.
fn build_watch_record(
    envelope: &AcceptedCiEnvelope,
    request: &buzz_core::ci::CiRequestEnvelope,
) -> Result<WatchRecord, CliError> {
    let (scope, job_id, state, attempt, timestamp) = match &envelope.envelope {
        ValidatedCiEnvelope::RunStatus(s) => {
            let state = map_run_state(s.state);
            (
                WatchScope::Run,
                None,
                Some(state),
                s.attempt,
                s.finished_at.unwrap_or(s.started_at.unwrap_or(0)),
            )
        }
        ValidatedCiEnvelope::JobStatus(s) => {
            let state = map_job_state(s.state);
            (
                WatchScope::Job,
                Some(s.job_id.clone()),
                Some(state),
                s.attempt,
                s.finished_at.unwrap_or(s.started_at.unwrap_or(0)),
            )
        }
        ValidatedCiEnvelope::LogReference(l) => (
            WatchScope::Evidence,
            Some(l.job_id.clone()),
            None,
            l.attempt,
            l.created_at,
        ),
        ValidatedCiEnvelope::ArtifactReference(a) => (
            WatchScope::Evidence,
            Some(a.job_id.clone()),
            None,
            a.attempt,
            a.created_at,
        ),
        ValidatedCiEnvelope::EvidenceFinalized(f) => {
            (WatchScope::Evidence, None, None, f.attempt, f.finalized_at)
        }
        ValidatedCiEnvelope::TeardownAttestation(t) => {
            (WatchScope::Teardown, None, None, t.attempt, t.teardown_at)
        }
        ValidatedCiEnvelope::Request(request) => (
            WatchScope::Run,
            None,
            None,
            request.attempt,
            request.issued_at,
        ),
    };
    Ok(WatchRecord {
        run_id: request.run_id.clone(),
        sha: request.tip_oid.clone(),
        attempt: attempt.max(1),
        watch_cursor: envelope.watch_cursor,
        event_id: envelope.event_id.clone(),
        scope,
        job_id,
        state,
        timestamp,
    })
}

fn map_run_state(state: buzz_core::ci::CiRunState) -> WatchEventState {
    use buzz_core::ci::CiRunState;
    use WatchEventState;
    match state {
        CiRunState::Queued => WatchEventState::Queued,
        CiRunState::Running => WatchEventState::Running,
        CiRunState::Success => WatchEventState::Success,
        CiRunState::Failure => WatchEventState::Failure,
        CiRunState::Cancelled => WatchEventState::Cancelled,
        CiRunState::TimedOut => WatchEventState::TimedOut,
        CiRunState::InfrastructureFailure => WatchEventState::InfrastructureFailure,
    }
}

fn map_job_state(state: buzz_core::ci::CiJobState) -> WatchEventState {
    use buzz_core::ci::CiJobState;
    use WatchEventState;
    match state {
        CiJobState::Queued => WatchEventState::Queued,
        CiJobState::Running => WatchEventState::Running,
        CiJobState::Success => WatchEventState::Success,
        CiJobState::Failure => WatchEventState::Failure,
        CiJobState::Cancelled => WatchEventState::Cancelled,
        CiJobState::TimedOut => WatchEventState::TimedOut,
        CiJobState::Skipped => WatchEventState::Skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reduction(state: red::CiReducedState) -> CiReduction {
        CiReduction {
            run_id: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
            sha: "11".repeat(20),
            attempt: 2,
            state,
            jobs: vec![red::CiReducedJob {
                job_id: "test".into(),
                name: Some("Test".into()),
                state: Some(buzz_core::ci::CiJobState::Success),
                required: Some(true),
                started_at: Some(10),
                finished_at: Some(20),
                attempt: 2,
            }],
            jobs_terminal: 1,
            jobs_total: 1,
            required_failing: Vec::new(),
            reason: None,
        }
    }

    #[test]
    fn status_and_verdict_outputs_are_frozen_flat_schemas() {
        let status = serde_json::to_value(status_output(reduction(red::CiReducedState::Green)))
            .expect("serialize status");
        assert_eq!(
            status
                .as_object()
                .expect("status object")
                .keys()
                .collect::<Vec<_>>(),
            vec!["attempt", "jobs", "run_id", "sha", "state"]
        );
        assert!(status.get("reduction").is_none());

        let verdict = serde_json::to_value(verdict_output(reduction(red::CiReducedState::Green)))
            .expect("serialize verdict");
        assert_eq!(
            verdict
                .as_object()
                .expect("verdict object")
                .keys()
                .collect::<Vec<_>>(),
            vec![
                "attempt",
                "jobs_terminal",
                "jobs_total",
                "required_failing",
                "run_id",
                "sha",
                "verdict",
            ]
        );
    }

    #[test]
    fn watch_output_includes_the_real_durable_cursor_coordinates() {
        let output = WatchRecordOutput {
            run_id: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
            sha: "11".repeat(20),
            attempt: 2,
            watch_cursor: 37,
            event_id: "22".repeat(32),
            scope: "job".into(),
            job_id: Some("test".into()),
            state: Some("success".into()),
            timestamp: 20,
        };
        let value = serde_json::to_value(output).expect("serialize watch output");
        assert_eq!(value["watch_cursor"], 37);
        assert_eq!(value["run_id"], "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45");
        assert_eq!(value["attempt"], 2);
        assert_eq!(value["scope"], "job");
    }

    #[test]
    fn verdict_reason_is_frozen_to_infrastructure_failures() {
        let mut failure = reduction(red::CiReducedState::InfrastructureFailure);
        failure.reason = Some("terminal fact deadline expired".into());
        let value = serde_json::to_value(verdict_output(failure)).expect("serialize verdict");
        assert_eq!(value["verdict"], "infrastructure_failure");
        assert_eq!(value["reason"], "terminal fact deadline expired");

        let pending = reduction(red::CiReducedState::Pending);
        let value = serde_json::to_value(verdict_output(pending)).expect("serialize verdict");
        assert!(value.get("reason").is_none());

        let green = reduction(red::CiReducedState::Green);
        let value = serde_json::to_value(verdict_output(green)).expect("serialize verdict");
        assert!(value.get("reason").is_none());
    }

    #[test]
    fn request_envelopes_become_run_scope_watch_records() {
        let request = buzz_core::ci::CiRequestEnvelope {
            schema_version: buzz_core::ci::CI_SCHEMA_VERSION,
            request_type: buzz_core::ci::CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "a".repeat(64)),
            pr_root_event_id: "11".repeat(32),
            pr_update_event_id: None,
            source_clone_url: "https://example.invalid/buzz.git".into(),
            immutable_source_ref: format!("refs/nostr/{}", "11".repeat(32)),
            tip_oid: "22".repeat(20),
            source_branch: "feature/ci".into(),
            base_ref: "refs/heads/main".into(),
            base_oid: "33".repeat(20),
            workflow_id: "ci".into(),
            workflow_digest: "44".repeat(32),
            job_ids: vec!["test".into()],
            run_id: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "11".repeat(32),
            actor: "55".repeat(64),
            timeout_seconds: 300,
            idempotency_key: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd46".into(),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_600,
        };
        let accepted = AcceptedCiEnvelope {
            event_id: "22".repeat(32),
            watch_cursor: 41,
            envelope: ValidatedCiEnvelope::Request(request.clone()),
        };

        let record = build_watch_record(&accepted, &request).expect("run-scope record");
        assert_eq!(record.run_id, request.run_id);
        assert_eq!(record.sha, request.tip_oid);
        assert_eq!(record.attempt, request.attempt);
        assert_eq!(record.timestamp, request.issued_at);
        assert_eq!(record.scope, WatchScope::Run);
        assert_eq!(record.job_id, None);
        assert_eq!(record.state, None);
        assert_eq!(record.watch_cursor, 41);
        assert_eq!(record.event_id, "22".repeat(32));
    }
}
