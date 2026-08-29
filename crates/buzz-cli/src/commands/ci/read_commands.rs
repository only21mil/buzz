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

/// JSON output for `buzz ci status` and the Pending honest report.
#[derive(Debug, Serialize)]
struct StatusOutput {
    run_id: String,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reduction: Option<CiReduction>,
}

pub(super) async fn cmd_status(
    client: &BuzzClient,
    run_id: &str,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    let events =
        super::dispatch::fetch_run_events(client, run_id, trusted, &super::dispatch::STATUS_KINDS)
            .await?;
    let (request_event_id, request, accepted) =
        match super::dispatch::extract_request(&events, trusted) {
            Some(triple) => triple,
            None => {
                return super::dispatch::print_json(&StatusOutput {
                    run_id: run_id.to_owned(),
                    state: "pending".into(),
                    reduction: None,
                });
            }
        };
    let reduction = red::reduce_status(&request_event_id, &request, &accepted, false);
    let state = match reduction.state {
        red::CiReducedState::Pending => "pending",
        red::CiReducedState::Green => "green",
        red::CiReducedState::Red => "red",
        red::CiReducedState::InfrastructureFailure => "infrastructure_failure",
    };
    super::dispatch::print_json(&StatusOutput {
        run_id: run_id.to_owned(),
        state: state.into(),
        reduction: Some(reduction),
    })
}

// ── Verdict ──

pub(super) async fn cmd_verdict(
    client: &BuzzClient,
    run_id: &str,
    expect_sha: &str,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    let events =
        super::dispatch::fetch_run_events(client, run_id, trusted, &super::dispatch::STATUS_KINDS)
            .await?;
    let (request_event_id, request, accepted) =
        match super::dispatch::extract_request(&events, trusted) {
            Some(triple) => triple,
            None => {
                return super::dispatch::print_json(&StatusOutput {
                    run_id: run_id.to_owned(),
                    state: "pending".into(),
                    reduction: None,
                });
            }
        };
    match red::reduce_verdict(&request_event_id, &request, &accepted, expect_sha, false) {
        Ok(reduction) => {
            let state = match reduction.state {
                red::CiReducedState::Pending => "pending",
                red::CiReducedState::Green => "green",
                red::CiReducedState::Red => "red",
                red::CiReducedState::InfrastructureFailure => "infrastructure_failure",
            };
            super::dispatch::print_json(&StatusOutput {
                run_id: run_id.to_owned(),
                state: state.into(),
                reduction: Some(reduction),
            })
        }
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
    let events =
        super::dispatch::fetch_run_events(client, run_id, trusted, &super::dispatch::ALL_CI_KINDS)
            .await?;
    let (request_event_id, request, accepted) =
        match super::dispatch::extract_request(&events, trusted) {
            Some(triple) => triple,
            None => {
                return super::dispatch::print_json(&LogsPendingOutput {
                    run_id: run_id.to_owned(),
                    state: "pending".into(),
                    message: "run has no accepted CI events; logs are not available yet".into(),
                });
            }
        };

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
    event_id: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    timestamp: u64,
}

/// JSON output for a watch exit.
#[derive(Debug, Serialize)]
#[serde(tag = "exit")]
enum WatchExitOutput {
    #[serde(rename = "terminal")]
    Terminal { state: String },
    #[serde(rename = "infrastructure_failure")]
    InfrastructureFailure { reason: String },
}

pub(super) async fn cmd_watch(
    client: &BuzzClient,
    run_id: &str,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    let events =
        super::dispatch::fetch_run_events(client, run_id, trusted, &super::dispatch::ALL_CI_KINDS)
            .await?;
    let (_request_event_id, request, accepted) =
        match super::dispatch::extract_request(&events, trusted) {
            Some(triple) => triple,
            None => {
                // No request event — nothing to watch yet.
                return super::dispatch::print_json(&WatchExitOutput::Terminal {
                    state: "pending".into(),
                });
            }
        };

    // Build watch records from accepted events, synthesizing watch_cursor
    // from created_at since the relay does not assign cursors yet.
    let records: Vec<WatchRecord> = accepted
        .iter()
        .map(|e| build_watch_record(e, &request))
        .collect::<Result<Vec<_>, CliError>>()?;

    let replay_limit = std::num::NonZeroUsize::new(16).expect("nonzero");
    let mut stream = WatchStream::new(&request.run_id, &request.tip_oid, 0, replay_limit);

    let mut last_exit = WatchExitOutput::Terminal {
        state: "pending".into(),
    };

    for record in records {
        for action in stream.consume(record) {
            match action {
                WatchAction::Emit(rec) => {
                    super::dispatch::print_json(&WatchRecordOutput {
                        event_id: rec.event_id,
                        scope: watch_scope_str(rec.scope).into(),
                        job_id: rec.job_id,
                        state: rec.state.map(watch_state_str).map(str::to_owned),
                        timestamp: rec.timestamp,
                    })?;
                }
                WatchAction::RequestReplay(_) => {}
                WatchAction::Exit(exit) => match exit {
                    WatchExit::Terminal { state } => {
                        last_exit = WatchExitOutput::Terminal {
                            state: format!("{state:?}").to_lowercase(),
                        };
                    }
                    WatchExit::InfrastructureFailure(failure) => {
                        last_exit = WatchExitOutput::InfrastructureFailure {
                            reason: format!("{failure:?}"),
                        };
                    }
                },
            }
        }
    }

    super::dispatch::print_json(&last_exit)
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
        ValidatedCiEnvelope::Request(_) => {
            // The request event itself is not a watch record.
            return Err(CliError::Other(
                "request event cannot be converted to a watch record".into(),
            ));
        }
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
