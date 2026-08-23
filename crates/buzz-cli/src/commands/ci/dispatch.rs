//! Dispatch and CLI-facing wrappers for `buzz ci` subcommands.
//! Wires the parsed [`CiCmd`] to the frozen pure helpers in `run`,
//! `reducer`, `evidence`, and `watch`. Owns trusted-context resolution,
//! relay I/O, event validation, and honest reporting when the relay does
//! not yet expose the CI execution plane.

use std::collections::HashSet;

use buzz_core::ci::validate_signed_ci_event;
use buzz_core::kind::{
    KIND_CI_ARTIFACT_REFERENCE, KIND_CI_EVIDENCE_FINALIZED, KIND_CI_JOB_STATUS,
    KIND_CI_LOG_REFERENCE, KIND_CI_REQUEST, KIND_CI_RUN_STATUS, KIND_CI_TEARDOWN_ATTESTATION,
};
use nostr::Event;
use serde::Serialize;

use crate::client::BuzzClient;
use crate::commands::ci::evidence as ev;
use crate::commands::ci::reducer::AcceptedCiEnvelope;
use crate::commands::ci::run::{RunArgs, RunTrustedContext};
use crate::commands::ci::CiCmd;
use crate::error::CliError;

/// All CI event kinds for broad queries.
pub(super) const ALL_CI_KINDS: [u32; 7] = [
    KIND_CI_REQUEST,
    KIND_CI_RUN_STATUS,
    KIND_CI_JOB_STATUS,
    KIND_CI_LOG_REFERENCE,
    KIND_CI_ARTIFACT_REFERENCE,
    KIND_CI_EVIDENCE_FINALIZED,
    KIND_CI_TEARDOWN_ATTESTATION,
];

/// Status query kinds (request + status + facts, no logs/artifacts).
pub(super) const STATUS_KINDS: [u32; 5] = [
    KIND_CI_REQUEST,
    KIND_CI_RUN_STATUS,
    KIND_CI_JOB_STATUS,
    KIND_CI_EVIDENCE_FINALIZED,
    KIND_CI_TEARDOWN_ATTESTATION,
];

/// Honest message for the missing CI execution plane.
const EXECUTION_PLANE_UNAVAILABLE: &str =
    "CI execution plane unavailable: the relay does not expose the /ci/preflight endpoint. \
     Host backends are missing (canonical() is fail-closed). \
     See issue fedbc43e.";

/// Dispatch a parsed CI subcommand to the appropriate handler.
pub async fn dispatch(cmd: CiCmd, client: &BuzzClient) -> Result<(), CliError> {
    match cmd {
        CiCmd::Run {
            repo_owner,
            repo_id,
            sha,
            workflow,
            jobs,
        } => {
            let trusted = resolve_required_trusted_context()?;
            let args = RunArgs {
                repo_owner,
                repo_id,
                sha,
                workflow,
                jobs: if jobs.is_empty() { None } else { Some(jobs) },
            };
            cmd_run(client, &args, &trusted).await
        }
        CiCmd::Status { run } => {
            let trusted = resolve_optional_trusted_context();
            super::read_commands::cmd_status(client, &run, &trusted).await
        }
        CiCmd::Logs {
            run,
            job,
            attempt,
            raw,
        } => {
            let trusted = resolve_optional_trusted_context();
            super::read_commands::cmd_logs(client, &run, &job, attempt, raw, &trusted).await
        }
        CiCmd::Rerun { run, job } => {
            let trusted = resolve_required_trusted_context()?;
            cmd_rerun(client, &run, &job, &trusted).await
        }
        CiCmd::Verdict { run, expect_sha } => {
            let trusted = resolve_optional_trusted_context();
            super::read_commands::cmd_verdict(client, &run, &expect_sha, &trusted).await
        }
        CiCmd::Watch { run } => {
            let trusted = resolve_optional_trusted_context();
            super::read_commands::cmd_watch(client, &run, &trusted).await
        }
    }
}

// ── Trusted-context resolution ──
/// Resolve the trusted context required for write operations (Run, Rerun).
fn resolve_required_trusted_context() -> Result<RunTrustedContext, CliError> {
    let channel_id = std::env::var("BUZZ_CI_CHANNEL").map_err(|_| {
        CliError::Usage(
            "CI trusted context is required: set BUZZ_CI_CHANNEL to the owner-configured \
             channel UUID (see docs/ci/BUZZ_CI_RELAY_API_CONTRACT.md section 1)"
                .into(),
        )
    })?;
    let signers = parse_status_signers()?;
    Ok(RunTrustedContext {
        channel_id,
        status_signers: signers,
    })
}

/// Resolve the trusted context for read operations (Status, Logs, Verdict, Watch).
/// Best-effort: absent channel/signers means queries return empty (Pending).
fn resolve_optional_trusted_context() -> RunTrustedContext {
    let channel_id = std::env::var("BUZZ_CI_CHANNEL").unwrap_or_default();
    let status_signers = std::env::var("BUZZ_CI_STATUS_SIGNERS")
        .ok()
        .and_then(|raw| parse_signer_list(&raw))
        .unwrap_or_default();
    RunTrustedContext {
        channel_id,
        status_signers,
    }
}

fn parse_status_signers() -> Result<HashSet<String>, CliError> {
    let raw = std::env::var("BUZZ_CI_STATUS_SIGNERS").map_err(|_| {
        CliError::Usage(
            "CI trusted context is required: set BUZZ_CI_STATUS_SIGNERS to a \
             comma-delimited list of authorized status-signer pubkeys"
                .into(),
        )
    })?;
    parse_signer_list(&raw).ok_or_else(|| {
        CliError::Usage(
            "BUZZ_CI_STATUS_SIGNERS must be a non-empty comma-delimited list of \
             64-character lowercase-hex pubkeys"
                .into(),
        )
    })
}

fn parse_signer_list(raw: &str) -> Option<HashSet<String>> {
    let set: HashSet<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if set.is_empty() {
        return None;
    }
    if set.iter().any(|s| {
        s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return None;
    }
    Some(set)
}

// ── Run ──
async fn cmd_run(
    client: &BuzzClient,
    args: &RunArgs,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    match crate::commands::ci::run::cmd_run(client, args, trusted).await {
        Ok(()) => Ok(()),
        Err(CliError::Relay { status: 404, .. }) => {
            Err(CliError::Other(EXECUTION_PLANE_UNAVAILABLE.into()))
        }
        Err(e) => Err(e),
    }
}

// ── Rerun ──

async fn cmd_rerun(
    client: &BuzzClient,
    run_id: &str,
    job: &str,
    trusted: &RunTrustedContext,
) -> Result<(), CliError> {
    let events = fetch_run_events(client, run_id, trusted, &ALL_CI_KINDS).await?;
    let (request_event_id, request, accepted) = match extract_request(&events, trusted) {
        Some(triple) => triple,
        None => {
            return Err(CliError::Other(
                "cannot derive rerun: no accepted CI request event found for this run".into(),
            ));
        }
    };

    let statuses: Vec<buzz_core::ci::CiJobStatusEnvelope> = accepted
        .iter()
        .filter_map(|e| match &e.envelope {
            buzz_core::ci::ValidatedCiEnvelope::JobStatus(s) => Some(s.clone()),
            _ => None,
        })
        .collect();

    let actor = client.keys().public_key().to_hex();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CliError::Other("system clock precedes Unix epoch".into()))?
        .as_secs();
    let parameters = ev::RerunParameters {
        actor,
        timeout_seconds: request.timeout_seconds,
        issued_at: now,
        expires_at: now.saturating_add(request.expires_at.saturating_sub(request.issued_at)),
        max_attempts: 5,
    };

    let plan = ev::derive_rerun_plan(&request_event_id, &request, &statuses, job, parameters)
        .map_err(|e| CliError::Other(format!("failed to derive rerun plan: {e}")))?;

    // Build and sign the rerun request event (kind 46100).
    let content = serde_json::to_string(&plan.request)
        .map_err(|e| CliError::Other(format!("failed to serialize rerun request: {e}")))?;
    let tags = buzz_core::ci::request_tags(&trusted.channel_id, &plan.request)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let event = client.sign_event(
        nostr::EventBuilder::new(nostr::Kind::Custom(KIND_CI_REQUEST as u16), content)
            .tags(tags)
            .custom_created_at(nostr::Timestamp::from(plan.request.issued_at)),
    )?;
    let rerun_event_id = event.id.to_hex();

    // Submit — the relay must accept this rerun request.
    let raw_submit = client.submit_event(event).await?;
    let submit_response: serde_json::Value = serde_json::from_str(&raw_submit)
        .map_err(|e| CliError::Other(format!("invalid event submission response: {e}")))?;
    if !submit_response
        .get("accepted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(CliError::Relay {
            status: 400,
            body: submit_response
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("relay did not accept the rerun request")
                .to_owned(),
        });
    }

    // Wait for the queued job-status acknowledgment (kind 46102).
    // The relay does not emit CI events yet, so this will time out.
    let poll = async {
        loop {
            let filter = serde_json::json!({
                "kinds": [KIND_CI_JOB_STATUS],
                "#e": [&rerun_event_id],
                "#h": [&trusted.channel_id],
            });
            let raw = client.query(&filter).await?;
            let values: Vec<serde_json::Value> = serde_json::from_str(&raw).map_err(|error| {
                CliError::Other(format!("invalid rerun ack query response: {error}"))
            })?;
            for value in &values {
                let event: Event = serde_json::from_value(value.clone()).map_err(|error| {
                    CliError::Other(format!("invalid rerun ack event: {error}"))
                })?;
                let envelope = match validate_signed_ci_event(
                    &event,
                    &trusted.channel_id,
                    &trusted.status_signers,
                ) {
                    Ok(buzz_core::ci::ValidatedCiEnvelope::JobStatus(s)) => s,
                    _ => continue,
                };
                if let Ok(result) = ev::validate_rerun_ack(&plan, &rerun_event_id, &envelope) {
                    return Ok(result);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(request.expires_at.saturating_sub(now).max(1)),
        poll,
    )
    .await;
    match result {
        Ok(Ok(rerun_result)) => print_json(&rerun_result),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            // The ack timed out — likely the relay does not emit CI events.
            Err(CliError::Other(
                "timed out waiting for rerun acknowledgment. \
                 The relay may not support CI event emission yet."
                    .into(),
            ))
        }
    }
}

// ── Shared helpers ──

/// Fetch CI events for a run from the relay via POST /query.
pub(super) async fn fetch_run_events(
    client: &BuzzClient,
    run_id: &str,
    trusted: &RunTrustedContext,
    kinds: &[u32],
) -> Result<Vec<Event>, CliError> {
    if trusted.channel_id.is_empty() {
        // Without a channel we cannot scope the query. Return empty — the
        // caller will report Pending honestly.
        return Ok(Vec::new());
    }
    let kind_array: Vec<serde_json::Value> = kinds.iter().map(|k| serde_json::json!(k)).collect();
    let filter = serde_json::json!({
        "kinds": kind_array,
        "#h": [&trusted.channel_id],
        "#run": [run_id],
    });
    let raw = client.query(&filter).await?;
    let values: Vec<serde_json::Value> = serde_json::from_str(&raw)
        .map_err(|e| CliError::Other(format!("invalid CI query response: {e}")))?;
    let mut events = Vec::with_capacity(values.len());
    for value in values {
        let event: Event = serde_json::from_value(value)
            .map_err(|e| CliError::Other(format!("invalid CI event in query response: {e}")))?;
        events.push(event);
    }
    Ok(events)
}

/// Validate events and extract the request + accepted envelope list.
/// Returns `None` if no valid kind-46100 request is found (report Pending).
pub(super) fn extract_request(
    events: &[Event],
    trusted: &RunTrustedContext,
) -> Option<(
    String,
    buzz_core::ci::CiRequestEnvelope,
    Vec<AcceptedCiEnvelope>,
)> {
    let mut request_event_id = None;
    let mut request_envelope = None;
    let mut accepted = Vec::new();

    for event in events {
        let validated =
            match validate_signed_ci_event(event, &trusted.channel_id, &trusted.status_signers) {
                Ok(v) => v,
                Err(_) => continue,
            };
        let event_id = event.id.to_hex();
        let watch_cursor = event.created_at.as_secs().max(1);

        if let buzz_core::ci::ValidatedCiEnvelope::Request(ref req) = validated {
            if request_event_id.is_some() {
                // Duplicate request — skip.
                continue;
            }
            request_event_id = Some(event_id.clone());
            request_envelope = Some(req.clone());
        }

        accepted.push(AcceptedCiEnvelope {
            event_id: event_id.clone(),
            watch_cursor,
            envelope: validated,
        });
    }

    let request_event_id = request_event_id?;
    let request_envelope = request_envelope?;
    Some((request_event_id, request_envelope, accepted))
}

/// Serialize a value as JSON and print it to stdout.
pub(super) fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    let json = serde_json::to_string(value)
        .map_err(|e| CliError::Other(format!("failed to serialize output: {e}")))?;
    println!("{json}");
    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderMap, Response, StatusCode};
    use axum::Router;
    use nostr::Keys;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    type Handler = Arc<dyn Fn(u32) -> (StatusCode, String) + Send + Sync>;

    struct RelayState {
        preflight: Handler,
        query: Handler,
        pf_ctr: Arc<AtomicU32>,
        qy_ctr: Arc<AtomicU32>,
    }

    async fn mock_relay<F, G>(pf: F, qy: G) -> (String, Arc<AtomicU32>, Arc<AtomicU32>)
    where
        F: Fn(u32) -> (StatusCode, String) + Send + Sync + 'static,
        G: Fn(u32) -> (StatusCode, String) + Send + Sync + 'static,
    {
        let (pf_ctr, qy_ctr) = (Arc::new(AtomicU32::new(0)), Arc::new(AtomicU32::new(0)));
        let app = Router::new()
            .route(
                "/ci/preflight",
                axum::routing::post(
                    |State(st): State<Arc<RelayState>>, _h: HeaderMap, _b: Body| async move {
                        let n = st.pf_ctr.fetch_add(1, Ordering::SeqCst) + 1;
                        let (status, body) = (st.preflight)(n);
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap()
                    },
                ),
            )
            .route(
                "/query",
                axum::routing::post(
                    |State(st): State<Arc<RelayState>>, _h: HeaderMap, _b: Body| async move {
                        let n = st.qy_ctr.fetch_add(1, Ordering::SeqCst) + 1;
                        let (status, body) = (st.query)(n);
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap()
                    },
                ),
            )
            .with_state(Arc::new(RelayState {
                preflight: Arc::new(pf),
                query: Arc::new(qy),
                pf_ctr: pf_ctr.clone(),
                qy_ctr: qy_ctr.clone(),
            }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), pf_ctr, qy_ctr)
    }

    fn test_client(base_url: &str) -> BuzzClient {
        BuzzClient::new(base_url.to_string(), Keys::generate(), None, None).unwrap()
    }

    async fn env_lock<F, Fut>(f: F)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future,
    {
        use tokio::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::const_new(());
        let _guard = LOCK.lock().await;
        f().await;
    }

    const CHANNEL: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const RUN_ID: &str = "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45";
    fn signer() -> String {
        "a".repeat(64)
    }

    fn run_cmd() -> CiCmd {
        CiCmd::Run {
            repo_owner: "a".repeat(64),
            repo_id: "buzz".into(),
            sha: "b".repeat(40),
            workflow: None,
            jobs: vec![],
        }
    }

    /// Run with no trusted context (no BUZZ_CI_CHANNEL) errors with a clear
    /// usage message.
    #[tokio::test]
    async fn run_without_trusted_context_errors() {
        env_lock(|| async {
            std::env::remove_var("BUZZ_CI_CHANNEL");
            std::env::remove_var("BUZZ_CI_STATUS_SIGNERS");
            let (url, _, _) = mock_relay(
                |_| (StatusCode::OK, "{}".into()),
                |_| (StatusCode::OK, "[]".into()),
            )
            .await;
            let err = dispatch(run_cmd(), &test_client(&url)).await.unwrap_err();
            assert!(
                matches!(err, CliError::Usage(ref msg) if msg.contains("BUZZ_CI_CHANNEL")),
                "expected usage error mentioning BUZZ_CI_CHANNEL, got: {err:?}"
            );
        })
        .await;
    }

    /// Run dispatch returns the honest "execution plane unavailable" message
    /// when the relay 404s on preflight.
    #[tokio::test]
    async fn run_dispatch_reports_execution_plane_unavailable_on_404() {
        env_lock(|| async {
            std::env::set_var("BUZZ_CI_CHANNEL", CHANNEL);
            std::env::set_var("BUZZ_CI_STATUS_SIGNERS", signer());
            let (url, pf_ctr, _) = mock_relay(
                |_| (StatusCode::NOT_FOUND, r#"{"error":"not found"}"#.into()),
                |_| (StatusCode::OK, "[]".into()),
            )
            .await;
            let err = dispatch(run_cmd(), &test_client(&url)).await.unwrap_err();
            assert!(pf_ctr.load(Ordering::SeqCst) >= 1, "preflight should have been attempted");
            assert!(
                matches!(err, CliError::Other(ref msg) if msg.contains("execution plane unavailable")),
                "expected honest 'execution plane unavailable' message, got: {err:?}"
            );
            std::env::remove_var("BUZZ_CI_CHANNEL");
            std::env::remove_var("BUZZ_CI_STATUS_SIGNERS");
        })
        .await;
    }

    /// Status on a run with no events returns Pending.
    #[tokio::test]
    async fn status_no_events_returns_pending() {
        env_lock(|| async {
            std::env::set_var("BUZZ_CI_CHANNEL", CHANNEL);
            std::env::set_var("BUZZ_CI_STATUS_SIGNERS", signer());
            let (url, _, qy_ctr) = mock_relay(
                |_| (StatusCode::OK, "{}".into()),
                |_| (StatusCode::OK, "[]".into()),
            )
            .await;
            let cmd = CiCmd::Status { run: RUN_ID.into() };
            let result = dispatch(cmd, &test_client(&url)).await;
            assert!(
                result.is_ok(),
                "status with no events should not error: {result:?}"
            );
            assert!(
                qy_ctr.load(Ordering::SeqCst) >= 1,
                "query should have been attempted"
            );
            std::env::remove_var("BUZZ_CI_CHANNEL");
            std::env::remove_var("BUZZ_CI_STATUS_SIGNERS");
        })
        .await;
    }

    /// Status without a channel configured returns Pending without querying.
    #[tokio::test]
    async fn status_no_channel_returns_pending_without_query() {
        env_lock(|| async {
            std::env::remove_var("BUZZ_CI_CHANNEL");
            std::env::remove_var("BUZZ_CI_STATUS_SIGNERS");
            let (url, _, qy_ctr) = mock_relay(
                |_| (StatusCode::OK, "{}".into()),
                |_| (StatusCode::OK, "[]".into()),
            )
            .await;
            let cmd = CiCmd::Status { run: RUN_ID.into() };
            assert!(dispatch(cmd, &test_client(&url)).await.is_ok());
            assert_eq!(
                qy_ctr.load(Ordering::SeqCst),
                0,
                "no query without a channel"
            );
        })
        .await;
    }
}
