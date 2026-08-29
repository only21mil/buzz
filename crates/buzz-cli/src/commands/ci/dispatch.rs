//! Dispatch and CLI-facing wrappers for `buzz ci` subcommands.
//! Wires the parsed [`CiCmd`] to the frozen pure helpers in `run`,
//! `reducer`, `evidence`, and `watch`. Owns trusted-context resolution,
//! relay I/O, event validation, and honest reporting when the relay does
//! not yet expose the CI execution plane.

use std::collections::HashSet;

use buzz_core::ci::validate_signed_ci_event;
use buzz_core::kind::{KIND_CI_JOB_STATUS, KIND_CI_REQUEST};
use nostr::Event;
use serde::{Deserialize, Serialize};

use crate::client::BuzzClient;
use crate::commands::ci::evidence as ev;
use crate::commands::ci::reducer::AcceptedCiEnvelope;
use crate::commands::ci::run::{RunArgs, RunTrustedContext};
use crate::commands::ci::CiCmd;
use crate::error::CliError;

pub(super) const CI_RUN_EVENT_PAGE_LIMIT: u32 = 1_000;
const MAX_CI_RUN_EVENTS: usize = 10_000;
const MAX_SAFE_CURSOR: u64 = (1_u64 << 53) - 1;

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
            let trusted = resolve_required_trusted_context()?;
            super::read_commands::cmd_status(client, &run, &trusted).await
        }
        CiCmd::Logs {
            run,
            job,
            attempt,
            raw,
        } => {
            let trusted = resolve_required_trusted_context()?;
            super::read_commands::cmd_logs(client, &run, &job, attempt, raw, &trusted).await
        }
        CiCmd::Rerun { run, job } => {
            let trusted = resolve_required_trusted_context()?;
            cmd_rerun(client, &run, &job, &trusted).await
        }
        CiCmd::Verdict { run, expect_sha } => {
            let trusted = resolve_required_trusted_context()?;
            super::read_commands::cmd_verdict(client, &run, &expect_sha, &trusted).await
        }
        CiCmd::Watch { run } => {
            let trusted = resolve_required_trusted_context()?;
            super::read_commands::cmd_watch(client, &run, &trusted).await
        }
    }
}

// ── Trusted-context resolution ──
/// Resolve the trusted channel and signer authority required by every CI operation.
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
    let snapshot = fetch_ci_run_snapshot(client, run_id, trusted).await?;
    let request_event_id = snapshot.request_event_id;
    let request = snapshot.request;
    let accepted = snapshot.accepted;

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CiRunRequestResponse {
    run_id: String,
    request_event_id: String,
    watch_cursor: u64,
    #[serde(rename = "accepted_at")]
    _accepted_at: chrono::DateTime<chrono::Utc>,
    event: Event,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CiRunEventResponse {
    watch_cursor: u64,
    #[serde(rename = "accepted_at")]
    _accepted_at: chrono::DateTime<chrono::Utc>,
    event: Event,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CiRunEventsResponse {
    run_id: String,
    request_event_id: String,
    events: Vec<CiRunEventResponse>,
    next_cursor: u64,
}

/// Signature-verified immutable request identity returned by the relay exporter.
pub(super) struct ValidatedCiRequest {
    pub request_event_id: String,
    pub request: buzz_core::ci::CiRequestEnvelope,
    pub watch_cursor: u64,
}

/// Complete bounded durable run history consumed by status, verdict, logs, and rerun.
pub(super) struct CiRunSnapshot {
    pub request_event_id: String,
    pub request: buzz_core::ci::CiRequestEnvelope,
    pub accepted: Vec<AcceptedCiEnvelope>,
}

/// Resolve and validate the immutable request through the authenticated exporter.
pub(super) async fn fetch_ci_run_request(
    client: &BuzzClient,
    run_id: &str,
    trusted: &RunTrustedContext,
) -> Result<ValidatedCiRequest, CliError> {
    let run_id = canonical_run_id(run_id)?;
    let raw = client
        .get_authed(&format!("/ci/runs/{run_id}/request"))
        .await?;
    let response: CiRunRequestResponse = serde_json::from_str(&raw)
        .map_err(|error| CliError::Other(format!("invalid CI request response: {error}")))?;
    if response.run_id != run_id
        || response.request_event_id != response.event.id.to_hex()
        || !valid_watch_cursor(response.watch_cursor)
    {
        return Err(CliError::Other(
            "CI request exporter returned conflicting identity metadata".into(),
        ));
    }
    let request = match validate_signed_ci_event(
        &response.event,
        &trusted.channel_id,
        &trusted.status_signers,
    )
    .map_err(|error| CliError::Other(format!("invalid signed CI request: {error}")))?
    {
        buzz_core::ci::ValidatedCiEnvelope::Request(request) => request,
        _ => {
            return Err(CliError::Other(
                "CI request exporter returned a non-request event".into(),
            ));
        }
    };
    if request.run_id != run_id {
        return Err(CliError::Other(
            "CI request immutable run ID differs from the requested run".into(),
        ));
    }
    Ok(ValidatedCiRequest {
        request_event_id: response.request_event_id,
        request,
        watch_cursor: response.watch_cursor,
    })
}

/// Fetch and validate one exclusive cursor page from the authenticated exporter.
pub(super) async fn fetch_ci_run_events_page(
    client: &BuzzClient,
    run_id: &str,
    request: &ValidatedCiRequest,
    trusted: &RunTrustedContext,
    after_cursor: u64,
) -> Result<(Vec<AcceptedCiEnvelope>, u64), CliError> {
    let run_id = canonical_run_id(run_id)?;
    if !valid_watch_cursor_or_origin(after_cursor) {
        return Err(CliError::Other("invalid CI watch checkpoint".into()));
    }
    let path =
        format!("/ci/runs/{run_id}/events?after={after_cursor}&limit={CI_RUN_EVENT_PAGE_LIMIT}");
    let raw = client.get_authed(&path).await?;
    let response: CiRunEventsResponse = serde_json::from_str(&raw)
        .map_err(|error| CliError::Other(format!("invalid CI events response: {error}")))?;
    if response.run_id != run_id
        || response.request_event_id != request.request_event_id
        || !valid_watch_cursor_or_origin(response.next_cursor)
    {
        return Err(CliError::Other(
            "CI events exporter returned conflicting page identity".into(),
        ));
    }
    if response.events.len() > CI_RUN_EVENT_PAGE_LIMIT as usize {
        return Err(CliError::Other(
            "CI events exporter exceeded the requested page limit".into(),
        ));
    }

    let mut previous = after_cursor;
    let mut accepted = Vec::with_capacity(response.events.len());
    for stored in response.events {
        if !valid_watch_cursor(stored.watch_cursor) || stored.watch_cursor <= previous {
            return Err(CliError::Other(
                "CI events exporter returned a non-increasing cursor page".into(),
            ));
        }
        previous = stored.watch_cursor;
        let event_id = stored.event.id.to_hex();
        let envelope =
            validate_signed_ci_event(&stored.event, &trusted.channel_id, &trusted.status_signers)
                .map_err(|error| CliError::Other(format!("invalid signed CI event: {error}")))?;
        accepted.push(AcceptedCiEnvelope {
            event_id,
            watch_cursor: stored.watch_cursor,
            envelope,
        });
    }
    let expected_next = accepted
        .last()
        .map_or(after_cursor, |event| event.watch_cursor);
    if response.next_cursor != expected_next {
        return Err(CliError::Other(
            "CI events exporter next cursor does not match the accepted page".into(),
        ));
    }
    Ok((accepted, response.next_cursor))
}

/// Load a complete bounded run history, replaying each page after its durable cursor.
pub(super) async fn fetch_ci_run_snapshot(
    client: &BuzzClient,
    run_id: &str,
    trusted: &RunTrustedContext,
) -> Result<CiRunSnapshot, CliError> {
    let request = fetch_ci_run_request(client, run_id, trusted).await?;
    let mut after_cursor = 0;
    let mut accepted = Vec::new();
    loop {
        let (mut page, next_cursor) =
            fetch_ci_run_events_page(client, run_id, &request, trusted, after_cursor).await?;
        let page_len = page.len();
        if accepted.len().saturating_add(page_len) > MAX_CI_RUN_EVENTS {
            return Err(CliError::Other(
                "CI run history exceeds the bounded reducer window".into(),
            ));
        }
        accepted.append(&mut page);
        after_cursor = next_cursor;
        if page_len < CI_RUN_EVENT_PAGE_LIMIT as usize {
            break;
        }
    }
    validate_ci_request_history(&request, &accepted)?;
    Ok(CiRunSnapshot {
        request_event_id: request.request_event_id,
        request: request.request,
        accepted,
    })
}

/// Require the request endpoint and durable event page to name the same signed request.
pub(super) fn validate_ci_request_history(
    request: &ValidatedCiRequest,
    accepted: &[AcceptedCiEnvelope],
) -> Result<(), CliError> {
    let request_event = accepted
        .iter()
        .find(|event| event.event_id == request.request_event_id)
        .ok_or_else(|| CliError::Other("CI run history omitted its immutable request".into()))?;
    if request_event.watch_cursor != request.watch_cursor
        || request_event.envelope
            != buzz_core::ci::ValidatedCiEnvelope::Request(request.request.clone())
    {
        return Err(CliError::Other(
            "CI request endpoint conflicts with the durable event history".into(),
        ));
    }
    Ok(())
}

fn canonical_run_id(run_id: &str) -> Result<String, CliError> {
    uuid::Uuid::parse_str(run_id)
        .map(|run_id| run_id.to_string())
        .map_err(|_| CliError::Usage("CI run ID must be a UUID".into()))
}

const fn valid_watch_cursor(cursor: u64) -> bool {
    cursor > 0 && cursor <= MAX_SAFE_CURSOR
}

const fn valid_watch_cursor_or_origin(cursor: u64) -> bool {
    cursor <= MAX_SAFE_CURSOR
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

    fn ci_request_fixture() -> (Keys, Event) {
        use buzz_core::ci::{request_tags, CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};

        let keys = Keys::parse(&"11".repeat(32)).unwrap();
        let request = CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", keys.public_key().to_hex()),
            pr_root_event_id: "22".repeat(32),
            pr_update_event_id: None,
            source_clone_url: "https://example.invalid/buzz.git".into(),
            immutable_source_ref: format!("refs/nostr/{}", "22".repeat(32)),
            tip_oid: "33".repeat(20),
            source_branch: "feature/ci".into(),
            base_ref: "refs/heads/main".into(),
            base_oid: "44".repeat(20),
            workflow_id: "ci".into(),
            workflow_digest: "55".repeat(32),
            job_ids: vec!["test".into()],
            run_id: RUN_ID.into(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "22".repeat(32),
            actor: keys.public_key().to_hex(),
            timeout_seconds: 300,
            idempotency_key: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd46".into(),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_600,
        };
        let event = nostr::EventBuilder::new(
            nostr::Kind::Custom(KIND_CI_REQUEST as u16),
            serde_json::to_string(&request).unwrap(),
        )
        .tags(request_tags(CHANNEL, &request).unwrap())
        .custom_created_at(nostr::Timestamp::from(1_700_000_000))
        .sign_with_keys(&keys)
        .unwrap();
        (keys, event)
    }

    async fn mock_ci_exporter(event: &Event, cursor: u64) -> (String, Arc<AtomicU32>) {
        let calls = Arc::new(AtomicU32::new(0));
        let request_body = serde_json::json!({
            "run_id": RUN_ID,
            "request_event_id": event.id.to_hex(),
            "watch_cursor": cursor,
            "accepted_at": "2026-08-29T00:00:00Z",
            "event": event,
        })
        .to_string();
        let events_body = serde_json::json!({
            "run_id": RUN_ID,
            "request_event_id": event.id.to_hex(),
            "events": [{
                "watch_cursor": cursor,
                "accepted_at": "2026-08-29T00:00:00Z",
                "event": event,
            }],
            "next_cursor": cursor,
        })
        .to_string();
        let app = Router::new()
            .route(
                "/ci/runs/{run_id}/request",
                axum::routing::get({
                    let calls = calls.clone();
                    let request_body = request_body.clone();
                    move || {
                        let calls = calls.clone();
                        let request_body = request_body.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            request_body
                        }
                    }
                }),
            )
            .route(
                "/ci/runs/{run_id}/events",
                axum::routing::get({
                    let calls = calls.clone();
                    let events_body = events_body.clone();
                    move || {
                        let calls = calls.clone();
                        let events_body = events_body.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            events_body
                        }
                    }
                }),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), calls)
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

    /// Status consumes the authenticated request and durable event exporters.
    #[tokio::test]
    async fn status_reads_exported_request_and_events() {
        env_lock(|| async {
            let (keys, event) = ci_request_fixture();
            std::env::set_var("BUZZ_CI_CHANNEL", CHANNEL);
            std::env::set_var("BUZZ_CI_STATUS_SIGNERS", keys.public_key().to_hex());
            let (url, calls) = mock_ci_exporter(&event, 37).await;
            let cmd = CiCmd::Status { run: RUN_ID.into() };
            let result = dispatch(cmd, &test_client(&url)).await;
            assert!(
                result.is_ok(),
                "status should reduce the request: {result:?}"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            std::env::remove_var("BUZZ_CI_CHANNEL");
            std::env::remove_var("BUZZ_CI_STATUS_SIGNERS");
        })
        .await;
    }

    /// Status fails closed before I/O when reducer authority is absent.
    #[tokio::test]
    async fn status_without_trusted_context_is_a_usage_error() {
        env_lock(|| async {
            std::env::remove_var("BUZZ_CI_CHANNEL");
            std::env::remove_var("BUZZ_CI_STATUS_SIGNERS");
            let (keys, event) = ci_request_fixture();
            let (url, calls) = mock_ci_exporter(&event, 37).await;
            drop(keys);
            let cmd = CiCmd::Status { run: RUN_ID.into() };
            assert!(matches!(
                dispatch(cmd, &test_client(&url)).await,
                Err(CliError::Usage(_))
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0, "must fail before I/O");
        })
        .await;
    }

    #[tokio::test]
    async fn snapshot_preserves_exported_cursor_not_event_created_at() {
        let (keys, event) = ci_request_fixture();
        let (url, _) = mock_ci_exporter(&event, 37).await;
        let trusted = RunTrustedContext {
            channel_id: CHANNEL.into(),
            status_signers: HashSet::from([keys.public_key().to_hex()]),
        };
        let snapshot = fetch_ci_run_snapshot(&test_client(&url), RUN_ID, &trusted)
            .await
            .unwrap();
        assert_eq!(snapshot.accepted[0].watch_cursor, 37);
        assert_eq!(event.created_at.as_secs(), 1_700_000_000);
    }
}
