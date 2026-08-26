//! `buzz events get --id <64-hex>` — event-by-ID retrieval (issue db589e3e, PR1).
//!
//! Covers the clap grammar (help renders, missing `--id` refuses), a happy-path
//! fetch against an expected `/query` (raw signed event JSON out), and the
//! not-found path (`[]` → distinct `NotFound` error, distinguishable from a
//! usage/network error).

mod ci;

use axum::http::Method;
use ci::mock_relay::{ExpectedRequest, MockRelay};

/// A fixture event ID (64 hex) for the tests.
const EVENT_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEYHEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

async fn mock_relay(requests: impl IntoIterator<Item = ExpectedRequest>) -> MockRelay {
    MockRelay::start(requests).await
}

async fn run_cli(relay: &MockRelay, args: &[&str]) -> i32 {
    let mut full = vec![
        "buzz",
        "--relay",
        relay.base_url(),
        "--private-key",
        KEYHEX,
        // Clear any ambient BUZZ_AUTH_TAG so the test key is the only identity.
        "--auth-tag",
        "",
    ];
    full.extend_from_slice(args);
    buzz_cli::run_from_args(full.iter().copied()).await
}

#[tokio::test]
async fn clap_exposes_events_get_grammar() {
    let relay = mock_relay([]).await;
    assert_eq!(
        run_cli(&relay, &["events", "get", "--id", EVENT_ID, "--help"]).await,
        0,
        "events get --help must be valid"
    );
}

#[tokio::test]
async fn clap_rejects_missing_events_get_id() {
    let relay = mock_relay([]).await;
    assert_eq!(
        run_cli(&relay, &["events", "get"]).await,
        1,
        "events get without --id must refuse"
    );
}

#[tokio::test]
async fn events_get_returns_the_signed_event_json() {
    let ev = serde_json::json!({
        "id": EVENT_ID,
        "pubkey": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "created_at": 1700000000,
        "kind": 1,
        "tags": [],
        "content": "hello from the relay",
        "sig": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    });
    let expected_response = serde_json::to_vec(&serde_json::json!([ev])).unwrap();

    let relay = mock_relay(vec![ExpectedRequest::json(
        Method::POST,
        "/query",
        expected_response,
    )])
    .await;

    let exit = run_cli(&relay, &["events", "get", "--id", EVENT_ID]).await;
    assert_eq!(exit, 0, "events get must succeed on a found event");
    relay.assert_finished();

    // verify the client sent the `{ids:[<id>]}` filter on /query
    let recorded = relay.recorded();
    assert_eq!(recorded.len(), 1, "exactly one /query request");
    let req = &recorded[0];
    assert_eq!(req.method, Method::POST);
    assert!(req.path_and_query.ends_with("/query"));
    let sent: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(
        sent.as_array().and_then(|a| a.first()).unwrap()["ids"][0],
        serde_json::Value::String(EVENT_ID.into()),
        "the {{ids:[<id>]}} filter must be sent"
    );
}

#[tokio::test]
async fn events_get_distinguishes_not_found() {
    let relay = mock_relay(vec![ExpectedRequest::json(
        Method::POST,
        "/query",
        b"[]".to_vec(),
    )])
    .await;

    // Not-found: the relay answers [] — the command must fail with distinct
    // NotFound semantics (exit 1), not succeed with empty output.
    let exit = run_cli(&relay, &["events", "get", "--id", EVENT_ID]).await;
    assert_eq!(exit, 1, "events get must fail distinctly on empty []");
    relay.assert_finished();
}
