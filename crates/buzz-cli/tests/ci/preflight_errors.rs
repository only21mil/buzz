//! Exercise the real CLI error renderer and dispatch against recorded HTTP traffic.
use super::ci::fixtures::{
    preflight_response, relay_keys, target_repo_a, BASE_OID, CHANNEL_ID, OWNER_HEX, TIP_OID,
    WORKFLOW_ID,
};
use super::ci::mock_relay::{ExpectedRequest, MockRelay};
use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use std::process::Output;
use tokio::process::Command;

async fn run(relay: &MockRelay) -> Output {
    run_at_url(relay.base_url()).await
}

async fn run_at_url(url: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_buzz"))
        .env_clear()
        // Public fixture key, used only against the loopback mock.
        .env("BUZZ_PRIVATE_KEY", "11".repeat(32))
        .env("BUZZ_RELAY_URL", url)
        .env("BUZZ_CI_CHANNEL", CHANNEL_ID)
        .env("BUZZ_CI_STATUS_SIGNERS", relay_keys().public_key().to_hex())
        .env("BUZZ_TIMEOUT_SECS", "2")
        .args([
            "ci",
            "run",
            "--repo-owner",
            OWNER_HEX,
            "--repo-id",
            "buzz",
            "--sha",
            TIP_OID,
            "--workflow",
            WORKFLOW_ID,
            "--jobs",
            "lint,test",
        ])
        .kill_on_drop(true)
        .output()
        .await
        .expect("run CLI against mock")
}

fn binding() -> String {
    // Struct field order is the preflight wire order, not JSON map order.
    format!(
        "{{\"target_repo_a\":\"{}\",\"requested_tip_oid\":\"{TIP_OID}\",\"workflow_selector\":\"{WORKFLOW_ID}\",\"requested_job_ids\":[\"lint\",\"test\"]}}",
        target_repo_a()
    )
}

fn preflight_message(cause: &str) -> String {
    format!(
        "CI preflight failed before request signing for {}: {cause}",
        binding()
    )
}

fn assert_error(output: &Output, exit: i32, category: &str, message: &str, retryable: bool) {
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    assert!(output.stdout.is_empty(), "refusal must not print success");
    let error: Value = serde_json::from_slice(&output.stderr).expect("exactly one JSON error");
    assert_eq!(
        error,
        json!({"error": category, "message": message, "retryable": retryable})
    );
}

fn assert_preflight_only(relay: &MockRelay, attempts: usize) {
    relay.assert_finished();
    let recorded = relay.recorded();
    assert_eq!(recorded.len(), attempts);
    for request in recorded {
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.path_and_query, "/ci/preflight");
        assert_eq!(request.body, binding().as_bytes());
    }
}

#[tokio::test]
async fn structured_preflight_404_preserves_exact_cause_and_request_before_publication() {
    for cause in [
        format!("source_not_found: no PR snapshot for {} at tip {TIP_OID}", target_repo_a()),
        format!("workflow_not_found: selector {WORKFLOW_ID} does not resolve to the workflow at .github/workflows/ci.yml in trusted base {BASE_OID}"),
    ] {
        let body = json!({"error": cause}).to_string();
        let relay = MockRelay::start([
            ExpectedRequest::json(Method::POST, "/ci/preflight", body.clone())
                .with_status(StatusCode::NOT_FOUND),
        ]).await;
        let output = run(&relay).await;
        assert_error(&output, 2, "relay_error", &preflight_message(&format!("relay error 404: {body}")), false);
        assert_preflight_only(&relay, 1);
    }
}

#[tokio::test]
async fn empty_preflight_404_diagnoses_possible_missing_endpoint_before_publication() {
    let relay =
        MockRelay::start([ExpectedRequest::json(Method::POST, "/ci/preflight", "")
            .with_status(StatusCode::NOT_FOUND)])
        .await;
    assert_error(
        &run(&relay).await,
        4,
        "error",
        &preflight_message(
            "relay returned an empty HTTP 404 for /ci/preflight; the endpoint may be unavailable",
        ),
        false,
    );
    assert_preflight_only(&relay, 1);
}

#[tokio::test]
async fn malformed_and_server_preflight_errors_never_become_selector_refusals() {
    for (status, body, retryable, attempts) in [
        (StatusCode::NOT_FOUND, "<html>not found</html>", false, 1),
        (StatusCode::NOT_FOUND, "{\"error\":", false, 1),
        (StatusCode::NOT_FOUND, "{\"error\":\"\"}", false, 1),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "{\"error\":\"workflow_not_found: spoof\"}",
            false,
            1,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "{\"error\":\"workflow_not_found: spoof\"}",
            true,
            3,
        ),
        (StatusCode::UNAUTHORIZED, "{\"error\":\"denied\"}", false, 1),
    ] {
        let relay = MockRelay::start((0..attempts).map(|_| {
            ExpectedRequest::json(Method::POST, "/ci/preflight", body).with_status(status)
        }))
        .await;
        let (exit, category) = if status == StatusCode::UNAUTHORIZED {
            (3, "auth_error")
        } else {
            (2, "relay_error")
        };
        assert_error(
            &run(&relay).await,
            exit,
            category,
            &preflight_message(&format!("relay error {}: {body}", status.as_u16())),
            retryable,
        );
        assert_preflight_only(&relay, attempts);
    }
}

#[tokio::test]
async fn malformed_successful_preflight_does_not_publish() {
    let relay = MockRelay::start([ExpectedRequest::json(
        Method::POST,
        "/ci/preflight",
        "not JSON",
    )])
    .await;
    let output = run(&relay).await;
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "error");
    assert_eq!(error["retryable"], false);
    assert!(error["message"]
        .as_str()
        .unwrap()
        .starts_with(&preflight_message(
            "failed to parse authenticated POST response:"
        )));
    assert_preflight_only(&relay, 1);
}

#[tokio::test]
async fn submission_404_after_valid_preflight_has_no_preflight_refusal_claim() {
    let body = preflight_response().to_string();
    let relay = MockRelay::start([
        ExpectedRequest::json(Method::POST, "/ci/preflight", body),
        ExpectedRequest::json(
            Method::POST,
            "/events",
            "{\"error\":\"event route absent\"}",
        )
        .with_status(StatusCode::NOT_FOUND),
    ])
    .await;
    assert_error(
        &run(&relay).await,
        2,
        "relay_error",
        "relay error 404: event route absent",
        false,
    );
    relay.assert_finished();
    let recorded = relay.recorded();
    assert_eq!(recorded.len(), 2);
    let published: Value = serde_json::from_slice(&recorded[1].body).unwrap();
    assert_eq!(published["kind"], 46_100);
}

#[tokio::test]
async fn export_404_after_publication_has_no_preflight_refusal_claim() {
    use axum::{routing::post, Json, Router};
    use std::sync::{Arc, Mutex};
    let calls = Arc::new(Mutex::new(Vec::new()));
    let pf_calls = calls.clone();
    let event_calls = calls.clone();
    let export_calls = calls.clone();
    let app = Router::new()
        .route(
            "/ci/preflight",
            post(move || async move {
                pf_calls.lock().unwrap().push("preflight");
                Json(preflight_response())
            }),
        )
        .route(
            "/events",
            post(move |Json(event): Json<Value>| async move {
                assert_eq!(event["kind"], 46_100);
                event_calls.lock().unwrap().push("publication");
                Json(json!({"accepted": true, "event_id": event["id"]}))
            }),
        )
        .fallback(move || async move {
            export_calls.lock().unwrap().push("export");
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "export route absent"})),
            )
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let output = run_at_url(&url).await;
    server.abort();
    assert_error(
        &output,
        2,
        "relay_error",
        "relay error 404: export route absent",
        false,
    );
    assert_eq!(
        *calls.lock().unwrap(),
        ["preflight", "publication", "export"]
    );
}

#[tokio::test]
async fn unreadable_preflight_404_body_is_network_error_not_missing_endpoint() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 4096];
            loop {
                let read = socket.read(&mut buf).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buf[..read]);
                if let Some(end) = request.windows(4).position(|chunk| chunk == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|value| value.parse().unwrap())
                        })
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            assert!(request.starts_with(b"POST /ci/preflight HTTP/1.1\r\n"));
            // An empty body read due to truncation must not be a bare-route 404.
            socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 100\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            socket.shutdown().await.unwrap();
        }
    });
    let output = tokio::time::timeout(std::time::Duration::from_secs(15), run_at_url(&url))
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "network_error");
    assert_eq!(error["retryable"], true);
    assert!(error["message"]
        .as_str()
        .unwrap()
        .starts_with(&preflight_message("network error:")));
    assert!(!error["message"]
        .as_str()
        .unwrap()
        .contains("endpoint may be unavailable"));
}
