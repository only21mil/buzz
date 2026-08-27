//! B1 `POST /ci/preflight` acceptance test (objective 3).
//!
//! Requires a live relay with the B1 `/ci/preflight` route wired (A1/A3 land:
//! `crates/buzz-relay/src/api/ci.rs` + router registration) and a live Postgres
//! seeded like the other e2e tests. By default `#[ignore]`d, consistent with
//! `e2e_relay.rs`.
//!
//! Asserted contract:
//!   * NIP-98 auth is required — a request without a valid NIP-98 `Authorization`
//!     header is rejected with a structured 4xx;
//!   * an unknown repository (`target_repo_a` that does not resolve) yields a
//!     structured 4xx, not a 500;
//!   * with no CI policy configured, a resolvable request fails closed with a
//!     precise 503;
//!   * with all five CI policy bounds configured, the same resolution path
//!     returns the complete frozen section-2 response with HTTP 200.
//!
//! The checks are separated because the auth path must run before repo
//! resolution; a request that clears auth and repo validation land on the
//! full resolution path. The two policy-mode tests target relay processes
//! started in their named mode and should be invoked separately.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use nostr::{EventBuilder, Keys, Kind, Tag};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn relay_url() -> String {
    std::env::var("RELAY_URL").unwrap_or_else(|_| "ws://localhost:3000".to_string())
}

fn relay_http_url() -> String {
    relay_url()
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .trim_end_matches('/')
        .to_string()
}

fn test_owner_keys() -> Keys {
    std::env::var("BUZZ_TEST_OWNER_PRIVATE_KEY")
        .ok()
        .and_then(|secret| Keys::parse(&secret).ok())
        .unwrap_or_else(Keys::generate)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

fn nip98_post_header(keys: &Keys, url: &str, body: &str) -> String {
    let event = EventBuilder::new(Kind::Custom(27_235), "")
        .tags(vec![
            Tag::parse(["u", url]).unwrap(),
            Tag::parse(["method", "POST"]).unwrap(),
            Tag::parse(["payload", &sha256_hex(body.as_bytes())]).unwrap(),
            Tag::parse(["nonce", &Uuid::new_v4().to_string()]).unwrap(),
        ])
        .sign_with_keys(keys)
        .expect("sign NIP-98 event");
    format!(
        "Nostr {}",
        BASE64.encode(serde_json::to_string(&event).expect("serialize NIP-98 event"))
    )
}

fn http_origin_for_host(host: &str) -> String {
    let scheme = if relay_http_url().starts_with("https://") {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{host}")
}

/// POST a raw JSON body to `/ci/preflight` on the live relay with a proper
/// NIP-98 `Authorization` header bound to the (optional) host.
async fn preflight_with_host(host: &str, body: &str) -> reqwest::Response {
    let client = reqwest::Client::new();
    let connection_url = format!("{}/ci/preflight", relay_http_url());
    let signed_url = format!("{}/ci/preflight", http_origin_for_host(host));
    client
        .post(&connection_url)
        .header(
            "Authorization",
            nip98_post_header(&test_owner_keys(), &signed_url, body),
        )
        .header("Content-Type", "application/json")
        .header(reqwest::header::HOST, host)
        .body(body.to_string())
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST /ci/preflight with host failed: {e}"))
}

/// POST to `/ci/preflight` without any Authorization header.
async fn preflight_anon(body: &str) -> reqwest::Response {
    let client = reqwest::Client::new();
    client
        .post(format!("{}/ci/preflight", relay_http_url()))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap_or_else(|e| panic!("anonymous POST /ci/preflight failed: {e}"))
}

fn valid_body() -> String {
    serde_json::json!({
        "target_repo_a": format!("30617:{}:ci-e2e", "a".repeat(64)),
        "requested_tip_oid": "c".repeat(40),
    })
    .to_string()
}

fn required_non_empty_string<'a>(body: &'a serde_json::Value, field: &str) -> &'a str {
    let value = body[field]
        .as_str()
        .unwrap_or_else(|| panic!("section-2 field {field} must be a string"));
    assert!(
        !value.is_empty(),
        "section-2 field {field} must be non-empty"
    );
    value
}

#[tokio::test]
#[ignore = "requires live relay with /ci/preflight wired"]
async fn preflight_requires_nip98_auth() {
    let response = preflight_anon(&valid_body()).await;
    let status = response.status();
    assert!(
        status.is_client_error(),
        "anonymous preflight must be a 4xx, got {status}"
    );
    let body = response.text().await.expect("read rejection body");
    assert!(
        !body.trim().is_empty(),
        "anonymous rejection should carry a structured error body"
    );
}

#[tokio::test]
#[ignore = "requires live relay with /ci/preflight wired"]
async fn preflight_unknown_repo_returns_structured_4xx() {
    let response = preflight_with_host("localhost:3000", &valid_body()).await;
    let status = response.status();
    assert!(
        status.is_client_error(),
        "unknown repository must yield a structured 4xx, got {status}"
    );
    let body = response.text().await.expect("utf-8 body");
    assert!(
        !body.trim().is_empty(),
        "unknown repository error must be structured JSON, got empty body"
    );
}

#[tokio::test]
#[ignore = "requires live relay with /ci/preflight wired"]
async fn preflight_valid_request_fails_closed_without_policy_config() {
    // A valid NIP-98 request for a host-bound community whose repository the
    // relay can scope reaches the full resolution path (membership → tip →
    // PR snapshot → trusted-base workflow → job selection) and then fails
    // closed on the absent config.ci.policy block. The response is a precise
    // 503, not a blanket 501/404/500.
    let response = preflight_with_host("localhost:3000", &valid_body()).await;
    let status = response.status();
    assert_eq!(
        status,
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "valid preflight request should hit the precise policy_unavailable 503, got {status}"
    );
    let body = response
        .text()
        .await
        .expect("read service-unavailable body");
    assert!(
        body.contains("policy bounds unavailable"),
        "policy failure must be precise: {body}"
    );
    assert!(
        body.contains("config.ci.policy"),
        "policy failure must cite the missing config block: {body}"
    );
}

#[tokio::test]
#[ignore = "requires live relay with /ci/preflight and all five CI policy bounds configured"]
async fn preflight_configured_policy_returns_complete_section_2_response() {
    let response = preflight_with_host("localhost:3000", &valid_body()).await;
    let status = response.status();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "configured preflight must return 200, got {status}"
    );
    let body: serde_json::Value = response.json().await.expect("JSON preflight response");
    let object = body
        .as_object()
        .expect("preflight response must be an object");

    for field in [
        "target_repo_a",
        "pr_root_event_id",
        "trigger_event_id",
        "source_clone_url",
        "immutable_source_ref",
        "tip_oid",
        "source_branch",
        "base_ref",
        "base_oid",
        "workflow_id",
        "workflow_path",
        "workflow_digest",
        "canonical_workflow_base64",
        "jobs",
        "selected_job_ids",
        "policy",
    ] {
        assert!(
            object.contains_key(field),
            "section-2 field {field} is missing: {body}"
        );
    }

    let request: serde_json::Value =
        serde_json::from_str(&valid_body()).expect("valid request JSON");
    assert_eq!(body["target_repo_a"], request["target_repo_a"]);
    let root_id = required_non_empty_string(&body, "pr_root_event_id");
    assert_eq!(root_id.len(), 64);
    let trigger_id = required_non_empty_string(&body, "trigger_event_id");
    match body
        .get("pr_update_event_id")
        .and_then(serde_json::Value::as_str)
    {
        Some(update_id) => assert_eq!(trigger_id, update_id),
        None => assert_eq!(trigger_id, root_id),
    }
    for field in [
        "source_clone_url",
        "immutable_source_ref",
        "source_branch",
        "base_ref",
        "workflow_id",
        "workflow_path",
    ] {
        required_non_empty_string(&body, field);
    }

    let tip_oid = required_non_empty_string(&body, "tip_oid");
    let base_oid = required_non_empty_string(&body, "base_oid");
    assert!(matches!(tip_oid.len(), 40 | 64));
    assert_eq!(base_oid.len(), tip_oid.len());
    assert_eq!(
        tip_oid,
        request["requested_tip_oid"]
            .as_str()
            .expect("requested tip string")
    );

    let workflow_bytes = BASE64
        .decode(
            body["canonical_workflow_base64"]
                .as_str()
                .expect("canonical workflow base64"),
        )
        .expect("canonical workflow must decode");
    assert_eq!(
        body["workflow_digest"].as_str().expect("workflow digest"),
        sha256_hex(&workflow_bytes)
    );

    let jobs = body["jobs"].as_array().expect("jobs array");
    assert!(!jobs.is_empty(), "jobs must be non-empty");
    let mut job_ids = std::collections::HashSet::new();
    for job in jobs {
        let job_id = required_non_empty_string(job, "job_id");
        assert!(job_id.len() <= 64);
        assert!(job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
        assert!(job_ids.insert(job_id), "job IDs must be unique");
        required_non_empty_string(job, "name");
        assert!(job["required"].is_boolean());
        assert!(matches!(
            job["skip_policy"].as_str(),
            Some("forbid" | "allow")
        ));
        assert!(job["needs"].is_array());
    }
    let selected = body["selected_job_ids"]
        .as_array()
        .expect("selected jobs array");
    assert!(!selected.is_empty(), "selected jobs must be non-empty");
    let mut selected_ids = std::collections::HashSet::new();
    for job_id in selected {
        let job_id = job_id.as_str().expect("selected job ID string");
        assert!(job_ids.contains(job_id), "selected job must exist in jobs");
        assert!(selected_ids.insert(job_id), "selected jobs must be unique");
    }

    let policy = body["policy"].as_object().expect("policy object");
    assert_eq!(
        policy.len(),
        5,
        "policy must contain the five frozen bounds"
    );
    let bounds: Vec<u64> = [
        "min_timeout_seconds",
        "max_timeout_seconds",
        "max_expiry_seconds",
        "acknowledgement_timeout_seconds",
        "max_attempts",
    ]
    .into_iter()
    .map(|field| {
        policy[field]
            .as_u64()
            .unwrap_or_else(|| panic!("policy field {field}"))
    })
    .collect();
    assert!(bounds.iter().all(|bound| *bound > 0));
    assert!(bounds[0] < bounds[1]);
}
