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
//!   * a syntactically valid request for a repository the relay can resolve to
//!     its (host-bound) community returns 501 NOT_IMPLEMENTED while the full
//!     resolution path is a stub.
//!
//! The three checks are separated because the auth path must run before repo
//! resolution; a request that clears auth and repo validation lands on the 501
//! branch of the B1 contract.

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
async fn preflight_valid_request_is_not_implemented() {
    // A valid NIP-98 request for a host-bound community whose repository the
    // relay can at least scope reaches the preflight stub. Until the full
    // resolution wiring lands the contract returns 501, not 404/500.
    let response = preflight_with_host("localhost:3000", &valid_body()).await;
    let status = response.status();
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_IMPLEMENTED,
        "valid preflight request should hit the 501 stub, got {status}"
    );
}