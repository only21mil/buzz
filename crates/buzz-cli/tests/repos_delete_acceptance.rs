//! Live acceptance tests for deleting NIP-34 repository announcements.
//!
//! These tests exercise the public `buzz repos` CLI against a running relay.
//! They are ignored by default because they require that relay:
//!
//! ```text
//! RELAY_URL=ws://localhost:3000 \
//!   cargo test -p buzz-cli --test repos_delete_acceptance -- --ignored --nocapture
//! ```

use std::process::{Command, Output};

use buzz_test_client::BuzzTestClient;
use nostr::{EventBuilder, Keys, Kind, Tag};
use serde_json::Value;

const REPO_ANNOUNCEMENT_KIND: u16 = 30617;

fn relay_ws_url() -> String {
    std::env::var("RELAY_URL").unwrap_or_else(|_| "ws://localhost:3000".to_string())
}

fn relay_http_url() -> String {
    std::env::var("RELAY_HTTP_URL").unwrap_or_else(|_| {
        relay_ws_url()
            .replacen("ws://", "http://", 1)
            .replacen("wss://", "https://", 1)
    })
}

fn unique_repo_id(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn run_buzz(keys: &Keys, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_buzz"))
        .args(args)
        .env("BUZZ_RELAY_URL", relay_http_url())
        .env("BUZZ_PRIVATE_KEY", keys.secret_key().to_secret_hex())
        .env_remove("BUZZ_AUTH_TAG")
        .output()
        .expect("run buzz CLI")
}

fn output_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn listed_repo_ids(output: &Output) -> Vec<String> {
    assert!(
        output.status.success(),
        "repos list failed: stdout={} stderr={}",
        output_text(&output.stdout),
        output_text(&output.stderr)
    );
    let events: Vec<Value> =
        serde_json::from_slice(&output.stdout).expect("repos list must return a JSON array");
    events
        .iter()
        .filter_map(|event| event.get("tags")?.as_array())
        .filter_map(|tags| {
            tags.iter().find_map(|tag| {
                let values = tag.as_array()?;
                (values.first()?.as_str()? == "d")
                    .then(|| values.get(1)?.as_str().map(str::to_owned))
                    .flatten()
            })
        })
        .collect()
}

async fn announce_repo(keys: &Keys, repo_id: &str) {
    install_crypto_provider();
    let event = EventBuilder::new(Kind::Custom(REPO_ANNOUNCEMENT_KIND), "")
        .tags(vec![
            Tag::parse(["d", repo_id]).expect("d tag"),
            Tag::parse(["name", repo_id]).expect("name tag"),
        ])
        .sign_with_keys(keys)
        .expect("sign repository announcement");
    let mut client = BuzzTestClient::connect(&relay_ws_url(), keys)
        .await
        .expect("connect to relay");
    let response = client
        .send_event(event)
        .await
        .expect("publish repository announcement");
    assert!(
        response.accepted,
        "relay rejected repository announcement: {}",
        response.message
    );
    client.disconnect().await.expect("disconnect from relay");
}

async fn cleanup_repo(keys: &Keys, repo_id: &str) {
    install_crypto_provider();
    let coordinate = format!(
        "{REPO_ANNOUNCEMENT_KIND}:{}:{repo_id}",
        keys.public_key().to_hex()
    );
    let event = EventBuilder::new(Kind::EventDeletion, "")
        .tags(vec![Tag::parse(["a", coordinate.as_str()]).expect("a tag")])
        .sign_with_keys(keys)
        .expect("sign cleanup deletion");
    let mut client = BuzzTestClient::connect(&relay_ws_url(), keys)
        .await
        .expect("connect for cleanup");
    client
        .send_event(event)
        .await
        .expect("publish cleanup deletion");
    // Cleanup is best-effort. After an authoritative CLI deletion, a newly
    // signed second tombstone correctly returns repo-delete:not-found.
    client.disconnect().await.expect("disconnect after cleanup");
}

fn list_repos(caller: &Keys, owner: &Keys) -> Output {
    let owner_hex = owner.public_key().to_hex();
    run_buzz(caller, &["repos", "list", "--owner", &owner_hex])
}

#[tokio::test]
#[ignore = "requires a running Buzz relay"]
async fn owner_delete_removes_repository_from_repos_list() {
    let owner = Keys::generate();
    let repo_id = unique_repo_id("delete-owner");
    announce_repo(&owner, &repo_id).await;

    assert!(
        listed_repo_ids(&list_repos(&owner, &owner)).contains(&repo_id),
        "precondition: owner must see the repository before deletion"
    );

    let deletion = run_buzz(&owner, &["repos", "delete", "--id", &repo_id]);
    let deletion_response: Result<Value, _> = serde_json::from_slice(&deletion.stdout);
    let repository_absent = deletion.status.success()
        && !listed_repo_ids(&list_repos(&owner, &owner)).contains(&repo_id);
    cleanup_repo(&owner, &repo_id).await;

    assert!(
        deletion.status.success(),
        "owner deletion failed: stdout={} stderr={}",
        output_text(&deletion.stdout),
        output_text(&deletion.stderr)
    );
    let deletion_response = deletion_response.expect("owner deletion must return relay JSON");
    assert_eq!(deletion_response["accepted"], true);
    assert_eq!(deletion_response["message"], "repo-delete:deleted");
    assert!(
        repository_absent,
        "deleted repository must disappear from repos list"
    );
}

#[tokio::test]
#[ignore = "requires a running Buzz relay"]
async fn non_owner_delete_is_rejected_and_repository_remains_listed() {
    let owner = Keys::generate();
    let non_owner = Keys::generate();
    let repo_id = unique_repo_id("delete-non-owner");
    announce_repo(&owner, &repo_id).await;

    let deletion = run_buzz(&non_owner, &["repos", "delete", "--id", &repo_id]);
    let rejection: Result<Value, _> = serde_json::from_slice(&deletion.stderr);
    let repository_survived = listed_repo_ids(&list_repos(&non_owner, &owner)).contains(&repo_id);
    cleanup_repo(&owner, &repo_id).await;

    assert_eq!(
        deletion.status.code(),
        Some(1),
        "non-owner deletion must be a user/not-found error: stdout={} stderr={}",
        output_text(&deletion.stdout),
        output_text(&deletion.stderr)
    );
    let error = rejection.expect("non-owner rejection must use the CLI JSON error contract");
    assert_eq!(error["error"], "not_found");
    assert!(
        repository_survived,
        "a non-owner delete attempt must not remove the owner's repository"
    );
}
