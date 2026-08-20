mod ci;

use axum::http::{Method, StatusCode};
use ci::fixtures::{
    BASE_OID, CANONICAL_WORKFLOW_BASE64, OTHER_TIP_OID, RUN_ID, TIP_OID, WORKFLOW_DIGEST,
    log_reference_event, mixed_attempt_status_events, preflight_response, preflight_tip_mismatch,
    preflight_workflow_digest_mismatch, queued_ack_event, request_content, request_event,
    rerun_request_event, unauthorized_ack_event, watch_page, wrong_request_ack_event,
};
use ci::mock_relay::{ExpectedRequest, MockRelay};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn clap_exposes_the_frozen_ci_v14_grammar() {
    let cases: &[&[&str]] = &[
        &[
            "buzz",
            "ci",
            "run",
            "--repo-owner",
            "aa",
            "--repo-id",
            "buzz",
            "--sha",
            TIP_OID,
            "--workflow",
            "ci",
            "--jobs",
            "lint,test",
            "--help",
        ],
        &["buzz", "ci", "status", "--run", RUN_ID, "--help"],
        &[
            "buzz",
            "ci",
            "logs",
            "--run",
            RUN_ID,
            "--job",
            "test",
            "--attempt",
            "2",
            "--raw",
            "--help",
        ],
        &[
            "buzz", "ci", "rerun", "--run", RUN_ID, "--job", "test", "--help",
        ],
        &[
            "buzz",
            "ci",
            "verdict",
            "--run",
            RUN_ID,
            "--expect-sha",
            TIP_OID,
            "--help",
        ],
        &["buzz", "ci", "watch", "--run", RUN_ID, "--help"],
    ];

    for args in cases {
        assert_eq!(
            buzz_cli::run_from_args(args.iter().copied()).await,
            0,
            "frozen grammar must accept {args:?}"
        );
    }
}

#[tokio::test]
async fn clap_rejects_missing_required_ci_coordinates() {
    for args in [
        vec!["buzz", "ci", "run", "--repo-id", "buzz"],
        vec!["buzz", "ci", "logs", "--run", RUN_ID],
        vec!["buzz", "ci", "rerun", "--job", "test"],
        vec!["buzz", "ci", "verdict", "--run", RUN_ID],
    ] {
        assert_eq!(
            buzz_cli::run_from_args(args.iter().copied()).await,
            1,
            "incomplete grammar must refuse {args:?}"
        );
    }
}

#[test]
fn request_fixture_is_a_byte_stable_signed_kind_46100_event() {
    let first = request_event();
    let second = request_event();

    // BIP-340 signatures may use fresh auxiliary randomness. The signed event
    // identity and every byte submitted to the relay remain stable because a
    // retry reuses one built event rather than signing it again.
    assert_eq!(first.id, second.id);
    assert_eq!(first.pubkey, second.pubkey);
    assert_eq!(first.created_at, second.created_at);
    assert_eq!(first.kind, second.kind);
    assert_eq!(first.tags, second.tags);
    assert_eq!(first.content, second.content);
    assert_eq!(first.kind.as_u16(), 46_100);
    assert_eq!(first.content.as_bytes(), request_content().as_bytes());
    first
        .verify()
        .expect("request fixture signature must verify");
    assert!(first.content.contains("\"schema_version\":1"));
    assert!(!first.content.contains(":null"));
}

#[test]
fn preflight_fixture_binds_trusted_base_workflow_bytes() {
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        CANONICAL_WORKFLOW_BASE64,
    )
    .expect("canonical workflow fixture must decode");
    assert_eq!(hex::encode(Sha256::digest(decoded)), WORKFLOW_DIGEST);

    let response = preflight_response();
    assert_eq!(response["tip_oid"], TIP_OID);
    assert_eq!(response["base_oid"], BASE_OID);
    assert_eq!(response["workflow_digest"], WORKFLOW_DIGEST);
    assert_eq!(
        response["selected_job_ids"],
        serde_json::json!(["lint", "test"])
    );
}

#[test]
fn negative_preflight_fixtures_change_one_trust_binding_each() {
    let valid = preflight_response();
    let tip_mismatch = preflight_tip_mismatch();
    let digest_mismatch = preflight_workflow_digest_mismatch();

    assert_eq!(tip_mismatch["tip_oid"], OTHER_TIP_OID);
    assert_eq!(digest_mismatch["workflow_digest"], "00".repeat(32));

    let mut repaired_tip = tip_mismatch;
    repaired_tip["tip_oid"] = Value::String(TIP_OID.to_owned());
    assert_eq!(repaired_tip, valid);

    let mut repaired_digest = digest_mismatch;
    repaired_digest["workflow_digest"] = Value::String(WORKFLOW_DIGEST.to_owned());
    assert_eq!(repaired_digest, valid);
}

#[test]
fn acknowledgement_negative_fixtures_have_valid_signatures_but_wrong_authority_bindings() {
    let valid = queued_ack_event();
    let wrong_request = wrong_request_ack_event();
    let unauthorized = unauthorized_ack_event();

    valid
        .verify()
        .expect("valid acknowledgement signature must verify");
    wrong_request
        .verify()
        .expect("wrong-request acknowledgement remains cryptographically valid");
    unauthorized
        .verify()
        .expect("unauthorized acknowledgement remains cryptographically valid");
    assert_ne!(wrong_request.id, unauthorized.id);
    assert_ne!(valid.id, wrong_request.id);
    assert_eq!(wrong_request.kind.as_u16(), 46_101);
    assert_eq!(unauthorized.kind.as_u16(), 46_101);
}

#[test]
fn mixed_attempt_fixture_selects_each_jobs_greatest_contiguous_attempt() {
    let events = mixed_attempt_status_events();
    let mut lint_attempts = Vec::new();
    let mut test_attempts = Vec::new();

    for event in events {
        event.verify().expect("job status fixture must verify");
        let content: Value = serde_json::from_str(&event.content).expect("job status content");
        let attempt = content["attempt"].as_u64().expect("attempt number");
        match content["job_id"].as_str().expect("job ID") {
            "lint" => lint_attempts.push(attempt),
            "test" => test_attempts.push(attempt),
            other => panic!("unexpected fixture job {other}"),
        }
    }

    assert_eq!(lint_attempts.into_iter().max(), Some(1));
    assert_eq!(test_attempts.into_iter().max(), Some(2));
}

#[test]
fn log_fixture_supports_default_greatest_attempt_selection() {
    let attempt_one = log_reference_event("test", 1, b"first attempt failed\n");
    let attempt_two = log_reference_event("test", 2, b"second attempt passed\n");
    let selected = [&attempt_one, &attempt_two]
        .into_iter()
        .max_by_key(|event| {
            serde_json::from_str::<Value>(&event.content).expect("log reference content")["attempt"]
                .as_u64()
                .expect("attempt number")
        })
        .expect("one log reference");

    let content: Value = serde_json::from_str(&selected.content).expect("selected log content");
    assert_eq!(content["attempt"], 2);
    assert_eq!(content["truncated"], false);
}

#[test]
fn rerun_fixture_preserves_the_immutable_tuple_and_advances_one_attempt() {
    let original: Value = serde_json::from_str(&request_event().content).expect("request content");
    let rerun_event = rerun_request_event();
    let rerun: Value = serde_json::from_str(&rerun_event.content).expect("rerun content");

    for field in [
        "target_repo_a",
        "pr_root_event_id",
        "pr_update_event_id",
        "source_clone_url",
        "immutable_source_ref",
        "tip_oid",
        "source_branch",
        "base_ref",
        "base_oid",
        "workflow_id",
        "workflow_digest",
        "trigger_event_id",
    ] {
        assert_eq!(rerun[field], original[field], "rerun changed {field}");
    }
    assert_eq!(rerun["run_id"], original["run_id"]);
    assert_eq!(rerun["job_ids"], serde_json::json!(["test"]));
    assert_eq!(rerun["attempt"], 2);
    assert_eq!(rerun["parent_attempt"], 1);
    assert_eq!(rerun["parent_run_id"], RUN_ID);
}

#[test]
fn watch_fixture_uses_durable_contiguous_cursors_not_stream_sequences() {
    let page = watch_page();
    let events = page["events"].as_array().expect("watch events");
    assert_eq!(events[0]["watch_cursor"], 40);
    assert_eq!(events[1]["watch_cursor"], 41);
    assert_eq!(page["next_cursor"], 41);
    assert_eq!(events[0]["scope"], "run");
    assert_eq!(events[1]["scope"], "job");
}

#[tokio::test]
async fn mock_relay_records_raw_retry_bodies_without_normalizing_them() {
    let expected = [
        ExpectedRequest::json(Method::POST, "/events", r#"{"signed":"bytes"}"#)
            .with_status(StatusCode::SERVICE_UNAVAILABLE),
        ExpectedRequest::json(Method::POST, "/events", r#"{"accepted":true}"#),
    ];
    let relay = MockRelay::start(expected).await;
    let client = reqwest::Client::new();
    let body = br#"{"event":"byte-identical"}"#;

    for _ in 0..2 {
        client
            .post(format!("{}/events", relay.base_url()))
            .body(body.as_slice())
            .send()
            .await
            .expect("send mock request");
    }

    relay.assert_finished();
    let recorded = relay.recorded();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0].body, recorded[1].body);
    assert_eq!(recorded[0].path_and_query, "/events");
}
