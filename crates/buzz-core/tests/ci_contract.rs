use buzz_core::{
    ci::{
        request_tags, validate_request_tags, CiJobState, CiLogReferenceEnvelope, CiRequestEnvelope,
        CiRequestType, CiRunState, CiSkipPolicy, CI_PROTOCOL_CONTRACT_SHA256, CI_SCHEMA_VERSION,
    },
    kind::{
        is_workflow_execution_kind, KIND_CI_ARTIFACT_REFERENCE, KIND_CI_JOB_STATUS,
        KIND_CI_LOG_REFERENCE, KIND_CI_REQUEST, KIND_CI_RUN_STATUS,
    },
};

fn valid_run_request() -> CiRequestEnvelope {
    CiRequestEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_type: CiRequestType::Run,
        target_repo_a: format!("30617:{}:buzz", "a".repeat(64)),
        pr_root_event_id: "b".repeat(64),
        pr_update_event_id: None,
        source_clone_url: "https://example.test/repo.git".into(),
        immutable_source_ref: format!("refs/nostr/{}", "b".repeat(64)),
        tip_oid: "c".repeat(40),
        source_branch: "feature/ci".into(),
        base_ref: "refs/heads/main".into(),
        base_oid: "d".repeat(40),
        workflow_id: "ci".into(),
        workflow_digest: "e".repeat(64),
        job_ids: vec!["rust_lint".into()],
        run_id: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
        attempt: 1,
        parent_attempt: None,
        parent_run_id: None,
        trigger_event_id: "f".repeat(64),
        actor: "1".repeat(64),
        timeout_seconds: 900,
        idempotency_key: "run-018f47a2".into(),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_300,
    }
}

#[test]
fn ci_kinds_are_dedicated_and_outside_workflow_lifecycle() {
    assert_eq!(
        CI_PROTOCOL_CONTRACT_SHA256,
        "50bb013fe1af573a000ba8c47eb9d0a42be69ab2dde2a5a0b1c12afe81e501fe"
    );
    assert_eq!(KIND_CI_REQUEST, 46100);
    assert_eq!(KIND_CI_RUN_STATUS, 46101);
    assert_eq!(KIND_CI_JOB_STATUS, 46102);
    assert_eq!(KIND_CI_LOG_REFERENCE, 46103);
    assert_eq!(KIND_CI_ARTIFACT_REFERENCE, 46104);

    for kind in 46100..=46104 {
        assert!(!is_workflow_execution_kind(kind));
    }
}

#[test]
fn closed_states_use_the_frozen_wire_names() {
    let job_states = [
        (CiJobState::Queued, "\"queued\""),
        (CiJobState::Running, "\"running\""),
        (CiJobState::Success, "\"success\""),
        (CiJobState::Failure, "\"failure\""),
        (CiJobState::Cancelled, "\"cancelled\""),
        (CiJobState::TimedOut, "\"timed_out\""),
        (CiJobState::Skipped, "\"skipped\""),
    ];
    for (state, wire) in job_states {
        assert_eq!(serde_json::to_string(&state).expect("serialize"), wire);
    }

    assert_eq!(
        serde_json::to_string(&CiRunState::InfrastructureFailure).expect("serialize"),
        "\"infrastructure_failure\""
    );
    assert!(serde_json::from_str::<CiRunState>("\"unknown\"").is_err());
    assert_eq!(
        serde_json::to_string(&CiSkipPolicy::Forbid).expect("serialize"),
        "\"forbid\""
    );
    assert_eq!(
        serde_json::to_string(&CiSkipPolicy::Allow).expect("serialize"),
        "\"allow\""
    );
    assert!(serde_json::from_str::<CiSkipPolicy>("\"unknown\"").is_err());
}

#[test]
fn initial_run_request_accepts_only_attempt_one_without_parent() {
    let request = valid_run_request();
    request.validate().expect("valid request");

    let mut bad_attempt = request.clone();
    bad_attempt.attempt = 2;
    assert!(bad_attempt.validate().is_err());

    let mut bad_parent = request;
    bad_parent.parent_attempt = Some(1);
    assert!(bad_parent.validate().is_err());
}

#[test]
fn request_tag_builder_and_validator_bind_every_index() {
    let request = valid_run_request();
    let channel = "46bba699-8251-43c7-943e-66be58376585";
    let tags = request_tags(channel, &request).expect("build request tags");
    validate_request_tags(&tags, channel, &request).expect("tags match request");

    let mut duplicate = tags.clone();
    duplicate.push(duplicate[0].clone());
    assert!(validate_request_tags(&duplicate, channel, &request).is_err());

    let mut changed = request;
    changed.tip_oid = "2".repeat(40);
    assert!(validate_request_tags(&tags, channel, &changed).is_err());
}

#[test]
fn rerun_requires_one_job_and_complete_parent_lineage() {
    let mut request = valid_run_request();
    request.request_type = CiRequestType::Rerun;
    request.attempt = 2;
    request.parent_attempt = Some(1);
    request.parent_run_id = Some(request.run_id.clone());
    request.validate().expect("valid rerun");

    request.job_ids.push("unit_tests".into());
    assert!(request.validate().is_err());
}

#[test]
fn state_transitions_are_closed_and_terminal_states_do_not_move() {
    assert!(CiJobState::Queued.can_transition_to(CiJobState::Running));
    assert!(CiJobState::Running.can_transition_to(CiJobState::TimedOut));
    assert!(!CiJobState::Queued.can_transition_to(CiJobState::Success));
    assert!(!CiJobState::Success.can_transition_to(CiJobState::Running));

    assert!(CiRunState::Queued.can_transition_to(CiRunState::InfrastructureFailure));
    assert!(CiRunState::Running.can_transition_to(CiRunState::Success));
    assert!(!CiRunState::Success.can_transition_to(CiRunState::Running));
}

#[test]
fn log_reference_requires_exactly_one_location_and_valid_digest() {
    let bytes = b"hello world\n";
    let mut log = CiLogReferenceEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "a".repeat(64),
        run_id: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
        workflow_id: "ci".into(),
        target_repo_a: format!("30617:{}:buzz", "b".repeat(64)),
        tip_oid: "c".repeat(40),
        job_id: "rust_lint".into(),
        attempt: 1,
        log_sha256: "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447".into(),
        byte_length: 12,
        cap_bytes: 1024,
        truncated: false,
        url: None,
        inline: Some("aGVsbG8gd29ybGQK".into()),
        created_at: 1_800_000_001,
        relay_signer: "e".repeat(64),
    };
    log.validate().expect("valid log reference");

    assert_eq!(bytes.len() as u64, log.byte_length);
    log.url = Some("https://example.test/log".into());
    assert!(log.validate().is_err());
    log.inline = None;
    log.log_sha256 = "short".into();
    assert!(log.validate().is_err());
}

#[test]
fn inline_log_hashes_decoded_bytes_and_rejects_truncation() {
    let mut log = CiLogReferenceEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "a".repeat(64),
        run_id: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
        workflow_id: "ci".into(),
        target_repo_a: format!("30617:{}:buzz", "b".repeat(64)),
        tip_oid: "c".repeat(40),
        job_id: "rust_lint".into(),
        attempt: 1,
        log_sha256: "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447".into(),
        byte_length: 12,
        cap_bytes: 1024,
        truncated: false,
        url: None,
        inline: Some("aGVsbG8gd29ybGQK".into()),
        created_at: 1_800_000_001,
        relay_signer: "e".repeat(64),
    };
    log.validate().expect("valid inline evidence");

    log.inline = Some("aGVsbG8gd29ybGQK\n".into());
    assert!(log.validate().is_err());
    log.inline = Some("aGVsbG8gd29ybGQK".into());
    log.truncated = true;
    assert!(log.validate().is_err());
}

#[test]
fn url_log_is_same_origin_and_path_bound() {
    let log = CiLogReferenceEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "a".repeat(64),
        run_id: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
        workflow_id: "ci".into(),
        target_repo_a: format!("30617:{}:buzz", "b".repeat(64)),
        tip_oid: "c".repeat(40),
        job_id: "rust_lint".into(),
        attempt: 1,
        log_sha256: "d".repeat(64),
        byte_length: 12,
        cap_bytes: 1024,
        truncated: false,
        url: Some(format!(
            "https://relay.example/ci/logs/{}/{}/{}/{}/{}",
            "a".repeat(64),
            "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45",
            "rust_lint",
            1,
            "d".repeat(64)
        )),
        inline: None,
        created_at: 1_800_000_001,
        relay_signer: "e".repeat(64),
    };
    log.validate_url_for_relay("wss://relay.example")
        .expect("same relay and bound path");

    let mut off_origin = log;
    off_origin.url = off_origin
        .url
        .map(|url| url.replace("relay.example", "evil.example"));
    assert!(off_origin
        .validate_url_for_relay("wss://relay.example")
        .is_err());
}
