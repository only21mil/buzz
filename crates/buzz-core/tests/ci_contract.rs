use buzz_core::{
    ci::{
        artifact_reference_tags, evidence_finalized_tags, job_status_tags, log_reference_tags,
        request_tags, run_status_tags, teardown_attestation_tags, validate_artifact_reference_tags,
        validate_evidence_finalized_tags, validate_job_status_tags, validate_log_reference_tags,
        validate_request_tags, validate_run_status_tags, validate_signed_ci_event,
        validate_teardown_attestation_tags, CiArtifactReferenceEnvelope,
        CiEvidenceFinalizedEnvelope, CiFinalizedJobAttempt, CiJobState, CiJobStatusEnvelope,
        CiLogReferenceEnvelope, CiRequestEnvelope, CiRequestType, CiRunState, CiRunStatusEnvelope,
        CiSkipPolicy, CiTeardownAttestationEnvelope, CiTeardownLease, ValidatedCiEnvelope,
        CI_MAX_SAFE_INTEGER, CI_PROTOCOL_CONTRACT_SHA256, CI_SCHEMA_VERSION,
    },
    kind::{
        is_workflow_execution_kind, ALL_KINDS, KIND_CI_ARTIFACT_REFERENCE,
        KIND_CI_EVIDENCE_FINALIZED, KIND_CI_JOB_STATUS, KIND_CI_LOG_REFERENCE, KIND_CI_REQUEST,
        KIND_CI_RUN_STATUS, KIND_CI_TEARDOWN_ATTESTATION,
    },
};
use nostr::{EventBuilder, Keys, Kind, Tag};
use std::collections::HashSet;

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
        trigger_event_id: "b".repeat(64),
        actor: "1".repeat(64),
        timeout_seconds: 900,
        idempotency_key: "run-018f47a2".into(),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_300,
    }
}

fn valid_run_status() -> CiRunStatusEnvelope {
    CiRunStatusEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "a".repeat(64),
        run_id: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
        workflow_id: "ci".into(),
        target_repo_a: format!("30617:{}:buzz", "b".repeat(64)),
        tip_oid: "c".repeat(40),
        base_oid: "d".repeat(40),
        attempt: 1,
        sequence: 2,
        state: CiRunState::Success,
        conclusion: Some("success".into()),
        reason: None,
        started_at: Some(1_800_000_000),
        finished_at: Some(1_800_000_001),
        job_ids: vec!["rust_lint".into()],
        relay_signer: "e".repeat(64),
    }
}

fn valid_job_status() -> CiJobStatusEnvelope {
    CiJobStatusEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "a".repeat(64),
        run_id: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
        workflow_id: "ci".into(),
        target_repo_a: format!("30617:{}:buzz", "b".repeat(64)),
        tip_oid: "c".repeat(40),
        base_oid: "d".repeat(40),
        job_id: "rust_lint".into(),
        name: "Rust lint".into(),
        attempt: 1,
        parent_attempt: None,
        sequence: 2,
        state: CiJobState::Success,
        conclusion: Some("success".into()),
        reason: None,
        required: true,
        skip_policy: CiSkipPolicy::Forbid,
        selected_job_instance: "rust_lint".into(),
        also_reruns: Vec::new(),
        started_at: Some(1_800_000_000),
        finished_at: Some(1_800_000_001),
        log_ref: Some("f".repeat(64)),
        artifact_refs: vec!["1".repeat(64)],
        relay_signer: "e".repeat(64),
    }
}

fn valid_log_reference() -> CiLogReferenceEnvelope {
    CiLogReferenceEnvelope {
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
    }
}

fn valid_artifact_reference() -> CiArtifactReferenceEnvelope {
    CiArtifactReferenceEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "a".repeat(64),
        run_id: "018f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
        workflow_id: "ci".into(),
        target_repo_a: format!("30617:{}:buzz", "b".repeat(64)),
        tip_oid: "c".repeat(40),
        job_id: "rust_lint".into(),
        attempt: 1,
        artifact_id: "coverage".into(),
        name: "coverage.json".into(),
        media_type: "application/json".into(),
        sha256: "d".repeat(64),
        byte_length: 12,
        url: "https://relay.example/artifacts/coverage".into(),
        created_at: 1_800_000_001,
        relay_signer: "e".repeat(64),
    }
}

fn valid_evidence_finalized() -> CiEvidenceFinalizedEnvelope {
    CiEvidenceFinalizedEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "1".repeat(64),
        run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
        workflow_id: "required-ci".into(),
        target_repo_a: format!("30617:{}:buzz", "a".repeat(64)),
        tip_oid: "b".repeat(40),
        attempt: 1,
        finalized_job_attempts: vec![CiFinalizedJobAttempt {
            job_id: "unit_linux".into(),
            attempt: 1,
            log_ref: "2".repeat(64),
            artifact_refs: vec!["3".repeat(64)],
        }],
        finalized_at: 1_700_000_010,
        relay_signer: "d".repeat(64),
    }
}

fn valid_teardown_attestation() -> CiTeardownAttestationEnvelope {
    CiTeardownAttestationEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "1".repeat(64),
        run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
        workflow_id: "required-ci".into(),
        target_repo_a: format!("30617:{}:buzz", "a".repeat(64)),
        tip_oid: "b".repeat(40),
        base_oid: "c".repeat(40),
        workflow_digest: "e".repeat(64),
        attempt: 2,
        leases: vec![
            CiTeardownLease {
                job_id: "unit_linux".into(),
                attempt: 1,
                lease_id: "lease-unit-linux-attempt-1".into(),
            },
            CiTeardownLease {
                job_id: "unit_macos".into(),
                attempt: 2,
                lease_id: "lease-unit-macos-attempt-2".into(),
            },
        ],
        lease_empty: true,
        teardown_at: 1_700_000_011,
        relay_signer: "d".repeat(64),
    }
}

#[test]
fn ci_kinds_are_dedicated_and_outside_workflow_lifecycle() {
    assert_eq!(
        CI_PROTOCOL_CONTRACT_SHA256,
        "ac335626526aba0a0c429e6fbbe387600155d539f456075375cb6f11fb0a18d1"
    );
    assert_eq!(KIND_CI_REQUEST, 46100);
    assert_eq!(KIND_CI_RUN_STATUS, 46101);
    assert_eq!(KIND_CI_JOB_STATUS, 46102);
    assert_eq!(KIND_CI_LOG_REFERENCE, 46103);
    assert_eq!(KIND_CI_ARTIFACT_REFERENCE, 46104);
    assert_eq!(KIND_CI_EVIDENCE_FINALIZED, 46105);
    assert_eq!(KIND_CI_TEARDOWN_ATTESTATION, 46106);

    for kind in 46100..=46106 {
        assert!(
            ALL_KINDS.contains(&kind),
            "CI kind {kind} missing from ALL_KINDS"
        );
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
    for relay_url in ["wss://relay.example", "https://relay.example"] {
        log.validate_url_for_relay(relay_url)
            .expect("same normalized relay origin and bound path");
    }

    let mut insecure_log = log.clone();
    insecure_log.url = insecure_log
        .url
        .map(|url| url.replacen("https://", "http://", 1));
    for relay_url in ["ws://relay.example", "http://relay.example"] {
        insecure_log
            .validate_url_for_relay(relay_url)
            .expect("same normalized relay origin and bound path");
    }

    let mut off_origin = log;
    off_origin.url = off_origin
        .url
        .map(|url| url.replace("relay.example", "evil.example"));
    assert!(off_origin
        .validate_url_for_relay("wss://relay.example")
        .is_err());
}

fn assert_every_tag_is_bound(
    tags: Vec<Tag>,
    validate: impl Fn(&[Tag]) -> Result<(), buzz_core::ci::CiValidationError>,
) {
    validate(&tags).expect("valid generated tags");
    for index in 0..tags.len() {
        let mut changed = tags.clone();
        let mut parts: Vec<String> = changed[index]
            .as_slice()
            .iter()
            .map(|part| part.as_str().to_string())
            .collect();
        parts[1] = "wrong".into();
        changed[index] = Tag::parse(parts).expect("mutated tag parses");
        assert!(
            validate(&changed).is_err(),
            "tag index {index} was not bound"
        );
    }
    let mut duplicate = tags.clone();
    duplicate.push(tags[0].clone());
    assert!(
        validate(&duplicate).is_err(),
        "duplicate reserved tag accepted"
    );
}

#[test]
fn every_ci_kind_binds_every_required_tag_and_rejects_forbidden_reserved_tags() {
    let channel = "46bba699-8251-43c7-943e-66be58376585";

    let request = valid_run_request();
    let request_tags = request_tags(channel, &request).expect("request tags");
    assert_every_tag_is_bound(request_tags.clone(), |tags| {
        validate_request_tags(tags, channel, &request)
    });
    for forbidden in ["job", "e", "x"] {
        let mut tags = request_tags.clone();
        tags.push(Tag::parse(vec![forbidden, "forbidden"]).expect("forbidden tag parses"));
        assert!(validate_request_tags(&tags, channel, &request).is_err());
    }

    let run = valid_run_status();
    let run_tags = run_status_tags(channel, &run).expect("run tags");
    assert_every_tag_is_bound(run_tags.clone(), |tags| {
        validate_run_status_tags(tags, channel, &run)
    });
    for forbidden in ["job", "x"] {
        let mut tags = run_tags.clone();
        tags.push(Tag::parse(vec![forbidden, "forbidden"]).expect("forbidden tag parses"));
        assert!(validate_run_status_tags(&tags, channel, &run).is_err());
    }

    let job = valid_job_status();
    let job_tags = job_status_tags(channel, &job).expect("job tags");
    assert_every_tag_is_bound(job_tags.clone(), |tags| {
        validate_job_status_tags(tags, channel, &job)
    });
    let mut forbidden_job = job_tags;
    forbidden_job.push(Tag::parse(vec!["x", "forbidden"]).expect("forbidden tag parses"));
    assert!(validate_job_status_tags(&forbidden_job, channel, &job).is_err());

    let log = valid_log_reference();
    let log_tags = log_reference_tags(channel, &log).expect("log tags");
    assert_every_tag_is_bound(log_tags, |tags| {
        validate_log_reference_tags(tags, channel, &log)
    });

    let artifact = valid_artifact_reference();
    let artifact_tags = artifact_reference_tags(channel, &artifact).expect("artifact tags");
    assert_every_tag_is_bound(artifact_tags, |tags| {
        validate_artifact_reference_tags(tags, channel, &artifact)
    });
}

#[test]
fn request_rejects_malformed_coordinates_sources_jobs_triggers_and_numbers() {
    let valid = valid_run_request();
    valid.validate().expect("valid request");

    let mut bad = valid.clone();
    bad.target_repo_a = format!("30618:{}:buzz", "a".repeat(64));
    assert!(bad.validate().is_err());

    let mut bad = valid.clone();
    bad.source_clone_url = "https://user:password@example.test/repo.git".into();
    assert!(bad.validate().is_err());

    for field in ["workflow", "immutable_ref", "source_branch", "base_ref"] {
        let mut bad = valid.clone();
        match field {
            "workflow" => bad.workflow_id.clear(),
            "immutable_ref" => bad.immutable_source_ref.clear(),
            "source_branch" => bad.source_branch.clear(),
            "base_ref" => bad.base_ref.clear(),
            _ => unreachable!(),
        }
        assert!(bad.validate().is_err(), "empty {field} accepted");
    }

    for job_id in [
        "0bad-job",
        "-bad-job",
        "bad.job",
        "bad/job",
        "bad:job",
        "has space",
        "é",
        "",
        &"a".repeat(65),
    ] {
        let mut bad = valid.clone();
        bad.job_ids = vec![job_id.to_string()];
        assert!(bad.validate().is_err(), "invalid job ID accepted: {job_id}");
    }

    for job_id in ["rust-lint", "desktop-smoke-e2e", "_internal-job"] {
        let mut accepted = valid.clone();
        accepted.job_ids = vec![job_id.to_string()];
        accepted
            .validate()
            .unwrap_or_else(|error| panic!("valid GitHub job ID rejected: {job_id}: {error}"));
    }

    let mut bad = valid.clone();
    bad.trigger_event_id = "f".repeat(64);
    assert!(bad.validate().is_err());

    let mut bad = valid;
    bad.issued_at = CI_MAX_SAFE_INTEGER + 1;
    assert!(bad.validate().is_err());
}

#[test]
fn status_lineage_times_references_and_numbers_fail_closed() {
    let run = valid_run_status();
    run.validate().expect("valid run status");
    let mut bad_run = run.clone();
    bad_run.finished_at = Some(1_799_999_999);
    assert!(bad_run.validate().is_err());
    let mut bad_run = run;
    bad_run.sequence = CI_MAX_SAFE_INTEGER + 1;
    assert!(bad_run.validate().is_err());

    let job = valid_job_status();
    job.validate().expect("valid job status");
    let mut bad_job = job.clone();
    bad_job.attempt = 2;
    assert!(bad_job.validate().is_err());
    let mut bad_job = job.clone();
    bad_job.also_reruns = vec![bad_job.job_id.clone()];
    assert!(bad_job.validate().is_err());
    let mut bad_job = job.clone();
    bad_job.artifact_refs.push(bad_job.artifact_refs[0].clone());
    assert!(bad_job.validate().is_err());
    let mut bad_job = job;
    bad_job.log_ref = Some("short".into());
    assert!(bad_job.validate().is_err());
}

#[test]
fn absent_optionals_are_omitted_and_inline_size_is_bounded_before_decode() {
    let request_json = serde_json::to_value(valid_run_request()).expect("serialize request");
    assert!(request_json.get("pr_update_event_id").is_none());
    assert!(request_json.get("parent_attempt").is_none());
    assert!(request_json.get("parent_run_id").is_none());

    let log_json = serde_json::to_value(valid_log_reference()).expect("serialize log");
    assert!(log_json.get("url").is_none());
    assert!(log_json.get("inline").is_some());

    let mut oversized = valid_log_reference();
    oversized.cap_bytes = 1;
    oversized.inline = Some("A".repeat(1_000_000));
    assert!(oversized.validate().is_err());
}

#[test]
fn every_reference_kind_validates_coordinates_and_static_job_ids() {
    let mut log = valid_log_reference();
    log.job_id = "bad.job".into();
    assert!(log.validate().is_err());

    let mut artifact = valid_artifact_reference();
    artifact.target_repo_a = "30617:short:buzz".into();
    assert!(artifact.validate().is_err());
}

#[test]
fn signed_event_validator_checks_signature_kind_tags_actor_and_authorized_signer() {
    let channel = "46bba699-8251-43c7-943e-66be58376585";
    let actor_keys = Keys::generate();
    let mut request = valid_run_request();
    request.actor = actor_keys.public_key().to_hex();
    let request_event = EventBuilder::new(
        Kind::Custom(KIND_CI_REQUEST as u16),
        serde_json::to_string(&request).expect("serialize request"),
    )
    .tags(request_tags(channel, &request).expect("request tags"))
    .sign_with_keys(&actor_keys)
    .expect("sign request");
    let validated = validate_signed_ci_event(&request_event, channel, &HashSet::new())
        .expect("valid signed request");
    assert!(matches!(validated, ValidatedCiEnvelope::Request(_)));

    let mut tampered = request_event.clone();
    tampered.content.push(' ');
    assert!(validate_signed_ci_event(&tampered, channel, &HashSet::new()).is_err());

    let wrong_kind = EventBuilder::new(
        Kind::Custom(KIND_CI_RUN_STATUS as u16),
        serde_json::to_string(&request).expect("serialize request"),
    )
    .tags(request_tags(channel, &request).expect("request tags"))
    .sign_with_keys(&actor_keys)
    .expect("sign wrong kind");
    assert!(validate_signed_ci_event(&wrong_kind, channel, &HashSet::new()).is_err());

    let runner_keys = Keys::generate();
    let mut run = valid_run_status();
    run.relay_signer = runner_keys.public_key().to_hex();
    let run_event = EventBuilder::new(
        Kind::Custom(KIND_CI_RUN_STATUS as u16),
        serde_json::to_string(&run).expect("serialize run"),
    )
    .tags(run_status_tags(channel, &run).expect("run tags"))
    .sign_with_keys(&runner_keys)
    .expect("sign run");
    assert!(validate_signed_ci_event(&run_event, channel, &HashSet::new()).is_err());
    let authorized = HashSet::from([runner_keys.public_key().to_hex()]);
    assert!(matches!(
        validate_signed_ci_event(&run_event, channel, &authorized).expect("authorized run"),
        ValidatedCiEnvelope::RunStatus(_)
    ));

    let mut forged_content = run;
    forged_content.relay_signer = actor_keys.public_key().to_hex();
    let forged = EventBuilder::new(
        Kind::Custom(KIND_CI_RUN_STATUS as u16),
        serde_json::to_string(&forged_content).expect("serialize forged run"),
    )
    .tags(run_status_tags(channel, &forged_content).expect("forged tags"))
    .sign_with_keys(&runner_keys)
    .expect("sign forged run");
    assert!(validate_signed_ci_event(&forged, channel, &authorized).is_err());
}

#[test]
fn explicit_terminal_facts_are_nonempty_unique_tag_bound_and_signer_authorized() {
    let channel = "46bba699-8251-43c7-943e-66be58376585";
    let evidence = valid_evidence_finalized();
    evidence.validate().expect("valid evidence fact");
    let evidence_tags = evidence_finalized_tags(channel, &evidence).expect("evidence tags");
    assert_every_tag_is_bound(evidence_tags.clone(), |tags| {
        validate_evidence_finalized_tags(tags, channel, &evidence)
    });

    let mut duplicate = evidence.clone();
    let repeated_log_ref = duplicate.finalized_job_attempts[0].log_ref.clone();
    duplicate.finalized_job_attempts[0]
        .artifact_refs
        .push(repeated_log_ref);
    assert!(duplicate.validate().is_err());
    let mut missing = evidence.clone();
    missing.finalized_job_attempts.clear();
    assert!(missing.validate().is_err());

    let teardown = valid_teardown_attestation();
    teardown.validate().expect("valid teardown fact");
    assert_every_tag_is_bound(
        teardown_attestation_tags(channel, &teardown).expect("teardown tags"),
        |tags| validate_teardown_attestation_tags(tags, channel, &teardown),
    );
    let mut not_empty = teardown.clone();
    not_empty.lease_empty = false;
    assert!(not_empty.validate().is_err());

    let mut unsorted = teardown.clone();
    unsorted.leases.swap(0, 1);
    assert!(unsorted.validate().is_err());
    let mut duplicate_job_attempt = teardown.clone();
    duplicate_job_attempt.leases[1].job_id = duplicate_job_attempt.leases[0].job_id.clone();
    duplicate_job_attempt.leases[1].attempt = duplicate_job_attempt.leases[0].attempt;
    assert!(duplicate_job_attempt.validate().is_err());
    let mut duplicate_lease = teardown.clone();
    duplicate_lease.leases[1].lease_id = duplicate_lease.leases[0].lease_id.clone();
    assert!(duplicate_lease.validate().is_err());
    let mut invalid_job = teardown.clone();
    invalid_job.leases[0].job_id = "bad.job".into();
    assert!(invalid_job.validate().is_err());
    let mut zero_attempt = teardown.clone();
    zero_attempt.leases[0].attempt = 0;
    assert!(zero_attempt.validate().is_err());
    let mut empty_lease = teardown.clone();
    empty_lease.leases[0].lease_id.clear();
    assert!(empty_lease.validate().is_err());
    let mut empty_lease_set = teardown.clone();
    empty_lease_set.leases.clear();
    assert!(empty_lease_set.validate().is_err());
    let mut wrong_max_attempt = teardown.clone();
    wrong_max_attempt.attempt = 1;
    assert!(wrong_max_attempt.validate().is_err());

    let keys = Keys::generate();
    let mut signed_evidence = evidence;
    signed_evidence.relay_signer = keys.public_key().to_hex();
    let event = EventBuilder::new(
        Kind::Custom(KIND_CI_EVIDENCE_FINALIZED as u16),
        serde_json::to_string(&signed_evidence).expect("serialize evidence"),
    )
    .tags(evidence_finalized_tags(channel, &signed_evidence).expect("evidence tags"))
    .sign_with_keys(&keys)
    .expect("sign evidence");
    let authorized = HashSet::from([keys.public_key().to_hex()]);
    assert!(matches!(
        validate_signed_ci_event(&event, channel, &authorized).expect("authorized evidence"),
        ValidatedCiEnvelope::EvidenceFinalized(_)
    ));
}

#[test]
fn teardown_context_binds_request_provenance_and_exact_selected_graph() {
    let request_event_id = "1".repeat(64);
    let mut request = valid_run_request();
    request.run_id = "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into();
    request.workflow_id = "required-ci".into();
    request.workflow_digest = "e".repeat(64);
    request.target_repo_a = format!("30617:{}:buzz", "a".repeat(64));
    request.tip_oid = "b".repeat(40);
    request.base_oid = "c".repeat(40);
    let teardown = valid_teardown_attestation();
    let selected = vec![("unit_linux".into(), 1), ("unit_macos".into(), 2)];

    teardown
        .validate_context(&request_event_id, &request, &selected)
        .expect("matching request and selected graph");

    let mut wrong_provenance = teardown.clone();
    wrong_provenance.workflow_digest = "f".repeat(64);
    assert!(wrong_provenance
        .validate_context(&request_event_id, &request, &selected)
        .is_err());
    assert!(teardown
        .validate_context(&request_event_id, &request, &[("unit_linux".into(), 1)])
        .is_err());
    assert!(teardown
        .validate_context(
            &request_event_id,
            &request,
            &[("unit_linux".into(), 1), ("unit_linux".into(), 1)],
        )
        .is_err());
    assert!(teardown
        .validate_context(
            &request_event_id,
            &request,
            &[("unit_linux".into(), 1), ("unit_linux".into(), 2)],
        )
        .is_err());
}

#[test]
fn teardown_wire_shape_pins_provenance_and_canonical_lease_tuple_spelling() {
    let json = serde_json::to_string(&valid_teardown_attestation()).expect("serialize teardown");
    assert_eq!(
        json,
        format!(
            "{{\"schema_version\":1,\"request_event_id\":\"{}\",\"run_id\":\"018f47a2-7f0f-7cc1-9a55-01f93e42b1e0\",\"workflow_id\":\"required-ci\",\"target_repo_a\":\"30617:{}:buzz\",\"tip_oid\":\"{}\",\"base_oid\":\"{}\",\"workflow_digest\":\"{}\",\"attempt\":2,\"leases\":[{{\"job_id\":\"unit_linux\",\"attempt\":1,\"lease_id\":\"lease-unit-linux-attempt-1\"}},{{\"job_id\":\"unit_macos\",\"attempt\":2,\"lease_id\":\"lease-unit-macos-attempt-2\"}}],\"lease_empty\":true,\"teardown_at\":1700000011,\"relay_signer\":\"{}\"}}",
            "1".repeat(64),
            "a".repeat(64),
            "b".repeat(40),
            "c".repeat(40),
            "e".repeat(64),
            "d".repeat(64),
        )
    );
}
