//! B1 CI authenticity gate — deterministic acceptance for the static-signer
//! and grant-set authorization of signed CI events.
//!
//! Coverage (B1 lane objective 2):
//!   * kinds 46101-46106 from an unauthorized signer MUST be rejected by
//!     `buzz_core::ci::validate_signed_ci_event`;
//!   * kind 46100 (CI request) is NOT gated by the status-signer set — its
//!     actor binding is the request-author check and it passes an empty set;
//!   * the grant-set gate (A2/A3 wiring: `get_active_ci_signers` feeding the
//!     `authorized_status_signers` set) must observe the same fail-closed rule.
//!
//! Pure/deterministic: no network, no Postgres, no live relay.

use buzz_core::{
    ci::{
        artifact_reference_tags, evidence_finalized_tags, job_status_tags, log_reference_tags,
        request_tags, run_status_tags, teardown_attestation_tags, validate_signed_ci_event,
        CiArtifactReferenceEnvelope, CiEvidenceFinalizedEnvelope, CiFinalizedJobAttempt,
        CiJobState, CiJobStatusEnvelope, CiLogReferenceEnvelope, CiRequestEnvelope, CiRequestType,
        CiRunState, CiRunStatusEnvelope, CiSkipPolicy, CiTeardownAttestationEnvelope,
        CiTeardownLease, ValidatedCiEnvelope, CI_SCHEMA_VERSION,
    },
    kind::{
        KIND_CI_ARTIFACT_REFERENCE, KIND_CI_EVIDENCE_FINALIZED, KIND_CI_JOB_STATUS,
        KIND_CI_LOG_REFERENCE, KIND_CI_REQUEST, KIND_CI_RUN_STATUS, KIND_CI_TEARDOWN_ATTESTATION,
    },
};
use nostr::{Event, EventBuilder, Keys, Kind};
use std::collections::HashSet;

/// Deterministic channel for every test event.
const CHANNEL: &str = "46bba699-8251-43c7-943e-66be58376585";

/// Every kind in the 46101-46106 status/control-plane range.
const STATUS_KINDS: [u32; 6] = [
    KIND_CI_RUN_STATUS,
    KIND_CI_JOB_STATUS,
    KIND_CI_LOG_REFERENCE,
    KIND_CI_ARTIFACT_REFERENCE,
    KIND_CI_EVIDENCE_FINALIZED,
    KIND_CI_TEARDOWN_ATTESTATION,
];

fn empty_set() -> HashSet<String> {
    HashSet::new()
}

fn set_of(pubkey: &str) -> HashSet<String> {
    HashSet::from([pubkey.to_owned()])
}

fn valid_request(signer: &Keys) -> CiRequestEnvelope {
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
        actor: signer.public_key().to_hex(),
        timeout_seconds: 900,
        idempotency_key: "run-018f47a2".into(),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_300,
    }
}

fn signed_request(signer: &Keys) -> Event {
    let envelope = valid_request(signer);
    EventBuilder::new(
        Kind::Custom(KIND_CI_REQUEST as u16),
        serde_json::to_string(&envelope).expect("serialize request"),
    )
    .tags(request_tags(CHANNEL, &envelope).expect("request tags"))
    .sign_with_keys(signer)
    .expect("sign request")
}

/// Build a signed event for the given status kind with `relay_signer` pinned
/// to the signing key.
fn signed_status_event(kind: u32, signer: &Keys) -> Event {
    let (content, tags) = match kind {
        KIND_CI_RUN_STATUS => {
            let mut envelope = valid_run_status();
            envelope.relay_signer = signer.public_key().to_hex();
            let tags = run_status_tags(CHANNEL, &envelope).expect("run status tags");
            (
                serde_json::to_string(&envelope).expect("serialize run status"),
                tags,
            )
        }
        KIND_CI_JOB_STATUS => {
            let mut envelope = valid_job_status();
            envelope.relay_signer = signer.public_key().to_hex();
            let tags = job_status_tags(CHANNEL, &envelope).expect("job status tags");
            (
                serde_json::to_string(&envelope).expect("serialize job status"),
                tags,
            )
        }
        KIND_CI_LOG_REFERENCE => {
            let mut envelope = valid_log_reference();
            envelope.relay_signer = signer.public_key().to_hex();
            let tags = log_reference_tags(CHANNEL, &envelope).expect("log reference tags");
            (
                serde_json::to_string(&envelope).expect("serialize log reference"),
                tags,
            )
        }
        KIND_CI_ARTIFACT_REFERENCE => {
            let mut envelope = valid_artifact_reference();
            envelope.relay_signer = signer.public_key().to_hex();
            let tags =
                artifact_reference_tags(CHANNEL, &envelope).expect("artifact reference tags");
            (
                serde_json::to_string(&envelope).expect("serialize artifact reference"),
                tags,
            )
        }
        KIND_CI_EVIDENCE_FINALIZED => {
            let mut envelope = valid_evidence_finalized();
            envelope.relay_signer = signer.public_key().to_hex();
            let tags = evidence_finalized_tags(CHANNEL, &envelope).expect("evidence tags");
            (
                serde_json::to_string(&envelope).expect("serialize evidence"),
                tags,
            )
        }
        KIND_CI_TEARDOWN_ATTESTATION => {
            let mut envelope = valid_teardown_attestation();
            envelope.relay_signer = signer.public_key().to_hex();
            let tags = teardown_attestation_tags(CHANNEL, &envelope).expect("teardown tags");
            (
                serde_json::to_string(&envelope).expect("serialize teardown"),
                tags,
            )
        }
        other => panic!("unexpected status kind {other}"),
    };
    EventBuilder::new(Kind::Custom(kind as u16), content)
        .tags(tags)
        .sign_with_keys(signer)
        .expect("sign status event")
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
        relay_signer: String::new(),
    }
}

fn valid_job_status() -> CiJobStatusEnvelope {
    CiJobStatusEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "a".repeat(64),
        run_id: "019f47a2-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
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
        relay_signer: String::new(),
    }
}

fn valid_log_reference() -> CiLogReferenceEnvelope {
    CiLogReferenceEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "a".repeat(64),
        run_id: "019f47a2-5563-7c08-b8f3-5b6df7f9dd45".into(),
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
        relay_signer: String::new(),
    }
}

fn valid_artifact_reference() -> CiArtifactReferenceEnvelope {
    CiArtifactReferenceEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "a".repeat(64),
        run_id: "019f5562-4ce1-7c08-b8f3-5b6df7f9dd45".into(),
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
        relay_signer: String::new(),
    }
}

fn valid_evidence_finalized() -> CiEvidenceFinalizedEnvelope {
    CiEvidenceFinalizedEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "1".repeat(64),
        run_id: "219f5562-7f0f-7cc1-9a55-01f93e42b1e0".into(),
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
        relay_signer: String::new(),
    }
}

fn valid_teardown_attestation() -> CiTeardownAttestationEnvelope {
    CiTeardownAttestationEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: "1".repeat(64),
        run_id: "019f5562-7f0f-7cc1-9a55-01f93e42b1e0".into(),
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
        relay_signer: String::new(),
    }
}

/// Status events must fail closed when the authority set is empty, when it is
/// the grant-set output for a different repo/channel, and must validate under
/// the exact signer grant (mirroring `get_active_ci_signers` results).
#[test]
fn all_status_kinds_reject_an_empty_or_unrelated_authority_set() {
    let signer = Keys::generate();
    let other = Keys::generate();

    for kind in STATUS_KINDS {
        let event = signed_status_event(kind, &signer);

        // Empty set: grant-set gate finds no signer.
        let err = validate_signed_ci_event(&event, CHANNEL, &empty_set())
            .expect_err(&format!("kind {kind} must reject an empty authority set"));
        assert!(
            err.0.contains("unauthorized CI status signer"),
            "kind {kind}: expected signer-authorization error, got {err:?}"
        );

        // Wrong pubkey in set: static gate enumeration must not match.
        let err = validate_signed_ci_event(&event, CHANNEL, &set_of(&other.public_key().to_hex()))
            .expect_err(&format!(
                "kind {kind} must reject an unrelated authority set"
            ));
        assert!(
            err.0.contains("unauthorized CI status signer"),
            "kind {kind}: expected signer-authorization error, got {err:?}"
        );
    }
}

/// Each status kind validates when its exact signer is in the authority set —
/// the grant-set gate's accept path.
#[test]
fn status_kinds_validate_when_the_exact_signer_is_authorized() {
    let signer = Keys::generate();
    let signer_hex = signer.public_key().to_hex();

    let parse_as = |validated: &ValidatedCiEnvelope| -> u8 {
        match validated {
            ValidatedCiEnvelope::Request(_) => 0,
            ValidatedCiEnvelope::RunStatus(_) => 1,
            ValidatedCiEnvelope::JobStatus(_) => 2,
            ValidatedCiEnvelope::LogReference(_) => 3,
            ValidatedCiEnvelope::ArtifactReference(_) => 4,
            ValidatedCiEnvelope::EvidenceFinalized(_) => 5,
            ValidatedCiEnvelope::TeardownAttestation(_) => 6,
        }
    };

    let expected_arm = |kind: u32| -> u8 {
        match kind {
            KIND_CI_RUN_STATUS => 1,
            KIND_CI_JOB_STATUS => 2,
            KIND_CI_LOG_REFERENCE => 3,
            KIND_CI_ARTIFACT_REFERENCE => 4,
            KIND_CI_EVIDENCE_FINALIZED => 5,
            KIND_CI_TEARDOWN_ATTESTATION => 6,
            other => panic!("unexpected status kind {other}"),
        }
    };

    for kind in STATUS_KINDS {
        let event = signed_status_event(kind, &signer);
        let validated = validate_signed_ci_event(&event, CHANNEL, &set_of(&signer_hex))
            .unwrap_or_else(|err| panic!("kind {kind}: authorized signer failed: {err:?}"));
        assert_eq!(
            parse_as(&validated),
            expected_arm(kind),
            "kind {kind} must parse to its own envelope variant"
        );
    }
}

/// Kind 46100 passes with an empty status-signer set — the grant gate must
/// never gate the request class.
#[test]
fn request_event_is_exempt_from_the_status_signer_gate() {
    let owner = Keys::generate();
    let event = signed_request(&owner);

    let validated = validate_signed_ci_event(&event, CHANNEL, &empty_set())
        .expect("valid kind-46100 must validate with an empty signer set");
    assert!(
        matches!(validated, ValidatedCiEnvelope::Request(_)),
        "request must parse as Request, got {validated:?}"
    );

    // Even with the owner in the set (e.g. they were granted a status signer
    // that would be wrong for a request), the request still validates.
    validate_signed_ci_event(&event, CHANNEL, &set_of(&owner.public_key().to_hex()))
        .expect("valid kind-46100 must validate regardless of status-set contents");
}

/// The gate must fail closed for kinds outside the CI block even when the
/// signer is itself authorized inside the status set.
#[test]
fn unknown_kind_is_rejected_even_with_the_signer_authorized() {
    let signer = Keys::generate();
    let event = EventBuilder::new(
        Kind::Custom(46030), // KIND_APPROVAL_GRANT, outside the CI block.
        "{}",
    )
    .sign_with_keys(&signer)
    .expect("sign unknown kind");
    let err = validate_signed_ci_event(&event, CHANNEL, &set_of(&signer.public_key().to_hex()))
        .expect_err("non-CI kind must not validate");
    assert!(err.0.contains("not a CI envelope kind"));
}

/// The grant-set wiring (`get_active_ci_signers` feeding this validator) must
/// authorize exactly the active signers — an empty grant set (no signer, or
/// an expired/future-only grant) must reject; a populated set must validate.
#[test]
fn grant_set_gate_is_the_same_fail_closed_rule_as_the_static_gate() {
    let runner = Keys::generate();
    let event = signed_status_event(KIND_CI_RUN_STATUS, &runner);

    // Active grant for the exact signer (get_active_ci_signers return).
    let grant = set_of(&runner.public_key().to_hex());
    validate_signed_ci_event(&event, CHANNEL, &grant).expect("granted signer event passes");

    // No grant recorded (empty set) -> must reject; this is the failed-close.
    let result = validate_signed_ci_event(&event, CHANNEL, &empty_set());
    assert!(result.is_err(), "empty grant set must reject status event");
}
