//! Shared acceptance binding fixture and adversarial mutation corpus.

use buzz_core::ci::{request_tags, CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};
use buzz_core::kind::{KIND_CI_GRANT, KIND_CI_REQUEST, KIND_DELETION};
use sha2::{Digest, Sha256};

use crate::acceptance::{EvidenceObject, FixtureSpec};
use crate::acceptance_binding::{
    AcceptanceActorBinding, AcceptanceAuthorityBinding, AcceptanceBindingReceipt,
    ACCEPTANCE_BINDING_SCHEMA,
};

/// Distinct client identities mirrored by the activation cross-language fixture.
pub const CANONICAL_CONTROLD_UID: u32 = 62_002;
pub const CANONICAL_CONTROLD_GID: u32 = 62_002;
pub const CANONICAL_QUALIFICATION_UID: u32 = 961;
pub const CANONICAL_QUALIFICATION_GID: u32 = 961;

/// One named invalid receipt encoding consumed by both daemons' tests.
pub struct AcceptanceBindingMutation {
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

/// Build the single canonical receipt fixture shared by consumer tests.
pub fn canonical_acceptance_binding() -> AcceptanceBindingReceipt {
    let actor = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let ci_signer = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let channel = "123e4567-e89b-12d3-a456-426614174099";
    let mut run = CiRequestEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_type: CiRequestType::Run,
        target_repo_a: format!("30617:{}:buzz", "22".repeat(32)),
        pr_root_event_id: "33".repeat(32),
        pr_update_event_id: None,
        source_clone_url: "https://relay.example/git/repo".to_owned(),
        immutable_source_ref: "refs/nostr/source".to_owned(),
        tip_oid: "16".repeat(20),
        source_branch: "feature".to_owned(),
        base_ref: "refs/heads/main".to_owned(),
        base_oid: "55".repeat(20),
        workflow_id: "native-ci".to_owned(),
        workflow_digest: "66".repeat(32),
        job_ids: vec!["test".to_owned()],
        run_id: "13131313-1313-1313-1313-131313131313".to_owned(),
        attempt: 1,
        parent_attempt: None,
        parent_run_id: None,
        trigger_event_id: "33".repeat(32),
        actor: actor.to_owned(),
        timeout_seconds: 30,
        idempotency_key: "123e4567-e89b-12d3-a456-426614174012".to_owned(),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_300,
    };
    let run_event = serde_json::json!([
        0,
        actor,
        run.issued_at,
        KIND_CI_REQUEST,
        request_tags(channel, &run).expect("run tags"),
        serde_json::to_string(&run).expect("run content")
    ]);
    let grant_event = serde_json::json!([
        0,
        actor,
        1_800_000_001_u64,
        KIND_CI_GRANT,
        [["h", channel]],
        serde_json::to_string(&serde_json::json!({
            "schema_version": 1,
            "target_repo_a": run.target_repo_a,
            "signer_pubkey": ci_signer,
            "valid_from": 1_800_000_001_i64,
            "valid_until": 1_800_000_600_i64,
        }))
        .expect("grant content")
    ]);
    run.request_type = CiRequestType::Rerun;
    run.attempt = 2;
    run.parent_attempt = Some(1);
    run.parent_run_id = Some(run.run_id.clone());
    run.idempotency_key = "123e4567-e89b-12d3-a456-426614174013".to_owned();
    run.issued_at += 10;
    run.expires_at += 10;
    let rerun_event = serde_json::json!([
        0,
        actor,
        run.issued_at,
        KIND_CI_REQUEST,
        request_tags(channel, &run).expect("rerun tags"),
        serde_json::to_string(&run).expect("rerun content")
    ]);
    let rerun_id = Sha256::digest(serde_json::to_vec(&rerun_event).expect("rerun bytes"));
    let tombstone_event = serde_json::json!([
        0,
        actor,
        1_800_000_020_u64,
        KIND_DELETION,
        [["e", hex::encode(rerun_id)]],
        ""
    ]);
    let request_digest = event_id(&run_event);
    let grant_event_id = event_id(&grant_event);
    AcceptanceBindingReceipt {
        schema_version: ACCEPTANCE_BINDING_SCHEMA.to_owned(),
        activation_id: "activation-1".to_owned(),
        activation_package_digest: "12".repeat(32),
        scenario_sha256: "09".repeat(32),
        keyholder_peer_uid: CANONICAL_CONTROLD_UID,
        keyholder_peer_gid: CANONICAL_CONTROLD_GID,
        acceptance_peer_uid: CANONICAL_QUALIFICATION_UID,
        acceptance_peer_gid: CANONICAL_QUALIFICATION_GID,
        timeout_millis: 1_000,
        fixture: FixtureSpec {
            integrated_candidate_sha: "11".repeat(20),
            activation_id: "activation-1".to_owned(),
            activation_package_digest: "12".repeat(32),
            run_id: "13".repeat(16),
            job_id: "test".to_owned(),
            request_digest,
            manifest_digest: "15".repeat(32),
            source_oid: "16".repeat(20),
            approval_id: "17".repeat(16),
            grant_event_id,
            grant_digest: "19".repeat(32),
            approved_by: actor.to_owned(),
            export_subject: "1b".repeat(32),
            export_authorization_digest: "1c".repeat(32),
            controller_generation: 7,
            runner_generation: 9,
            expected_log: EvidenceObject {
                name: "job.log".to_owned(),
                sha256: "1d".repeat(32),
                bytes: 1,
            },
            expected_artifacts: vec![EvidenceObject {
                name: "result.json".to_owned(),
                sha256: "1e".repeat(32),
                bytes: 1,
            }],
        },
        acceptance: AcceptanceAuthorityBinding {
            actor: AcceptanceActorBinding {
                public_key: actor.to_owned(),
                generation: 10,
            },
            scenario_sha256: "09".repeat(32),
            run_event,
            grant_event,
            rerun_event,
            tombstone_event,
        },
    }
}

/// Return canonical, structural, identity, fixture, and event-semantic mutations.
pub fn acceptance_binding_mutation_corpus() -> Vec<AcceptanceBindingMutation> {
    let expected = canonical_acceptance_binding();
    let mut cases = Vec::new();
    let mut newline = serde_json::to_vec(&expected).expect("canonical receipt");
    newline.push(b'\n');
    cases.push(AcceptanceBindingMutation {
        name: "trailing_newline",
        bytes: newline,
    });
    cases.push(AcceptanceBindingMutation {
        name: "pretty_json",
        bytes: serde_json::to_vec_pretty(&expected).expect("pretty receipt"),
    });
    cases.push(AcceptanceBindingMutation {
        name: "truncated_json",
        bytes: b"{".to_vec(),
    });
    let mut unknown = serde_json::to_value(&expected).expect("receipt value");
    unknown["unexpected"] = serde_json::json!(true);
    cases.push(AcceptanceBindingMutation {
        name: "unknown_field",
        bytes: serde_json::to_vec(&unknown).expect("unknown field receipt"),
    });

    push_receipt_mutation(&mut cases, "schema", |receipt| {
        receipt.schema_version.push_str("-drift")
    });
    push_receipt_mutation(&mut cases, "activation", |receipt| {
        receipt.activation_id = "other-activation".to_owned()
    });
    push_receipt_mutation(&mut cases, "package", |receipt| {
        receipt.activation_package_digest = "23".repeat(32)
    });
    push_receipt_mutation(&mut cases, "candidate", |receipt| {
        receipt.fixture.integrated_candidate_sha = "not-a-candidate".to_owned()
    });
    push_receipt_mutation(&mut cases, "scenario", |receipt| {
        receipt.acceptance.scenario_sha256 = "24".repeat(32)
    });
    push_receipt_mutation(&mut cases, "keyholder_peer_uid", |receipt| {
        receipt.keyholder_peer_uid = 0;
    });
    push_receipt_mutation(&mut cases, "keyholder_peer_gid", |receipt| {
        receipt.keyholder_peer_gid = 0;
    });
    push_receipt_mutation(&mut cases, "acceptance_peer_uid", |receipt| {
        receipt.acceptance_peer_uid = 0;
    });
    push_receipt_mutation(&mut cases, "acceptance_peer_gid", |receipt| {
        receipt.acceptance_peer_gid = 0;
    });
    push_receipt_mutation(&mut cases, "peer_pairs_equal", |receipt| {
        receipt.acceptance_peer_uid = receipt.keyholder_peer_uid;
        receipt.acceptance_peer_gid = receipt.keyholder_peer_gid;
    });
    push_receipt_mutation(&mut cases, "timeout", |receipt| receipt.timeout_millis = 0);
    push_receipt_mutation(&mut cases, "actor", |receipt| {
        receipt.acceptance.actor.public_key = "25".repeat(32)
    });
    push_receipt_mutation(&mut cases, "generation", |receipt| {
        receipt.acceptance.actor.generation = 0
    });
    push_receipt_mutation(&mut cases, "request_id", |receipt| {
        receipt.fixture.request_digest = "26".repeat(32)
    });
    push_receipt_mutation(&mut cases, "grant_id", |receipt| {
        receipt.fixture.grant_event_id = "27".repeat(32)
    });
    push_receipt_mutation(&mut cases, "run_actor", |receipt| {
        receipt.acceptance.run_event[1] = serde_json::json!("28".repeat(32))
    });
    push_receipt_mutation(&mut cases, "run_kind", |receipt| {
        receipt.acceptance.run_event[3] = serde_json::json!(KIND_CI_GRANT)
    });
    push_receipt_mutation(&mut cases, "grant_target", |receipt| {
        let mut grant: serde_json::Value = serde_json::from_str(
            receipt.acceptance.grant_event[5]
                .as_str()
                .expect("grant content"),
        )
        .expect("grant");
        grant["target_repo_a"] = serde_json::json!("30617:bad:repo");
        receipt.acceptance.grant_event[5] =
            serde_json::json!(serde_json::to_string(&grant).expect("grant"));
    });
    push_receipt_mutation(&mut cases, "rerun_parent", |receipt| {
        let mut rerun: serde_json::Value = serde_json::from_str(
            receipt.acceptance.rerun_event[5]
                .as_str()
                .expect("rerun content"),
        )
        .expect("rerun");
        rerun["parent_attempt"] = serde_json::json!(2);
        receipt.acceptance.rerun_event[5] =
            serde_json::json!(serde_json::to_string(&rerun).expect("rerun"));
    });
    push_receipt_mutation(&mut cases, "tombstone_target", |receipt| {
        receipt.acceptance.tombstone_event[4] = serde_json::json!([["e", "29".repeat(32)]])
    });
    cases
}

fn push_receipt_mutation(
    cases: &mut Vec<AcceptanceBindingMutation>,
    name: &'static str,
    mutate: impl FnOnce(&mut AcceptanceBindingReceipt),
) {
    let mut receipt = canonical_acceptance_binding();
    mutate(&mut receipt);
    cases.push(AcceptanceBindingMutation {
        name,
        bytes: serde_json::to_vec(&receipt).expect("mutated receipt"),
    });
}

fn event_id(event: &serde_json::Value) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(event).expect("event bytes"),
    ))
}
