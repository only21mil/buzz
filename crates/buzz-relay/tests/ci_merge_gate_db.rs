//! Merge gate storage contract: the landing read the gate selects runs
//! with (workflow and channel scoping) and the append-only decision record
//! the finalize fence reads.
//! Run with scripts/postgres-test-local.py.

use std::collections::HashSet;

use buzz_core::ci::{
    request_tags, validate_signed_ci_event, CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION,
};
use buzz_core::CommunityId;
use buzz_db::ci::store_ci_event;
use buzz_db::ci_landing::list_ci_runs_for_tip;
use buzz_db::git_merge_gate::{
    find_merge_gate_allow, insert_merge_gate_decision, MergeGateDecisionInsert,
};
use chrono::{Duration, Utc};
use nostr::{EventBuilder, Keys, Kind};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

async fn pool() -> PgPool {
    let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("explicit isolated test database URL required");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("connect to merge gate storage database");
    buzz_db::migration::run_migrations(&pool)
        .await
        .expect("apply migrations");
    pool
}

async fn tenant_channel(pool: &PgPool) -> (CommunityId, Uuid) {
    let community_uuid = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
        .bind(community_uuid)
        .bind(format!("merge-gate-{}.test", community_uuid.simple()))
        .execute(pool)
        .await
        .expect("insert community");
    let channel_id = Uuid::new_v4();
    sqlx::query("INSERT INTO channels (community_id,id,name,created_by) VALUES ($1,$2,$3,$4)")
        .bind(community_uuid)
        .bind(channel_id)
        .bind("merge-gate")
        .bind(vec![7_u8; 32])
        .execute(pool)
        .await
        .expect("insert channel");
    (CommunityId::from_uuid(community_uuid), channel_id)
}

fn request(actor: &Keys, tip: &str, base: &str, digest: &str) -> CiRequestEnvelope {
    CiRequestEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_type: CiRequestType::Run,
        target_repo_a: format!("30617:{}:gate", actor.public_key().to_hex()),
        pr_root_event_id: "11".repeat(32),
        pr_update_event_id: None,
        source_clone_url: "https://example.com/gate.git".into(),
        immutable_source_ref: "refs/buzz/objects/gate".into(),
        tip_oid: tip.into(),
        source_branch: "feature".into(),
        base_ref: "refs/heads/main".into(),
        base_oid: base.into(),
        workflow_id: "ci".into(),
        workflow_digest: digest.into(),
        job_ids: vec!["test".into()],
        run_id: Uuid::new_v4().to_string(),
        attempt: 1,
        parent_attempt: None,
        parent_run_id: None,
        trigger_event_id: "11".repeat(32),
        actor: actor.public_key().to_hex(),
        timeout_seconds: 300,
        idempotency_key: Uuid::new_v4().to_string(),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_600,
    }
}

async fn store_request(
    pool: &PgPool,
    community: CommunityId,
    channel: Uuid,
    actor: &Keys,
    envelope: &CiRequestEnvelope,
) -> Uuid {
    let event = EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_CI_REQUEST as u16),
        serde_json::to_string(envelope).expect("serialize request"),
    )
    .tags(request_tags(&channel.to_string(), envelope).expect("request tags"))
    .sign_with_keys(actor)
    .expect("sign request");
    let validated = validate_signed_ci_event(&event, &channel.to_string(), &HashSet::new())
        .expect("validate request");
    store_ci_event(pool, community, channel, &event, &validated)
        .await
        .expect("store request");
    Uuid::parse_str(&envelope.run_id).expect("run id")
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn runs_for_tip_are_newest_first_and_scoped_to_repo_tip_and_workflow() {
    let pool = pool().await;
    let (community, channel) = tenant_channel(&pool).await;
    let actor = Keys::generate();
    let tip = "22".repeat(20);
    let base = "33".repeat(20);
    let coordinate = format!("30617:{}:gate", actor.public_key().to_hex());

    let older = store_request(
        &pool,
        community,
        channel,
        &actor,
        &request(&actor, &tip, &base, &"44".repeat(32)),
    )
    .await;
    let newer = store_request(
        &pool,
        community,
        channel,
        &actor,
        &request(&actor, &tip, &"55".repeat(20), &"66".repeat(32)),
    )
    .await;
    // Another tip and another workflow never appear.
    store_request(
        &pool,
        community,
        channel,
        &actor,
        &request(&actor, &"77".repeat(20), &base, &"44".repeat(32)),
    )
    .await;
    let mut other_workflow = request(&actor, &tip, &base, &"44".repeat(32));
    other_workflow.workflow_id = "release".into();
    store_request(&pool, community, channel, &actor, &other_workflow).await;

    let runs = list_ci_runs_for_tip(
        &pool,
        community,
        channel,
        &coordinate,
        &tip,
        Some("ci"),
        100,
    )
    .await
    .expect("list runs");
    assert_eq!(
        runs.iter().map(|r| r.run_id).collect::<Vec<_>>(),
        vec![newer, older]
    );
    assert_eq!(runs[1].base_oid, base);
    assert_eq!(hex::encode(&runs[1].workflow_digest), "44".repeat(32));
    assert_eq!(runs[0].base_oid, "55".repeat(20));
    assert_eq!(runs[0].channel_id, channel);
    assert!(runs[0].created_at >= runs[1].created_at);

    let none = list_ci_runs_for_tip(
        &pool,
        community,
        channel,
        &coordinate,
        &tip,
        Some("deploy"),
        100,
    )
    .await
    .expect("list runs");
    assert!(none.is_empty());
    let all = list_ci_runs_for_tip(&pool, community, channel, &coordinate, &tip, None, 100)
        .await
        .expect("list runs");
    assert_eq!(
        all.len(),
        3,
        "no workflow filter lists every workflow's run for the tip"
    );
    let other_channel = list_ci_runs_for_tip(
        &pool,
        community,
        Uuid::new_v4(),
        &coordinate,
        &tip,
        None,
        100,
    )
    .await
    .expect("list runs");
    assert!(
        other_channel.is_empty(),
        "runs stay invisible outside their channel"
    );
}

fn decision(coordinate: &str, code: &str, pusher: &str) -> MergeGateDecisionInsert {
    MergeGateDecisionInsert {
        target_repo_a: coordinate.into(),
        ref_name: "refs/heads/main".into(),
        old_oid: "1".repeat(40),
        new_oid: "2".repeat(40),
        candidate_oid: Some("2".repeat(40)),
        classification: "fast_forward".into(),
        run_id: None,
        check_event_id: None,
        signer: None,
        code: code.into(),
        mode: "enforce".into(),
        pusher: pusher.into(),
        bypass_event_id: None,
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn finalize_fence_finds_only_a_recent_allow_for_the_exact_update_and_pusher() {
    let pool = pool().await;
    let (community, _channel) = tenant_channel(&pool).await;
    let coordinate = format!("30617:{}:gate", "a".repeat(64));
    let pusher = "b".repeat(64);
    let window = Utc::now() - Duration::seconds(300);

    // A refusal is not an allow.
    insert_merge_gate_decision(
        &pool,
        community,
        &decision(&coordinate, "no_check", &pusher),
    )
    .await
    .expect("refusal row");
    assert!(find_merge_gate_allow(
        &pool,
        community,
        &coordinate,
        "refs/heads/main",
        &"1".repeat(40),
        &"2".repeat(40),
        &pusher,
        window
    )
    .await
    .expect("lookup")
    .is_none());

    // Another pusher's allow does not count.
    insert_merge_gate_decision(
        &pool,
        community,
        &decision(&coordinate, "allow", &"c".repeat(64)),
    )
    .await
    .expect("other pusher row");
    assert!(find_merge_gate_allow(
        &pool,
        community,
        &coordinate,
        "refs/heads/main",
        &"1".repeat(40),
        &"2".repeat(40),
        &pusher,
        window
    )
    .await
    .expect("lookup")
    .is_none());

    // The pusher's own allow is found, with its bypass when any.
    let mut with_bypass = decision(&coordinate, "allow", &pusher);
    with_bypass.classification = "bypass".into();
    with_bypass.bypass_event_id = Some(vec![9; 32]);
    let id = insert_merge_gate_decision(&pool, community, &with_bypass)
        .await
        .expect("allow row");
    let found = find_merge_gate_allow(
        &pool,
        community,
        &coordinate,
        "refs/heads/main",
        &"1".repeat(40),
        &"2".repeat(40),
        &pusher,
        window,
    )
    .await
    .expect("lookup")
    .expect("allow found");
    assert_eq!(found.id, id);
    assert_eq!(found.bypass_event_id, Some(vec![9; 32]));

    // A window that starts after the decision excludes it.
    assert!(find_merge_gate_allow(
        &pool,
        community,
        &coordinate,
        "refs/heads/main",
        &"1".repeat(40),
        &"2".repeat(40),
        &pusher,
        Utc::now() + Duration::seconds(60)
    )
    .await
    .expect("lookup")
    .is_none());

    // Another new OID is another update.
    assert!(find_merge_gate_allow(
        &pool,
        community,
        &coordinate,
        "refs/heads/main",
        &"1".repeat(40),
        &"3".repeat(40),
        &pusher,
        window
    )
    .await
    .expect("lookup")
    .is_none());

    // Unknown codes never reach the table.
    assert!(insert_merge_gate_decision(
        &pool,
        community,
        &decision(&coordinate, "refuse", &pusher)
    )
    .await
    .is_err());
}
