//! PostgreSQL integration contract for CI ingest storage and reducer loading.

use std::collections::HashSet;

use buzz_core::ci::{
    job_status_tags, request_tags, validate_signed_ci_event, CiJobState, CiJobStatusEnvelope,
    CiRequestEnvelope, CiRequestType, CiSkipPolicy, CI_SCHEMA_VERSION,
};
use buzz_core::CommunityId;
use buzz_db::ci::{
    get_ci_run_request, list_ci_run_events, load_ci_reducer_events, store_ci_event,
    StoreCiEventOutcome,
};
use buzz_relay::ci::{reduce_signed_ci_graph, SignedCiGraphInput};
use nostr::{Event, EventBuilder, Keys, Kind};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

async fn pool() -> PgPool {
    let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".into());
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("connect to CI ingest storage database");
    buzz_db::migration::run_migrations(&pool)
        .await
        .expect("apply migrations");
    pool
}

async fn tenant_channel(pool: &PgPool) -> (CommunityId, Uuid) {
    let community_uuid = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
        .bind(community_uuid)
        .bind(format!("ci-ingest-{}.test", community_uuid.simple()))
        .execute(pool)
        .await
        .expect("insert community");
    let channel_id = Uuid::new_v4();
    sqlx::query("INSERT INTO channels (community_id,id,name,created_by) VALUES ($1,$2,$3,$4)")
        .bind(community_uuid)
        .bind(channel_id)
        .bind("ci-ingest")
        .bind(vec![7_u8; 32])
        .execute(pool)
        .await
        .expect("insert channel");
    (CommunityId::from_uuid(community_uuid), channel_id)
}

fn request(actor: &Keys, run_id: Uuid) -> CiRequestEnvelope {
    let root = "11".repeat(32);
    CiRequestEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_type: CiRequestType::Run,
        target_repo_a: format!("30617:{}:ci-ingest", actor.public_key().to_hex()),
        pr_root_event_id: root.clone(),
        pr_update_event_id: None,
        source_clone_url: "https://example.com/ci-ingest.git".into(),
        immutable_source_ref: "refs/buzz/objects/ci-ingest".into(),
        tip_oid: "22".repeat(20),
        source_branch: "feature".into(),
        base_ref: "refs/heads/main".into(),
        base_oid: "33".repeat(20),
        workflow_id: "ci".into(),
        workflow_digest: "44".repeat(32),
        job_ids: vec!["test".into()],
        run_id: run_id.to_string(),
        attempt: 1,
        parent_attempt: None,
        parent_run_id: None,
        trigger_event_id: root,
        actor: actor.public_key().to_hex(),
        timeout_seconds: 300,
        idempotency_key: Uuid::new_v4().to_string(),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_600,
    }
}

fn signed_request(keys: &Keys, channel_id: Uuid, request: &CiRequestEnvelope) -> Event {
    EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_CI_REQUEST as u16),
        serde_json::to_string(request).expect("serialize request"),
    )
    .tags(request_tags(&channel_id.to_string(), request).expect("request tags"))
    .sign_with_keys(keys)
    .expect("sign request")
}

fn job_status(
    control: &Keys,
    channel_id: Uuid,
    request: &CiRequestEnvelope,
    request_event_id: &str,
    sequence: u64,
    state: CiJobState,
) -> Event {
    let terminal = state.is_terminal();
    let envelope = CiJobStatusEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: request_event_id.to_owned(),
        run_id: request.run_id.clone(),
        workflow_id: request.workflow_id.clone(),
        target_repo_a: request.target_repo_a.clone(),
        tip_oid: request.tip_oid.clone(),
        base_oid: request.base_oid.clone(),
        job_id: "test".into(),
        name: "test".into(),
        attempt: 1,
        parent_attempt: None,
        sequence,
        state,
        conclusion: terminal.then(|| "success".into()),
        reason: None,
        required: true,
        skip_policy: CiSkipPolicy::Forbid,
        selected_job_instance: "test".into(),
        also_reruns: Vec::new(),
        started_at: (sequence >= 2).then_some(1_800_000_010),
        finished_at: terminal.then_some(1_800_000_020),
        log_ref: terminal.then(|| "55".repeat(32)),
        artifact_refs: Vec::new(),
        relay_signer: control.public_key().to_hex(),
    };
    EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_CI_JOB_STATUS as u16),
        serde_json::to_string(&envelope).expect("serialize job status"),
    )
    .tags(job_status_tags(&channel_id.to_string(), &envelope).expect("job status tags"))
    .sign_with_keys(control)
    .expect("sign job status")
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn request_and_status_chain_round_trip_into_reducer() {
    let pool = pool().await;
    let (community_id, channel_id) = tenant_channel(&pool).await;
    let actor = Keys::generate();
    let control = Keys::generate();
    let authorized_status_signers = HashSet::from([control.public_key().to_hex()]);
    let run_id = Uuid::new_v4();
    let request_envelope = request(&actor, run_id);
    let request_event = signed_request(&actor, channel_id, &request_envelope);
    let validated = validate_signed_ci_event(
        &request_event,
        &channel_id.to_string(),
        &authorized_status_signers,
    )
    .expect("validate request");
    assert!(matches!(
        store_ci_event(&pool, community_id, channel_id, &request_event, &validated)
            .await
            .expect("store request"),
        StoreCiEventOutcome::Stored(_)
    ));

    for (sequence, state) in [
        (1, CiJobState::Queued),
        (2, CiJobState::Running),
        (3, CiJobState::Success),
    ] {
        let event = job_status(
            &control,
            channel_id,
            &request_envelope,
            &request_event.id.to_hex(),
            sequence,
            state,
        );
        let validated =
            validate_signed_ci_event(&event, &channel_id.to_string(), &authorized_status_signers)
                .expect("validate status");
        assert!(matches!(
            store_ci_event(&pool, community_id, channel_id, &event, &validated)
                .await
                .expect("store status"),
            StoreCiEventOutcome::Stored(_)
        ));
    }

    let stored_request = get_ci_run_request(&pool, community_id, channel_id, run_id)
        .await
        .expect("query request")
        .expect("stored request");
    assert_eq!(stored_request.watch_cursor, 1);
    assert_eq!(stored_request.stored_event.event, request_event);

    let events = list_ci_run_events(&pool, community_id, channel_id, run_id, 0, 10)
        .await
        .expect("list run events");
    assert_eq!(events.len(), 4);
    assert_eq!(
        events
            .iter()
            .map(|event| event.watch_cursor)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );

    let reducer_events = load_ci_reducer_events(&pool, community_id, channel_id, run_id)
        .await
        .expect("load reducer events");
    let graph = reduce_signed_ci_graph(&SignedCiGraphInput {
        channel_id: channel_id.to_string(),
        authorized_status_signers,
        request_events: reducer_events.request_events,
        job_status_events: reducer_events.job_status_events,
    })
    .expect("reduce stored graph");
    assert_eq!(graph.run_id, run_id.to_string());
    assert_eq!(graph.selected_job_attempts, vec![("test".into(), 1)]);
}
