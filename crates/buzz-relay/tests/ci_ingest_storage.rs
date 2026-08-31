//! PostgreSQL integration contract for CI ingest storage and reducer loading.

use std::collections::HashSet;

use buzz_core::ci::{
    evidence_finalized_tags, job_status_tags, log_reference_tags, request_tags, run_status_tags,
    teardown_attestation_tags, validate_signed_ci_event, CiEvidenceFinalizedEnvelope,
    CiFinalizedJobAttempt, CiJobState, CiJobStatusEnvelope, CiLogReferenceEnvelope,
    CiRequestEnvelope, CiRequestType, CiRunState, CiRunStatusEnvelope, CiSkipPolicy,
    CiTeardownAttestationEnvelope, CiTeardownLease, ValidatedCiEnvelope, CI_SCHEMA_VERSION,
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

fn rerun_request(
    initial: &CiRequestEnvelope,
    job_id: &str,
    parent_attempt: u32,
) -> CiRequestEnvelope {
    let mut rerun = initial.clone();
    rerun.request_type = CiRequestType::Rerun;
    rerun.job_ids = vec![job_id.to_string()];
    rerun.attempt = parent_attempt + 1;
    rerun.parent_attempt = Some(parent_attempt);
    rerun.parent_run_id = Some(initial.run_id.clone());
    rerun.idempotency_key = Uuid::new_v4().to_string();
    rerun
}

#[allow(clippy::too_many_arguments)]
fn selected_job_status(
    control: &Keys,
    channel_id: Uuid,
    request: &CiRequestEnvelope,
    request_event_id: &str,
    job_id: &str,
    attempt: u32,
    parent_attempt: Option<u32>,
    sequence: u64,
    state: CiJobState,
    also_reruns: &[&str],
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
        job_id: job_id.into(),
        name: job_id.into(),
        attempt,
        parent_attempt,
        sequence,
        state,
        conclusion: terminal.then(|| match state {
            CiJobState::Success => "success".into(),
            CiJobState::Failure => "failure".into(),
            _ => "terminal".into(),
        }),
        reason: None,
        required: true,
        skip_policy: CiSkipPolicy::Forbid,
        selected_job_instance: job_id.into(),
        also_reruns: also_reruns
            .iter()
            .map(|job_id| (*job_id).to_string())
            .collect(),
        started_at: (sequence >= 2).then_some(1_800_000_010),
        finished_at: terminal.then_some(1_800_000_020),
        log_ref: None,
        artifact_refs: Vec::new(),
        relay_signer: control.public_key().to_hex(),
    };
    EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_CI_JOB_STATUS as u16),
        serde_json::to_string(&envelope).expect("serialize selected job status"),
    )
    .tags(job_status_tags(&channel_id.to_string(), &envelope).expect("selected job status tags"))
    .sign_with_keys(control)
    .expect("sign selected job status")
}

#[allow(clippy::too_many_arguments)]
async fn store_selected_job_chain(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    control: &Keys,
    request: &CiRequestEnvelope,
    request_event: &Event,
    job_id: &str,
    attempt: u32,
    parent_attempt: Option<u32>,
    terminal_state: CiJobState,
    also_reruns: &[&str],
    authorized_status_signers: &HashSet<String>,
) {
    for (sequence, state) in [
        (1, CiJobState::Queued),
        (2, CiJobState::Running),
        (3, terminal_state),
    ] {
        let event = selected_job_status(
            control,
            channel_id,
            request,
            &request_event.id.to_hex(),
            job_id,
            attempt,
            parent_attempt,
            sequence,
            state,
            also_reruns,
        );
        store(
            pool,
            community_id,
            channel_id,
            &event,
            authorized_status_signers,
        )
        .await
        .expect("store selected job status fixture");
    }
}

fn job_status(
    control: &Keys,
    channel_id: Uuid,
    request: &CiRequestEnvelope,
    request_event_id: &str,
    sequence: u64,
    state: CiJobState,
    log_ref: Option<String>,
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
        attempt: request.attempt,
        parent_attempt: request.parent_attempt,
        sequence,
        state,
        conclusion: terminal.then(|| match state {
            CiJobState::Success => "success".into(),
            CiJobState::Failure => "failure".into(),
            CiJobState::Cancelled => "cancelled".into(),
            CiJobState::TimedOut => "timed_out".into(),
            CiJobState::Skipped => "skipped".into(),
            CiJobState::Queued | CiJobState::Running => unreachable!(),
        }),
        reason: None,
        required: true,
        skip_policy: CiSkipPolicy::Forbid,
        selected_job_instance: "test".into(),
        also_reruns: Vec::new(),
        started_at: (sequence >= 2).then_some(1_800_000_010),
        finished_at: terminal.then_some(1_800_000_020),
        log_ref,
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

fn run_status(
    control: &Keys,
    channel_id: Uuid,
    request: &CiRequestEnvelope,
    request_event_id: &str,
    sequence: u64,
    state: CiRunState,
) -> Event {
    let terminal = state.is_terminal();
    let envelope = CiRunStatusEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: request_event_id.to_owned(),
        run_id: request.run_id.clone(),
        workflow_id: request.workflow_id.clone(),
        target_repo_a: request.target_repo_a.clone(),
        tip_oid: request.tip_oid.clone(),
        base_oid: request.base_oid.clone(),
        attempt: request.attempt,
        sequence,
        state,
        conclusion: terminal.then(|| match state {
            CiRunState::Success => "success".into(),
            CiRunState::Failure => "failure".into(),
            CiRunState::Cancelled => "cancelled".into(),
            CiRunState::TimedOut => "timed_out".into(),
            CiRunState::InfrastructureFailure => "infrastructure_failure".into(),
            CiRunState::Queued | CiRunState::Running => unreachable!(),
        }),
        reason: None,
        started_at: (sequence >= 2).then_some(1_800_000_010),
        finished_at: terminal.then_some(1_800_000_040),
        job_ids: request.job_ids.clone(),
        relay_signer: control.public_key().to_hex(),
    };
    EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_CI_RUN_STATUS as u16),
        serde_json::to_string(&envelope).expect("serialize run status"),
    )
    .tags(run_status_tags(&channel_id.to_string(), &envelope).expect("run status tags"))
    .sign_with_keys(control)
    .expect("sign run status")
}

fn log_reference(
    control: &Keys,
    channel_id: Uuid,
    request: &CiRequestEnvelope,
    request_event_id: &str,
) -> Event {
    let envelope = CiLogReferenceEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: request_event_id.to_owned(),
        run_id: request.run_id.clone(),
        workflow_id: request.workflow_id.clone(),
        target_repo_a: request.target_repo_a.clone(),
        tip_oid: request.tip_oid.clone(),
        job_id: "test".into(),
        attempt: request.attempt,
        log_sha256: "55".repeat(32),
        byte_length: 3,
        cap_bytes: 1024,
        truncated: false,
        url: Some("https://example.com/log".into()),
        inline: None,
        created_at: 1_800_000_020,
        relay_signer: control.public_key().to_hex(),
    };
    EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_CI_LOG_REFERENCE as u16),
        serde_json::to_string(&envelope).expect("serialize log reference"),
    )
    .tags(log_reference_tags(&channel_id.to_string(), &envelope).expect("log reference tags"))
    .sign_with_keys(control)
    .expect("sign log reference")
}

fn evidence_finalized(
    control: &Keys,
    channel_id: Uuid,
    request: &CiRequestEnvelope,
    request_event_id: &str,
    job_id: &str,
    log_ref: &str,
) -> Event {
    let envelope = CiEvidenceFinalizedEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: request_event_id.to_owned(),
        run_id: request.run_id.clone(),
        workflow_id: request.workflow_id.clone(),
        target_repo_a: request.target_repo_a.clone(),
        tip_oid: request.tip_oid.clone(),
        attempt: request.attempt,
        finalized_job_attempts: vec![CiFinalizedJobAttempt {
            job_id: job_id.into(),
            attempt: request.attempt,
            log_ref: log_ref.into(),
            artifact_refs: Vec::new(),
        }],
        finalized_at: 1_800_000_030,
        relay_signer: control.public_key().to_hex(),
    };
    EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_CI_EVIDENCE_FINALIZED as u16),
        serde_json::to_string(&envelope).expect("serialize evidence fact"),
    )
    .tags(evidence_finalized_tags(&channel_id.to_string(), &envelope).expect("evidence fact tags"))
    .sign_with_keys(control)
    .expect("sign evidence fact")
}

fn teardown_attestation(
    control: &Keys,
    channel_id: Uuid,
    request: &CiRequestEnvelope,
    request_event_id: &str,
) -> Event {
    let envelope = CiTeardownAttestationEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: request_event_id.to_owned(),
        run_id: request.run_id.clone(),
        workflow_id: request.workflow_id.clone(),
        target_repo_a: request.target_repo_a.clone(),
        tip_oid: request.tip_oid.clone(),
        base_oid: request.base_oid.clone(),
        workflow_digest: request.workflow_digest.clone(),
        attempt: request.attempt,
        leases: vec![CiTeardownLease {
            job_id: "test".into(),
            attempt: request.attempt,
            lease_id: Uuid::new_v4().to_string(),
        }],
        lease_empty: true,
        teardown_at: 1_800_000_035,
        relay_signer: control.public_key().to_hex(),
    };
    EventBuilder::new(
        Kind::Custom(buzz_core::kind::KIND_CI_TEARDOWN_ATTESTATION as u16),
        serde_json::to_string(&envelope).expect("serialize teardown fact"),
    )
    .tags(
        teardown_attestation_tags(&channel_id.to_string(), &envelope).expect("teardown fact tags"),
    )
    .sign_with_keys(control)
    .expect("sign teardown fact")
}

async fn store(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    event: &Event,
    authorized_status_signers: &HashSet<String>,
) -> buzz_db::Result<StoreCiEventOutcome> {
    let validated: ValidatedCiEnvelope =
        validate_signed_ci_event(event, &channel_id.to_string(), authorized_status_signers)
            .expect("validate signed CI event");
    store_ci_event(pool, community_id, channel_id, event, &validated).await
}

async fn new_stored_request(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    actor: &Keys,
    authorized_status_signers: &HashSet<String>,
) -> (CiRequestEnvelope, Event) {
    let envelope = request(actor, Uuid::new_v4());
    let event = signed_request(actor, channel_id, &envelope);
    store(
        pool,
        community_id,
        channel_id,
        &event,
        authorized_status_signers,
    )
    .await
    .expect("store request fixture");
    (envelope, event)
}

async fn store_terminal_job_chain(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    control: &Keys,
    request: &CiRequestEnvelope,
    request_event: &Event,
    authorized_status_signers: &HashSet<String>,
) -> Event {
    for (sequence, state) in [(1, CiRunState::Queued), (2, CiRunState::Running)] {
        let event = run_status(
            control,
            channel_id,
            request,
            &request_event.id.to_hex(),
            sequence,
            state,
        );
        store(
            pool,
            community_id,
            channel_id,
            &event,
            authorized_status_signers,
        )
        .await
        .expect("store run status fixture");
    }
    for (sequence, state) in [(1, CiJobState::Queued), (2, CiJobState::Running)] {
        let event = job_status(
            control,
            channel_id,
            request,
            &request_event.id.to_hex(),
            sequence,
            state,
            None,
        );
        store(
            pool,
            community_id,
            channel_id,
            &event,
            authorized_status_signers,
        )
        .await
        .expect("store job status fixture");
    }
    let log = log_reference(control, channel_id, request, &request_event.id.to_hex());
    store(
        pool,
        community_id,
        channel_id,
        &log,
        authorized_status_signers,
    )
    .await
    .expect("store log fixture");
    let terminal = job_status(
        control,
        channel_id,
        request,
        &request_event.id.to_hex(),
        3,
        CiJobState::Success,
        Some(log.id.to_hex()),
    );
    store(
        pool,
        community_id,
        channel_id,
        &terminal,
        authorized_status_signers,
    )
    .await
    .expect("store terminal job fixture");
    log
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

    for (sequence, state) in [(1, CiRunState::Queued), (2, CiRunState::Running)] {
        let event = run_status(
            &control,
            channel_id,
            &request_envelope,
            &request_event.id.to_hex(),
            sequence,
            state,
        );
        store(
            &pool,
            community_id,
            channel_id,
            &event,
            &authorized_status_signers,
        )
        .await
        .expect("store run status");
    }

    for (sequence, state) in [(1, CiJobState::Queued), (2, CiJobState::Running)] {
        let event = job_status(
            &control,
            channel_id,
            &request_envelope,
            &request_event.id.to_hex(),
            sequence,
            state,
            None,
        );
        store(
            &pool,
            community_id,
            channel_id,
            &event,
            &authorized_status_signers,
        )
        .await
        .expect("store job status");
    }

    let log = log_reference(
        &control,
        channel_id,
        &request_envelope,
        &request_event.id.to_hex(),
    );
    store(
        &pool,
        community_id,
        channel_id,
        &log,
        &authorized_status_signers,
    )
    .await
    .expect("store log reference");
    let terminal_job = job_status(
        &control,
        channel_id,
        &request_envelope,
        &request_event.id.to_hex(),
        3,
        CiJobState::Success,
        Some(log.id.to_hex()),
    );
    store(
        &pool,
        community_id,
        channel_id,
        &terminal_job,
        &authorized_status_signers,
    )
    .await
    .expect("store terminal job status");
    let evidence = evidence_finalized(
        &control,
        channel_id,
        &request_envelope,
        &request_event.id.to_hex(),
        "test",
        &log.id.to_hex(),
    );
    store(
        &pool,
        community_id,
        channel_id,
        &evidence,
        &authorized_status_signers,
    )
    .await
    .expect("store evidence fact");
    let teardown = teardown_attestation(
        &control,
        channel_id,
        &request_envelope,
        &request_event.id.to_hex(),
    );
    store(
        &pool,
        community_id,
        channel_id,
        &teardown,
        &authorized_status_signers,
    )
    .await
    .expect("store teardown fact");
    let success = run_status(
        &control,
        channel_id,
        &request_envelope,
        &request_event.id.to_hex(),
        3,
        CiRunState::Success,
    );
    store(
        &pool,
        community_id,
        channel_id,
        &success,
        &authorized_status_signers,
    )
    .await
    .expect("store terminal run success");

    let stored_request = get_ci_run_request(&pool, community_id, channel_id, run_id)
        .await
        .expect("query request")
        .expect("stored request");
    assert_eq!(stored_request.watch_cursor, 1);
    assert_eq!(stored_request.stored_event.event, request_event);

    let events = list_ci_run_events(&pool, community_id, channel_id, run_id, 0, 10)
        .await
        .expect("list run events");
    assert_eq!(events.len(), 10);
    assert_eq!(
        events
            .iter()
            .map(|event| event.watch_cursor)
            .collect::<Vec<_>>(),
        (1..=10).collect::<Vec<_>>()
    );

    let reducer_events = load_ci_reducer_events(&pool, community_id, channel_id, run_id)
        .await
        .expect("load reducer events");
    let graph = reduce_signed_ci_graph(&SignedCiGraphInput {
        channel_id: channel_id.to_string(),
        authorized_status_signers: authorized_status_signers.clone(),
        request_events: reducer_events.request_events,
        job_status_events: reducer_events.job_status_events,
    })
    .expect("reduce stored graph");
    assert_eq!(graph.run_id, run_id.to_string());
    assert_eq!(graph.selected_job_attempts, vec![("test".into(), 1)]);

    let (missing_status_request, missing_status_event) = new_stored_request(
        &pool,
        community_id,
        channel_id,
        &actor,
        &authorized_status_signers,
    )
    .await;
    for (sequence, state) in [(1, CiRunState::Queued), (2, CiRunState::Running)] {
        let event = run_status(
            &control,
            channel_id,
            &missing_status_request,
            &missing_status_event.id.to_hex(),
            sequence,
            state,
        );
        store(
            &pool,
            community_id,
            channel_id,
            &event,
            &authorized_status_signers,
        )
        .await
        .expect("store missing-status run transition");
    }
    let missing_status_evidence = evidence_finalized(
        &control,
        channel_id,
        &missing_status_request,
        &missing_status_event.id.to_hex(),
        "test",
        &"66".repeat(32),
    );
    assert!(matches!(
        store(
            &pool,
            community_id,
            channel_id,
            &missing_status_evidence,
            &authorized_status_signers,
        )
        .await,
        Err(buzz_db::DbError::InvalidData(_))
    ));
    let missing_status_success = run_status(
        &control,
        channel_id,
        &missing_status_request,
        &missing_status_event.id.to_hex(),
        3,
        CiRunState::Success,
    );
    assert!(matches!(
        store(
            &pool,
            community_id,
            channel_id,
            &missing_status_success,
            &authorized_status_signers,
        )
        .await,
        Err(buzz_db::DbError::InvalidData(_))
    ));

    let (wrong_jobs_request, wrong_jobs_event) = new_stored_request(
        &pool,
        community_id,
        channel_id,
        &actor,
        &authorized_status_signers,
    )
    .await;
    let wrong_jobs_log = store_terminal_job_chain(
        &pool,
        community_id,
        channel_id,
        &control,
        &wrong_jobs_request,
        &wrong_jobs_event,
        &authorized_status_signers,
    )
    .await;
    let wrong_jobs_evidence = evidence_finalized(
        &control,
        channel_id,
        &wrong_jobs_request,
        &wrong_jobs_event.id.to_hex(),
        "other",
        &wrong_jobs_log.id.to_hex(),
    );
    assert!(matches!(
        store(
            &pool,
            community_id,
            channel_id,
            &wrong_jobs_evidence,
            &authorized_status_signers,
        )
        .await,
        Err(buzz_db::DbError::InvalidData(_))
    ));
    let wrong_jobs_teardown = teardown_attestation(
        &control,
        channel_id,
        &wrong_jobs_request,
        &wrong_jobs_event.id.to_hex(),
    );
    store(
        &pool,
        community_id,
        channel_id,
        &wrong_jobs_teardown,
        &authorized_status_signers,
    )
    .await
    .expect("store teardown after rejected evidence");
    let wrong_jobs_success = run_status(
        &control,
        channel_id,
        &wrong_jobs_request,
        &wrong_jobs_event.id.to_hex(),
        3,
        CiRunState::Success,
    );
    assert!(matches!(
        store(
            &pool,
            community_id,
            channel_id,
            &wrong_jobs_success,
            &authorized_status_signers,
        )
        .await,
        Err(buzz_db::DbError::InvalidData(_))
    ));

    let (wrong_run_request, wrong_run_event) = new_stored_request(
        &pool,
        community_id,
        channel_id,
        &actor,
        &authorized_status_signers,
    )
    .await;
    let wrong_run_log = store_terminal_job_chain(
        &pool,
        community_id,
        channel_id,
        &control,
        &wrong_run_request,
        &wrong_run_event,
        &authorized_status_signers,
    )
    .await;
    let wrong_run_evidence = evidence_finalized(
        &control,
        channel_id,
        &wrong_run_request,
        &wrong_run_event.id.to_hex(),
        "test",
        &wrong_run_log.id.to_hex(),
    );
    store(
        &pool,
        community_id,
        channel_id,
        &wrong_run_evidence,
        &authorized_status_signers,
    )
    .await
    .expect("store evidence before wrong-run teardown");
    let mut other_run = wrong_run_request.clone();
    other_run.run_id = Uuid::new_v4().to_string();
    let wrong_run_teardown = teardown_attestation(
        &control,
        channel_id,
        &other_run,
        &wrong_run_event.id.to_hex(),
    );
    assert!(matches!(
        store(
            &pool,
            community_id,
            channel_id,
            &wrong_run_teardown,
            &authorized_status_signers,
        )
        .await,
        Err(buzz_db::DbError::NotFound(_)) | Err(buzz_db::DbError::InvalidData(_))
    ));
    let wrong_run_success = run_status(
        &control,
        channel_id,
        &wrong_run_request,
        &wrong_run_event.id.to_hex(),
        3,
        CiRunState::Success,
    );
    assert!(matches!(
        store(
            &pool,
            community_id,
            channel_id,
            &wrong_run_success,
            &authorized_status_signers,
        )
        .await,
        Err(buzz_db::DbError::InvalidData(_))
    ));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn rerun_final_facts_bind_only_the_final_request_and_selected_graph() {
    let pool = pool().await;
    let (community_id, channel_id) = tenant_channel(&pool).await;
    let actor = Keys::generate();
    let control = Keys::generate();
    let authorized_status_signers = HashSet::from([control.public_key().to_hex()]);
    let initial = request(&actor, Uuid::new_v4());
    let initial_event = signed_request(&actor, channel_id, &initial);
    store(
        &pool,
        community_id,
        channel_id,
        &initial_event,
        &authorized_status_signers,
    )
    .await
    .expect("store initial request");
    for (sequence, state) in [
        (1, CiRunState::Queued),
        (2, CiRunState::Running),
        (3, CiRunState::Failure),
    ] {
        let event = run_status(
            &control,
            channel_id,
            &initial,
            &initial_event.id.to_hex(),
            sequence,
            state,
        );
        store(
            &pool,
            community_id,
            channel_id,
            &event,
            &authorized_status_signers,
        )
        .await
        .expect("store initial run status");
    }
    store_selected_job_chain(
        &pool,
        community_id,
        channel_id,
        &control,
        &initial,
        &initial_event,
        "test",
        1,
        None,
        CiJobState::Failure,
        &[],
        &authorized_status_signers,
    )
    .await;

    let rerun = rerun_request(&initial, "test", 1);
    let rerun_event = signed_request(&actor, channel_id, &rerun);
    store(
        &pool,
        community_id,
        channel_id,
        &rerun_event,
        &authorized_status_signers,
    )
    .await
    .expect("store rerun request");
    for (sequence, state) in [(1, CiRunState::Queued), (2, CiRunState::Running)] {
        let event = run_status(
            &control,
            channel_id,
            &rerun,
            &rerun_event.id.to_hex(),
            sequence,
            state,
        );
        store(
            &pool,
            community_id,
            channel_id,
            &event,
            &authorized_status_signers,
        )
        .await
        .expect("store rerun status");
    }
    let log = store_terminal_job_chain(
        &pool,
        community_id,
        channel_id,
        &control,
        &rerun,
        &rerun_event,
        &authorized_status_signers,
    )
    .await;

    let stale_evidence = evidence_finalized(
        &control,
        channel_id,
        &rerun,
        &initial_event.id.to_hex(),
        "test",
        &log.id.to_hex(),
    );
    assert!(matches!(
        store(
            &pool,
            community_id,
            channel_id,
            &stale_evidence,
            &authorized_status_signers,
        )
        .await,
        Err(buzz_db::DbError::InvalidData(_))
    ));

    let evidence = evidence_finalized(
        &control,
        channel_id,
        &rerun,
        &rerun_event.id.to_hex(),
        "test",
        &log.id.to_hex(),
    );
    store(
        &pool,
        community_id,
        channel_id,
        &evidence,
        &authorized_status_signers,
    )
    .await
    .expect("store final-request evidence");
    let teardown = teardown_attestation(&control, channel_id, &rerun, &rerun_event.id.to_hex());
    store(
        &pool,
        community_id,
        channel_id,
        &teardown,
        &authorized_status_signers,
    )
    .await
    .expect("store final-request teardown");
    let success = run_status(
        &control,
        channel_id,
        &rerun,
        &rerun_event.id.to_hex(),
        3,
        CiRunState::Success,
    );
    store(
        &pool,
        community_id,
        channel_id,
        &success,
        &authorized_status_signers,
    )
    .await
    .expect("store terminal success after final facts");

    let events = list_ci_run_events(
        &pool,
        community_id,
        channel_id,
        Uuid::parse_str(&initial.run_id).unwrap(),
        0,
        100,
    )
    .await
    .expect("list final run history");
    let terminal_facts = events
        .iter()
        .filter(|stored| {
            matches!(
                stored.stored_event.event.kind.as_u16() as u32,
                buzz_core::kind::KIND_CI_EVIDENCE_FINALIZED
                    | buzz_core::kind::KIND_CI_TEARDOWN_ATTESTATION
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(terminal_facts.len(), 2);
    assert!(terminal_facts.iter().all(|stored| {
        let envelope: serde_json::Value =
            serde_json::from_str(&stored.stored_event.event.content).unwrap();
        envelope["request_event_id"] == rerun_event.id.to_hex() && envelope["attempt"] == 2
    }));
    let evidence_position = events
        .iter()
        .position(|stored| stored.stored_event.event.id == evidence.id)
        .expect("finalized evidence event");
    let teardown_position = events
        .iter()
        .position(|stored| stored.stored_event.event.id == teardown.id)
        .expect("teardown event");
    let success_position = events
        .iter()
        .position(|stored| stored.stored_event.event.id == success.id)
        .expect("terminal success event");
    assert!(evidence_position < success_position);
    assert!(teardown_position < success_position);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn stale_fanout_rerun_is_rejected_without_poisoning_selected_graph() {
    let pool = pool().await;
    let (community_id, channel_id) = tenant_channel(&pool).await;
    let actor = Keys::generate();
    let control = Keys::generate();
    let authorized_status_signers = HashSet::from([control.public_key().to_hex()]);

    let mut initial = request(&actor, Uuid::new_v4());
    initial.job_ids = vec!["build".into(), "test".into()];
    let initial_event = signed_request(&actor, channel_id, &initial);
    store(
        &pool,
        community_id,
        channel_id,
        &initial_event,
        &authorized_status_signers,
    )
    .await
    .expect("store initial request");
    for job_id in ["build", "test"] {
        store_selected_job_chain(
            &pool,
            community_id,
            channel_id,
            &control,
            &initial,
            &initial_event,
            job_id,
            1,
            None,
            CiJobState::Failure,
            &[],
            &authorized_status_signers,
        )
        .await;
    }

    let build_rerun = rerun_request(&initial, "build", 1);
    let build_rerun_event = signed_request(&actor, channel_id, &build_rerun);
    store(
        &pool,
        community_id,
        channel_id,
        &build_rerun_event,
        &authorized_status_signers,
    )
    .await
    .expect("store build rerun");
    store_selected_job_chain(
        &pool,
        community_id,
        channel_id,
        &control,
        &build_rerun,
        &build_rerun_event,
        "build",
        2,
        Some(1),
        CiJobState::Success,
        &["test"],
        &authorized_status_signers,
    )
    .await;
    store_selected_job_chain(
        &pool,
        community_id,
        channel_id,
        &control,
        &build_rerun,
        &build_rerun_event,
        "test",
        2,
        Some(1),
        CiJobState::Failure,
        &[],
        &authorized_status_signers,
    )
    .await;

    let stale_test_rerun = rerun_request(&initial, "test", 1);
    let stale_test_rerun_event = signed_request(&actor, channel_id, &stale_test_rerun);
    assert!(matches!(
        store(
            &pool,
            community_id,
            channel_id,
            &stale_test_rerun_event,
            &authorized_status_signers,
        )
        .await,
        Err(buzz_db::DbError::Conflict(message)) if message.contains("currently selects attempt 2")
    ));

    let reducer_after_rejection = load_ci_reducer_events(
        &pool,
        community_id,
        channel_id,
        Uuid::parse_str(&initial.run_id).unwrap(),
    )
    .await
    .expect("load graph after rejected rerun");
    assert_eq!(reducer_after_rejection.request_events.len(), 2);

    let fresh_test_rerun = rerun_request(&initial, "test", 2);
    let fresh_test_rerun_event = signed_request(&actor, channel_id, &fresh_test_rerun);
    store(
        &pool,
        community_id,
        channel_id,
        &fresh_test_rerun_event,
        &authorized_status_signers,
    )
    .await
    .expect("store fresh test rerun");
    store_selected_job_chain(
        &pool,
        community_id,
        channel_id,
        &control,
        &fresh_test_rerun,
        &fresh_test_rerun_event,
        "test",
        3,
        Some(2),
        CiJobState::Success,
        &[],
        &authorized_status_signers,
    )
    .await;

    let reducer_events = load_ci_reducer_events(
        &pool,
        community_id,
        channel_id,
        Uuid::parse_str(&initial.run_id).unwrap(),
    )
    .await
    .expect("load completable graph");
    let graph = reduce_signed_ci_graph(&SignedCiGraphInput {
        channel_id: channel_id.to_string(),
        authorized_status_signers,
        request_events: reducer_events.request_events,
        job_status_events: reducer_events.job_status_events,
    })
    .expect("rejected stale rerun must leave a completable selected graph");
    assert_eq!(
        graph.selected_job_attempts,
        vec![("build".into(), 2), ("test".into(), 3)]
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn run_read_exports_bind_membership_channel_and_cursor_bounds() {
    let pool = pool().await;
    let (community_id, channel_id) = tenant_channel(&pool).await;
    let db = buzz_db::Db::from_pool(pool.clone());
    let actor = Keys::generate();
    let control = Keys::generate();
    let authorized_status_signers = HashSet::from([control.public_key().to_hex()]);

    // Membership fixtures: a standing member, a removed member, and one
    // pubkey that was never a member.
    let member: Vec<u8> = (0..32).collect();
    let removed_member: Vec<u8> = (32..64).collect();
    let stranger: Vec<u8> = (200..232).collect();
    for (pubkey, role) in [
        (member.clone(), "owner"),
        (removed_member.clone(), "member"),
    ] {
        sqlx::query(
            "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
             VALUES ($1, $2, $3, $4::member_role)",
        )
        .bind(community_id.as_uuid())
        .bind(channel_id)
        .bind(&pubkey)
        .bind(role)
        .execute(&pool)
        .await
        .expect("insert channel member fixture");
    }
    sqlx::query(
        "UPDATE channel_members SET removed_at = now() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(&removed_member)
    .execute(&pool)
    .await
    .expect("remove member fixture");

    let (request_envelope, request_event) = new_stored_request(
        &pool,
        community_id,
        channel_id,
        &actor,
        &authorized_status_signers,
    )
    .await;
    let run_id = Uuid::parse_str(&request_envelope.run_id).expect("run uuid");
    store_terminal_job_chain(
        &pool,
        community_id,
        channel_id,
        &control,
        &request_envelope,
        &request_event,
        &authorized_status_signers,
    )
    .await;

    // The Db-level read surface resolves the run's channel only for a
    // current channel member.
    let member_channel = db
        .get_ci_run_member_channel(community_id, run_id, &member)
        .await
        .expect("member channel query");
    assert_eq!(member_channel, Some(channel_id));

    for stranger_pk in [&removed_member[..], stranger.as_slice()] {
        assert_eq!(
            db.get_ci_run_member_channel(community_id, run_id, stranger_pk)
                .await
                .expect("membership query"),
            None,
            "removed and non-members must not resolve the run"
        );
    }
    assert_eq!(
        db.get_ci_run_member_channel(community_id, Uuid::new_v4(), &member)
            .await
            .expect("unknown run query"),
        None,
        "an unknown run must not resolve"
    );
    let (other_community, _) = tenant_channel(&pool).await;
    assert_eq!(
        db.get_ci_run_member_channel(other_community, run_id, &member)
            .await
            .expect("cross-community query"),
        None
    );

    // The request read is bound to the run's own channel.
    assert!(
        db.get_ci_run_request(community_id, Uuid::new_v4(), run_id)
            .await
            .expect("request query")
            .is_none(),
        "a foreign channel must not read another channel's run"
    );

    // Durable event pages are exclusive of the checkpoint cursor and ordered.
    let page = db
        .list_ci_run_events(community_id, channel_id, run_id, 0, 2)
        .await
        .expect("first page");
    assert_eq!(
        page.iter()
            .map(|stored| stored.watch_cursor)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    let after = page.last().expect("page").watch_cursor;
    let rest = db
        .list_ci_run_events(community_id, channel_id, run_id, after, 1_000)
        .await
        .expect("remaining page");
    assert_eq!(
        rest.iter()
            .map(|stored| stored.watch_cursor)
            .collect::<Vec<_>>(),
        (3..=7).collect::<Vec<_>>()
    );
    assert_eq!(
        db.get_ci_run_request(community_id, channel_id, run_id)
            .await
            .expect("request read")
            .expect("stored request")
            .stored_event
            .event,
        request_event,
    );

    // Cursors outside the safe integer range fail closed.
    assert!(matches!(
        db.list_ci_run_events(community_id, channel_id, run_id, -1, 10)
            .await,
        Err(buzz_db::DbError::InvalidData(_))
    ));

    // A soft-deleted channel hides its runs from member resolution.
    sqlx::query("UPDATE channels SET deleted_at = now() WHERE community_id=$1 AND id=$2")
        .bind(community_id.as_uuid())
        .bind(channel_id)
        .execute(&pool)
        .await
        .expect("soft-delete channel");
    assert_eq!(
        db.get_ci_run_member_channel(community_id, run_id, &member)
            .await
            .expect("deleted channel query"),
        None,
        "deleted channels must not resolve runs"
    );
}
