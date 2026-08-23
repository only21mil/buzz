//! Contract tests for durable workflow state revision and replay semantics.
//!
//! The adapter below is the only provisional seam. If the production API uses
//! different Rust names, adapt `read_state` and `write_state`; the tests should
//! not change.
//!
//! Incarnation mutation check for `stale_revision_from_expired_incarnation_conflicts`:
//! locally change the production recreate path to reuse the expired row's
//! incarnation, or replace its fresh `Uuid::new_v4()` with the old/fixed value.
//! Run:
//!
//! ```text
//! cargo test -p buzz-db --test workflow_state_contract \
//!   stale_revision_from_expired_incarnation_conflicts -- --exact
//! ```
//!
//! The test must turn red because the pre-expiry revision can then authorize a
//! write to the recreated key. Revert that local mutation after recording the
//! result; do not apply it to another worktree.

use std::sync::Arc;

use buzz_core::CommunityId;
use buzz_db::workflow_state::{
    read_workflow_state, write_workflow_state, WorkflowStateEntry, WorkflowStateWriteOutcome,
};
use chrono::{DateTime, Duration, Utc};
use sqlx::postgres::{PgPool, PgPoolOptions};
use tokio::sync::Barrier;
use uuid::Uuid;

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";
const EXPIRES_IN_SECS: i64 = 3_600;
const ABSENT_REVISION: &str = "0";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedState {
    value: String,
    revision: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObservedWrite {
    Written { value: String, revision: String },
    Conflict { current: Option<ObservedState> },
}

impl From<WorkflowStateEntry> for ObservedState {
    fn from(record: WorkflowStateEntry) -> Self {
        Self {
            value: record.value,
            revision: record.revision.to_string(),
            expires_at: record.expires_at,
        }
    }
}

async fn read_state(
    pool: &PgPool,
    community: CommunityId,
    workflow_id: Uuid,
    key: &str,
) -> buzz_db::Result<Option<ObservedState>> {
    Ok(read_workflow_state(pool, community, workflow_id, key)
        .await?
        .map(ObservedState::from))
}

#[allow(clippy::too_many_arguments)]
async fn write_state(
    pool: &PgPool,
    community: CommunityId,
    workflow_id: Uuid,
    run_id: Uuid,
    step_id: &str,
    key: &str,
    value: &str,
    expires_in_secs: i64,
    expected_revision: Option<&str>,
) -> buzz_db::Result<ObservedWrite> {
    let outcome = write_workflow_state(
        pool,
        community,
        run_id,
        step_id,
        key,
        value,
        expires_in_secs,
        expected_revision,
    )
    .await?;

    Ok(match outcome {
        WorkflowStateWriteOutcome::Written { value, revision } => ObservedWrite::Written {
            value,
            revision: revision.to_string(),
        },
        WorkflowStateWriteOutcome::Conflict {
            current_value,
            current_revision,
        } => {
            let current = match (current_value, current_revision) {
                (Some(value), Some(revision)) => {
                    let expires_at = read_workflow_state(pool, community, workflow_id, key)
                        .await?
                        .expect("conflict current row remains live")
                        .expires_at;
                    Some(ObservedState {
                        value,
                        revision: revision.to_string(),
                        expires_at,
                    })
                }
                (None, None) => None,
                _ => panic!("conflict value and revision must both be present or absent"),
            };
            ObservedWrite::Conflict { current }
        }
        other => panic!("unexpected workflow-state outcome in contract test: {other:?}"),
    })
}

struct Fixture {
    pool: PgPool,
    community: CommunityId,
    workflow_id: Uuid,
    run_id: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_owned());
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .expect("connect to workflow state contract test database");
        buzz_db::migration::run_migrations(&pool)
            .await
            .expect("apply workflow state migration");

        let community_uuid = Uuid::new_v4();
        let community = CommunityId::from_uuid(community_uuid);
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(community_uuid)
            .bind(format!("workflow-state-{}.test", community_uuid.simple()))
            .execute(&pool)
            .await
            .expect("insert test community");

        let owner = [0x51; 32];
        buzz_db::user::ensure_user(&pool, community, &owner)
            .await
            .expect("insert workflow owner");
        let workflow_id = buzz_db::workflow::create_workflow(
            &pool,
            community,
            None,
            &owner,
            "workflow-state-contract",
            r#"{"trigger":{"on":"message_posted"},"steps":[]}"#,
            &[0x52; 32],
            true,
        )
        .await
        .expect("insert workflow");
        let definition_snapshot = serde_json::json!({"trigger":{"on":"message_posted"},"steps":[]});
        let run_id = buzz_db::workflow::create_workflow_run(
            &pool,
            community,
            workflow_id,
            None,
            None,
            &definition_snapshot,
            &[0x52; 32],
        )
        .await
        .expect("insert workflow run");

        Self {
            pool,
            community,
            workflow_id,
            run_id,
        }
    }
}

fn expect_written(outcome: ObservedWrite) -> (String, String) {
    match outcome {
        ObservedWrite::Written { value, revision } => (value, revision),
        other => panic!("expected write to succeed, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Postgres"]
async fn concurrent_writers_with_one_expected_revision_have_one_winner() {
    let fixture = Fixture::new().await;
    let key = "race-key";
    let initial_value = r#"{"writer":"initial"}"#;
    let (_, initial_revision) = expect_written(
        write_state(
            &fixture.pool,
            fixture.community,
            fixture.workflow_id,
            fixture.run_id,
            "seed",
            key,
            initial_value,
            EXPIRES_IN_SECS,
            Some(ABSENT_REVISION),
        )
        .await
        .expect("seed state"),
    );

    let barrier = Arc::new(Barrier::new(2));
    let pool = &fixture.pool;
    let community = fixture.community;
    let workflow_id = fixture.workflow_id;
    let run_id = fixture.run_id;
    let writer_a = {
        let barrier = Arc::clone(&barrier);
        let expected_revision = initial_revision.clone();
        async move {
            barrier.wait().await;
            write_state(
                pool,
                community,
                workflow_id,
                run_id,
                "writer-a",
                key,
                r#"{"writer":"a"}"#,
                EXPIRES_IN_SECS,
                Some(&expected_revision),
            )
            .await
        }
    };
    let writer_b = {
        let barrier = Arc::clone(&barrier);
        let expected_revision = initial_revision.clone();
        async move {
            barrier.wait().await;
            write_state(
                pool,
                community,
                workflow_id,
                run_id,
                "writer-b",
                key,
                r#"{"writer":"b"}"#,
                EXPIRES_IN_SECS,
                Some(&expected_revision),
            )
            .await
        }
    };

    let (outcome_a, outcome_b) = tokio::join!(writer_a, writer_b);
    let outcome_a = outcome_a.expect("writer A DB call");
    let outcome_b = outcome_b.expect("writer B DB call");
    let (winning_value, winning_revision, conflict_current) = match (outcome_a, outcome_b) {
        (ObservedWrite::Written { value, revision }, ObservedWrite::Conflict { current })
        | (ObservedWrite::Conflict { current }, ObservedWrite::Written { value, revision }) => {
            (value, revision, current)
        }
        outcomes => panic!("expected exactly one write and one conflict, got {outcomes:?}"),
    };

    let conflict_current = conflict_current.expect("conflict reports the winner");
    assert_eq!(conflict_current.value, winning_value);
    assert_eq!(conflict_current.revision, winning_revision);
    let stored = read_state(&fixture.pool, fixture.community, fixture.workflow_id, key)
        .await
        .expect("read winning state")
        .expect("winning state exists");
    assert_eq!(stored.value, winning_value, "stale writer clobbered winner");
    assert_eq!(stored.revision, winning_revision);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Postgres"]
async fn stale_revision_from_expired_incarnation_conflicts() {
    let fixture = Fixture::new().await;
    let key = "recreated-key";
    let (_, old_revision) = expect_written(
        write_state(
            &fixture.pool,
            fixture.community,
            fixture.workflow_id,
            fixture.run_id,
            "old-incarnation",
            key,
            r#"{"incarnation":"old"}"#,
            EXPIRES_IN_SECS,
            Some(ABSENT_REVISION),
        )
        .await
        .expect("write old incarnation"),
    );
    let captured = read_state(&fixture.pool, fixture.community, fixture.workflow_id, key)
        .await
        .expect("read old incarnation")
        .expect("old incarnation exists before expiry");
    assert_eq!(captured.revision, old_revision);

    let expired = sqlx::query(
        "UPDATE workflow_state \
         SET expires_at = clock_timestamp() - interval '1 second' \
         WHERE community_id = $1 AND workflow_id = $2 AND state_key = $3",
    )
    .bind(fixture.community.as_uuid())
    .bind(fixture.workflow_id)
    .bind(key)
    .execute(&fixture.pool)
    .await
    .expect("expire state with database time");
    assert_eq!(expired.rows_affected(), 1);
    assert_eq!(
        read_state(&fixture.pool, fixture.community, fixture.workflow_id, key,)
            .await
            .expect("read expired state"),
        None,
        "expired state must be absent to the API"
    );

    let recreated_value = r#"{"incarnation":"new"}"#;
    let (_, recreated_revision) = expect_written(
        write_state(
            &fixture.pool,
            fixture.community,
            fixture.workflow_id,
            fixture.run_id,
            "new-incarnation",
            key,
            recreated_value,
            EXPIRES_IN_SECS,
            Some(ABSENT_REVISION),
        )
        .await
        .expect("recreate expired key"),
    );
    assert_ne!(
        old_revision, recreated_revision,
        "recreating a key must mint a new incarnation"
    );

    let stale_outcome = write_state(
        &fixture.pool,
        fixture.community,
        fixture.workflow_id,
        fixture.run_id,
        "stale-pre-expiry-writer",
        key,
        r#"{"incarnation":"stale-clobber"}"#,
        EXPIRES_IN_SECS,
        Some(&old_revision),
    )
    .await
    .expect("attempt stale write");
    let current = match stale_outcome {
        ObservedWrite::Conflict {
            current: Some(current),
        } => current,
        other => panic!("pre-expiry revision must conflict after recreation, got {other:?}"),
    };
    assert_eq!(current.value, recreated_value);
    assert_eq!(current.revision, recreated_revision);

    let stored = read_state(&fixture.pool, fixture.community, fixture.workflow_id, key)
        .await
        .expect("read recreated state")
        .expect("recreated state exists");
    assert_eq!(
        stored.value, recreated_value,
        "stale token clobbered new incarnation"
    );
    assert_eq!(stored.revision, recreated_revision);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Postgres"]
async fn exact_request_replay_returns_original_receipt_without_mutating_state() {
    let fixture = Fixture::new().await;
    let key = "idempotent-key";
    let value = r#"{"status":"reserved"}"#;
    let step_id = "idempotent-step";

    let first = write_state(
        &fixture.pool,
        fixture.community,
        fixture.workflow_id,
        fixture.run_id,
        step_id,
        key,
        value,
        EXPIRES_IN_SECS,
        Some(ABSENT_REVISION),
    )
    .await
    .expect("first request");
    let (first_value, first_revision) = expect_written(first);
    assert_eq!(first_value, value);
    let first_state = read_state(&fixture.pool, fixture.community, fixture.workflow_id, key)
        .await
        .expect("read first state")
        .expect("first state exists");

    let first_write_time = first_state.expires_at - Duration::seconds(EXPIRES_IN_SECS);
    let later_db_time: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&fixture.pool)
        .await
        .expect("read later database time");
    assert!(
        later_db_time > first_write_time,
        "database time must advance before replay"
    );

    let replay = write_state(
        &fixture.pool,
        fixture.community,
        fixture.workflow_id,
        fixture.run_id,
        step_id,
        key,
        value,
        EXPIRES_IN_SECS,
        Some(ABSENT_REVISION),
    )
    .await
    .expect("exact request replay");
    let (replay_value, replay_revision) = expect_written(replay);
    assert_eq!(replay_value, value);
    assert_eq!(
        replay_revision, first_revision,
        "replay must return the original receipt revision"
    );

    let replayed_state = read_state(&fixture.pool, fixture.community, fixture.workflow_id, key)
        .await
        .expect("read replayed state")
        .expect("replayed state exists");
    assert_eq!(replayed_state.value, first_state.value);
    assert_eq!(replayed_state.revision, first_state.revision);
    assert_eq!(
        replayed_state.expires_at, first_state.expires_at,
        "replay must not derive a fresh expiry or mutate the stored row"
    );
}
