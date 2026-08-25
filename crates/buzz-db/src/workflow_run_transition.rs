//! Atomic, generation-fenced workflow-run status transitions.
//!
//! Resume workers use this module to claim a run without consulting the
//! workflow's current definition. The single `UPDATE` fences ownership by the
//! run's tenant, status, and generation.

use buzz_core::CommunityId;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::workflow::RunStatus;
use crate::Result;

/// A relay-owned approval continuation eligible for a fenced recovery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowResumeCandidate {
    /// Tenant that owns the run.
    pub community_id: CommunityId,
    /// Workflow run identifier.
    pub run_id: Uuid,
    /// Status observed by the recovery scan.
    pub status: RunStatus,
    /// Generation observed by the recovery scan.
    pub generation: i64,
}

/// Namespace shared with channel membership mutations.
const CHANNEL_MEMBERSHIP_LOCK_NAMESPACE: &str = "buzz_channel_membership:";

/// Acquire the channel-membership advisory lock for an approval transaction.
///
/// This must remain the first database statement after `BEGIN`. The key is
/// byte-for-byte identical to the private membership helper in `channel.rs`, so
/// gate creation and later approval decisions serialize with role changes.
pub(crate) async fn acquire_workflow_approval_channel_lock(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    channel_id: Uuid,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "{CHANNEL_MEMBERSHIP_LOCK_NAMESPACE}{}:{}",
            community_id.as_uuid(),
            channel_id
        ))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Result of a generation-fenced workflow-run transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum WorkflowRunTransitionOutcome {
    /// The caller acquired the run and advanced its generation.
    Applied {
        /// Generation owned by the caller after the transition.
        generation: i64,
    },
    /// The tenant, run, expected status, or expected generation did not match.
    Conflict,
}

/// Change a run's status if its tenant, status, and generation still match.
///
/// A successful transition increments `generation` in the same statement and
/// returns the new value. A missing run and every fence mismatch return
/// [`WorkflowRunTransitionOutcome::Conflict`], which avoids a separate read and
/// does not reveal whether the run exists in another tenant. This query never
/// joins or loads the mutable workflow definition.
pub async fn transition_workflow_run(
    pool: &PgPool,
    community_id: CommunityId,
    id: Uuid,
    expected_status: RunStatus,
    expected_generation: i64,
    next_status: RunStatus,
) -> Result<WorkflowRunTransitionOutcome> {
    let row = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET status = $1::run_status,
            generation = generation + 1
        WHERE community_id = $2
          AND id = $3
          AND status = $4::run_status
          AND generation = $5
        RETURNING generation
        "#,
    )
    .bind(next_status.to_string())
    .bind(community_id.as_uuid())
    .bind(id)
    .bind(expected_status.to_string())
    .bind(expected_generation)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(row) => Ok(WorkflowRunTransitionOutcome::Applied {
            generation: row.try_get("generation")?,
        }),
        None => Ok(WorkflowRunTransitionOutcome::Conflict),
    }
}

/// List approved continuations whose durable claim is absent or expired.
///
/// `resume_pending` rows age from the canonical grant's database timestamp.
/// `running` rows are eligible only when a resume worker set a lease and that
/// lease has expired. The later claim still checks status, generation, and
/// lease expiry in one update, so this read does not confer ownership.
pub async fn list_recoverable_workflow_resumes(
    pool: &PgPool,
    resume_pending_age_secs: i64,
    limit: i64,
) -> Result<Vec<WorkflowResumeCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT run.community_id, run.id, run.status::text AS status, run.generation
        FROM workflow_runs AS run
        WHERE (
            run.status = 'resume_pending'
            AND EXISTS (
                SELECT 1
                FROM workflow_approval_gates AS gate
                WHERE gate.community_id = run.community_id
                  AND gate.run_id = run.id
                  AND gate.status = 'granted'
                  AND gate.deleted_at IS NULL
                  AND gate.generation = run.generation - 1
                  AND gate.decided_at <= clock_timestamp()
                      - ($1::bigint * INTERVAL '1 second')
            )
        ) OR (
            run.status = 'running'
            AND run.resume_lease_expires_at IS NOT NULL
            AND run.resume_lease_expires_at <= clock_timestamp()
        )
        ORDER BY COALESCE(run.resume_lease_expires_at, run.created_at),
                 run.community_id, run.id
        LIMIT $2
        "#,
    )
    .bind(resume_pending_age_secs)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let community_id: Uuid = row.try_get("community_id")?;
            Ok(WorkflowResumeCandidate {
                community_id: CommunityId::from_uuid(community_id),
                run_id: row.try_get("id")?,
                status: row.try_get::<String, _>("status")?.parse()?,
                generation: row.try_get("generation")?,
            })
        })
        .collect()
}

/// Claim a pending approval continuation or reclaim its expired running lease.
///
/// A successful claim advances the generation and installs a new lease in the
/// same statement. A running row must have an expired resume lease; ordinary
/// workflow runs, which have no resume lease, are never reclaimed here.
pub async fn claim_workflow_resume(
    pool: &PgPool,
    community_id: CommunityId,
    id: Uuid,
    expected_status: RunStatus,
    expected_generation: i64,
    lease_secs: i64,
) -> Result<WorkflowRunTransitionOutcome> {
    if !matches!(
        expected_status,
        RunStatus::ResumePending | RunStatus::Running
    ) {
        return Ok(WorkflowRunTransitionOutcome::Conflict);
    }
    let row = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET status = 'running',
            generation = generation + 1,
            started_at = COALESCE(started_at, clock_timestamp()),
            resume_lease_expires_at = clock_timestamp()
                + ($1::bigint * INTERVAL '1 second')
        WHERE community_id = $2
          AND id = $3
          AND status = $4::run_status
          AND generation = $5
          AND ($4::run_status = 'resume_pending'
               OR resume_lease_expires_at <= clock_timestamp())
        RETURNING generation
        "#,
    )
    .bind(lease_secs)
    .bind(community_id.as_uuid())
    .bind(id)
    .bind(expected_status.to_string())
    .bind(expected_generation)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(row) => Ok(WorkflowRunTransitionOutcome::Applied {
            generation: row.try_get("generation")?,
        }),
        None => Ok(WorkflowRunTransitionOutcome::Conflict),
    }
}

/// Extend the lease only while the caller still owns the running generation.
pub async fn renew_workflow_resume_lease(
    pool: &PgPool,
    community_id: CommunityId,
    id: Uuid,
    expected_generation: i64,
    lease_secs: i64,
) -> Result<bool> {
    let affected = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET resume_lease_expires_at = clock_timestamp()
            + ($1::bigint * INTERVAL '1 second')
        WHERE community_id = $2
          AND id = $3
          AND status = 'running'
          AND generation = $4
          AND resume_lease_expires_at IS NOT NULL
        "#,
    )
    .bind(lease_secs)
    .bind(community_id.as_uuid())
    .bind(id)
    .bind(expected_generation)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected == 1)
}

/// Complete a claimed approval continuation under its running generation.
pub async fn complete_running_workflow_run(
    pool: &PgPool,
    community_id: CommunityId,
    id: Uuid,
    expected_generation: i64,
    current_step: i32,
    trace: &serde_json::Value,
) -> Result<WorkflowRunTransitionOutcome> {
    let row = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET status = 'completed',
            current_step = $1,
            execution_trace = $2,
            error_message = NULL,
            completed_at = clock_timestamp(),
            resume_lease_expires_at = NULL,
            generation = generation + 1
        WHERE community_id = $3
          AND id = $4
          AND status = 'running'
          AND generation = $5
        RETURNING generation
        "#,
    )
    .bind(current_step)
    .bind(trace)
    .bind(community_id.as_uuid())
    .bind(id)
    .bind(expected_generation)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(row) => Ok(WorkflowRunTransitionOutcome::Applied {
            generation: row.try_get("generation")?,
        }),
        None => Ok(WorkflowRunTransitionOutcome::Conflict),
    }
}

/// Mark a running workflow failed only while its generation still matches.
///
/// This is the error-path counterpart to [`transition_workflow_run`]. It keeps
/// the status fence, trace, error, completion timestamp, and generation
/// advance in one statement so a stale executor cannot overwrite a newer
/// waiting or terminal state.
pub async fn fail_running_workflow_run(
    pool: &PgPool,
    community_id: CommunityId,
    id: Uuid,
    expected_generation: i64,
    current_step: i32,
    trace: &serde_json::Value,
    error: &str,
) -> Result<WorkflowRunTransitionOutcome> {
    let row = sqlx::query(
        r#"
        UPDATE workflow_runs
        SET status = 'failed',
            current_step = $1,
            execution_trace = $2,
            error_message = $3,
            completed_at = NOW(),
            resume_lease_expires_at = NULL,
            generation = generation + 1
        WHERE community_id = $4
          AND id = $5
          AND status = 'running'
          AND generation = $6
        RETURNING generation
        "#,
    )
    .bind(current_step)
    .bind(trace)
    .bind(error)
    .bind(community_id.as_uuid())
    .bind(id)
    .bind(expected_generation)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(row) => Ok(WorkflowRunTransitionOutcome::Applied {
            generation: row.try_get("generation")?,
        }),
        None => Ok(WorkflowRunTransitionOutcome::Conflict),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::ensure_user;

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";

    async fn setup_pool() -> PgPool {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_owned());

        PgPool::connect(&database_url)
            .await
            .expect("connect to test DB")
    }

    async fn insert_run(
        pool: &PgPool,
        community_id: CommunityId,
        workflow_id: Uuid,
        run_id: Uuid,
        status: RunStatus,
        generation: i64,
    ) {
        let owner = [0xa5; 32];
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(community_id.as_uuid())
            .bind(format!(
                "transition-{}.example",
                community_id.as_uuid().simple()
            ))
            .execute(pool)
            .await
            .expect("insert community");
        ensure_user(pool, community_id, &owner)
            .await
            .expect("insert workflow owner");
        sqlx::query(
            r#"
            INSERT INTO workflows
                (community_id, id, name, owner_pubkey, definition, definition_hash)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(community_id.as_uuid())
        .bind(workflow_id)
        .bind(format!("transition-{}", workflow_id.simple()))
        .bind(owner.as_slice())
        .bind(serde_json::json!({"version": 1, "steps": []}))
        .bind([0u8; 32].as_slice())
        .execute(pool)
        .await
        .expect("insert workflow");
        sqlx::query(
            r#"
            INSERT INTO workflow_runs
                (community_id, id, workflow_id, status, definition_snapshot,
                 definition_hash, generation)
            VALUES ($1, $2, $3, $4::run_status, $5, $6, $7)
            "#,
        )
        .bind(community_id.as_uuid())
        .bind(run_id)
        .bind(workflow_id)
        .bind(status.to_string())
        .bind(serde_json::json!({"version": 1, "steps": []}))
        .bind([0u8; 32].as_slice())
        .bind(generation)
        .execute(pool)
        .await
        .expect("insert workflow run");
    }

    async fn run_state(pool: &PgPool, community_id: CommunityId, run_id: Uuid) -> (String, i64) {
        let row = sqlx::query(
            "SELECT status::text AS status, generation FROM workflow_runs \
             WHERE community_id = $1 AND id = $2",
        )
        .bind(community_id.as_uuid())
        .bind(run_id)
        .fetch_one(pool)
        .await
        .expect("fetch workflow run");

        (
            row.try_get("status").expect("status"),
            row.try_get("generation").expect("generation"),
        )
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn matching_fence_applies_and_increments_generation() {
        let pool = setup_pool().await;
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let workflow_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        insert_run(
            &pool,
            community_id,
            workflow_id,
            run_id,
            RunStatus::WaitingApproval,
            7,
        )
        .await;

        let outcome = transition_workflow_run(
            &pool,
            community_id,
            run_id,
            RunStatus::WaitingApproval,
            7,
            RunStatus::Running,
        )
        .await
        .expect("transition run");

        assert_eq!(
            outcome,
            WorkflowRunTransitionOutcome::Applied { generation: 8 }
        );
        assert_eq!(
            run_state(&pool, community_id, run_id).await,
            ("running".to_owned(), 8)
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn stale_fences_conflict_without_mutation() {
        let pool = setup_pool().await;
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let workflow_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        insert_run(
            &pool,
            community_id,
            workflow_id,
            run_id,
            RunStatus::WaitingApproval,
            4,
        )
        .await;

        let stale_status = transition_workflow_run(
            &pool,
            community_id,
            run_id,
            RunStatus::Pending,
            4,
            RunStatus::Running,
        )
        .await
        .expect("status conflict");
        let stale_generation = transition_workflow_run(
            &pool,
            community_id,
            run_id,
            RunStatus::WaitingApproval,
            3,
            RunStatus::Running,
        )
        .await
        .expect("generation conflict");

        assert_eq!(stale_status, WorkflowRunTransitionOutcome::Conflict);
        assert_eq!(stale_generation, WorkflowRunTransitionOutcome::Conflict);
        assert_eq!(
            run_state(&pool, community_id, run_id).await,
            ("waiting_approval".to_owned(), 4)
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn fenced_failure_cannot_overwrite_a_waiting_gate() {
        let pool = setup_pool().await;
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let workflow_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        insert_run(
            &pool,
            community_id,
            workflow_id,
            run_id,
            RunStatus::WaitingApproval,
            4,
        )
        .await;
        let before = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT to_jsonb(r) FROM workflow_runs r WHERE community_id = $1 AND id = $2",
        )
        .bind(community_id.as_uuid())
        .bind(run_id)
        .fetch_one(&pool)
        .await
        .expect("read waiting run");

        let outcome = fail_running_workflow_run(
            &pool,
            community_id,
            run_id,
            3,
            2,
            &serde_json::json!([{"status": "failed"}]),
            "stale finalizer",
        )
        .await
        .expect("attempt fenced failure");

        assert_eq!(outcome, WorkflowRunTransitionOutcome::Conflict);
        let after = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT to_jsonb(r) FROM workflow_runs r WHERE community_id = $1 AND id = $2",
        )
        .bind(community_id.as_uuid())
        .bind(run_id)
        .fetch_one(&pool)
        .await
        .expect("read waiting run after conflict");
        assert_eq!(after, before);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn fenced_failure_closes_the_original_running_generation() {
        let pool = setup_pool().await;
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let workflow_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        insert_run(
            &pool,
            community_id,
            workflow_id,
            run_id,
            RunStatus::Running,
            3,
        )
        .await;
        let trace = serde_json::json!([{"step_id": "approve", "status": "failed"}]);

        let outcome = fail_running_workflow_run(
            &pool,
            community_id,
            run_id,
            3,
            2,
            &trace,
            "approval gate conflict",
        )
        .await
        .expect("fail the matching running generation");

        assert_eq!(
            outcome,
            WorkflowRunTransitionOutcome::Applied { generation: 4 }
        );
        let row = sqlx::query(
            "SELECT status::text AS status, generation, current_step, execution_trace, \
                    error_message, completed_at IS NOT NULL AS completed \
             FROM workflow_runs WHERE community_id = $1 AND id = $2",
        )
        .bind(community_id.as_uuid())
        .bind(run_id)
        .fetch_one(&pool)
        .await
        .expect("read failed run");
        assert_eq!(row.try_get::<String, _>("status").unwrap(), "failed");
        assert_eq!(row.try_get::<i64, _>("generation").unwrap(), 4);
        assert_eq!(row.try_get::<i32, _>("current_step").unwrap(), 2);
        assert_eq!(
            row.try_get::<serde_json::Value, _>("execution_trace")
                .unwrap(),
            trace
        );
        assert_eq!(
            row.try_get::<String, _>("error_message").unwrap(),
            "approval gate conflict"
        );
        assert!(row.try_get::<bool, _>("completed").unwrap());
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn tenant_scope_conflicts_even_when_run_ids_match() {
        let pool = setup_pool().await;
        let community_a = CommunityId::from_uuid(Uuid::new_v4());
        let community_b = CommunityId::from_uuid(Uuid::new_v4());
        let run_id = Uuid::new_v4();
        insert_run(
            &pool,
            community_a,
            Uuid::new_v4(),
            run_id,
            RunStatus::WaitingApproval,
            2,
        )
        .await;
        insert_run(
            &pool,
            community_b,
            Uuid::new_v4(),
            run_id,
            RunStatus::WaitingApproval,
            2,
        )
        .await;

        let outcome = transition_workflow_run(
            &pool,
            CommunityId::from_uuid(Uuid::new_v4()),
            run_id,
            RunStatus::WaitingApproval,
            2,
            RunStatus::Running,
        )
        .await
        .expect("tenant conflict");

        assert_eq!(outcome, WorkflowRunTransitionOutcome::Conflict);
        assert_eq!(
            run_state(&pool, community_a, run_id).await,
            ("waiting_approval".to_owned(), 2)
        );
        assert_eq!(
            run_state(&pool, community_b, run_id).await,
            ("waiting_approval".to_owned(), 2)
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn concurrent_claims_have_one_applied_outcome() {
        let pool = setup_pool().await;
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let workflow_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        insert_run(
            &pool,
            community_id,
            workflow_id,
            run_id,
            RunStatus::WaitingApproval,
            11,
        )
        .await;

        let first = transition_workflow_run(
            &pool,
            community_id,
            run_id,
            RunStatus::WaitingApproval,
            11,
            RunStatus::Running,
        );
        let second = transition_workflow_run(
            &pool,
            community_id,
            run_id,
            RunStatus::WaitingApproval,
            11,
            RunStatus::Running,
        );
        let (first, second) = tokio::join!(first, second);
        let outcomes = [first.expect("first claim"), second.expect("second claim")];

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, WorkflowRunTransitionOutcome::Applied { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == WorkflowRunTransitionOutcome::Conflict)
                .count(),
            1
        );
        assert_eq!(
            run_state(&pool, community_id, run_id).await,
            ("running".to_owned(), 12)
        );
    }
}
