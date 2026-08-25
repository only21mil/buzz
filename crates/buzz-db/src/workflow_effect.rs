//! Durable, generation-independent workflow effect claims.
//!
//! Executors claim `(run, step, effect_index)` while they own the run's current
//! generation. Recovery reuses the claim across later generations. A fired
//! claim stores the action output, so replay can advance without firing again.

use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{DbError, Result};

/// Stable identity supplied to an external sink for replay deduplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowEffectClaim {
    /// Key reused on every attempt to deliver this effect.
    pub idempotency_key: Uuid,
    /// Database time fixed when the effect was first claimed.
    pub claimed_at: DateTime<Utc>,
    /// Fully rendered delivery input fixed by the first claim.
    pub effect_payload: Value,
}

/// Result of claiming a workflow effect under a generation fence.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum WorkflowEffectClaimOutcome {
    /// The effect still needs delivery, using this stable identity.
    Ready(WorkflowEffectClaim),
    /// A prior executor delivered the effect and stored this output.
    Fired(Value),
    /// The caller no longer owns the running generation.
    Conflict,
}

/// Result of marking an external effect as fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum WorkflowEffectMarkOutcome {
    /// The effect was marked fired under the caller's generation.
    Applied,
    /// The caller no longer owns the running generation.
    Conflict,
}

/// Claim an effect while locking and checking the current run generation.
#[allow(clippy::too_many_arguments)]
pub async fn claim_workflow_effect(
    pool: &PgPool,
    community_id: CommunityId,
    run_id: Uuid,
    expected_generation: i64,
    step_id: &str,
    effect_index: i16,
    effect_kind: &str,
    effect_spec: &Value,
) -> Result<WorkflowEffectClaimOutcome> {
    claim_workflow_effect_with_payload(
        pool,
        community_id,
        run_id,
        expected_generation,
        step_id,
        effect_index,
        effect_kind,
        effect_spec,
        effect_spec,
    )
    .await
}

/// Claim an effect and pin its fully rendered delivery payload.
#[allow(clippy::too_many_arguments)]
pub async fn claim_workflow_effect_with_payload(
    pool: &PgPool,
    community_id: CommunityId,
    run_id: Uuid,
    expected_generation: i64,
    step_id: &str,
    effect_index: i16,
    effect_kind: &str,
    effect_spec: &Value,
    effect_payload: &Value,
) -> Result<WorkflowEffectClaimOutcome> {
    let mut tx = pool.begin().await?;
    let owned = sqlx::query(
        "SELECT 1 FROM workflow_runs WHERE community_id = $1 AND id = $2 \
         AND status = 'running' AND generation = $3 FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(expected_generation)
    .fetch_optional(&mut *tx)
    .await?;
    if owned.is_none() {
        tx.rollback().await?;
        return Ok(WorkflowEffectClaimOutcome::Conflict);
    }

    let idempotency_key = Uuid::new_v4();
    let mut effect_payload = effect_payload.clone();
    let payload_object = effect_payload.as_object_mut().ok_or_else(|| {
        DbError::InvalidData("workflow effect payload must be a JSON object".to_owned())
    })?;
    payload_object.insert(
        "idempotency_key".to_owned(),
        Value::String(idempotency_key.to_string()),
    );

    let row = sqlx::query(
        r#"
        INSERT INTO workflow_effect_claims
            (community_id, run_id, step_id, effect_index, effect_kind, effect_spec,
             effect_payload, idempotency_key)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (community_id, run_id, step_id, effect_index) DO NOTHING
        RETURNING effect_kind, effect_spec, effect_payload, idempotency_key,
                  claimed_at, fired_at, output
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(step_id)
    .bind(effect_index)
    .bind(effect_kind)
    .bind(effect_spec)
    .bind(&effect_payload)
    .bind(idempotency_key)
    .fetch_optional(&mut *tx)
    .await?;

    let row =
        match row {
            Some(row) => row,
            None => sqlx::query(
                "SELECT effect_kind, effect_spec, effect_payload, idempotency_key, claimed_at, fired_at, output \
                 FROM workflow_effect_claims WHERE community_id = $1 AND run_id = $2 \
                 AND step_id = $3 AND effect_index = $4 FOR UPDATE",
            )
            .bind(community_id.as_uuid())
            .bind(run_id)
            .bind(step_id)
            .bind(effect_index)
            .fetch_one(&mut *tx)
            .await?,
        };

    let stored_kind: String = row.try_get("effect_kind")?;
    let stored_spec: Value = row.try_get("effect_spec")?;
    if stored_kind != effect_kind || stored_spec != *effect_spec {
        return Err(DbError::Conflict(format!(
            "workflow effect {run_id}/{step_id}/{effect_index} was replayed with different inputs"
        )));
    }

    let fired_at: Option<DateTime<Utc>> = row.try_get("fired_at")?;
    let outcome = if fired_at.is_some() {
        WorkflowEffectClaimOutcome::Fired(row.try_get("output")?)
    } else {
        WorkflowEffectClaimOutcome::Ready(WorkflowEffectClaim {
            idempotency_key: row.try_get("idempotency_key")?,
            claimed_at: row.try_get("claimed_at")?,
            effect_payload: row.try_get("effect_payload")?,
        })
    };
    tx.commit().await?;
    Ok(outcome)
}

/// Mark an effect fired only while the executor still owns its generation.
#[allow(clippy::too_many_arguments)]
pub async fn mark_workflow_effect_fired(
    pool: &PgPool,
    community_id: CommunityId,
    run_id: Uuid,
    expected_generation: i64,
    step_id: &str,
    effect_index: i16,
    output: &Value,
) -> Result<WorkflowEffectMarkOutcome> {
    let affected = sqlx::query(
        r#"
        UPDATE workflow_effect_claims AS effect
        SET fired_at = clock_timestamp(), output = $1
        WHERE effect.community_id = $2
          AND effect.run_id = $3
          AND effect.step_id = $4
          AND effect.effect_index = $5
          AND effect.fired_at IS NULL
          AND EXISTS (
              SELECT 1 FROM workflow_runs AS run
              WHERE run.community_id = effect.community_id
                AND run.id = effect.run_id
                AND run.status = 'running'
                AND run.generation = $6
          )
        "#,
    )
    .bind(output)
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(step_id)
    .bind(effect_index)
    .bind(expected_generation)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(if affected == 1 {
        WorkflowEffectMarkOutcome::Applied
    } else {
        WorkflowEffectMarkOutcome::Conflict
    })
}
