//! Append-only merge-gate decision records (`git_merge_gate_decisions`,
//! migration 0042, design section 1.7).
//!
//! The relay's pre-receive policy callback inserts one row per gated ref
//! evaluation in shadow and enforce mode alike. The publish fence in
//! `finalize_push` reads the latest allowing row for the exact
//! `(repository, ref, old, new, pusher)` update inside the decision window,
//! and a bypass consumption points at the allowing row's id.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use crate::{CommunityId, DbError, Result};

/// Reason codes the decision table accepts (`code` CHECK in migration 0042).
pub const MERGE_GATE_DECISION_CODES: &[&str] = &[
    "allow",
    "no_check",
    "check_pending",
    "check_not_success",
    "reducer_disagrees",
    "base_moved",
    "not_descendant",
    "parent_shape",
    "tree_mismatch",
    "workflow_digest_mismatch",
    "required_jobs_missing",
    "signer_unauthorized",
    "check_expired",
    "bypass_invalid",
    "gate_misconfigured",
];

/// One decision to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeGateDecisionInsert {
    /// Immutable repository coordinate `30617:<owner>:<repo>`.
    pub target_repo_a: String,
    /// Full ref name of the update.
    pub ref_name: String,
    /// Old object ID.
    pub old_oid: String,
    /// New object ID.
    pub new_oid: String,
    /// Candidate the gate resolved, when the push classified.
    pub candidate_oid: Option<String>,
    /// `fast_forward`, `merge`, `bypass`, or `unclassified`.
    pub classification: String,
    /// Selected `ci_runs` row, when one was selected.
    pub run_id: Option<Uuid>,
    /// Selected kind-46108 event ID (32 bytes), when one was reached.
    pub check_event_id: Option<Vec<u8>>,
    /// Signer of the selected check (hex), when one was reached.
    pub signer: Option<String>,
    /// `allow` or a refusal code from [`MERGE_GATE_DECISION_CODES`].
    pub code: String,
    /// `shadow` or `enforce`.
    pub mode: String,
    /// Pusher pubkey (hex).
    pub pusher: String,
    /// Kind-46109 event ID (32 bytes) the decision evaluated, when any.
    pub bypass_event_id: Option<Vec<u8>>,
}

/// An allowing decision the publish fence found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeGateAllowRecord {
    /// Decision row id.
    pub id: Uuid,
    /// Bypass the decision consumed, when the allow came from a bypass.
    pub bypass_event_id: Option<Vec<u8>>,
    /// Relay clock at the decision.
    pub decided_at: DateTime<Utc>,
}

fn validate_insert(insert: &MergeGateDecisionInsert) -> Result<()> {
    if !MERGE_GATE_DECISION_CODES.contains(&insert.code.as_str()) {
        return Err(DbError::InvalidData(format!(
            "unknown merge gate decision code {:?}",
            insert.code
        )));
    }
    if insert.mode != "shadow" && insert.mode != "enforce" {
        return Err(DbError::InvalidData(format!(
            "merge gate decision mode must be shadow or enforce (got {:?})",
            insert.mode
        )));
    }
    for (name, value) in [
        ("check_event_id", &insert.check_event_id),
        ("bypass_event_id", &insert.bypass_event_id),
    ] {
        if value.as_ref().is_some_and(|bytes| bytes.len() != 32) {
            return Err(DbError::InvalidData(format!(
                "merge gate decision {name} must be 32 bytes"
            )));
        }
    }
    Ok(())
}

/// Append one decision and return its row id.
pub async fn insert_merge_gate_decision(
    pool: &PgPool,
    community_id: CommunityId,
    insert: &MergeGateDecisionInsert,
) -> Result<Uuid> {
    validate_insert(insert)?;
    let row = sqlx::query(
        "INSERT INTO git_merge_gate_decisions \
         (community_id, target_repo_a, ref_name, old_oid, new_oid, candidate_oid, \
          classification, run_id, check_event_id, signer, code, mode, pusher, bypass_event_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         RETURNING id",
    )
    .bind(community_id.as_uuid())
    .bind(&insert.target_repo_a)
    .bind(&insert.ref_name)
    .bind(&insert.old_oid)
    .bind(&insert.new_oid)
    .bind(&insert.candidate_oid)
    .bind(&insert.classification)
    .bind(insert.run_id)
    .bind(&insert.check_event_id)
    .bind(&insert.signer)
    .bind(&insert.code)
    .bind(&insert.mode)
    .bind(&insert.pusher)
    .bind(&insert.bypass_event_id)
    .fetch_one(
        &mut *crate::observability::acquire(
            pool,
            crate::observability::PoolRole::Writer,
            crate::observability::Operation::Ci,
        )
        .await?,
    )
    .await?;
    Ok(row.try_get("id")?)
}

/// The latest `allow` decision for one exact update by one pusher decided at
/// or after `not_before`, when any.
#[allow(clippy::too_many_arguments)]
pub async fn find_merge_gate_allow(
    pool: &PgPool,
    community_id: CommunityId,
    target_repo_a: &str,
    ref_name: &str,
    old_oid: &str,
    new_oid: &str,
    pusher: &str,
    not_before: DateTime<Utc>,
) -> Result<Option<MergeGateAllowRecord>> {
    let row = sqlx::query(
        "SELECT id, bypass_event_id, decided_at FROM git_merge_gate_decisions \
         WHERE community_id = $1 AND target_repo_a = $2 AND ref_name = $3 \
           AND old_oid = $4 AND new_oid = $5 AND pusher = $6 \
           AND code = 'allow' AND decided_at >= $7 \
         ORDER BY decided_at DESC LIMIT 1",
    )
    .bind(community_id.as_uuid())
    .bind(target_repo_a)
    .bind(ref_name)
    .bind(old_oid)
    .bind(new_oid)
    .bind(pusher)
    .bind(not_before)
    .fetch_optional(
        &mut *crate::observability::acquire(
            pool,
            crate::observability::PoolRole::Writer,
            crate::observability::Operation::Ci,
        )
        .await?,
    )
    .await?;
    row.map(|row| {
        Ok(MergeGateAllowRecord {
            id: row.try_get("id")?,
            bypass_event_id: row.try_get("bypass_event_id")?,
            decided_at: row.try_get("decided_at")?,
        })
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(code: &str, mode: &str) -> MergeGateDecisionInsert {
        MergeGateDecisionInsert {
            target_repo_a: format!("30617:{}:buzz", "a".repeat(64)),
            ref_name: "refs/heads/main".into(),
            old_oid: "1".repeat(40),
            new_oid: "2".repeat(40),
            candidate_oid: None,
            classification: "unclassified".into(),
            run_id: None,
            check_event_id: None,
            signer: None,
            code: code.into(),
            mode: mode.into(),
            pusher: "b".repeat(64),
            bypass_event_id: None,
        }
    }

    #[test]
    fn insert_validation_refuses_unknown_code_mode_and_short_ids() {
        assert!(validate_insert(&insert("allow", "shadow")).is_ok());
        assert!(validate_insert(&insert("refuse", "shadow")).is_err());
        assert!(validate_insert(&insert("allow", "off")).is_err());
        let mut short = insert("allow", "enforce");
        short.bypass_event_id = Some(vec![1; 31]);
        assert!(validate_insert(&short).is_err());
    }
}
