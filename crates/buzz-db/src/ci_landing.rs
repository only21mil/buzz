//! Read-only queries behind the Buzz-native landing verifier
//! (`docs/ci/BUZZ_MERGE_GATE_DESIGN.md` section 2).
//!
//! Nothing here writes. `list_ci_runs_for_tip` enumerates the runs a
//! repository recorded for one exact tip, newest first, so a verifier can
//! apply the latest-run rule; `list_ci_run_checks` returns the stored
//! kind-46108 checks of one run with the relay clock's `accepted_at`;
//! `list_merge_gate_decisions` reads the append-only decision rows the merge
//! gate wrote for one ref update.

use buzz_core::kind::KIND_CI_CHECK;
use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use crate::ci::{row_to_ci_stored_event, CiStoredEvent};
use crate::{DbError, Result};

/// Upper bound on runs or decisions returned by one read.
pub const MAX_CI_LANDING_ROWS: u32 = 100;

/// One `ci_runs` row as the landing verifier reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiRunRecord {
    /// Run identifier.
    pub run_id: Uuid,
    /// Repository channel the run belongs to.
    pub channel_id: Uuid,
    /// Accepted initial kind-46100 request event ID (32 bytes).
    pub initial_request_event_id: Vec<u8>,
    /// Immutable repository coordinate.
    pub target_repo_a: String,
    /// Exact head object ID the run tests.
    pub tip_oid: String,
    /// Base object ID the request named.
    pub base_oid: String,
    /// Workflow identifier.
    pub workflow_id: String,
    /// SHA-256 of the workflow bytes the run executed (32 bytes).
    pub workflow_digest: Vec<u8>,
    /// Relay clock time the run row was created.
    pub created_at: DateTime<Utc>,
}

/// One append-only `git_merge_gate_decisions` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeGateDecisionRecord {
    /// Row identifier.
    pub id: Uuid,
    /// Immutable repository coordinate.
    pub target_repo_a: String,
    /// Gated ref.
    pub ref_name: String,
    /// Old object ID of the update.
    pub old_oid: String,
    /// New object ID of the update.
    pub new_oid: String,
    /// Candidate the gate resolved, when the shape allowed one.
    pub candidate_oid: Option<String>,
    /// Push classification.
    pub classification: String,
    /// Run the gate selected, when any.
    pub run_id: Option<Uuid>,
    /// Kind-46108 check the gate selected (32 bytes), when any.
    pub check_event_id: Option<Vec<u8>>,
    /// Signer of the selected check, when any.
    pub signer: Option<String>,
    /// `allow` or a refusal code.
    pub code: String,
    /// Gate mode at decision time (`shadow` or `enforce`).
    pub mode: String,
    /// Pusher pubkey.
    pub pusher: String,
    /// Bypass event evaluated (32 bytes), when any.
    pub bypass_event_id: Option<Vec<u8>>,
    /// Relay clock time of the decision.
    pub decided_at: DateTime<Utc>,
}

fn bounded_limit(limit: u32) -> i64 {
    i64::from(limit.clamp(1, MAX_CI_LANDING_ROWS))
}

/// Every run recorded for `(target_repo_a, tip_oid)` in `channel_id`, newest
/// first, optionally narrowed to one workflow. The caller resolves
/// `channel_id` through membership before calling; the filter keeps a run of
/// another channel invisible even when the coordinate string matches.
pub async fn list_ci_runs_for_tip(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    target_repo_a: &str,
    tip_oid: &str,
    workflow_id: Option<&str>,
    limit: u32,
) -> Result<Vec<CiRunRecord>> {
    let rows = sqlx::query(
        r#"
        SELECT run_id,channel_id,initial_request_event_id,target_repo_a,tip_oid,base_oid,
               workflow_id,workflow_digest,created_at
        FROM ci_runs
        WHERE community_id=$1 AND channel_id=$2 AND target_repo_a=$3 AND tip_oid=$4
          AND ($5::text IS NULL OR workflow_id=$5)
        ORDER BY created_at DESC, run_id DESC
        LIMIT $6
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(target_repo_a)
    .bind(tip_oid)
    .bind(workflow_id)
    .bind(bounded_limit(limit))
    .fetch_all(
        &mut *crate::observability::acquire(
            pool,
            crate::observability::PoolRole::Writer,
            crate::observability::Operation::Ci,
        )
        .await?,
    )
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(CiRunRecord {
                run_id: row.try_get("run_id")?,
                channel_id: row.try_get("channel_id")?,
                initial_request_event_id: row.try_get("initial_request_event_id")?,
                target_repo_a: row.try_get("target_repo_a")?,
                tip_oid: row.try_get("tip_oid")?,
                base_oid: row.try_get("base_oid")?,
                workflow_id: row.try_get("workflow_id")?,
                workflow_digest: row.try_get("workflow_digest")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect()
}

/// Every stored kind-46108 check of `run_id` in acceptance order, each with
/// the relay clock's `accepted_at`. Bound to the run's channel like
/// `list_ci_run_events`.
pub async fn list_ci_run_checks(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    run_id: Uuid,
) -> Result<Vec<CiStoredEvent>> {
    let rows = sqlx::query(
        r#"
        SELECT index.watch_cursor,index.accepted_at,index.event_kind,
               stored.id,stored.pubkey,stored.created_at,stored.kind,stored.tags,
               stored.content,stored.sig,stored.received_at,stored.channel_id
        FROM ci_run_events AS index
        JOIN ci_runs AS run
          ON run.community_id=index.community_id AND run.run_id=index.run_id
        JOIN events AS stored
          ON stored.community_id=index.community_id
         AND stored.created_at=index.event_created_at
         AND stored.id=index.event_id
        WHERE index.community_id=$1 AND run.channel_id=$2 AND index.run_id=$3
          AND index.event_kind=$4
        ORDER BY index.watch_cursor
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(run_id)
    .bind(KIND_CI_CHECK as i32)
    .fetch_all(
        &mut *crate::observability::acquire(
            pool,
            crate::observability::PoolRole::Writer,
            crate::observability::Operation::Ci,
        )
        .await?,
    )
    .await?;
    rows.into_iter().map(row_to_ci_stored_event).collect()
}

/// Decision rows for `(target_repo_a, ref_name, new_oid)`, newest first,
/// optionally narrowed to one `old_oid`. The caller keys `target_repo_a` on
/// the kind-30617 coordinate it resolved and authorized, never on a value an
/// event carried.
pub async fn list_merge_gate_decisions(
    pool: &PgPool,
    community_id: CommunityId,
    target_repo_a: &str,
    ref_name: &str,
    new_oid: &str,
    old_oid: Option<&str>,
    limit: u32,
) -> Result<Vec<MergeGateDecisionRecord>> {
    if target_repo_a.is_empty() || ref_name.is_empty() || new_oid.is_empty() {
        return Err(DbError::InvalidData(
            "merge gate decision lookup needs a repository, a ref, and a new OID".into(),
        ));
    }
    let rows = sqlx::query(
        r#"
        SELECT id,target_repo_a,ref_name,old_oid,new_oid,candidate_oid,classification,run_id,
               check_event_id,signer,code,mode,pusher,bypass_event_id,decided_at
        FROM git_merge_gate_decisions
        WHERE community_id=$1 AND target_repo_a=$2 AND ref_name=$3 AND new_oid=$4
          AND ($5::text IS NULL OR old_oid=$5)
        ORDER BY decided_at DESC, id DESC
        LIMIT $6
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(target_repo_a)
    .bind(ref_name)
    .bind(new_oid)
    .bind(old_oid)
    .bind(bounded_limit(limit))
    .fetch_all(
        &mut *crate::observability::acquire(
            pool,
            crate::observability::PoolRole::Writer,
            crate::observability::Operation::Ci,
        )
        .await?,
    )
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(MergeGateDecisionRecord {
                id: row.try_get("id")?,
                target_repo_a: row.try_get("target_repo_a")?,
                ref_name: row.try_get("ref_name")?,
                old_oid: row.try_get("old_oid")?,
                new_oid: row.try_get("new_oid")?,
                candidate_oid: row.try_get("candidate_oid")?,
                classification: row.try_get("classification")?,
                run_id: row.try_get("run_id")?,
                check_event_id: row.try_get("check_event_id")?,
                signer: row.try_get("signer")?,
                code: row.try_get("code")?,
                mode: row.try_get("mode")?,
                pusher: row.try_get("pusher")?,
                bypass_event_id: row.try_get("bypass_event_id")?,
                decided_at: row.try_get("decided_at")?,
            })
        })
        .collect()
}
