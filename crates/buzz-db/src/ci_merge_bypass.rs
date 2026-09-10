//! Owner-signed merge-gate bypasses (kind 46109) and their one-time consumption.
//!
//! The relay ingest pipeline stores an accepted bypass after the canonical
//! event row. The merge gate reads every bypass for the exact
//! `(repository, ref, old, new)` update it evaluates and accepts one that is
//! inside its window and unconsumed; the publish it covered then sets
//! `consumed_by` to the allowing `git_merge_gate_decisions` row, once.

use buzz_core::ci::CiMergeBypassEnvelope;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use crate::{CommunityId, DbError, Result};

/// One stored kind-46109 bypass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiMergeBypassRecord {
    /// Signed event ID (32 bytes).
    pub event_id: Vec<u8>,
    /// Repository channel the bypass was published to.
    pub channel_id: Uuid,
    /// Repository owner who signed it (hex).
    pub issuer_pubkey: String,
    /// Immutable repository coordinate.
    pub target_repo_a: String,
    /// Exact ref the bypass covers.
    pub ref_name: String,
    /// Exact old object ID.
    pub old_oid: String,
    /// Exact new object ID.
    pub new_oid: String,
    /// Owner's reason.
    pub reason: String,
    /// Window start.
    pub issued_at: DateTime<Utc>,
    /// Window end, exclusive.
    pub expires_at: DateTime<Utc>,
    /// Allowing decision row that consumed it, once consumed.
    pub consumed_by: Option<Uuid>,
    /// Relay acceptance time.
    pub accepted_at: DateTime<Utc>,
}

impl CiMergeBypassRecord {
    /// Whether the bypass is unconsumed and `now` is inside its window.
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.consumed_by.is_none() && self.issued_at <= now && now < self.expires_at
    }
}

fn unix_seconds(value: u64, what: &'static str) -> Result<DateTime<Utc>> {
    i64::try_from(value)
        .ok()
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        .ok_or_else(|| DbError::InvalidData(format!("CI merge bypass {what} is out of range")))
}

/// Store an accepted bypass. Returns `false` when the exact event was already
/// stored (a replay), which leaves the existing row and its consumption alone.
pub async fn insert_ci_merge_bypass(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    event_id: &[u8],
    issuer_pubkey: &str,
    envelope: &CiMergeBypassEnvelope,
) -> Result<bool> {
    envelope
        .validate()
        .map_err(|error| DbError::InvalidData(error.to_string()))?;
    if event_id.len() != 32 {
        return Err(DbError::InvalidData(
            "CI merge bypass event ID must be 32 bytes".into(),
        ));
    }
    let issued_at = unix_seconds(envelope.issued_at, "issued_at")?;
    let expires_at = unix_seconds(envelope.expires_at, "expires_at")?;
    let inserted = sqlx::query(
        "INSERT INTO ci_merge_bypasses \
         (community_id, event_id, channel_id, issuer_pubkey, target_repo_a, ref_name, \
          old_oid, new_oid, reason, issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT (community_id, event_id) DO NOTHING",
    )
    .bind(community_id.as_uuid())
    .bind(event_id)
    .bind(channel_id)
    .bind(issuer_pubkey)
    .bind(&envelope.target_repo_a)
    .bind(&envelope.ref_name)
    .bind(&envelope.old_oid)
    .bind(&envelope.new_oid)
    .bind(&envelope.reason)
    .bind(issued_at)
    .bind(expires_at)
    .execute(
        &mut *crate::observability::acquire(
            pool,
            crate::observability::PoolRole::Writer,
            crate::observability::Operation::Ci,
        )
        .await?,
    )
    .await?
    .rows_affected();
    Ok(inserted == 1)
}

/// Every stored bypass for one exact ref update, oldest accepted first.
///
/// The caller applies window and consumption (`is_usable_at`); reading all of
/// them keeps a consumed or expired bypass visible to the decision record.
pub async fn list_ci_merge_bypasses(
    pool: &PgPool,
    community_id: CommunityId,
    target_repo_a: &str,
    ref_name: &str,
    old_oid: &str,
    new_oid: &str,
) -> Result<Vec<CiMergeBypassRecord>> {
    let rows = sqlx::query(
        "SELECT event_id, channel_id, issuer_pubkey, target_repo_a, ref_name, old_oid, new_oid, \
                reason, issued_at, expires_at, consumed_by, accepted_at \
         FROM ci_merge_bypasses \
         WHERE community_id = $1 AND target_repo_a = $2 AND ref_name = $3 \
           AND old_oid = $4 AND new_oid = $5 \
         ORDER BY accepted_at, event_id",
    )
    .bind(community_id.as_uuid())
    .bind(target_repo_a)
    .bind(ref_name)
    .bind(old_oid)
    .bind(new_oid)
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
            Ok(CiMergeBypassRecord {
                event_id: row.try_get("event_id")?,
                channel_id: row.try_get("channel_id")?,
                issuer_pubkey: row.try_get("issuer_pubkey")?,
                target_repo_a: row.try_get("target_repo_a")?,
                ref_name: row.try_get("ref_name")?,
                old_oid: row.try_get("old_oid")?,
                new_oid: row.try_get("new_oid")?,
                reason: row.try_get("reason")?,
                issued_at: row.try_get("issued_at")?,
                expires_at: row.try_get("expires_at")?,
                consumed_by: row.try_get("consumed_by")?,
                accepted_at: row.try_get("accepted_at")?,
            })
        })
        .collect()
}

/// Mark a bypass consumed by the allowing decision row.
///
/// Returns `true` only for the first call on an unconsumed row; a second
/// call, a foreign community, or an unknown event returns `false` and changes
/// nothing. The decision row must exist (foreign key).
pub async fn consume_ci_merge_bypass(
    pool: &PgPool,
    community_id: CommunityId,
    event_id: &[u8],
    decision_id: Uuid,
) -> Result<bool> {
    let updated = sqlx::query(
        "UPDATE ci_merge_bypasses SET consumed_by = $3 \
         WHERE community_id = $1 AND event_id = $2 AND consumed_by IS NULL",
    )
    .bind(community_id.as_uuid())
    .bind(event_id)
    .bind(decision_id)
    .execute(
        &mut *crate::observability::acquire(
            pool,
            crate::observability::PoolRole::Writer,
            crate::observability::Operation::Ci,
        )
        .await?,
    )
    .await?
    .rows_affected();
    Ok(updated == 1)
}
