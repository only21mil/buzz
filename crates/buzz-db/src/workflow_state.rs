//! Durable, workflow-scoped key/value state.

use std::{fmt, str::FromStr};

use buzz_core::CommunityId;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use crate::{DbError, Result};

const MAX_KEY_BYTES: usize = 512;
const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_LIVE_ROWS: i64 = 256;
const MAX_LIVE_VALUE_BYTES: i64 = 4 * 1024 * 1024;

/// Opaque compare-and-set token for one incarnation of a state key.
///
/// The wire form is `<incarnation-uuid>:<counter>`. Recreating an expired key
/// uses a new incarnation, so an old token cannot match after an ABA cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowStateRevision {
    incarnation: Uuid,
    counter: i64,
}

impl WorkflowStateRevision {
    fn new(incarnation: Uuid, counter: i64) -> Result<Self> {
        if counter < 1 {
            return Err(DbError::InvalidData(
                "workflow state revision counter must be positive".into(),
            ));
        }
        Ok(Self {
            incarnation,
            counter,
        })
    }
}

impl fmt::Display for WorkflowStateRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.incarnation, self.counter)
    }
}

impl FromStr for WorkflowStateRevision {
    type Err = DbError;

    fn from_str(value: &str) -> Result<Self> {
        let (incarnation, counter) = value.rsplit_once(':').ok_or_else(|| {
            DbError::InvalidData("workflow state revision must be <uuid>:<counter>".into())
        })?;
        let incarnation = Uuid::parse_str(incarnation).map_err(|_| {
            DbError::InvalidData("workflow state revision contains an invalid UUID".into())
        })?;
        let counter = counter.parse::<i64>().map_err(|_| {
            DbError::InvalidData("workflow state revision contains an invalid counter".into())
        })?;
        Self::new(incarnation, counter)
    }
}

impl Serialize for WorkflowStateRevision {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for WorkflowStateRevision {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// A live workflow-state value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowStateEntry {
    /// Stored UTF-8 value.
    pub value: String,
    /// Opaque compare-and-set token.
    pub revision: WorkflowStateRevision,
    /// Database expiry timestamp.
    pub expires_at: DateTime<Utc>,
}

/// Quota that rejected a workflow-state write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStateLimit {
    /// The write would exceed 256 live keys.
    LiveRows,
    /// The write would exceed 4 MiB across live values.
    LiveValueBytes,
}

/// Durable result of a workflow-state write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WorkflowStateWriteOutcome {
    /// The value was created or updated.
    Written {
        /// Value now stored for the key.
        value: String,
        /// New opaque revision token.
        revision: WorkflowStateRevision,
    },
    /// The expected revision did not match the live row.
    Conflict {
        /// Current value, or `None` when the key is absent or expired.
        current_value: Option<String>,
        /// Current token, or `None` when the key is absent or expired.
        current_revision: Option<WorkflowStateRevision>,
    },
    /// The write would exceed a per-workflow live-state quota.
    LimitExceeded {
        /// Quota that the write would exceed.
        limit: WorkflowStateLimit,
    },
    /// This run step already has a receipt for a different request hash.
    RequestConflict,
}

enum ExpectedRevision {
    Any,
    Absent,
    Exact(WorkflowStateRevision),
}

impl ExpectedRevision {
    fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None => Ok(Self::Any),
            Some("0") => Ok(Self::Absent),
            Some(value) => Ok(Self::Exact(value.parse()?)),
        }
    }
}

struct StoredState {
    value: String,
    revision: WorkflowStateRevision,
    expires_at: DateTime<Utc>,
}

/// Read a live value for a workflow.
///
/// A row whose expiry is equal to or earlier than the database clock is absent.
pub async fn read_workflow_state(
    pool: &PgPool,
    community_id: CommunityId,
    workflow_id: Uuid,
    key: &str,
) -> Result<Option<WorkflowStateEntry>> {
    validate_key(key)?;
    sqlx::query(
        "SELECT value,state_incarnation,revision,expires_at FROM workflow_state \
         WHERE community_id=$1 AND workflow_id=$2 AND state_key=$3 AND expires_at>now()",
    )
    .bind(community_id.as_uuid())
    .bind(workflow_id)
    .bind(key)
    .fetch_optional(pool)
    .await?
    .map(row_to_entry)
    .transpose()
}

/// Read a live value after resolving the workflow from a run.
pub async fn read_workflow_state_for_run(
    pool: &PgPool,
    community_id: CommunityId,
    run_id: Uuid,
    key: &str,
) -> Result<Option<WorkflowStateEntry>> {
    validate_key(key)?;
    let row = sqlx::query(
        r#"SELECT s.value,s.state_incarnation,s.revision,s.expires_at
           FROM workflow_runs r
           LEFT JOIN workflow_state s
             ON s.community_id=r.community_id AND s.workflow_id=r.workflow_id
            AND s.state_key=$3 AND s.expires_at>now()
           WHERE r.community_id=$1 AND r.id=$2"#,
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(key)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| DbError::NotFound(format!("workflow_run {run_id}")))?;
    let value: Option<String> = row.try_get("value")?;
    value
        .map(|value| {
            Ok(WorkflowStateEntry {
                value,
                revision: WorkflowStateRevision::new(
                    row.try_get("state_incarnation")?,
                    row.try_get("revision")?,
                )?,
                expires_at: row.try_get("expires_at")?,
            })
        })
        .transpose()
}

/// Delete a bounded batch of expired state rows.
///
/// Reads already treat expired rows as absent, so correctness does not depend
/// on this reclamation job running on time.
pub async fn purge_expired_workflow_state(pool: &PgPool, limit: u32) -> Result<u64> {
    let limit = i64::from(limit.clamp(1, 1_000));
    let deleted = sqlx::query(
        r#"
        WITH doomed AS (
            SELECT ctid
            FROM workflow_state
            WHERE expires_at <= clock_timestamp()
            ORDER BY expires_at
            FOR UPDATE SKIP LOCKED
            LIMIT $1
        )
        DELETE FROM workflow_state AS state
        USING doomed
        WHERE state.ctid = doomed.ctid
        "#,
    )
    .bind(limit)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(deleted)
}

/// Write state for the workflow that owns `run_id`.
///
/// The receipt request hash is SHA-256 over this module's stable domain-v1 tuple:
/// run id, step id, key, value, logical expiry seconds, and expected revision.
/// It must not hash the newly computed `expires_at`. A matching receipt is
/// replayed before a new absolute expiry is derived, so delayed retries return
/// the original result without applying the write again.
///
/// `expected_revision = Some("0")` is create-only. Other supplied values must
/// be opaque tokens previously returned by this module.
#[allow(clippy::too_many_arguments)]
pub async fn write_workflow_state(
    pool: &PgPool,
    community_id: CommunityId,
    run_id: Uuid,
    step_id: &str,
    key: &str,
    value: &str,
    expires_in_secs: i64,
    expected_revision: Option<&str>,
) -> Result<WorkflowStateWriteOutcome> {
    validate_step_id(step_id)?;
    validate_key(key)?;
    validate_value(value)?;
    let expected = ExpectedRevision::parse(expected_revision)?;
    let request_hash = state_write_request_hash(
        run_id,
        step_id,
        key,
        value,
        expires_in_secs,
        expected_revision,
    )?;

    let mut tx = pool.begin().await?;
    let workflow_id: Uuid =
        sqlx::query_scalar("SELECT workflow_id FROM workflow_runs WHERE community_id=$1 AND id=$2")
            .bind(community_id.as_uuid())
            .bind(run_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("workflow_run {run_id}")))?;

    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(workflow_lock_key(community_id, workflow_id))
        .execute(&mut *tx)
        .await?;

    if let Some(receipt) = sqlx::query(
        "SELECT request_hash,result FROM workflow_state_receipts \
         WHERE community_id=$1 AND run_id=$2 AND step_id=$3",
    )
    .bind(community_id.as_uuid())
    .bind(run_id)
    .bind(step_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        let stored_hash: Vec<u8> = receipt.try_get("request_hash")?;
        if stored_hash.as_slice() != request_hash {
            tx.commit().await?;
            return Ok(WorkflowStateWriteOutcome::RequestConflict);
        }
        let result: serde_json::Value = receipt.try_get("result")?;
        let outcome = serde_json::from_value(result)?;
        tx.commit().await?;
        return Ok(outcome);
    }

    if !(1..=365 * 24 * 60 * 60).contains(&expires_in_secs) {
        return Err(DbError::InvalidData(
            "workflow state expiry must be 1 second through 365 days".into(),
        ));
    }

    // `now()` is fixed at transaction start, which may precede a long wait on
    // the workflow lock. Read the database wall clock after acquiring it, then
    // derive the deadline only after the receipt replay check.
    let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let expires_at = database_now
        .checked_add_signed(Duration::seconds(expires_in_secs))
        .ok_or_else(|| DbError::InvalidData("workflow state expiry overflow".into()))?;

    let stored = sqlx::query(
        "SELECT value,state_incarnation,revision,expires_at FROM workflow_state \
         WHERE community_id=$1 AND workflow_id=$2 AND state_key=$3 FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(workflow_id)
    .bind(key)
    .fetch_optional(&mut *tx)
    .await?
    .map(row_to_stored)
    .transpose()?;
    let live = stored.filter(|state| state.expires_at > database_now);
    if live.is_none() {
        sqlx::query(
            "DELETE FROM workflow_state WHERE community_id=$1 AND workflow_id=$2 AND state_key=$3",
        )
        .bind(community_id.as_uuid())
        .bind(workflow_id)
        .bind(key)
        .execute(&mut *tx)
        .await?;
    }

    let conflict = match (&expected, &live) {
        (ExpectedRevision::Any, _) | (ExpectedRevision::Absent, None) => false,
        (ExpectedRevision::Absent, Some(_)) | (ExpectedRevision::Exact(_), None) => true,
        (ExpectedRevision::Exact(expected), Some(current)) => expected != &current.revision,
    };
    if conflict {
        let outcome = WorkflowStateWriteOutcome::Conflict {
            current_value: live.as_ref().map(|state| state.value.clone()),
            current_revision: live.as_ref().map(|state| state.revision),
        };
        store_receipt(
            &mut tx,
            community_id,
            workflow_id,
            run_id,
            step_id,
            &request_hash,
            &outcome,
        )
        .await?;
        tx.commit().await?;
        return Ok(outcome);
    }

    let (live_rows, live_bytes): (i64, i64) = sqlx::query_as(
        "SELECT count(*)::bigint,COALESCE(sum(octet_length(value)),0)::bigint \
         FROM workflow_state WHERE community_id=$1 AND workflow_id=$2 AND expires_at>$3",
    )
    .bind(community_id.as_uuid())
    .bind(workflow_id)
    .bind(database_now)
    .fetch_one(&mut *tx)
    .await?;
    let prior_bytes = live.as_ref().map_or(0, |state| state.value.len() as i64);
    let projected_rows = live_rows + i64::from(live.is_none());
    let projected_bytes = live_bytes - prior_bytes + value.len() as i64;
    let limit = if projected_rows > MAX_LIVE_ROWS {
        Some(WorkflowStateLimit::LiveRows)
    } else if projected_bytes > MAX_LIVE_VALUE_BYTES {
        Some(WorkflowStateLimit::LiveValueBytes)
    } else {
        None
    };
    if let Some(limit) = limit {
        let outcome = WorkflowStateWriteOutcome::LimitExceeded { limit };
        store_receipt(
            &mut tx,
            community_id,
            workflow_id,
            run_id,
            step_id,
            &request_hash,
            &outcome,
        )
        .await?;
        tx.commit().await?;
        return Ok(outcome);
    }

    let revision = match live {
        Some(current) => {
            let counter = current.revision.counter.checked_add(1).ok_or_else(|| {
                DbError::InvalidData("workflow state revision counter overflow".into())
            })?;
            let affected = sqlx::query(
                "UPDATE workflow_state SET value=$1,revision=$2,expires_at=$3,updated_at=now() \
                 WHERE community_id=$4 AND workflow_id=$5 AND state_key=$6",
            )
            .bind(value)
            .bind(counter)
            .bind(expires_at)
            .bind(community_id.as_uuid())
            .bind(workflow_id)
            .bind(key)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if affected != 1 {
                return Err(DbError::InvalidData(
                    "workflow state row disappeared during locked update".into(),
                ));
            }
            WorkflowStateRevision::new(current.revision.incarnation, counter)?
        }
        None => {
            let revision = WorkflowStateRevision::new(Uuid::new_v4(), 1)?;
            sqlx::query(
                "INSERT INTO workflow_state \
                 (community_id,workflow_id,state_key,value,state_incarnation,revision,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(community_id.as_uuid())
            .bind(workflow_id)
            .bind(key)
            .bind(value)
            .bind(revision.incarnation)
            .bind(revision.counter)
            .bind(expires_at)
            .execute(&mut *tx)
            .await?;
            revision
        }
    };
    let outcome = WorkflowStateWriteOutcome::Written {
        value: value.to_owned(),
        revision,
    };
    store_receipt(
        &mut tx,
        community_id,
        workflow_id,
        run_id,
        step_id,
        &request_hash,
        &outcome,
    )
    .await?;
    tx.commit().await?;
    Ok(outcome)
}

fn state_write_request_hash(
    run_id: Uuid,
    step_id: &str,
    key: &str,
    value: &str,
    expires_in_secs: i64,
    expected_revision: Option<&str>,
) -> Result<[u8; 32]> {
    let preimage = serde_json::to_vec(&(
        "buzz-workflow-state-write-v1",
        run_id,
        step_id,
        key,
        value,
        expires_in_secs,
        expected_revision,
    ))?;
    Ok(Sha256::digest(preimage).into())
}

#[allow(clippy::too_many_arguments)]
async fn store_receipt(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    community_id: CommunityId,
    workflow_id: Uuid,
    run_id: Uuid,
    step_id: &str,
    request_hash: &[u8; 32],
    outcome: &WorkflowStateWriteOutcome,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO workflow_state_receipts \
         (community_id,workflow_id,run_id,step_id,request_hash,result) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(community_id.as_uuid())
    .bind(workflow_id)
    .bind(run_id)
    .bind(step_id)
    .bind(request_hash.as_slice())
    .bind(serde_json::to_value(outcome)?)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn row_to_entry(row: sqlx::postgres::PgRow) -> Result<WorkflowStateEntry> {
    Ok(WorkflowStateEntry {
        value: row.try_get("value")?,
        revision: WorkflowStateRevision::new(
            row.try_get("state_incarnation")?,
            row.try_get("revision")?,
        )?,
        expires_at: row.try_get("expires_at")?,
    })
}

fn row_to_stored(row: sqlx::postgres::PgRow) -> Result<StoredState> {
    Ok(StoredState {
        value: row.try_get("value")?,
        revision: WorkflowStateRevision::new(
            row.try_get("state_incarnation")?,
            row.try_get("revision")?,
        )?,
        expires_at: row.try_get("expires_at")?,
    })
}

fn validate_step_id(step_id: &str) -> Result<()> {
    if step_id.is_empty() || step_id.chars().count() > 64 {
        return Err(DbError::InvalidData(
            "workflow state step_id must contain 1..=64 characters".into(),
        ));
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<()> {
    if !(1..=MAX_KEY_BYTES).contains(&key.len()) {
        return Err(DbError::InvalidData(
            "workflow state key must contain 1..=512 UTF-8 bytes".into(),
        ));
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<()> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(DbError::InvalidData(
            "workflow state value must not exceed 64 KiB".into(),
        ));
    }
    Ok(())
}

fn workflow_lock_key(community_id: CommunityId, workflow_id: Uuid) -> i64 {
    let mut bytes = [0_u8; 32];
    bytes[..16].copy_from_slice(community_id.as_uuid().as_bytes());
    bytes[16..].copy_from_slice(workflow_id.as_bytes());
    i64::from_le_bytes(Sha256::digest(bytes)[..8].try_into().expect("eight bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_round_trip_is_stable() {
        let revision: WorkflowStateRevision =
            "018f13e7-7f49-7cc1-8000-0123456789ab:42".parse().unwrap();
        assert_eq!(
            revision.to_string(),
            "018f13e7-7f49-7cc1-8000-0123456789ab:42"
        );
        let encoded = serde_json::to_string(&revision).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkflowStateRevision>(&encoded).unwrap(),
            revision
        );
    }

    #[test]
    fn zero_is_create_only_and_stale_shapes_fail() {
        assert!(matches!(
            ExpectedRevision::parse(Some("0")).unwrap(),
            ExpectedRevision::Absent
        ));
        assert!(ExpectedRevision::parse(Some("not-a-token")).is_err());
        assert!(ExpectedRevision::parse(Some("018f13e7-7f49-7cc1-8000-0123456789ab:0")).is_err());
    }

    #[test]
    fn limits_count_utf8_bytes() {
        assert!(validate_key(&"é".repeat(256)).is_ok());
        assert!(validate_key(&"é".repeat(257)).is_err());
        assert!(validate_value(&"x".repeat(MAX_VALUE_BYTES)).is_ok());
        assert!(validate_value(&"x".repeat(MAX_VALUE_BYTES + 1)).is_err());
    }

    #[test]
    fn receipt_json_preserves_conflict_value_and_token() {
        let outcome = WorkflowStateWriteOutcome::Conflict {
            current_value: Some("old".into()),
            current_revision: Some("018f13e7-7f49-7cc1-8000-0123456789ab:7".parse().unwrap()),
        };
        let encoded = serde_json::to_value(&outcome).unwrap();
        assert_eq!(
            serde_json::from_value::<WorkflowStateWriteOutcome>(encoded).unwrap(),
            outcome
        );
    }

    #[test]
    fn request_hash_has_a_pinned_stable_preimage() {
        let hash = state_write_request_hash(
            Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap(),
            "write",
            "counter",
            "1",
            60,
            Some("0"),
        )
        .unwrap();
        assert_eq!(
            hex::encode(hash),
            "01adf2dd30abefa70964179e7c01f7d386f1426e12b322caee6bcb26d82c3a46"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres with the workflow-state migration"]
    async fn postgres_receipt_replays_before_deriving_a_new_deadline() {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".into());
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect to test DB");
        let community = CommunityId::from_uuid(Uuid::new_v4());
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(community.as_uuid())
            .bind(format!(
                "state-test-{}.example",
                community.as_uuid().simple()
            ))
            .execute(&pool)
            .await
            .expect("insert community");
        let owner = vec![0x51; 32];
        crate::user::ensure_user(&pool, community, &owner)
            .await
            .expect("insert owner");
        let workflow_id = crate::workflow::create_workflow(
            &pool,
            community,
            None,
            &owner,
            "state test",
            "{}",
            &[0x52; 32],
        )
        .await
        .expect("insert workflow");
        let definition_snapshot = serde_json::json!({});
        let definition_hash = [0x52; 32];
        let run_id = crate::workflow::create_workflow_run(
            &pool,
            community,
            workflow_id,
            None,
            None,
            &definition_snapshot,
            &definition_hash,
        )
        .await
        .expect("insert run");
        let first = write_workflow_state(
            &pool,
            community,
            run_id,
            "write",
            "key",
            "value",
            3_600,
            Some("0"),
        )
        .await
        .expect("write state");
        assert!(matches!(first, WorkflowStateWriteOutcome::Written { .. }));

        let replay = write_workflow_state(
            &pool,
            community,
            run_id,
            "write",
            "key",
            "value",
            3_600,
            Some("0"),
        )
        .await
        .expect("replay receipt");
        assert_eq!(replay, first);

        let collision = write_workflow_state(
            &pool,
            community,
            run_id,
            "write",
            "key",
            "different-value",
            3_600,
            Some("0"),
        )
        .await
        .expect("detect request collision");
        assert_eq!(collision, WorkflowStateWriteOutcome::RequestConflict);
    }
}
