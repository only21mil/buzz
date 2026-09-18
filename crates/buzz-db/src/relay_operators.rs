//! Deployment-global relay operator/moderator roster persistence.
//!
//! Backs `relay_operators` and `relay_operator_audit` from migrations
//! `0045_relay_operators.sql` and `0049_relay_operator_audit.sql`.

use sqlx::{Acquire, Postgres, Row as _, Transaction};

use crate::error::{DbError, Result};

/// Advisory-lock namespace for per-target roster mutation serialization.
const OPERATOR_LOCK_NAMESPACE: &str = "relay_operator:";

/// Well-known advisory-lock key for roster-wide serialization.
const OPERATOR_ROSTER_LOCK: &str = "relay_operator_roster";

/// A row in `relay_operators`, as consumed by the admin roster seam.
#[derive(Debug, Clone)]
pub struct RelayOperatorRow {
    /// 32-byte pubkey (binary).
    pub pubkey: Vec<u8>,
    /// Stored role string (`operator` or `moderator`, or an unknown value preserved verbatim).
    pub role: String,
    /// Pubkey of the operator who added this entry (32 bytes binary).
    pub added_by: Vec<u8>,
}

async fn acquire_operator_lock(
    tx: &mut Transaction<'_, Postgres>,
    pubkey: &[u8; 32],
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("{OPERATOR_LOCK_NAMESPACE}{}", hex::encode(pubkey)))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn acquire_roster_lock(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(OPERATOR_ROSTER_LOCK)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn writer_connection(
    pool: &sqlx::PgPool,
) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
    crate::observability::acquire(
        pool,
        crate::observability::PoolRole::Writer,
        crate::observability::Operation::Other,
    )
    .await
    .map_err(DbError::from)
}

fn row_from_record(
    row: sqlx::postgres::PgRow,
) -> std::result::Result<RelayOperatorRow, sqlx::Error> {
    Ok(RelayOperatorRow {
        pubkey: row.try_get("pubkey")?,
        role: row.try_get("role")?,
        added_by: row.try_get("added_by")?,
    })
}

impl crate::Db {
    /// Fetch one relay operator/moderator row by pubkey.
    pub async fn get_relay_operator(&self, pubkey: &[u8; 32]) -> Result<Option<RelayOperatorRow>> {
        let mut connection = writer_connection(&self.pool).await?;
        let row =
            sqlx::query("SELECT pubkey, role, added_by FROM relay_operators WHERE pubkey = $1")
                .bind(pubkey.as_slice())
                .fetch_optional(&mut *connection)
                .await?;

        row.map(row_from_record).transpose().map_err(DbError::from)
    }

    /// List all relay operator/moderator rows ordered by creation time.
    pub async fn list_relay_operators(&self) -> Result<Vec<RelayOperatorRow>> {
        let mut connection = writer_connection(&self.pool).await?;
        let rows = sqlx::query(
            "SELECT pubkey, role, added_by FROM relay_operators ORDER BY created_at ASC",
        )
        .fetch_all(&mut *connection)
        .await?;

        rows.into_iter()
            .map(row_from_record)
            .collect::<std::result::Result<Vec<_>, sqlx::Error>>()
            .map_err(DbError::from)
    }

    /// Insert or update a relay operator/moderator row, recording the mutation
    /// in `relay_operator_audit` within the same transaction.
    ///
    /// Returns the previous role string when a row already existed.
    pub async fn upsert_relay_operator(
        &self,
        pubkey: &[u8; 32],
        role: &str,
        added_by: &[u8; 32],
    ) -> Result<Option<String>> {
        let mut connection = writer_connection(&self.pool).await?;
        let mut tx = connection.begin().await?;

        acquire_operator_lock(&mut tx, pubkey).await?;

        let prev_role: Option<String> =
            sqlx::query_scalar("SELECT role FROM relay_operators WHERE pubkey = $1 FOR UPDATE")
                .bind(pubkey.as_slice())
                .fetch_optional(&mut *tx)
                .await?;

        sqlx::query(
            r#"
            INSERT INTO relay_operators (pubkey, role, added_by)
            VALUES ($1, $2, $3)
            ON CONFLICT (pubkey) DO UPDATE SET
                role = EXCLUDED.role,
                added_by = EXCLUDED.added_by
            "#,
        )
        .bind(pubkey.as_slice())
        .bind(role)
        .bind(added_by.as_slice())
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO relay_operator_audit
                (actor_pubkey, target_pubkey, op, prev_role, new_role)
            VALUES ($1, $2, 'grant', $3, $4)
            "#,
        )
        .bind(added_by.as_slice())
        .bind(pubkey.as_slice())
        .bind(prev_role.as_deref())
        .bind(role)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(prev_role)
    }

    /// Remove a relay operator/moderator row and record the revocation audit row
    /// in the same transaction. Returns whether a row existed.
    pub async fn remove_relay_operator(&self, pubkey: &[u8; 32], actor: &[u8; 32]) -> Result<bool> {
        let mut connection = writer_connection(&self.pool).await?;
        let mut tx = connection.begin().await?;

        acquire_roster_lock(&mut tx).await?;

        let prev_role: Option<String> =
            sqlx::query_scalar("DELETE FROM relay_operators WHERE pubkey = $1 RETURNING role")
                .bind(pubkey.as_slice())
                .fetch_optional(&mut *tx)
                .await?;

        let removed = prev_role.is_some();
        if removed {
            sqlx::query(
                r#"
                INSERT INTO relay_operator_audit
                    (actor_pubkey, target_pubkey, op, prev_role, new_role)
                VALUES ($1, $2, 'revoke', $3, NULL)
                "#,
            )
            .bind(actor.as_slice())
            .bind(pubkey.as_slice())
            .bind(prev_role.as_deref())
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(removed)
    }

    /// Remove a relay operator/moderator row without writing an audit row.
    ///
    /// Prefer [`remove_relay_operator`] for staffing mutations; this exists for
    /// the narrow `delete_relay_operator` contract in the admin roster seam.
    pub async fn delete_relay_operator(&self, pubkey: &[u8; 32]) -> Result<bool> {
        let mut connection = writer_connection(&self.pool).await?;
        let removed: Option<String> =
            sqlx::query_scalar("DELETE FROM relay_operators WHERE pubkey = $1 RETURNING role")
                .bind(pubkey.as_slice())
                .fetch_optional(&mut *connection)
                .await?;
        Ok(removed.is_some())
    }
}
