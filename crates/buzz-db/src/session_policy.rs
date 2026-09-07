//! Shared serving-writer session policy.

use crate::{replica_fence, DbConfig};

/// Default writer lock wait limit in milliseconds.
pub const DEFAULT_LOCK_TIMEOUT_MS: u64 = 5_000;
/// Default writer idle transaction lifetime in milliseconds.
pub const DEFAULT_IDLE_TXN_TIMEOUT_MS: u64 = 60_000;

impl DbConfig {
    /// Apply shared timeout environment overrides. Missing, malformed, negative,
    /// and out-of-range PostgreSQL millisecond values retain the configured
    /// value. Explicit zero disables that timeout.
    pub fn with_session_timeouts_from_env(self) -> Self {
        self.with_session_timeout_values(|key| std::env::var(key).ok())
    }

    fn with_session_timeout_values(mut self, value: impl Fn(&str) -> Option<String>) -> Self {
        for (key, target) in [
            ("BUZZ_DB_LOCK_TIMEOUT_MS", &mut self.lock_timeout_ms),
            ("BUZZ_DB_IDLE_TXN_TIMEOUT_MS", &mut self.idle_txn_timeout_ms),
            (
                "BUZZ_DB_STATEMENT_TIMEOUT_MS",
                &mut self.statement_timeout_ms,
            ),
        ] {
            if let Some(parsed) = value(key)
                .and_then(|raw| raw.parse::<u64>().ok())
                .filter(|ms| *ms <= i32::MAX as u64)
            {
                *target = parsed;
            }
        }
        self
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SessionPolicy {
    lock_ms: u64,
    idle_ms: u64,
    statement_ms: u64,
}

impl From<&DbConfig> for SessionPolicy {
    fn from(config: &DbConfig) -> Self {
        Self {
            lock_ms: config.lock_timeout_ms,
            idle_ms: config.idle_txn_timeout_ms,
            statement_ms: config.statement_timeout_ms,
        }
    }
}

impl SessionPolicy {
    pub(crate) async fn apply(self, conn: &mut sqlx::PgConnection) -> sqlx::Result<()> {
        sqlx::query(
            "SELECT set_config('buzz.created_at_floor', $1, false), \
                    set_config('lock_timeout', $2, false), \
                    set_config('idle_in_transaction_session_timeout', $3, false), \
                    set_config('statement_timeout', $4, false)",
        )
        .bind(replica_fence::CREATED_AT_FLOOR_SECS.to_string())
        .bind(self.lock_ms.to_string())
        .bind(self.idle_ms.to_string())
        .bind(self.statement_ms.to_string())
        .execute(&mut *conn)
        .await?;
        let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
            .fetch_one(&mut *conn)
            .await?;
        if isolation != "read committed" {
            return Err(sqlx::Error::Protocol(
                "writer replica-floor policy requires read committed isolation".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    #[test]
    fn environment_timeout_values_preserve_defaults_and_allow_zero() {
        for value in [
            None,
            Some(""),
            Some("-1"),
            Some("nan"),
            Some("2147483648"),
            Some("18446744073709551616"),
        ] {
            let config =
                DbConfig::default().with_session_timeout_values(|_| value.map(str::to_owned));
            assert_eq!(config.lock_timeout_ms, 5_000);
            assert_eq!(config.idle_txn_timeout_ms, 60_000);
            assert_eq!(config.statement_timeout_ms, 0);
        }
        for value in [0, 37, i32::MAX as u64] {
            let config =
                DbConfig::default().with_session_timeout_values(|_| Some(value.to_string()));
            assert_eq!(config.lock_timeout_ms, value);
            assert_eq!(config.idle_txn_timeout_ms, value);
            assert_eq!(config.statement_timeout_ms, value);
        }
    }

    async fn test_db(lock_ms: u64, idle_ms: u64, statement_ms: u64) -> crate::Db {
        crate::Db::new(&DbConfig {
            database_url: std::env::var("BUZZ_TEST_DATABASE_URL")
                .expect("isolated fixture required"),
            min_connections: 0,
            max_connections: 1,
            lock_timeout_ms: lock_ms,
            idle_txn_timeout_ms: idle_ms,
            statement_timeout_ms: statement_ms,
            ..DbConfig::default()
        })
        .await
        .expect("connect writer")
    }

    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL"]
    async fn writer_policy_bounds_waits_preserves_floor_and_recovers() {
        let db = test_db(40, 0, 100).await;
        let mut holder =
            sqlx::PgConnection::connect(&std::env::var("BUZZ_TEST_DATABASE_URL").unwrap())
                .await
                .unwrap();
        sqlx::query("SELECT pg_advisory_lock(81231)")
            .execute(&mut holder)
            .await
            .unwrap();
        let error = sqlx::query("SELECT pg_advisory_lock(81231)")
            .execute(&db.pool)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("55P03")
        );
        let error = sqlx::query("SELECT pg_sleep(5)")
            .execute(&db.pool)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("57014")
        );
        let floor: String = sqlx::query_scalar("SHOW buzz.created_at_floor")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(floor, replica_fence::CREATED_AT_FLOOR_SECS.to_string());
        assert!(db.ping().await);
        db.pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL"]
    async fn idle_transaction_timeout_reaps_only_idle_transaction() {
        let db = test_db(0, 60, 0).await;
        let mut tx = db.pool.begin().await.unwrap();
        sqlx::query("SELECT 1").execute(&mut *tx).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(180)).await;
        assert!(sqlx::query("SELECT 1").execute(&mut *tx).await.is_err());
        drop(tx);
        assert!(db.ping().await);
        let mut connection = db.pool.acquire().await.unwrap();
        sqlx::query("SELECT pg_sleep(0.12)")
            .execute(&mut *connection)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        sqlx::query("SELECT 1")
            .execute(&mut *connection)
            .await
            .unwrap();
        drop(connection);
        db.pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL"]
    async fn explicit_zero_and_reader_sessions_keep_distinct_policy() {
        let db = test_db(0, 0, 0).await;
        let values: (String, String, String) = sqlx::query_as(
            "SELECT current_setting('lock_timeout'), current_setting('idle_in_transaction_session_timeout'), current_setting('statement_timeout')"
        ).fetch_one(&db.pool).await.unwrap();
        assert_eq!(values, ("0".into(), "0".into(), "0".into()));
        let config = DbConfig {
            database_url: std::env::var("BUZZ_TEST_DATABASE_URL").unwrap(),
            read_database_url: Some(std::env::var("BUZZ_TEST_DATABASE_URL").unwrap()),
            min_connections: 0,
            ..DbConfig::default()
        };
        let routed = crate::Db::new(&config).await.unwrap();
        let reader = routed.read_pool.as_ref().unwrap();
        let floor: Option<String> =
            sqlx::query_scalar("SELECT current_setting('buzz.created_at_floor', true)")
                .fetch_one(reader)
                .await
                .unwrap();
        assert!(floor.is_none());
        let lock: String = sqlx::query_scalar("SHOW lock_timeout")
            .fetch_one(reader)
            .await
            .unwrap();
        assert_eq!(lock, "0");
        reader.close().await;
        routed.pool.close().await;
        db.pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL"]
    async fn migration_wait_and_cancellation_never_return_relaxed_session() {
        let db = test_db(20, 0, 20).await;
        db.migrate().await.unwrap();
        let mut holder =
            sqlx::PgConnection::connect(&std::env::var("BUZZ_TEST_DATABASE_URL").unwrap())
                .await
                .unwrap();
        let mut tx = holder.begin().await.unwrap();
        sqlx::query("LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await
            .unwrap();
        // The serving 20 ms budget is exceeded while migration preflight waits.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), db.migrate())
                .await
                .is_err()
        );
        tx.rollback().await.unwrap();
        let limits: (String, String) = sqlx::query_as(
            "SELECT current_setting('lock_timeout'), current_setting('statement_timeout')",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(limits, ("20ms".into(), "20ms".into()));
        db.migrate().await.unwrap();
        sqlx::query("UPDATE _sqlx_migrations SET checksum = decode('00', 'hex') WHERE version = 1")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(
            db.migrate().await.is_err(),
            "checksum mismatch must fail closed"
        );
        let lock: String = sqlx::query_scalar("SHOW lock_timeout")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(lock, "20ms");
        assert!(db.ping().await);
        db.pool.close().await;
    }
    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL"]
    async fn writer_policy_rejects_non_read_committed_isolation() {
        let mut connection =
            sqlx::PgConnection::connect(&std::env::var("BUZZ_TEST_DATABASE_URL").unwrap())
                .await
                .unwrap();
        sqlx::query("SET default_transaction_isolation = 'repeatable read'")
            .execute(&mut connection)
            .await
            .unwrap();
        let error = SessionPolicy::from(&DbConfig::default())
            .apply(&mut connection)
            .await
            .unwrap_err();
        assert!(matches!(error, sqlx::Error::Protocol(_)));
        connection.close().await.unwrap();
    }
}
