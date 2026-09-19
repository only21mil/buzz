//! Serving connection policy for the audit writer.

use buzz_db::{Db, DbConfig};

/// Connect the bounded audit writer pool with the serving writer session policy.
pub async fn connect_audit_pool(config: &DbConfig) -> anyhow::Result<sqlx::PgPool> {
    let audit_config = DbConfig {
        read_database_url: None,
        max_connections: 5,
        min_connections: 1,
        ..config.clone()
    };
    Db::connect_writer_pool(&audit_config)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod postgres_tests {
    use super::*;
    use std::time::Duration;
    use uuid::Uuid;

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn audit_writer_pool_installs_timeouts_and_bounds_advisory_lock_waits() {
        let database_url = crate::test_support::database_url();
        let pool = connect_audit_pool(&DbConfig {
            database_url,
            max_connections: 2,
            min_connections: 0,
            lock_timeout_ms: 500,
            idle_txn_timeout_ms: 60_000,
            statement_timeout_ms: 0,
            ..DbConfig::default()
        })
        .await
        .expect("connect audit writer pool");

        let (lock, idle, statement): (String, String, String) = sqlx::query_as(
            "SELECT current_setting('lock_timeout'), \
                    current_setting('idle_in_transaction_session_timeout'), \
                    current_setting('statement_timeout')",
        )
        .fetch_one(&pool)
        .await
        .expect("read effective audit writer GUCs");
        assert_eq!(lock, "500ms");
        assert_eq!(idle, "1min");
        assert_eq!(statement, "0");

        let lock_key = i64::from_be_bytes(
            Uuid::new_v4().as_bytes()[..8]
                .try_into()
                .expect("eight UUID bytes"),
        );
        let mut holder = pool.acquire().await.expect("audit lock holder");
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(lock_key)
            .execute(&mut *holder)
            .await
            .expect("hold audit advisory lock");

        let started = std::time::Instant::now();
        let mut waiter = pool.acquire().await.expect("audit lock waiter");
        let error = sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(lock_key)
            .execute(&mut *waiter)
            .await
            .expect_err("audit advisory-lock waiter must time out");
        let code = match &error {
            sqlx::Error::Database(db_error) => db_error.code().map(|code| code.to_string()),
            other => panic!("expected database error, got {other:?}"),
        };
        assert_eq!(code.as_deref(), Some("55P03"));
        assert!(started.elapsed() < Duration::from_secs(5));

        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(lock_key)
            .execute(&mut *holder)
            .await
            .expect("release audit advisory lock");
    }
}
