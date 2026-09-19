use super::observability::{acquire_writer, WriterOperation};
use super::*;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use sqlx::postgres::PgPoolOptions;
use std::{collections::BTreeSet, time::Duration};

async fn fixture() -> Db {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .acquire_timeout(Duration::from_millis(80))
        .connect(&crate::test_support::database_url())
        .await
        .expect("connect fixture");
    Db::from_pool(pool)
}
fn deadline(ms: u64) -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_millis(ms)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn saturated_acquisition_and_cancellation_drain_bounded_waiters() {
    let db = fixture().await;
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let held = db.pool.acquire().await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_millis(15),
        acquire_writer(&db.pool, WriterOperation::EventWrite)
    )
    .await
    .is_err());
    assert!(matches!(
        acquire_writer(&db.pool, WriterOperation::Authorization).await,
        Err(sqlx::Error::PoolTimedOut)
    ));
    assert_eq!(
        db.readiness_check(deadline(15)).await,
        DbReadinessOutcome::PoolTimeout
    );
    drop(held);
    drop(
        acquire_writer(&db.pool, WriterOperation::EventWrite)
            .await
            .unwrap(),
    );
    db.pool.close().await;
    assert_eq!(
        db.readiness_check(deadline(100)).await,
        DbReadinessOutcome::PoolError
    );
    let mut seen = BTreeSet::new();
    for (key, _, _, value) in snapshotter.snapshot().into_vec() {
        let labels = key
            .key()
            .labels()
            .map(|label| (label.key().to_owned(), label.value().to_owned()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert!(labels
            .keys()
            .all(|key| ["pool_role", "operation", "phase", "outcome"].contains(&key.as_str())));
        if key.key().name() == "buzz_db_pool_waiters" {
            let DebugValue::Gauge(value) = value else {
                panic!("waiters must be a gauge")
            };
            assert_eq!(value.into_inner(), 0.0);
        }
        if key.key().name() == "buzz_db_pool_acquire_attempts_total" {
            seen.insert((
                labels["operation"].clone(),
                "acquire".to_owned(),
                labels["outcome"].clone(),
            ));
        }
    }
    for receipt in [
        ("event_write", "acquire", "cancelled"),
        ("event_write", "acquire", "success"),
        ("authorization", "acquire", "timeout"),
        ("readiness", "acquire", "timeout"),
        ("readiness", "acquire", "error"),
    ] {
        assert!(
            seen.contains(&(receipt.0.into(), receipt.1.into(), receipt.2.into())),
            "missing {receipt:?}"
        );
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn readiness_distinguishes_query_error_timeout_and_cancelled_future() {
    let db = fixture().await;
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);
    assert_eq!(
        db.readiness_check_sql(deadline(500), "SELECT 1/0").await,
        DbReadinessOutcome::QueryError
    );
    assert_eq!(
        db.readiness_check_sql(deadline(30), "SELECT pg_sleep(5)")
            .await,
        DbReadinessOutcome::QueryTimeout
    );
    assert_eq!(
        db.readiness_check(deadline(300)).await,
        DbReadinessOutcome::Success
    );
    assert!(tokio::time::timeout(
        Duration::from_millis(30),
        db.readiness_check_sql(deadline(5_000), "SELECT pg_sleep(5)")
    )
    .await
    .is_err());
    assert_eq!(
        db.readiness_check(deadline(300)).await,
        DbReadinessOutcome::Success
    );
    let mut outcomes = BTreeSet::new();
    for (key, _, _, _) in snapshotter.snapshot().into_vec() {
        if key.key().name() != "buzz_db_readiness_queries_total" {
            continue;
        }
        let labels = key
            .key()
            .labels()
            .map(|label| (label.key(), label.value()))
            .collect::<std::collections::BTreeMap<_, _>>();
        if labels.get("phase") == Some(&"query") {
            outcomes.insert(labels["outcome"].to_owned());
        }
    }
    assert_eq!(
        outcomes,
        BTreeSet::from([
            "success".into(),
            "error".into(),
            "timeout".into(),
            "cancelled".into()
        ])
    );
    db.pool.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn sql_statement_timeout_is_separate_from_acquisition_timeout() {
    let db = fixture().await;
    sqlx::query("SET statement_timeout = 30")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        db.readiness_check_sql(deadline(1_000), "SELECT pg_sleep(5)")
            .await,
        DbReadinessOutcome::QueryTimeout
    );
    assert_eq!(
        db.readiness_check(deadline(300)).await,
        DbReadinessOutcome::Success
    );
    db.pool.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_query_cancellation_is_reported_separately() {
    let db = fixture().await;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let admin = sqlx::PgPool::connect(&crate::test_support::database_url())
        .await
        .unwrap();
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let (outcome, ()) = tokio::join!(
        db.readiness_check_sql(deadline(2_000), "SELECT pg_sleep(5)"),
        async {
            // Cancel only after PostgreSQL reports this exact fixture query active.
            tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND state = 'active' AND query = 'SELECT pg_sleep(5)')")
                    .bind(pid).fetch_one(&admin).await.unwrap();
                if active { break; }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.unwrap();
            let cancelled: bool = sqlx::query_scalar("SELECT pg_cancel_backend($1)")
                .bind(pid)
                .fetch_one(&admin)
                .await
                .unwrap();
            assert!(cancelled);
        }
    );
    assert_eq!(outcome, DbReadinessOutcome::QueryError);
    assert!(snapshotter
        .snapshot()
        .into_vec()
        .iter()
        .any(|(key, _, _, _)| {
            key.key().name() == "buzz_db_readiness_queries_total"
                && key
                    .key()
                    .labels()
                    .any(|label| label.key() == "phase" && label.value() == "query")
                && key
                    .key()
                    .labels()
                    .any(|label| label.key() == "outcome" && label.value() == "cancelled")
        }));
    assert_eq!(
        db.readiness_check(deadline(300)).await,
        DbReadinessOutcome::Success
    );
    db.pool.close().await;
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and owns a cluster-global role"]
async fn cluster_global_restricted_telemetry_catalog_failure_does_not_block_serving() {
    let db = fixture().await;
    let role = "buzz_observability_fixture";
    sqlx::query("CREATE ROLE buzz_observability_fixture LOGIN NOSUPERUSER")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("REVOKE ALL ON pg_catalog.pg_stat_activity FROM PUBLIC")
        .execute(&db.pool)
        .await
        .unwrap();
    let url = crate::test_support::database_url();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(crate::test_connection::role_options(&url, role, ""))
        .await
        .unwrap();
    let restricted = Db::from_pool(pool);
    let error = sqlx::query("SELECT * FROM pg_catalog.pg_stat_activity")
        .execute(&restricted.pool)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
    // No recorder is installed, and catalog access failed. Metrics are still
    // optional; readiness depends solely on acquisition and its query.
    assert_eq!(
        restricted.readiness_check(deadline(300)).await,
        DbReadinessOutcome::Success
    );
    assert!(restricted.ping().await);
    restricted.pool.close().await;
    sqlx::query("GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("DROP ROLE buzz_observability_fixture")
        .execute(&db.pool)
        .await
        .unwrap();
    db.pool.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL desired schema"]
async fn production_fork_operations_report_ci_and_workflow_acquisitions() {
    let db = fixture().await;
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let community = buzz_core::CommunityId::from_uuid(uuid::Uuid::new_v4());
    db.get_active_ci_signers(
        community,
        uuid::Uuid::new_v4(),
        "bounded-fixture",
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    db.get_ci_run_request(community, uuid::Uuid::new_v4(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    assert!(matches!(
        db.get_workflow(community, uuid::Uuid::new_v4()).await,
        Err(DbError::NotFound(_))
    ));
    let mut operations = BTreeSet::new();
    let mut successes = 0;
    for (key, _, _, value) in snapshotter.snapshot().into_vec() {
        if key.key().name() != "buzz_db_pool_acquire_attempts_total" {
            continue;
        }
        let labels = key
            .key()
            .labels()
            .map(|label| (label.key(), label.value()))
            .collect::<std::collections::BTreeMap<_, _>>();
        if labels.get("outcome") == Some(&"success") {
            operations.insert(labels["operation"].to_owned());
            let DebugValue::Counter(count) = value else {
                panic!("expected counter")
            };
            successes += count;
        }
        assert!(labels
            .values()
            .all(|value| !value.contains("bounded-fixture")));
    }
    assert_eq!(operations, BTreeSet::from(["event_write".into()]));
    assert_eq!(
        successes, 3,
        "each production call must record its acquisition"
    );
    db.pool.close().await;
}
