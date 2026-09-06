//! Database pressure metrics with closed labels and cancellation-safe waiters.
//!
//! All observations use in-process state. Serving never depends on permission
//! to read PostgreSQL activity catalogs or availability of a metrics exporter.

use std::{future::Future, time::Instant};

use crate::{Db, DbError};

/// Describe bounded pressure metrics for the active exporter. This performs no I/O.
pub fn describe_metrics() {
    metrics::describe_counter!(
        "buzz_db_operations_total",
        "Database observations by physical pool, bounded operation, phase and outcome"
    );
    metrics::describe_histogram!(
        "buzz_db_operation_duration_seconds",
        metrics::Unit::Seconds,
        "Elapsed acquisition, query or operation time including cancellations"
    );
    metrics::describe_gauge!(
        "buzz_db_pool_waiters",
        "Currently pending instrumented pool acquisitions"
    );
}

/// Physical connection pool used by an operation.
#[derive(Clone, Copy, Debug)]
pub enum PoolRole {
    /// Serving writer.
    Writer,
    /// Optional bounded-staleness reader.
    Reader,
}
impl PoolRole {
    fn label(self) -> &'static str {
        match self {
            Self::Writer => "writer",
            Self::Reader => "reader",
        }
    }
}

/// Closed workload vocabulary. Never construct labels from SQL or tenant data.
#[derive(Clone, Copy, Debug)]
pub enum Operation {
    /// Readiness acquisition and health query.
    Readiness,
    /// Community lifecycle and tenant resolution.
    Community,
    /// Channel membership reads and writes.
    Membership,
    /// Coordinate-serialized replaceable event persistence.
    Replacement,
    /// Signed native CI event persistence and signer grants.
    Ci,
    /// Workflow history, approvals, effects, transitions and state.
    Workflow,
    /// Replica boot/fence and bounded background work.
    Maintenance,
    /// Replica-backed history acquisition.
    History,
    /// Compatibility entry points without narrower caller intent.
    Other,
}
impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::Readiness => "readiness",
            Self::Community => "community",
            Self::Membership => "membership",
            Self::Replacement => "replacement",
            Self::Ci => "ci",
            Self::Workflow => "workflow",
            Self::Maintenance => "maintenance",
            Self::History => "history",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy)]
enum Outcome {
    Success,
    Error,
    Timeout,
    Cancelled,
}
impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }
    fn sqlx(error: &sqlx::Error) -> Self {
        match error {
            sqlx::Error::PoolTimedOut => Self::Timeout,
            sqlx::Error::Database(error) => match error.code().as_deref() {
                Some("55P03") => Self::Timeout,
                Some("57014") if error.message().contains("statement timeout") => Self::Timeout,
                Some("57014") => Self::Cancelled,
                _ => Self::Error,
            },
            _ => Self::Error,
        }
    }
}

struct Observation {
    role: PoolRole,
    operation: Operation,
    phase: &'static str,
    started: Instant,
    outcome: Outcome,
    waiter: Option<metrics::Gauge>,
}
impl Observation {
    fn start(role: PoolRole, operation: Operation, phase: &'static str) -> Self {
        let waiter = (phase == "acquire").then(|| {
            let gauge = metrics::gauge!("buzz_db_pool_waiters", "pool_role" => role.label(), "operation" => operation.label());
            gauge.increment(1.0);
            gauge
        });
        Self {
            role,
            operation,
            phase,
            started: Instant::now(),
            outcome: Outcome::Cancelled,
            waiter,
        }
    }
    fn finish<T>(&mut self, result: &sqlx::Result<T>) {
        self.outcome = result
            .as_ref()
            .map(|_| Outcome::Success)
            .unwrap_or_else(Outcome::sqlx);
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        if let Some(waiter) = &self.waiter {
            waiter.decrement(1.0);
        }
        metrics::counter!("buzz_db_operations_total", "pool_role" => self.role.label(), "operation" => self.operation.label(), "phase" => self.phase, "outcome" => self.outcome.label()).increment(1);
        metrics::histogram!("buzz_db_operation_duration_seconds", "pool_role" => self.role.label(), "operation" => self.operation.label(), "phase" => self.phase, "outcome" => self.outcome.label()).record(self.started.elapsed().as_secs_f64());
    }
}

/// Acquire once from the specified pool and report success, timeout, error or
/// cancellation. Dropping this future always removes its waiter contribution.
pub async fn acquire(
    pool: &sqlx::PgPool,
    role: PoolRole,
    operation: Operation,
) -> sqlx::Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
    let mut observation = Observation::start(role, operation, "acquire");
    let result = pool.acquire().await;
    observation.finish(&result);
    result
}

pub(crate) async fn begin(
    pool: &sqlx::PgPool,
    operation: Operation,
) -> sqlx::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let connection = acquire(pool, PoolRole::Writer, operation).await?;
    sqlx::Transaction::begin(connection, None).await
}

pub(crate) async fn observe<T>(
    operation: Operation,
    future: impl Future<Output = crate::Result<T>>,
) -> crate::Result<T> {
    let mut observation = Observation::start(PoolRole::Writer, operation, "operation");
    let result = future.await;
    observation.outcome = match &result {
        Ok(_) => Outcome::Success,
        Err(DbError::Sqlx(error)) => Outcome::sqlx(error),
        Err(_) => Outcome::Error,
    };
    result
}

/// Bounded result of writer readiness under a shared acquisition/query deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DbReadinessOutcome {
    /// Writer checkout and query succeeded.
    Success,
    /// Writer checkout exceeded its budget.
    PoolTimeout,
    /// Writer checkout failed.
    PoolError,
    /// Query exceeded the remaining budget.
    QueryTimeout,
    /// Acquired writer returned a query error.
    QueryError,
}
struct ReadinessConnection {
    connection: sqlx::pool::PoolConnection<sqlx::Postgres>,
    completed: bool,
}
impl Drop for ReadinessConnection {
    fn drop(&mut self) {
        if !self.completed {
            self.connection.close_on_drop();
        }
    }
}

impl Db {
    /// Check the writer once against one absolute deadline. Reader health and
    /// telemetry availability do not determine whether the writer can serve.
    pub async fn readiness_check(&self, deadline: tokio::time::Instant) -> DbReadinessOutcome {
        self.readiness_check_sql(deadline, "SELECT 1").await
    }

    async fn readiness_check_sql(
        &self,
        deadline: tokio::time::Instant,
        query: &'static str,
    ) -> DbReadinessOutcome {
        let mut acquisition = Observation::start(PoolRole::Writer, Operation::Readiness, "acquire");
        let result = tokio::time::timeout_at(deadline, self.pool.acquire()).await;
        let connection = match result {
            Err(_) | Ok(Err(sqlx::Error::PoolTimedOut)) => {
                acquisition.outcome = Outcome::Timeout;
                return DbReadinessOutcome::PoolTimeout;
            }
            Ok(Err(_)) => {
                acquisition.outcome = Outcome::Error;
                return DbReadinessOutcome::PoolError;
            }
            Ok(Ok(connection)) => {
                acquisition.outcome = Outcome::Success;
                connection
            }
        };
        drop(acquisition);
        let mut connection = ReadinessConnection {
            connection,
            completed: false,
        };
        let mut execution = Observation::start(PoolRole::Writer, Operation::Readiness, "query");
        let result = tokio::time::timeout_at(
            deadline,
            sqlx::query(query).execute(&mut *connection.connection),
        )
        .await;
        match result {
            Err(_) => {
                // A cancelled SQL future can leave unread wire messages. Closing
                // the connection also prevents a long health query occupying it.
                execution.outcome = Outcome::Timeout;
                DbReadinessOutcome::QueryTimeout
            }
            Ok(Err(error)) => {
                connection.completed = true;
                execution.outcome = Outcome::sqlx(&error);
                if matches!(execution.outcome, Outcome::Timeout) {
                    DbReadinessOutcome::QueryTimeout
                } else {
                    DbReadinessOutcome::QueryError
                }
            }
            Ok(Ok(_)) => {
                connection.completed = true;
                execution.outcome = Outcome::Success;
                DbReadinessOutcome::Success
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use sqlx::postgres::PgPoolOptions;
    use std::{collections::BTreeSet, time::Duration};

    async fn fixture() -> Db {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .min_connections(0)
            .acquire_timeout(Duration::from_millis(80))
            .connect(&std::env::var("BUZZ_TEST_DATABASE_URL").expect("isolated fixture URL"))
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
            acquire(&db.pool, PoolRole::Writer, Operation::Ci)
        )
        .await
        .is_err());
        assert!(matches!(
            acquire(&db.pool, PoolRole::Writer, Operation::Workflow).await,
            Err(sqlx::Error::PoolTimedOut)
        ));
        assert_eq!(
            db.readiness_check(deadline(15)).await,
            DbReadinessOutcome::PoolTimeout
        );
        drop(held);
        drop(
            acquire(&db.pool, PoolRole::Writer, Operation::Ci)
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
            if key.key().name() == "buzz_db_operations_total" {
                seen.insert((
                    labels["operation"].clone(),
                    labels["phase"].clone(),
                    labels["outcome"].clone(),
                ));
            }
        }
        for receipt in [
            ("ci", "acquire", "cancelled"),
            ("ci", "acquire", "success"),
            ("workflow", "acquire", "timeout"),
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
            if key.key().name() != "buzz_db_operations_total" {
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
        let admin = sqlx::PgPool::connect(&std::env::var("BUZZ_TEST_DATABASE_URL").unwrap())
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
                key.key().name() == "buzz_db_operations_total"
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
    async fn restricted_telemetry_catalog_failure_does_not_block_serving() {
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
        let url = std::env::var("BUZZ_TEST_DATABASE_URL").unwrap();
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
        for (key, _, _, _) in snapshotter.snapshot().into_vec() {
            if key.key().name() != "buzz_db_operations_total" {
                continue;
            }
            let labels = key
                .key()
                .labels()
                .map(|label| (label.key(), label.value()))
                .collect::<std::collections::BTreeMap<_, _>>();
            if labels.get("phase") == Some(&"acquire") {
                operations.insert(labels["operation"].to_owned());
            }
            assert!(labels
                .values()
                .all(|value| !value.contains("bounded-fixture")));
        }
        assert_eq!(operations, BTreeSet::from(["ci".into(), "workflow".into()]));
        db.pool.close().await;
    }
}
