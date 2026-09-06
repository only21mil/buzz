# Writer policy and bounded database metrics

Serving writer connections use one after-connect hook for the replica created-at
floor, read-committed isolation check, and session timeouts. Relay, admin and the
relay audit pool share this constructor. Reader pools retain their lazy startup,
150 ms acquisition budget and replica proof/fallback rules.

| Environment variable | Default milliseconds |
| --- | ---: |
| `BUZZ_DB_LOCK_TIMEOUT_MS` | 5000 |
| `BUZZ_DB_IDLE_TXN_TIMEOUT_MS` | 60000 |
| `BUZZ_DB_STATEMENT_TIMEOUT_MS` | 0 |

Zero disables an individual timeout. Missing, malformed, negative or values above
PostgreSQL's signed 32-bit millisecond range retain the configured value. A very
small statement limit can prevent connection setup. Long-transaction staging
qualification is still required before rolling out these defaults.

Migrations acquire and detach one writer connection. They disable its lock and
statement limits before preflight and SQLx migration locking, retain its idle
transaction limit, and close it before serving-pool catalog verification. Error
and cancellation also close it. No relaxed session returns to the pool.

The closed operation vocabulary is `readiness`, `community`, `membership`,
`replacement`, `ci`, `workflow`, `maintenance`, `history`, and `other`. Pool role
is `writer` or `reader`; phase is `acquire`, `query`, or `operation`; outcome is
`success`, `error`, `timeout`, or `cancelled`. No label accepts SQL, hostnames,
tenant IDs, pubkeys, channels, signed events, credentials or request data.

- `buzz_db_operations_total` counts observations with those four labels.
- `buzz_db_operation_duration_seconds` measures elapsed time with the same labels.
- `buzz_db_pool_waiters` reports current instrumented acquisitions, labelled only
  by pool role and operation. A completed, failed, timed-out or dropped future
  removes its waiter contribution.

The vocabulary permits at most 216 distinct label tuples per counter or
histogram and 18 waiter series. Histograms create additional exporter bucket
series. This is a conservative label bound, not a promise that every combination
is emitted. Parent operation timing includes checkout time; it must not be added
to acquisition timing as if they represented disjoint intervals.

Instrumentation covers extracted community, replaceable and membership stores;
native CI/grants; workflow persistence, approvals, effects, transitions and state;
readiness; reader acquisition; migration checkout; and recurring writer-fence
sampling. Compatibility transaction entry points retain `other`. Existing
uninstrumented APIs are not included in waiter totals. This packet does not
claim whole-repository acquisition attribution or throughput improvement.

Readiness acquires once and executes its query against one absolute deadline.
Its result distinguishes pool and query timeouts/errors. Caller cancellation
closes an in-flight readiness connection. SQLSTATE 55P03 and statement timeouts
are counted as timeouts; PostgreSQL query cancellation and dropped futures are
counted as cancelled. PostgreSQL uses 57014 for both statement timeout and other
query cancellation, so its fixed diagnostic identifies the former. Diagnostics
are never metric labels.

Pressure metrics use process-local observations and never query PostgreSQL
activity catalogs. Readiness remains independent of exporter availability or
activity-view privileges. Restricted-role tests explicitly deny that catalog
access and verify serving still succeeds without a recorder.

Adapted in bounded packets from upstream commits
`3ed623bb217bf9697b0ce4562529254977e0ea04`,
`113a33b7e49b7173ee1767c49ef2f49c63803034`,
`beb76406c12ab8a7af9b2fcf7547c353e3369c34`, and
`91ab9d31b8f7249ff1db141ae9d8bb3f2a20bcdd`.
