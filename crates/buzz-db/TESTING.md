# Disposable PostgreSQL tests

Ignored database tests need an explicit run. `scripts/postgres-test-local.py`
runs each selected Rust libtest case in its own database and removes the whole
cluster on exit. This adapts per-test isolation from upstream
`bd73490418266f267d9bb3bdf13e64582adc8e80` without changing CI workflows or their
required contexts.

Activate Hermit, then compile only the packages needed for your change:

```sh
. ./bin/activate-hermit
cargo test -p buzz-db --tests --no-run --message-format=json > /path/to/task/binaries.jsonl
```

The JSON `compiler-artifact` records with a non-null `executable` identify the
compiled test binaries. Pass those executable paths to the runner. Do not pass
the build script executables or an application binary.

```sh
python3 scripts/postgres-test-local.py --task-root /path/to/task --list /path/to/test-binary
python3 scripts/postgres-test-local.py --task-root /path/to/task --pg-bin-dir /path/to/postgres/bin /path/to/test-binary
```

The task directory must already exist and its absolute path must be at most 75
bytes because PostgreSQL Unix sockets have a short path limit. PostgreSQL
server and client tools plus the `pgcrypto` extension are required. The runner
never starts a system service. It initializes a new cluster under that task
directory, disables TCP listening, and uses a private Unix socket. It runs tests
sequentially, which also separates cluster-global test operations. A failed test
stops the run. Use `--filter substring` to select tests, and `--list` to inspect
the ignored-test inventory without starting a server. A selection of zero tests
fails.

The runner refuses inherited `DATABASE_URL`, `TEST_DATABASE_URL`,
`BUZZ_TEST_DATABASE_URL`, `READ_DATABASE_URL`, or `BUZZ_POSTGRES_ADMIN_URL`. Unset
those variables before invocation. It discards inherited libpq `PG*` settings
and exports all three test database variables with the same disposable URL.
Never use an existing relay or live database as a test fixture. Only trusted
compiled tests are supported; the runner does not sandbox arbitrary binaries.

The fork's `ci_grants_contract`, `workflow_approval_contract`,
`workflow_enabled_persistence`, and `workflow_state_contract` binaries apply
migrations themselves, so they start empty. Migration-module tests also start
empty. Other tests get `schema/schema.sql` in a fresh database. Every test has
its own database, including tests that drop `public`. For a new self-migrating
fixture, use `--schema-mode migration`; `--schema-mode desired` explicitly
selects desired-schema initialization. Use `--repo-root /path/to/worktree` when
the desired schema belongs to another checkout. Each migration binary embeds
its own migrations at compile time, so recompile after changing SQL.

Run the frozen-prefix check before and after admitting a migration:

```sh
python3 scripts/check-frozen-migrations.py
python3 scripts/check-frozen-migrations.py --map /path/to/foundation-admission-map.json
python3 scripts/test-postgres-test-local.py
```

The SHA-256 ledger freezes versions 0001–0035 from Buzz main
`9daaf702afa3ed1146bd3cdd96af1f023f28f9fb`. The checker rejects changed or missing
historical bytes and duplicate migration versions. With `--map`, every new SQL
file must have a unique target above 35 and a complete admission entry whose
adapted SHA-256 matches. Proposed entries may remain absent from disk. The
foundation owner maintains the map and source provenance; this check does not
approve an admission or allocate a version.
