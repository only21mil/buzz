# Disposable PostgreSQL tests

Ignored database tests need an explicit run. `scripts/postgres-test-local.py`
runs each selected Rust libtest case in its own database and removes the whole
cluster after each case, including failure or interruption. This adapts isolation
from upstream `bd73490418266f267d9bb3bdf13e64582adc8e80` within the existing
Backend Integration CI job. Required context names,
full PR-to-main/manual conditions, and live relay E2E remain unchanged.

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

`scripts/postgres-tests.tsv` explicitly records every ignored Rust test under
`crates/`, its exact compiled name, source, target, schema mode, and fixture
reason. `desired` applies `schema/schema.sql`; `migration` starts empty for
fixtures that install their own schema or migrations. `external` records tests
requiring relay, Redis, object storage or model fixtures; those remain outside
the PostgreSQL-only runner and keep their existing execution paths.

The four fork database contract binaries, CI ingest storage, ten workflow
recovery cases, preflight fixtures, command persistence, push and migration
fixtures are explicitly classified. Auto mode rejects unknown names and
external cases. An explicit `--schema-mode migration|desired` supports local
fixture development, but does not admit that fixture to CI.

CI runs:

```sh
scripts/test-postgres-test-discovery.sh
scripts/postgres-test-run.sh --task-root /path/to/task --pg-bin-dir /path/to/postgres/bin
```

The first command checks every source ignore attribute (including bare and
raw-string annotations). New, removed, renamed or ambiguously classified tests
fail the guard. To add a test, review its actual setup and add an exact TSV row;
do not infer mode from a broad test-name prefix. Source-only discovery cannot
prove a case was compiled. The second command compiles every admitted library
and integration target, compares each binary's full ignored-test list with the
manifest, then runs every PostgreSQL-only case. Missing or unknown compiled
cases fail before any database starts. `--list` performs compilation and this
reconciliation without starting PostgreSQL. To reuse a current compilation,
pass `--artifacts /path/to/cargo-output.jsonl [...]`; only test-profile library
and integration executables are accepted, and every admitted target is required.

Each case uses a fresh cluster and database, sequentially. Role changes, scratch
databases, destructive schema fixtures and cluster-global locks cannot leak to
the next test. SQLx receives the socket in the URL; a deliberately invalid TCP
hostname prevents accidental network fallback. The FTS fixture parses SQLx
connection options instead of concatenating a second URL query. `--filter name
--exact` runs exactly one local case. Cleanup preserves a failing test's exit
status; if shutdown fails, data remains for explicit cleanup with a diagnostic.

Use `--repo-root /path/to/worktree` on the local runner when desired schema
belongs to another checkout. Migration binaries embed migrations at compile
time, so recompile after SQL changes. Complete discovery is not a claim that
all listed tests ran locally: record selected cases and unrun scope separately.

The existing native-CI Python suites now share
`scripts/test-native-ci-python.sh` between unit tests and pre-freeze. Schema
validator `check-jsonschema==0.38.0` and the existing clean-host ISO tools are
still required. This implements the local gate tracked by
[#160](https://github.com/only21mil/buzz/issues/160), alongside existing
[retry-policy #157](https://github.com/only21mil/buzz/issues/157) and
[runner schema drift #149](https://github.com/only21mil/buzz/issues/149).
No new issue or change to signed events, grants, receipts, promotion or delivery
authority is introduced.

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
