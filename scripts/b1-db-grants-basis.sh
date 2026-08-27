#!/usr/bin/env bash
# B1 rev-2 reproducible DB-grants basis (deliverable 3).
#
# Boots a scratch Postgres database (default: `buzz_b1_scratch` on the healthy
# `buzz-postgres` container that the previous B1 integrator used), applies the
# canonical migration set, and runs the `ci_grants_contract` integration suite
# against it. It captures the exact pass/fail record AND a deterministic
# sha256 of the output so the rev-2 report can state the grant acceptance
# (5/5 in rev-1, now the 7+ contract rows) with a standalone artifact path.
#
# Prereqs:
#   * A reachable Postgres writing to `localhost:${PGPORT:-5432}`
#     (the `buzz-postgres` container serves it by default).
#   * cargo accessed via the pinned 1.95.0 toolchain (see below) or your PATH.
#
# Usage:
#   ./scripts/b1-db-grants-basis.sh [database_url]
#
#   database_url   full sqlx URL to an ADMIN role that can CREATE DATABASE.
#                  Default: postgres://buzz:buzz_dev@localhost:5432/postgres
#
# Environment overrides:
#   PGPORT         host port for the Postgres container (default 5432).
#   DB_NAME        scratch database name (default buzz_b1_scratch).
#   CARGO          cargo binary (default: the pinned 1.95.0 toolchain cargo,
#                  else `cargo` on PATH).
#   KEEP_DB        if non-empty, do not drop the scratch DB after the run.
#
# Outputs (all printed to stdout):
#   * the exact cargo test invocation + its captured output;
#   * `GRANT_SCORE: N/N` line with N = passed, total;
#   * `GRANT_OUTPUT_SHA256: <hex>` over the deterministic verdict lines only
#     (the per-test result lines + the final `test result:` line), so the
#     artifact is reproducible across toolchain output noise.

set -euo pipefail

ADMIN_URL="${1:-postgres://buzz:buzz_dev@localhost:5432/postgres}"
DB_NAME="${DB_NAME:-buzz_b1_scratch}"
PGPORT="${PGPORT:-5432}"

# Resolve a cargo. Prefer the pinned 1.95.0 toolchain (matches the repo's
# rust-toolchain.toml and the rev-1 gate record); fall back to PATH cargo.
CARGO_BIN="${CARGO:-}"
if [[ -z "$CARGO_BIN" ]]; then
  if [[ -x "/home/victor/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo" ]]; then
    CARGO_BIN="/home/victor/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo"
  elif command -v cargo >/dev/null 2>&1; then
    CARGO_BIN="$(command -v cargo)"
  else
    echo "b1-db-grants-basis: no cargo found; set CARGO" >&2
    exit 2
  fi
fi

WORKTREE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# A fresh schema boundary for the scratch DB every run: if the previous run
# left the DB (KEEP_DB), the migration runner is idempotent, but the tests
# themselves create unique communities/channels, so state never collides.
echo "== b1-db-grants-basis =="
echo "== admin url host: $(printf '%s' "$ADMIN_URL" | sed -E 's#://[^@]*@#://#')"
echo "== scratch db: $DB_NAME (port $PGPORT)"

# 1. Ensure the scratch DB exists (terminate + recreate unless KEEP_DB).
#    Runs DDL via a local psql if present, else inside the healthy
#    `buzz-postgres` container (the previous integrator's Postgres).
#    NOTE: DROP DATABASE cannot run inside a transaction block, so the drop and
#    create are two SEPARATE `psql -c` commands (each its own implicit
#    transaction); do not wrap them with `-1`/`--single-transaction`.
if [[ -n "${KEEP_DB:-}" ]]; then
  echo "== KEEP_DB set: leaving existing $DB_NAME in place"
else
  echo "== dropping (if present) and recreating $DB_NAME"
  # Run as two separate `-c` invocations: DROP DATABASE cannot run inside a
  # transaction block, so a single `-1` menu of the two statements fails.
  if command -v psql >/dev/null 2>&1; then
    DROP_DDL="DROP DATABASE IF EXISTS \"$DB_NAME\" WITH (FORCE);"
    CREATE_DDL="CREATE DATABASE \"$DB_NAME\";"
    if ! psql -h 127.0.0.1 -p "$PGPORT" -U buzz -d postgres -v ON_ERROR_STOP=1 -c "$DROP_DDL" >/dev/null 2>&1 \
      || ! psql -h 127.0.0.1 -p "$PGPORT" -U buzz -d postgres -v ON_ERROR_STOP=1 -c "$CREATE_DDL" >/dev/null 2>&1; then
      psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "$DROP_DDL"
      psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "$CREATE_DDL"
    fi
  elif docker ps --format '{{.Names}}' 2>/dev/null | grep -qx buzz-postgres; then
    docker exec buzz-postgres sh -c "psql -U buzz -d postgres -v ON_ERROR_STOP=1 -c 'DROP DATABASE IF EXISTS \"$DB_NAME\" WITH (FORCE);' && psql -U buzz -d postgres -v ON_ERROR_STOP=1 -c 'CREATE DATABASE \"$DB_NAME\";'"
  else
    echo "b1-db-grants-basis: no psql and no buzz-postgres container; install psql or start the Postgres container" >&2
    exit 2
  fi
fi

export BUZZ_TEST_DATABASE_URL="postgres://buzz:buzz_dev@127.0.0.1:$PGPORT/$DB_NAME"
export DATABASE_URL="$BUZZ_TEST_DATABASE_URL"
export BUZZ_TEST_OWNER_PRIVATE_KEY=
export RUSTUP_HOME="${RUSTUP_HOME:-/home/victor/.rustup}"
export CARGO_HOME="${CARGO_HOME:-/home/victor/.cargo}"

echo "== running ci_grants_contract against $BUZZ_TEST_DATABASE_URL"
echo "== cargo: $CARGO_BIN"

set -o pipefail
cd "$WORKTREE_ROOT"
# `--ignored`: the Postgres-backed contract tests are #[ignore]d by default; a
# basis run must force them on so the artifact is a real acceptance, not a skip.
OUTPUT="$("$CARGO_BIN" test -p buzz-db --test ci_grants_contract -- --ignored 2>&1)"
STATUS=$?
set +o pipefail

# Print the full captured output verbatim.
printf '%s\n' "$OUTPUT"

if [[ $STATUS -ne 0 ]]; then
  echo "GRANT_SCORE: 0/N (cargo exit $STATUS)" >&2
  exit $STATUS
fi

# Deterministic verdict: only the per-test lines + the final test-result line.
VERDICT="$(printf '%s\n' "$OUTPUT" \
  | grep -E '^(test |test result:)' \
  | grep -vE '^test [^ ]+ \.\.\. (ignored|null; )' \
  || true)"

PASSED="$(printf '%s\n' "$OUTPUT" | grep -oE 'test result: ok\. [0-9]+ passed' | grep -oE '[0-9]+' | head -1 || echo 0)"
TOTAL="$(printf '%s\n' "$OUTPUT" | grep -oE '[0-9]+ passed; [0-9]+ failed' | awk -F' passed; ' '{print $1+$2}' | head -1 || echo 0)"
if [[ -z "$TOTAL" || "$TOTAL" == "0" ]]; then
  TOTAL="$(printf '%s\n' "$OUTPUT" | grep -cE '^test [^ ]+ \.\.\. (ok|ignored)' || true)"
fi

SHA256="$(printf '%s\n' "$VERDICT" | sha256sum | awk '{print $1}')"
echo "GRANT_SCORE: $PASSED/$TOTAL"
echo "GRANT_OUTPUT_SHA256: $SHA256"