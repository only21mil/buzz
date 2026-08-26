#!/usr/bin/env bash
# B1 rev-2 route-bearing isolated local preflight basis (deliverable 2).
#
# Runs the three env-guarded in-process preflight route tests
# (`api::ci::tests::route_*`) against a scratch Postgres, spinning the relay
# router in-process on the (unused) ephemeral port with the scratch DB, no
# Redis, and no live git store. Captures the exact pass/fail + deterministic
# sha256 like the grants basis.
#
# Prereqs: scratch Postgres reachable on localhost:${PGPORT:-5432} (the
# `buzz-postgres` container), and a cargo matching the pinned 1.95.0
# toolchain (or set CARGO). The route tests are `#[ignore]`d by default; this
# script forces them with `--ignored` so release/config automation never
# silently skips the acceptance contract.
#
# Usage:
#   ./scripts/b1-preflight-route-basis.sh [database_url]
#
# Environment overrides:
#   DB_SCRATCH       scratch database name (default buzz_b1_scratch).
#   PGPORT           host port for Postgres (default 5432).
#   CARGO            cargo binary override.
#   KEEP_DB          keep the scratch DB after the run.

set -euo pipefail

ADMIN_URL="${1:-postgres://buzz:buzz_dev@localhost:5432/postgres}"
DB_NAME="${DB_SCRATCH:-buzz_b1_scratch}"
PGPORT="${PGPORT:-5432}"

CARGO_BIN="${CARGO:-}"
if [[ -z "$CARGO_BIN" ]]; then
  if [[ -x "/home/victor/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo" ]]; then
    CARGO_BIN="/home/victor/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo"
  elif command -v cargo >/dev/null 2>&1; then
    CARGO_BIN="$(command -v cargo)"
  else
    echo "b1-preflight-route-basis: no cargo found; set CARGO" >&2
    exit 2
  fi
fi

WORKTREE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== b1-preflight-route-basis =="
echo "== scratch db: $DB_NAME (port $PGPORT)"

# NOTE: DROP DATABASE cannot run inside a transaction block, so the drop and
# create are two SEPARATE `psql -c` commands (each its own implicit
# transaction); do not wrap them with `-1`/`--single-transaction`.
if [[ -n "${KEEP_DB:-}" ]]; then
  echo "== KEEP_DB set: leaving existing $DB_NAME in place"
else
  echo "== dropping (if present) and recreating $DB_NAME"
  if command -v psql >/dev/null 2>&1; then
    DROP_DDL="DROP DATABASE IF EXISTS \"$DB_NAME\" WITH (FORCE);"
    CREATE_DDL="CREATE DATABASE \"$DB_NAME\";"
    if ! psql "postgres://buzz:buzz_dev@127.0.0.1:$PGPORT/postgres" -v ON_ERROR_STOP=1 -c "$DROP_DDL" >/dev/null 2>&1 \
      || ! psql "postgres://buzz:buzz_dev@127.0.0.1:$PGPORT/postgres" -v ON_ERROR_STOP=1 -c "$CREATE_DDL" >/dev/null 2>&1; then
      psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "$DROP_DDL"
      psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "$CREATE_DDL"
    fi
  elif docker ps --format '{{.Names}}' 2>/dev/null | grep -qx buzz-postgres; then
    docker exec buzz-postgres sh -c "psql -U buzz -d postgres -v ON_ERROR_STOP=1 -c 'DROP DATABASE IF EXISTS \"$DB_NAME\" WITH (FORCE);' && psql -U buzz -d postgres -v ON_ERROR_STOP=1 -c 'CREATE DATABASE \"$DB_NAME\";'"
  else
    echo "b1-preflight-route-basis: no psql and no buzz-postgres container; install psql or start the Postgres container" >&2
    exit 2
  fi
fi

export BUZZ_TEST_DATABASE_URL="postgres://buzz:buzz_dev@127.0.0.1:$PGPORT/$DB_NAME"
export DATABASE_URL="$BUZZ_TEST_DATABASE_URL"
export RUSTUP_HOME="${RUSTUP_HOME:-/home/victor/.rustup}"
export CARGO_HOME="${CARGO_HOME:-/home/victor/.cargo}"

echo "== running route preflight acceptance against $BUZZ_TEST_DATABASE_URL"
echo "== cargo: $CARGO_BIN"

cd "$WORKTREE_ROOT"
set -o pipefail
# `--ignored` must precede the test-name filter: it forces the env-guarded
# route tests on; each also self-checks BUZZ_TEST_DATABASE_URL so a missing
# scratch DB still fails loudly.
OUTPUT="$("$CARGO_BIN" test -p buzz-relay --lib -- --ignored 'api::ci::tests::route_' 2>&1)"
STATUS=$?
set +o pipefail

printf '%s\n' "$OUTPUT"

if [[ $STATUS -ne 0 ]]; then
  echo "PREFLIGHT_ROUTE_SCORE: 0/N (cargo exit $STATUS)" >&2
  exit $STATUS
fi

VERDICT="$(printf '%s\n' "$OUTPUT" \
  | grep -E '^(test |test result:)' \
  | grep -vE '^test [^ ]+ \.\.\. (ignored|null; )' \
  || true)"
PASSED="$(printf '%s\n' "$OUTPUT" | grep -oE 'test result: ok\. [0-9]+ passed' | grep -oE '[0-9]+' | head -1 || echo 0)"
TOTAL="$(printf '%s\n' "$OUTPUT" | grep -oE '[0-9]+ passed; [0-9]+ failed' | awk -F' passed; ' '{print $1+$2}' | head -1 || echo 0)"
if [[ -z "$TOTAL" || "$TOTAL" == "0" ]]; then
  TOTAL="$(printf '%s\n' "$OUTPUT" | grep -cE '^test [^ ]+ \.\.\. ok' || true)"
fi

SHA256="$(printf '%s\n' "$VERDICT" | sha256sum | awk '{print $1}')"
echo "PREFLIGHT_ROUTE_SCORE: $PASSED/$TOTAL"
echo "PREFLIGHT_ROUTE_OUTPUT_SHA256: $SHA256"