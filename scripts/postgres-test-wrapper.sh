#!/usr/bin/env bash
# Give each nextest process its own PostgreSQL database. The test binary and
# arguments supplied by nextest must always be executed by this wrapper.
set -euo pipefail

: "${NEXTEST_RUN_ID:?nextest must provide NEXTEST_RUN_ID}"
: "${NEXTEST_BINARY_ID:?nextest must provide NEXTEST_BINARY_ID}"
: "${NEXTEST_TEST_NAME:?nextest must provide NEXTEST_TEST_NAME}"
: "${NEXTEST_ATTEMPT_ID:?nextest must provide NEXTEST_ATTEMPT_ID}"
: "${BUZZ_POSTGRES_ADMIN_URL:?setup must provide BUZZ_POSTGRES_ADMIN_URL}"
: "${BUZZ_POSTGRES_DESIRED_TEMPLATE:?setup must provide BUZZ_POSTGRES_DESIRED_TEMPLATE}"

resolve_pg_command() {
  local name="$1"
  local candidate
  if [[ -n "${PG_BIN_DIR:-}" ]]; then
    candidate="${PG_BIN_DIR}/${name}"
  else
    candidate="$(command -v "$name" || true)"
  fi
  if [[ -z "$candidate" || ! -x "$candidate" ]]; then
    echo "required PostgreSQL client is not executable: ${candidate:-$name}" >&2
    exit 1
  fi
  printf '%s\n' "$candidate"
}

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 | awk '{print $NF}'
  else
    echo "a SHA-256 utility (sha256sum, shasum, or openssl) is required" >&2
    return 1
  fi
}

createdb="$(resolve_pg_command createdb)"
dropdb="$(resolve_pg_command dropdb)"

identity="${NEXTEST_RUN_ID}:${NEXTEST_BINARY_ID}:${NEXTEST_TEST_NAME}:${NEXTEST_ATTEMPT_ID}"
database_hash="$(printf '%s' "$identity" | sha256_hex)"
database_hash="${database_hash:0:24}"
database="buzz_nt_${database_hash}"
# Use the same exact admission ledger as the isolated Python runner. Nextest
# names library binaries by package and integration binaries as package::target.
workspace_root="${NEXTEST_WORKSPACE_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
schema_mode="$(python3 - "$workspace_root" <<'PY_MODE'
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(sys.argv[1]) / 'scripts'))
from postgres_test_inventory import read_inventory
identity = os.environ['NEXTEST_BINARY_ID']
package, separator, target = identity.partition('::')
binary = target if separator else package.replace('-', '_')
rows = [row for row in read_inventory(Path(sys.argv[1]))
        if row['package'] == package and row['binary'] == binary
        and row['test'] == os.environ['NEXTEST_TEST_NAME']]
if len(rows) != 1 or rows[0]['mode'] == 'external':
    raise SystemExit('refusing unknown, ambiguous or external PostgreSQL test')
print(rows[0]['mode'])
PY_MODE
)"
source_database="$BUZZ_POSTGRES_DESIRED_TEMPLATE"
if [[ "$schema_mode" == migration ]]; then
  source_database="template0"
fi

cleanup() {
  local attempt
  for attempt in 1 2 3 4 5; do
    if "$dropdb" --if-exists --force \
      --maintenance-db="$BUZZ_POSTGRES_ADMIN_URL" \
      "$database" >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$attempt" -lt 5 ]]; then
      sleep 1
    fi
  done
  echo "warning: failed to remove isolated PostgreSQL test database after 5 attempts: $database" >&2
  return 0
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$createdb" \
  --maintenance-db="$BUZZ_POSTGRES_ADMIN_URL" \
  --template="$source_database" \
  "$database"

database_url="${BUZZ_POSTGRES_ADMIN_URL%/*}/$database"
export DATABASE_URL="$database_url"
export TEST_DATABASE_URL="$database_url"
export BUZZ_TEST_DATABASE_URL="$database_url"
export BUZZ_TEST_SCHEMA_MODE="$schema_mode"

"$@"
