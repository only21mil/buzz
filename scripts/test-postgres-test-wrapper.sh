#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
wrapper="$repo_root/scripts/postgres-test-wrapper.sh"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/buzz-postgres-wrapper.XXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT

mkdir -p "$fixture_root/bin"

cat >"$fixture_root/bin/createdb" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >"$BUZZ_CREATEDB_LOG"
SH

cat >"$fixture_root/bin/dropdb" <<'SH'
#!/usr/bin/env bash
exit 0
SH

cat >"$fixture_root/bin/capture-schema-mode" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$BUZZ_TEST_SCHEMA_MODE" >"$BUZZ_SCHEMA_MODE_LOG"
SH

chmod +x "$fixture_root/bin/createdb" \
  "$fixture_root/bin/dropdb" \
  "$fixture_root/bin/capture-schema-mode"

run_case() {
  local binary_id="$1"
  local test_name="$2"
  local expected_mode="$3"
  local expected_template="$4"
  local case_id="${test_name//[^A-Za-z0-9]/_}"
  local createdb_log="$fixture_root/${case_id}.createdb"
  local mode_log="$fixture_root/${case_id}.mode"

  local status=0
  env \
    NEXTEST_RUN_ID=wrapper-test \
    NEXTEST_BINARY_ID="$binary_id" \
    NEXTEST_TEST_NAME="$test_name" \
    NEXTEST_ATTEMPT_ID=1 \
    BUZZ_POSTGRES_ADMIN_URL=postgres://buzz@localhost/postgres \
    BUZZ_POSTGRES_DESIRED_TEMPLATE=desired_template \
    BUZZ_CREATEDB_LOG="$createdb_log" \
    BUZZ_SCHEMA_MODE_LOG="$mode_log" \
    PG_BIN_DIR="$fixture_root/bin" \
    "$wrapper" "$fixture_root/bin/capture-schema-mode" || status=$?

  if [[ "$expected_mode" == refused ]]; then
    [[ "$status" -ne 0 && ! -e "$createdb_log" && ! -e "$mode_log" ]]
    return
  fi
  [[ "$status" -eq 0 ]]

  grep -Fxq "$expected_mode" "$mode_log"
  grep -Fq -- "--template=$expected_template" "$createdb_log"
}

# Real ledger entries cover package-library and package::integration identities.
run_case buzz-db \
  runtime::migration::postgres_tests::run_migrations_applies_consolidated_initial_schema_on_fresh_database \
  migration template0
run_case buzz-db \
  store::workflow_approval::tests_postgres_tests::prior_trace_is_persisted_once_and_replay_does_not_append \
  migration template0
run_case buzz-db \
  store::usage::postgres_tests::test_community_count_increases \
  desired desired_template

# Exercise every integration classification in the newly admitted fixture set.
while IFS=$'\t' read -r package binary test source mode reason; do
  case "$binary" in
    ci_grants_contract|postgres_ci_ingest_storage|postgres_agent_drafts_persistence|postgres_regression_channel_admin_bridge)
      case "$mode" in
        migration) run_case "$package::$binary" "$test" migration template0 ;;
        desired) run_case "$package::$binary" "$test" desired desired_template ;;
        external) run_case "$package::$binary" "$test" refused unused ;;
      esac
      ;;
  esac
done <"$repo_root/scripts/postgres-tests.tsv"
run_case buzz-db unknown_postgres_test refused unused
run_case wrong-package::ci_grants_contract unknown_postgres_test refused unused

echo "PostgreSQL wrapper schema-mode and admission checks passed"
