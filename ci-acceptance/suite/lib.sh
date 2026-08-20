#!/usr/bin/env bash
set -euo pipefail

# Helpers for the suite orchestrators. Security runners deliberately do not
# source this file. They have a small, standalone contract so they can be
# copied and exercised in isolation.

# shellcheck disable=SC2034
SUITE_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SUITE_ACCEPTANCE_DIR="$(cd -- "$SUITE_LIB_DIR/.." && pwd -P)"
# shellcheck disable=SC2034
SUITE_RECORD_SCHEMA="$SUITE_ACCEPTANCE_DIR/evidence/record.schema.json"
# shellcheck disable=SC2034
SUITE_TM_TESTS="$SUITE_ACCEPTANCE_DIR/evidence/tm_tests.json"
SUITE_PROBES_DIR="$SUITE_ACCEPTANCE_DIR/probes"
# shellcheck disable=SC2034
SUITE_RUN_PROBES="$SUITE_PROBES_DIR/run_probes.sh"

: "${SUITE_TIMEOUT_SECONDS:=600}"
if [[ ! "$SUITE_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  SUITE_TIMEOUT_SECONDS=600
fi
export SUITE_TIMEOUT_SECONDS

SUITE_LAST_RC=0

suite_now() {
  date +%s
}

suite_is_full_oid() {
  local value=${1-}
  [[ "$value" =~ ^[0-9a-f]{40}$ || "$value" =~ ^[0-9a-f]{64}$ ]]
}

suite_require_full_oid() {
  local value=${1-}
  if suite_is_full_oid "$value"; then
    return 0
  fi
  printf 'candidate must be a full lowercase 40- or 64-hex object id\n' >&2
  return 1
}

suite_detect_sudo() {
  SUITE_SUDO=''
  if command -v sudo >/dev/null 2>&1 \
    && timeout 5 sudo -n true >/dev/null 2>&1; then
    SUITE_SUDO='sudo -n'
  fi
  export SUITE_SUDO
}

suite_run_bounded() {
  local seconds=${1:?timeout seconds required}
  local stdout_file=${2:?stdout file required}
  local stderr_file=${3:?stderr file required}
  shift 3

  : >"$stdout_file"
  : >"$stderr_file"
  set +e
  timeout "$seconds" "$@" >"$stdout_file" 2>"$stderr_file"
  SUITE_LAST_RC=$?
  set -e
  export SUITE_LAST_RC
  return 0
}

suite_hash_file() {
  local file=${1:?file required}
  sha256sum -- "$file" | awk '{print $1}'
}

suite_hash_reference() {
  printf 'sha256:%s\n' "$(suite_hash_file "$1")"
}

suite_is_safe_relative_path() {
  local value=${1-}
  [[ -n "$value" && "$value" != /* && "$value" != . \
    && "$value" != ./* && "$value" != ../* && "$value" != */../* \
    && "$value" != */.. ]]
}

suite_path_is_under() {
  local base base_real target_real
  base=$(readlink -f -- "$1") || return 1
  target_real=$(readlink -f -- "$2" 2>/dev/null) || return 1
  base_real=${base%/}
  [[ "$target_real" == "$base_real"/* ]]
}

suite_write_manifest() {
  local test_dir=${1:?test directory required}
  local paths_file=${2:?path list required}
  local manifest=${3:?manifest path required}
  local relative absolute hash

  : >"$manifest"
  while IFS= read -r relative || [[ -n "$relative" ]]; do
    [[ -n "$relative" ]] || continue
    suite_is_safe_relative_path "$relative" || return 1
    absolute="$test_dir/$relative"
    [[ -f "$absolute" ]] || return 1
    suite_path_is_under "$test_dir" "$absolute" || return 1
    hash=$(suite_hash_file "$absolute")
    printf '%s  %s\n' "$hash" "$relative" >>"$manifest"
  done <"$paths_file"
}

suite_emit_record() {
  local suite=${1:?suite required}
  local test_id=${2:?test id required}
  local title=${3:?title required}
  local candidate=${4:?candidate required}
  local pass=${5:?pass required}
  local evidence_ref=${6:?evidence reference required}
  local executor=${7:?executor required}
  local host=${8:?host required}
  local started=${9:?started timestamp required}
  local finished=${10:?finished timestamp required}
  local run=${11-}

  [[ "$pass" == true || "$pass" == false ]] || return 1
  if [[ "$suite" == probe ]]; then
    [[ "$run" == 1 || "$run" == 2 ]] || return 1
    jq -cn \
      --arg suite "$suite" \
      --arg test_id "$test_id" \
      --arg title "$title" \
      --arg candidate_sha "$candidate" \
      --argjson pass "$pass" \
      --arg evidence_ref "$evidence_ref" \
      --arg executor "$executor" \
      --arg host "$host" \
      --argjson started_at "$started" \
      --argjson finished_at "$finished" \
      --argjson run "$run" \
      '{suite:$suite,test_id:$test_id,title:$title,candidate_sha:$candidate_sha,pass:$pass,run:$run,evidence_ref:$evidence_ref,executor:$executor,host:$host,started_at:$started_at,finished_at:$finished_at}'
    return 0
  fi
  [[ "$suite" == security && -z "$run" ]] || return 1
  jq -cn \
    --arg suite "$suite" \
    --arg test_id "$test_id" \
    --arg title "$title" \
    --arg candidate_sha "$candidate" \
    --argjson pass "$pass" \
    --arg evidence_ref "$evidence_ref" \
    --arg executor "$executor" \
    --arg host "$host" \
    --argjson started_at "$started" \
    --argjson finished_at "$finished" \
    '{suite:$suite,test_id:$test_id,title:$title,candidate_sha:$candidate_sha,pass:$pass,evidence_ref:$evidence_ref,executor:$executor,host:$host,started_at:$started_at,finished_at:$finished_at}'
}

suite_validate_record_line() {
  local line=${1:?record line required}
  local expected_suite=${2:?expected suite required}
  local expected_candidate=${3:?expected candidate required}
  local expected_id=${4:?expected id required}
  local expected_run=${5:-}

  jq -e \
    --arg expected_suite "$expected_suite" \
    --arg expected_candidate "$expected_candidate" \
    --arg expected_id "$expected_id" \
    --argjson expected_run "${expected_run:-null}" \
    '
      type == "object" and
      ([keys[]] - ["suite","test_id","title","candidate_sha","pass","run","evidence_ref","executor","host","started_at","finished_at"] | length == 0) and
      (.suite == $expected_suite and .test_id == $expected_id and
       (.title | type == "string" and length > 0) and
       ((.candidate_sha | type == "string") and
        (.candidate_sha | test("^([0-9a-f]{40}|[0-9a-f]{64})$")) and
        .candidate_sha == $expected_candidate) and
       (.pass | type == "boolean") and
       (.evidence_ref | type == "string" and length > 0) and
       (.executor | type == "string" and length > 0) and
       (.host | type == "string" and length > 0) and
       (.started_at | type == "number" and floor == . and . >= 0) and
       (.finished_at | type == "number" and floor == . and . >= 0) and
       (.finished_at >= .started_at) and
       (if $expected_suite == "probe"
        then has("run") and .run == $expected_run and (.run == 1 or .run == 2)
        else (has("run") | not)
        end))
    ' <<<"$line" >/dev/null
}

suite_validate_external_schema() {
  local object_file=${1:?record object file required}
  if command -v jsonschema >/dev/null 2>&1; then
    timeout 30 jsonschema -i "$object_file" "$SUITE_RECORD_SCHEMA" >/dev/null 2>&1
    return $?
  fi
  if command -v check-jsonschema >/dev/null 2>&1; then
    timeout 30 check-jsonschema --schemafile "$SUITE_RECORD_SCHEMA" "$object_file" >/dev/null 2>&1
    return $?
  fi
  return 0
}

suite_validate_jsonl() {
  local file=${1:?JSONL file required}
  local expected_suite=${2:?expected suite required}
  local expected_candidate=${3:?expected candidate required}
  local schema_tmp=${4:?schema temp directory required}
  local line object_file
  local line_number=0

  [[ -f "$file" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    [[ -n "$line" ]] || return 1
    object_file=$(mktemp "$schema_tmp/record.XXXXXX") || return 1
    printf '%s\n' "$line" >"$object_file"
    if ! suite_validate_record_line "$line" "$expected_suite" "$expected_candidate" \
      "$(jq -r '.test_id // empty' <<<"$line" 2>/dev/null || true)" \
      "$(jq -r 'if has("run") then .run else empty end' <<<"$line" 2>/dev/null || true)" \
      || ! suite_validate_external_schema "$object_file"; then
      rm -f -- "$object_file"
      printf 'invalid %s record at line %d\n' "$expected_suite" "$line_number" >&2
      return 1
    fi
    rm -f -- "$object_file"
  done <"$file"
}

suite_probe_title() {
  case "$1" in
    P-i) printf '%s\n' 'Trigger and identify a CI run' ;;
    P-ii) printf '%s\n' 'Monitor queued work through assignment' ;;
    P-iii) printf '%s\n' 'Retrieve bounded headless job logs' ;;
    P-iv) printf '%s\n' 'Rerun one failed job within its bound' ;;
    P-v) printf '%s\n' 'Report a dropped runner as infrastructure failure' ;;
    P-vi) printf '%s\n' 'Bound retries against an unavailable relay' ;;
    *) return 1 ;;
  esac
}

suite_resolve_command() {
  local value=${1:?command required}
  if [[ "$value" == */* ]]; then
    readlink -f -- "$value"
    return $?
  fi
  command -v -- "$value"
}
