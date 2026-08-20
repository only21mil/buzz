#!/usr/bin/env bash
set -euo pipefail

# Shared shell-only helpers for the Phase-2 probes. Probe assertions write
# JSONL to RESULTS_FILE; command output itself remains in the caller's
# variables so stdout cannot be contaminated by diagnostics.
# shellcheck disable=SC2034

PROBES_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROBE_ROOT="$(cd -- "$PROBES_DIR/.." && pwd -P)"

: "${PROBE_NAME:=unknown}"
: "${PROBE_RUN:=0}"
: "${RESULTS_FILE:=$PROBE_ROOT/results.jsonl}"
: "${BUZZ_CI_BIN:=buzz}"
: "${BUZZ_CI_SHA:=1111111111111111111111111111111111111111}"
: "${BUZZ_CI_REPO_OWNER:=probe-owner}"
: "${BUZZ_CI_REPO_ID:=probe-repo}"
: "${BUZZ_CI_WORKFLOW:=phase2-probe-workflow-v1}"
: "${MOCK_STATE_DIR:=$PROBE_ROOT/.mock-state}"

PROBE_FAILED=0
CAPTURE_EXIT=0
CAPTURE_STDOUT=''
CAPTURE_STDERR=''
export CAPTURE_EXIT

die() {
  printf 'error: %s\n' "$*" >&2
  exit 4
}

assert_exit() {
  local expected=${1:?expected exit code is required}
  local actual=${2:?actual exit code is required}
  if [[ "$expected" == "$actual" ]]; then
    return 0
  fi
  printf 'expected exit %s, got %s\n' "$expected" "$actual" >&2
  return 1
}

assert_json() {
  local value
  if (($# > 0)); then
    value=$1
  else
    value=$(cat)
  fi
  [[ -n "$value" ]] || {
    printf 'expected a JSON object, got empty output\n' >&2
    return 1
  }
  if ! jq -e 'type == "object"' <<<"$value" >/dev/null 2>&1; then
    printf 'expected one JSON object on stdout\n' >&2
    return 1
  fi
}

assert_jsonl() {
  local value=${1-}
  local line
  local saw_line=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] || continue
    saw_line=1
    if ! jq -e 'type == "object"' <<<"$line" >/dev/null 2>&1; then
      printf 'watch output contained a non-object JSON line\n' >&2
      return 1
    fi
  done <<<"$value"
  ((saw_line == 1)) || {
    printf 'expected at least one JSONL transition\n' >&2
    return 1
  }
}

assert_jq() {
  local expression=${1:?jq expression is required}
  local value
  if (($# > 1)); then
    value=$2
  else
    value=$(cat)
  fi
  if ! jq -e "$expression" <<<"$value" >/dev/null 2>&1; then
    printf 'jq assertion failed: %s\n' "$expression" >&2
    return 1
  fi
}

is_full_oid() {
  local oid=${1-}
  [[ "$oid" =~ ^[0-9a-f]{40}$ || "$oid" =~ ^[0-9a-f]{64}$ ]]
}

assert_full_oid() {
  local oid=${1-}
  if is_full_oid "$oid"; then
    return 0
  fi
  printf 'not a full lowercase SHA-1/SHA-256 OID: %s\n' "$oid" >&2
  return 1
}

emit_result() {
  local probe=${1:?probe is required}
  local run=${2:?run is required}
  local assertion=${3:?assertion is required}
  local pass=${4:?pass is required}
  local detail=${5-}
  local pass_json

  case "$pass" in
    true|TRUE|1) pass_json=true ;;
    false|FALSE|0) pass_json=false ;;
    *)
      printf 'invalid assertion pass value: %s\n' "$pass" >&2
      return 1
      ;;
  esac
  mkdir -p -- "$(dirname -- "$RESULTS_FILE")"
  jq -cn \
    --arg probe "$probe" \
    --arg run "$run" \
    --arg assertion "$assertion" \
    --arg detail "$detail" \
    --argjson pass "$pass_json" \
    '{probe:$probe, run:($run|tonumber), assertion:$assertion, pass:$pass, detail:$detail}' \
    >>"$RESULTS_FILE"
}

record_assertion() {
  local assertion=${1:?assertion is required}
  local pass=${2:?pass is required}
  local detail=${3-}
  if [[ "$pass" == true ]]; then
    emit_result "$PROBE_NAME" "$PROBE_RUN" "$assertion" true "$detail"
  else
    PROBE_FAILED=1
    emit_result "$PROBE_NAME" "$PROBE_RUN" "$assertion" false "$detail"
  fi
}

capture_cmd() {
  local out_file err_file
  out_file=$(mktemp "$PROBE_ROOT/.probe-stdout.XXXXXX")
  err_file=$(mktemp "$PROBE_ROOT/.probe-stderr.XXXXXX")
  set +e
  "$@" >"$out_file" 2>"$err_file"
  CAPTURE_EXIT=$?
  set -e
  CAPTURE_STDOUT=$(<"$out_file")
  CAPTURE_STDERR=$(<"$err_file")
  rm -f -- "$out_file" "$err_file"
}

capture_cli() {
  capture_cmd "$BUZZ_CI_BIN" "$@"
}

failure_json() {
  if jq -e 'type == "object"' <<<"$CAPTURE_STDOUT" >/dev/null 2>&1; then
    printf '%s' "$CAPTURE_STDOUT"
    return 0
  fi
  if jq -e 'type == "object"' <<<"$CAPTURE_STDERR" >/dev/null 2>&1; then
    printf '%s' "$CAPTURE_STDERR"
    return 0
  fi
  return 1
}

json_value() {
  local expression=${1:?jq expression is required}
  local value=${2:?JSON value is required}
  jq -r "$expression" <<<"$value"
}

fabricated_sha() {
  local candidate=${1:?candidate SHA is required}
  local replacement
  if [[ "$candidate" == f* ]]; then
    replacement=e
  else
    replacement=f
  fi
  printf '%040d' 0 | tr '0' "$replacement"
}

probe_finish() {
  if ((PROBE_FAILED == 0)); then
    return 0
  fi
  return 1
}

validate_probe_inputs() {
  [[ "$PROBE_RUN" =~ ^[12]$ ]] || die "--run must be 1 or 2"
  assert_full_oid "$BUZZ_CI_SHA" || die "BUZZ_CI_SHA must be a full lowercase OID"
}
