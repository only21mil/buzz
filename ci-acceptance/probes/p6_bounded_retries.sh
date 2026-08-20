#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC2034

PROBE_NAME=p6_bounded_retries
PROBE_RUN=
while (($# > 0)); do
  case "$1" in
    --run)
      (($# >= 2)) || { printf '%s\n' '--run needs a value' >&2; exit 4; }
      PROBE_RUN=$2
      shift 2
      ;;
    *)
      printf 'usage: %s --run 1|2\n' "$0" >&2
      exit 4
      ;;
  esac
done

export PROBE_NAME PROBE_RUN
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/lib.sh"
validate_probe_inputs

dead_relay="${BUZZ_CI_DEAD_RELAY_URL:-ws://127.0.0.1:9}"
retry_count="${BUZZ_CI_RETRIES:-3}"
command_timeout="${BUZZ_CI_RETRY_TIMEOUT:-5}"
dummy_run=dead-relay-run

check_dead_command() {
  local label=$1
  shift
  capture_cmd timeout "$command_timeout" env BUZZ_RELAY_URL="$dead_relay" BUZZ_CI_RETRIES="$retry_count" BUZZ_CI_RETRY_DELAY=0 "$BUZZ_CI_BIN" "$@"
  local rc=$CAPTURE_EXIT
  local stderr=$CAPTURE_STDERR
  local stdout=$CAPTURE_STDOUT
  local attempts
  attempts=$(grep -Eic "attempt[[:space:]]+[0-9]+/${retry_count}" <<<"$stderr" || true)
  local pass=false
  if assert_exit 2 "$rc" && [[ -z "$stdout" ]] && ((attempts >= retry_count)); then
    pass=true
  fi
  record_assertion "dead_relay_${label}" "$pass" "exit 2 after $attempts/$retry_count bounded attempts"
}

check_dead_command run ci run --repo-owner "$BUZZ_CI_REPO_OWNER" --repo-id "$BUZZ_CI_REPO_ID" --sha "$BUZZ_CI_SHA" --workflow "$BUZZ_CI_WORKFLOW"
check_dead_command status ci status --run "$dummy_run"
check_dead_command logs ci logs --run "$dummy_run" --job flaky --attempt 1
check_dead_command rerun ci rerun --run "$dummy_run" --job flaky
check_dead_command verdict ci verdict --run "$dummy_run" --expect-sha "$BUZZ_CI_SHA"
check_dead_command watch ci watch --run "$dummy_run"

probe_finish
