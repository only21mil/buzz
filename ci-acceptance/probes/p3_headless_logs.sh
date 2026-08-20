#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC2034

PROBE_NAME=p3_headless_logs
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

capture_cli ci run --repo-owner "$BUZZ_CI_REPO_OWNER" --repo-id "$BUZZ_CI_REPO_ID" --sha "$BUZZ_CI_SHA" --workflow "$BUZZ_CI_WORKFLOW"
trigger=$CAPTURE_STDOUT
run_id=
pass=false
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$trigger" && assert_jq '.state == "queued" and (.jobs | length == 4)' "$trigger"; then
  run_id=$(jq -r '.run_id' <<<"$trigger")
  pass=true
fi
record_assertion "trigger_probe_run" "$pass" "created a run for the failed-job log probe"

flaky_failed=false
polls=0
while ((polls < 100)) && [[ "$flaky_failed" == false ]]; do
  capture_cli ci status --run "$run_id"
  status_output=$CAPTURE_STDOUT
  if ! assert_exit 0 "$CAPTURE_EXIT" || ! assert_json "$status_output"; then
    break
  fi
  if jq -e 'any(.jobs[]; .name == "flaky" and .state == "failure")' <<<"$status_output" >/dev/null 2>&1; then
    flaky_failed=true
    break
  fi
  polls=$((polls + 1))
  sleep 0.1
done
record_assertion "flaky_reaches_failure" "$flaky_failed" "flaky attempt 1 is observable as a failed job"

log_output=
log_rc=4
if [[ -n "$run_id" ]]; then
  # setsid with stdin closed is the headless-auth probe required by §3.
  capture_cmd setsid --wait "$BUZZ_CI_BIN" ci logs --run "$run_id" --job flaky --attempt 1 < /dev/null
  log_output=$CAPTURE_STDOUT
  log_rc=$CAPTURE_EXIT
fi

pass=false
if assert_exit 0 "$log_rc" && assert_json "$log_output"; then
  pass=true
fi
record_assertion "headless_log_json" "$pass" "setsid log retrieval exits successfully with one JSON object"

pass=false
if assert_json "$log_output"; then
  content=$(jq -r '.url_or_inline // empty' <<<"$log_output")
  if grep -Fq 'flaky attempt 1 failure' <<<"$content"; then
    pass=true
  fi
fi
record_assertion "failure_line_grepable" "$pass" "failed-job log contains its deterministic failure line"

pass=false
if assert_json "$log_output" && assert_jq '.job_id == "flaky" and .attempt == 1 and (.log_sha256 | type == "string") and (.truncated | type == "boolean") and (.cap_bytes | type == "number")' "$log_output"; then
  log_sha=$(jq -r '.log_sha256' <<<"$log_output")
  if assert_full_oid "$log_sha"; then
    pass=true
  fi
fi
record_assertion "attempt_scoped_scrubbed_log" "$pass" "response carries attempt, full log hash, truncation flag, and cap"

probe_finish
