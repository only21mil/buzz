#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC2034

PROBE_NAME=p5_dropped_run
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

# An owner-operated runner kill is the live setup for P-v. The shipped mock
# has an explicit equivalent so this suite can exercise the same assertion
# without killing the local shell that is running the probes.
mock_drop=false
if [[ "$(basename -- "$BUZZ_CI_BIN")" == mock-buzz* || "${BUZZ_CI_MOCK_DROP_RUNNER:-}" == 1 ]]; then
  mock_drop=true
fi

if [[ "$mock_drop" == true ]]; then
  capture_cmd env MOCK_CI_INFRASTRUCTURE_FAILURE=1 "$BUZZ_CI_BIN" ci run --repo-owner "$BUZZ_CI_REPO_OWNER" --repo-id "$BUZZ_CI_REPO_ID" --sha "$BUZZ_CI_SHA" --workflow "$BUZZ_CI_WORKFLOW"
else
  capture_cli ci run --repo-owner "$BUZZ_CI_REPO_OWNER" --repo-id "$BUZZ_CI_REPO_ID" --sha "$BUZZ_CI_SHA" --workflow "$BUZZ_CI_WORKFLOW"
fi
trigger=$CAPTURE_STDOUT
run_id=
pass=false
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$trigger" && assert_jq '.state == "queued" and (.run_id | type == "string")' "$trigger"; then
  run_id=$(jq -r '.run_id' <<<"$trigger")
  pass=true
fi
record_assertion "trigger_drop_candidate" "$pass" "created a run to observe runner loss"

watch_output=
watch_rc=4
watch_timeout="${BUZZ_CI_WATCH_TIMEOUT:-15}"
if [[ -n "$run_id" ]]; then
  capture_cmd timeout "$watch_timeout" "$BUZZ_CI_BIN" ci watch --run "$run_id"
  watch_output=$CAPTURE_STDOUT
  watch_rc=$CAPTURE_EXIT
fi

pass=false
if assert_exit 0 "$watch_rc" && assert_jsonl "$watch_output"; then
  watch_events=$(printf '%s\n' "$watch_output" | jq -cs '.')
  if assert_jq 'length >= 2 and all(.[]; (.run_id | type == "string") and (.sha | type == "string") and (.attempt | type == "number"))' "$watch_events"; then
    pass=true
  fi
fi
record_assertion "watch_jsonl_and_identity" "$pass" "watch emits transition JSONL with run identity and exits"

pass=false
if [[ -n "$watch_output" ]]; then
  final_event=$(printf '%s\n' "$watch_output" | tail -n 1)
  if assert_json "$final_event" && assert_jq '(.state == "infrastructure_failure" or .state == "cancelled") and (.reason | type == "string" and length > 0)' "$final_event"; then
    pass=true
  fi
fi
record_assertion "terminal_reason_for_dropped_run" "$pass" "watch ends on infrastructure_failure/cancelled with a reason"

verdict_output=
verdict_rc=4
if [[ -n "$run_id" ]]; then
  capture_cli ci verdict --run "$run_id" --expect-sha "$BUZZ_CI_SHA"
  verdict_output=$CAPTURE_STDOUT
  verdict_rc=$CAPTURE_EXIT
fi

pass=false
if assert_exit 4 "$verdict_rc" && assert_json "$verdict_output"; then
  verdict_bound=$(jq -cn --arg expected_run_id "$run_id" --arg expected_sha "$BUZZ_CI_SHA" --argjson response "$verdict_output" '{expected_run_id:$expected_run_id,expected_sha:$expected_sha,response:$response}')
  if assert_jq '.response.run_id == .expected_run_id and .response.sha == .expected_sha and .response.attempt == 1 and .response.verdict == "infrastructure_failure" and .response.verdict != "red" and (.response.required_failing == []) and (.response.reason | type == "string") and (.response.reason | length > 0) and (.response.jobs_terminal | type == "number") and (.response.jobs_total | type == "number")' "$verdict_bound"; then
    pass=true
  fi
fi
record_assertion "infrastructure_verdict_exit_four" "$pass" "infrastructure verdict exits 4 with a distinct verdict and reason"

probe_finish
