#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC2034

PROBE_NAME=p1_trigger
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
first_output=$CAPTURE_STDOUT
first_run_id=
pass=false
first_bound=
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$first_output"; then
  first_bound=$(jq -cn --arg expected "$BUZZ_CI_SHA" --argjson response "$first_output" '{expected:$expected,response:$response}')
  if assert_jq '.response.sha == .expected and .response.attempt == 1 and .response.state == "queued" and (.response.jobs | type == "array")' "$first_bound"; then
    pass=true
    first_run_id=$(jq -r '.run_id' <<<"$first_output")
  fi
fi
record_assertion "trigger_json_sha_and_queued" "$pass" "run response is a JSON object with the requested full SHA"

pass=false
if [[ -n "$first_run_id" && "$first_run_id" != null ]] && assert_jq '.run_id | type == "string" and length > 0' "$first_output"; then
  pass=true
fi
record_assertion "trigger_run_id" "$pass" "trigger returned a non-empty run_id"

capture_cli ci run --repo-owner "$BUZZ_CI_REPO_OWNER" --repo-id "$BUZZ_CI_REPO_ID" --sha "$BUZZ_CI_SHA" --workflow "$BUZZ_CI_WORKFLOW"
second_output=$CAPTURE_STDOUT
second_run_id=
pass=false
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$second_output"; then
  second_run_id=$(jq -r '.run_id' <<<"$second_output")
  if [[ -n "$first_run_id" && -n "$second_run_id" && "$first_run_id" != "$second_run_id" ]]; then
    pass=true
  fi
fi
record_assertion "duplicate_trigger_distinct_run" "$pass" "same SHA/workflow creates a distinct run_id"

fake_sha=$(fabricated_sha "$BUZZ_CI_SHA")
capture_cli ci run --repo-owner "$BUZZ_CI_REPO_OWNER" --repo-id "$BUZZ_CI_REPO_ID" --sha "$fake_sha" --workflow "$BUZZ_CI_WORKFLOW"
fake_output=$(failure_json || true)
pass=false
if assert_exit 1 "$CAPTURE_EXIT" && assert_json "$fake_output"; then
  fake_bound=$(jq -cn --arg requested "$fake_sha" --argjson response "$fake_output" '{requested:$requested,response:$response}')
  if assert_jq '.response.error == "sha_mismatch" and .response.requested == .requested and (.response.resolved | type == "string")' "$fake_bound"; then
    pass=true
  fi
fi
record_assertion "fabricated_sha_refused" "$pass" "unfetchable full SHA is refused with sha_mismatch"

probe_finish
