#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC2034

PROBE_NAME=p2_assignment_monitor
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
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$trigger" && assert_jq '.state == "queued" and (.run_id | type == "string")' "$trigger"; then
  run_id=$(jq -r '.run_id' <<<"$trigger")
  pass=true
fi
record_assertion "trigger_queued" "$pass" "monitor starts from a queued run"

saw_running=false
saw_terminal=false
saw_infrastructure_failure=false
latest=
status_failure=false
polls=0
while ((polls < 100)); do
  capture_cli ci status --run "$run_id"
  status_output=$CAPTURE_STDOUT
  if ! assert_exit 0 "$CAPTURE_EXIT" || ! assert_json "$status_output"; then
    status_failure=true
    break
  fi
  latest=$status_output
  state=$(jq -r '.state' <<<"$status_output")
  jobs_ok=false
  if assert_jq '(.jobs | type == "array" and length == 4) and all(.jobs[]; (.state == "queued" or .state == "running" or .state == "success" or .state == "failure" or .state == "cancelled" or .state == "timed_out" or .state == "skipped"))' "$status_output"; then
    jobs_ok=true
  fi
  if [[ "$jobs_ok" != true ]]; then
    status_failure=true
    break
  fi
  if [[ "$state" == running ]]; then
    saw_running=true
  elif [[ "$state" == infrastructure_failure ]]; then
    saw_infrastructure_failure=true
    saw_terminal=true
    break
  elif [[ "$state" == failure || "$state" == success || "$state" == cancelled ]]; then
    saw_terminal=true
    break
  elif [[ "$state" != queued ]]; then
    status_failure=true
    break
  fi
  polls=$((polls + 1))
  sleep 0.1
done

pass=false
if [[ "$status_failure" == false && "$saw_running" == true ]]; then
  pass=true
elif [[ "$status_failure" == false && "$saw_infrastructure_failure" == true ]]; then
  pass=true
fi
record_assertion "queued_to_running_assignment" "$pass" "status visibly assigns the run or reports infrastructure_failure"

pass=false
if [[ "$status_failure" == false && "$saw_running" == true ]]; then
  pass=true
fi
record_assertion "per_job_states_visible" "$pass" "status includes four independently observable job states"

pass=false
if [[ "$status_failure" == false && "$saw_terminal" == true ]]; then
  if [[ "$saw_infrastructure_failure" == true ]] || assert_jq 'all(.jobs[]; .state == "success" or .state == "failure" or .state == "cancelled" or .state == "timed_out" or .state == "skipped")' "$latest"; then
    pass=true
  fi
fi
record_assertion "terminal_assignment_or_infrastructure" "$pass" "polling reaches a terminal job view within the assignment SLA"

probe_finish
