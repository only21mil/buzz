#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC2034

PROBE_NAME=p4_bounded_rerun
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
record_assertion "trigger_rerun_run" "$pass" "created a run for the single-job rerun probe"

capture_cli ci status --run "$run_id"
running_status=$CAPTURE_STDOUT
pass=false
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$running_status" && assert_jq '.state == "running" and all(.jobs[]; .state == "running")' "$running_status"; then
  pass=true
fi
record_assertion "running_baseline" "$pass" "baseline status exposes all jobs while running"

capture_cli ci rerun --run "$run_id" --job flaky
running_rerun_error=$(failure_json || true)
pass=false
if assert_exit 1 "$CAPTURE_EXIT" && assert_json "$running_rerun_error" && assert_jq '.error == "job_not_terminal"' "$running_rerun_error"; then
  pass=true
fi
record_assertion "rerun_nonterminal_refused" "$pass" "rerunning a running job returns job_not_terminal"

initial_terminal=
polls=0
while ((polls < 100)); do
  capture_cli ci status --run "$run_id"
  candidate=$CAPTURE_STDOUT
  if ! assert_exit 0 "$CAPTURE_EXIT" || ! assert_json "$candidate"; then
    break
  fi
  state=$(jq -r '.state' <<<"$candidate")
  if [[ "$state" == failure || "$state" == success || "$state" == cancelled || "$state" == infrastructure_failure ]]; then
    initial_terminal=$candidate
    break
  fi
  polls=$((polls + 1))
  sleep 0.1
done

pass=false
if [[ -n "$initial_terminal" ]] && assert_jq 'any(.jobs[]; .name == "flaky" and .state == "failure" and .attempt == 1)' "$initial_terminal"; then
  pass=true
fi
record_assertion "initial_flaky_failure" "$pass" "initial terminal view has flaky failure at attempt 1"

capture_cli ci rerun --run "$run_id" --job ok
terminal_success_rerun_error=$(failure_json || true)
pass=false
if assert_exit 1 "$CAPTURE_EXIT" && assert_json "$terminal_success_rerun_error"; then
  terminal_success_bound=$(jq -cn --arg expected_run_id "$run_id" --argjson response "$terminal_success_rerun_error" '{expected_run_id:$expected_run_id,response:$response}')
  if assert_jq '.response.error == "job_not_failed" and .response.run_id == .expected_run_id and .response.job_id == "ok" and .response.attempt == 1 and .response.state == "success"' "$terminal_success_bound"; then
    pass=true
  fi
fi
record_assertion "rerun_terminal_success_refused" "$pass" "rerunning terminal success returns job_not_failed"

capture_cli ci verdict --run "$run_id" --expect-sha "$BUZZ_CI_SHA"
initial_verdict=$CAPTURE_STDOUT
pass=false
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$initial_verdict" && assert_jq '.response.sha == .expected and .response.verdict == "red"' "$(jq -cn --arg expected "$BUZZ_CI_SHA" --argjson response "$initial_verdict" '{expected:$expected,response:$response}')"; then
  pass=true
fi
record_assertion "verdict_red_before_rerun" "$pass" "required flaky failure prevents a green verdict"

capture_cli ci rerun --run "$run_id" --job flaky
rerun_output=$CAPTURE_STDOUT
pass=false
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$rerun_output" && assert_jq '.response.run_id == .expected_run_id and .response.sha == .expected_sha and .response.job_id == "flaky" and .response.attempt == 2 and .response.parent_attempt == 1 and .response.state == "queued" and (.response.also_reruns | length == 0)' "$(jq -cn --arg expected_run_id "$run_id" --arg expected_sha "$BUZZ_CI_SHA" --argjson response "$rerun_output" '{expected_run_id:$expected_run_id,expected_sha:$expected_sha,response:$response}')"; then
  pass=true
fi
record_assertion "single_job_attempt_two" "$pass" "rerun creates only flaky attempt 2 with parent_attempt"

capture_cli ci verdict --run "$run_id" --expect-sha "$BUZZ_CI_SHA"
pending_verdict=$CAPTURE_STDOUT
pass=false
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$pending_verdict" && assert_jq '.verdict == "pending"' "$pending_verdict"; then
  pass=true
fi
record_assertion "verdict_pending_during_rerun" "$pass" "verdict stays pending while attempt 2 is queued/running"

capture_cli ci rerun --run "$run_id" --job flaky
second_rerun_error=$(failure_json || true)
pass=false
if assert_exit 1 "$CAPTURE_EXIT" && assert_json "$second_rerun_error" && assert_jq '.error == "job_not_terminal"' "$second_rerun_error"; then
  pass=true
fi
record_assertion "second_rerun_while_running_refused" "$pass" "a second rerun while attempt 2 is running is refused"

final_terminal=
polls=0
while ((polls < 100)); do
  capture_cli ci status --run "$run_id"
  candidate=$CAPTURE_STDOUT
  if ! assert_exit 0 "$CAPTURE_EXIT" || ! assert_json "$candidate"; then
    break
  fi
  state=$(jq -r '.state' <<<"$candidate")
  if [[ "$state" == failure || "$state" == success || "$state" == cancelled || "$state" == infrastructure_failure ]]; then
    final_terminal=$candidate
    break
  fi
  polls=$((polls + 1))
  sleep 0.1
done

pass=false
if [[ -n "$final_terminal" ]] && assert_jq 'any(.jobs[]; .name == "flaky" and .state == "success" and .attempt == 2)' "$final_terminal"; then
  pass=true
fi
record_assertion "flaky_attempt_two_succeeds" "$pass" "flaky passes only with BUZZ_CI_ATTEMPT=2"

pass=false
if [[ -n "$initial_terminal" && -n "$final_terminal" ]] && assert_jq '(.after.jobs[] | select(.name == "ok") | {attempt,state}) == (.before.jobs[] | select(.name == "ok") | {attempt,state}) and (.after.jobs[] | select(.name == "never") | {attempt,state}) == (.before.jobs[] | select(.name == "never") | {attempt,state})' "$(jq -cn --argjson before "$initial_terminal" --argjson after "$final_terminal" '{before:$before,after:$after}')"; then
  pass=true
fi
record_assertion "other_jobs_untouched" "$pass" "ok and never retain their original attempts and states"

capture_cli ci logs --run "$run_id" --job flaky --attempt 1
attempt_one_log=$CAPTURE_STDOUT
capture_cli ci logs --run "$run_id" --job flaky --attempt 2
attempt_two_log=$CAPTURE_STDOUT
pass=false
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$attempt_two_log" && assert_json "$attempt_one_log"; then
  one_hash=$(jq -r '.log_sha256' <<<"$attempt_one_log")
  two_hash=$(jq -r '.log_sha256' <<<"$attempt_two_log")
  if [[ "$one_hash" != "$two_hash" ]] && assert_jq '.attempt == 1 and .job_id == "flaky"' "$attempt_one_log" && assert_jq '.attempt == 2 and .job_id == "flaky"' "$attempt_two_log"; then
    pass=true
  fi
fi
record_assertion "attempt_logs_do_not_overwrite" "$pass" "attempt 1 and attempt 2 retain distinct log hashes"

capture_cli ci verdict --run "$run_id" --expect-sha "$BUZZ_CI_SHA"
final_verdict=$CAPTURE_STDOUT
pass=false
if assert_exit 0 "$CAPTURE_EXIT" && assert_json "$final_verdict"; then
  final_bound=$(jq -cn --arg expected "$BUZZ_CI_SHA" --argjson response "$final_verdict" '{expected:$expected,response:$response}')
  if assert_jq '.response.sha == .expected and .response.verdict == "green" and (.response.required_failing | length == 0)' "$final_bound"; then
    pass=true
  fi
fi
record_assertion "verdict_green_after_attempt_two" "$pass" "green is returned only after the required flaky retry succeeds"

probe_finish
