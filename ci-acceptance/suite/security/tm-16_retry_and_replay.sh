#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-16
TITLE='Run the Phase-2 retry probe with fresh workspaces using final `BUZZ_CI_RUN_ID`, `BUZZ_CI_SHA`, and `BUZZ_CI_ATTEMPT`'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
candidate=''
candidate_dir=''
evidence_dir=''
plan=0
checks=()
statuses=()
evidence_files=()
preconditions=(
  'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'
  'the published runner control entrypoint must support admit, get, cancel, request replay, nonce override, signer override, and capacity readback'
  'the accepted fixture repository must expose ci-acceptance/probe-repo/workflow.yml job flaky'
  'root readback of per-attempt receipts and proxy objects requires SUITE_SUDO or passwordless sudo'
)

usage() { printf 'usage: %s --candidate SHA --candidate-dir DIR --evidence-dir DIR [--plan]\n' "${0##*/}" >&2; exit 4; }
while (($#)); do
  case $1 in
    --candidate) (($# >= 2)) || usage; candidate=$2; shift 2 ;;
    --candidate-dir) (($# >= 2)) || usage; candidate_dir=$2; shift 2 ;;
    --evidence-dir) (($# >= 2)) || usage; evidence_dir=$2; shift 2 ;;
    --plan) plan=1; shift ;;
    *) usage ;;
  esac
done
[[ $candidate =~ ^[0-9a-f]{40}$ && -n $candidate_dir && -n $evidence_dir ]] || usage
[[ $TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]] || { printf 'invalid SUITE_TIMEOUT_SECONDS\n' >&2; exit 4; }
record() { local name=$1 status=$2 detail=$3; checks+=("$(timeout "$TIMEOUT_SECONDS" jq -cn --arg name "$name" --arg status "$status" --arg detail "$detail" '{name:$name,status:$status,detail:$detail}')"); statuses+=("$status"); }
string_array() { if (($# == 0)); then printf '[]'; else printf '%s\n' "$@" | timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n")[:-1]'; fi; }
emit() {
  local status summary pass_json=false checks_json evidence_json preconditions_json
  if ((plan)); then status=plan; summary='Plan only; no checks executed'
  elif [[ " ${statuses[*]} " == *' fail '* ]]; then status=fail; summary='At least one retry, replay, or admission-limit check failed'
  elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then status=not_runnable; summary='Retry and refusal checks need the published isolation wiring'
  else status=pass; pass_json=true; summary='Retry state was fresh and every replay, signer, nonce, and limit refusal used its stable name'
  fi
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(string_array "${evidence_files[@]}")
  preconditions_json=$(string_array "${preconditions[@]}")
  timeout "$TIMEOUT_SECONDS" jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" \
    --argjson pass "$pass_json" --arg summary "$summary" --argjson checks "$checks_json" \
    --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" \
    '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
}

check_names=(static_probe_contracts static_protocol_refusals fresh_retry_environment replay_refusal expired_nonce_refusal unauthorized_signer_refusal rate_limit_refusal concurrency_limit_refusal)
if ((plan)); then for name in "${check_names[@]}"; do record "$name" plan 'Would inspect the static contract or exercise the real retry/admission path'; done; emit; exit 0; fi
[[ -d $candidate_dir ]] || { printf 'candidate directory is not a directory\n' >&2; exit 4; }
out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"

probe_static=$out_dir/static-probe-contracts.txt
if timeout "$TIMEOUT_SECONDS" bash -n "$candidate_dir/ci-acceptance/probes/p4_bounded_rerun.sh" "$candidate_dir/ci-acceptance/probes/p6_bounded_retries.sh" \
  && timeout "$TIMEOUT_SECONDS" grep -nE 'job_not_terminal|job_not_failed|attempt == 2|log_sha256|verdict == "green"' "$candidate_dir/ci-acceptance/probes/p4_bounded_rerun.sh" >"$probe_static" \
  && timeout "$TIMEOUT_SECONDS" grep -nE 'BUZZ_CI_RETRIES|timeout|attempts >= retry_count' "$candidate_dir/ci-acceptance/probes/p6_bounded_retries.sh" >>"$probe_static"; then
  record static_probe_contracts pass 'p4_bounded_rerun.sh:46-169 binds terminal-only reruns, attempt 2, distinct logs, and green; p6_bounded_retries.sh:25-51 bounds retries'
else
  record static_probe_contracts fail 'The p4/p6 scripts fail bash -n or no longer expose their cited retry contracts'
fi
evidence_files+=("$TEST_ID/static-probe-contracts.txt")

broker_dir=${BUZZ_CI_BROKER_DIR:-$candidate_dir}
protocol_lib=$broker_dir/crates/buzz-ci-broker-protocol/src/lib.rs
runner_lib=$broker_dir/crates/buzz-ci-runner/src/lib.rs
protocol_static=$out_dir/static-protocol-refusals.txt
if [[ -f $protocol_lib && -f $runner_lib ]]; then
  { timeout "$TIMEOUT_SECONDS" awk 'NR>=231 && NR<=247 {print "broker-protocol:" NR ":" $0} NR>=642 && NR<=645 {print "broker-protocol:" NR ":" $0}' "$protocol_lib"; timeout "$TIMEOUT_SECONDS" awk 'NR>=55 && NR<=82 {print "runner:" NR ":" $0}' "$runner_lib"; } >"$protocol_static"
else
  : >"$protocol_static"
fi
evidence_files+=("$TEST_ID/static-protocol-refusals.txt")
if timeout 10 grep -Fq 'broker-protocol:238:    UnauthorizedPeer = 104' "$protocol_static" \
  && timeout 10 grep -Fq 'broker-protocol:240:    ReplayConflict = 106' "$protocol_static" \
  && timeout 10 grep -Fq 'broker-protocol:645:        return Err(DecodeError::InvalidDeadline)' "$protocol_static" \
  && timeout 10 grep -Fq 'runner:59:    Unauthorized' "$protocol_static" \
  && timeout 10 grep -Fq 'runner:80:        return Err(ControlError::Unauthorized)' "$protocol_static"; then
  record static_protocol_refusals pass 'broker-protocol/src/lib.rs:238,240,645 names unauthorized, replay, and deadline refusal; buzz-ci-runner/src/lib.rs:59,80 rejects unauthorized control input'
else
  record static_protocol_refusals fail 'A cited protocol or runner refusal name is missing or moved'
fi

dynamic_names=(fresh_retry_environment replay_refusal expired_nonce_refusal unauthorized_signer_refusal rate_limit_refusal concurrency_limit_refusal)
if [[ ! -e /etc/buzzci/harness.env ]]; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi
SUDO=()
if [[ -n ${SUITE_SUDO+x} ]]; then read -r -a SUDO <<<"$SUITE_SUDO"; elif timeout 5 sudo -n true >/dev/null 2>&1; then SUDO=(sudo -n); fi
if ((${#SUDO[@]} == 0)) && [[ ! -r /etc/buzzci/harness.env ]]; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'harness.env unreadable without sudo'; done
  emit
  exit 3
fi
if ((${#SUDO[@]} == 0)); then for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'Root receipt and proxy object readback requires SUITE_SUDO or passwordless sudo'; done; emit; exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"; fi
harness_text=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat /etc/buzzci/harness.env 2>/dev/null) || { for name in "${dynamic_names[@]}"; do record "$name" fail 'Published harness.env is not root-readable'; done; emit; exit 1; }
env_get() { local key=$1; printf '%s\n' "$harness_text" | timeout "$TIMEOUT_SECONDS" awk -F= -v key="$key" '$1==key{print substr($0,index($0,"=")+1); exit}'; }
runner_ctl=$(env_get BUZZ_CI_RUNNER_CTL)
lease_root=$(env_get BUZZ_CI_LEASE_STATE_ROOT)
fixture_repo=$(env_get BUZZ_CI_FIXTURE_REPO)
harness_signer=$(env_get BUZZ_CI_HARNESS_SIGNER)
if [[ ! -x $runner_ctl || ! -d $lease_root || -z $fixture_repo || -z $harness_signer ]]; then for name in "${dynamic_names[@]}"; do record "$name" fail 'Published runner control, lease root, fixture coordinate, or harness signer is missing'; done; emit; exit 1; fi

admit_retry() {
  local label=$1 attempt=$2
  shift 2
  timeout "$TIMEOUT_SECONDS" "$runner_ctl" admit --repo "$fixture_repo" --sha "$candidate" \
    --workflow ci-acceptance/probe-repo/workflow.yml --job flaky --attempt "$attempt" "$@" >"$out_dir/admit-$label.json" 2>"$out_dir/admit-$label.stderr"
}
wait_terminal() {
  local label=$1 lease_id=$2
  for _ in {1..120}; do
    if timeout 10 "$runner_ctl" get --lease "$lease_id" >"$out_dir/final-$label.json" 2>"$out_dir/final-$label.stderr" \
      && timeout 10 jq -e '.state == "terminal" or .terminal == true' "$out_dir/final-$label.json" >/dev/null; then return 0; fi
    timeout 2 sleep 0.25
  done
  return 1
}

retry_ok=1
if admit_retry attempt-1 1; then
  lease_one=$(timeout 10 jq -r '.lease_id // empty' "$out_dir/admit-attempt-1.json")
  run_id=$(timeout 10 jq -r '.run_id // empty' "$out_dir/admit-attempt-1.json")
  request_id=$(timeout 10 jq -r '.request_id // empty' "$out_dir/admit-attempt-1.json")
  [[ $lease_one =~ ^[A-Za-z0-9._-]+$ && -n $run_id && -n $request_id ]] || retry_ok=0
  ((retry_ok)) && wait_terminal attempt-1 "$lease_one" || retry_ok=0
else retry_ok=0; fi
if ((retry_ok)) && admit_retry attempt-2 2 --run-id "$run_id" --parent-attempt 1; then
  lease_two=$(timeout 10 jq -r '.lease_id // empty' "$out_dir/admit-attempt-2.json")
  [[ $lease_two =~ ^[A-Za-z0-9._-]+$ ]] || retry_ok=0
  ((retry_ok)) && wait_terminal attempt-2 "$lease_two" || retry_ok=0
else retry_ok=0; fi
evidence_files+=("$TEST_ID/admit-attempt-1.json" "$TEST_ID/admit-attempt-1.stderr" "$TEST_ID/final-attempt-1.json" "$TEST_ID/final-attempt-1.stderr" "$TEST_ID/admit-attempt-2.json" "$TEST_ID/admit-attempt-2.stderr" "$TEST_ID/final-attempt-2.json" "$TEST_ID/final-attempt-2.stderr")
if ((retry_ok)); then
  workspace_one=$(timeout 10 "${SUDO[@]}" jq -r '.workspace_dir // empty' "$lease_root/$lease_one/lease.json")
  workspace_two=$(timeout 10 "${SUDO[@]}" jq -r '.workspace_dir // empty' "$lease_root/$lease_two/lease.json")
  env_one=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" find "$lease_root/$lease_one/proxy/objects" -type f -name '*.json' -print -quit 2>/dev/null || true)
  env_two=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" find "$lease_root/$lease_two/proxy/objects" -type f -name '*.json' -print -quit 2>/dev/null || true)
  env_ok=0
  if [[ -n $env_one && -n $env_two ]] \
    && timeout 10 "${SUDO[@]}" jq -e --arg run "$run_id" --arg sha "$candidate" '.. | objects | .env? | select(type=="object") | select(.BUZZ_CI_RUN_ID==$run and .BUZZ_CI_SHA==$sha and (.BUZZ_CI_ATTEMPT|tostring)=="1")' "$env_one" >/dev/null \
    && timeout 10 "${SUDO[@]}" jq -e --arg run "$run_id" --arg sha "$candidate" '.. | objects | .env? | select(type=="object") | select(.BUZZ_CI_RUN_ID==$run and .BUZZ_CI_SHA==$sha and (.BUZZ_CI_ATTEMPT|tostring)=="2")' "$env_two" >/dev/null; then env_ok=1; fi
  printf 'attempt_1_workspace=%s\nattempt_2_workspace=%s\nenv_names=BUZZ_CI_RUN_ID,BUZZ_CI_SHA,BUZZ_CI_ATTEMPT\nenv_values_match=%s\n' "$workspace_one" "$workspace_two" "$env_ok" >"$out_dir/retry-readback.txt"
  evidence_files+=("$TEST_ID/retry-readback.txt")
  if ((env_ok)) && [[ -n $workspace_one && -n $workspace_two && $workspace_one != "$workspace_two" && $lease_one != "$lease_two" ]]; then record fresh_retry_environment pass 'Attempts 1 and 2 used distinct leases/workspaces and the final three BUZZ_CI job variables matched their attempt'; else record fresh_retry_environment fail 'Retry reused a lease/workspace or its final BUZZ_CI job variables did not match'; fi
else
  record fresh_retry_environment fail 'Could not complete the two-attempt retry through the real runner path'
  request_id=''
fi

refusal() {
  local name=$1 expected=$2
  shift 2
  local rc=0
  timeout "$TIMEOUT_SECONDS" "$runner_ctl" admit --repo "$fixture_repo" --sha "$candidate" \
    --workflow ci-acceptance/probe-repo/workflow.yml --job flaky --attempt 1 "$@" >"$out_dir/$name.json" 2>"$out_dir/$name.stderr" || rc=$?
  evidence_files+=("$TEST_ID/$name.json" "$TEST_ID/$name.stderr")
  if ((rc != 0)) && { timeout 10 jq -e --arg expected "$expected" '.error == $expected' "$out_dir/$name.json" >/dev/null 2>&1 || timeout 10 jq -e --arg expected "$expected" '.error == $expected' "$out_dir/$name.stderr" >/dev/null 2>&1; }; then record "$name" pass "Admission refused with stable error $expected"; else record "$name" fail "Admission did not refuse with stable error $expected"; fi
}

if [[ -n $request_id ]]; then refusal replay_refusal replay --replay-request "$request_id"; else record replay_refusal fail 'No captured signed request ID was available for replay'; fi
refusal expired_nonce_refusal nonce_expired --nonce-issued-at 1 --nonce-expires-at 2
refusal unauthorized_signer_refusal unauthorized_signer --signer "unauthorized-$harness_signer"
refusal rate_limit_refusal rate_limited --acceptance-case rate_limit

capacity_file=$out_dir/capacity.json
if timeout "$TIMEOUT_SECONDS" "$runner_ctl" get --capacity >"$capacity_file" 2>"$out_dir/capacity.stderr"; then
  limit=$(timeout 10 jq -r '.concurrency_limit // 0' "$capacity_file")
else limit=0; fi
evidence_files+=("$TEST_ID/capacity.json" "$TEST_ID/capacity.stderr")
if [[ $limit =~ ^[1-9][0-9]*$ ]] && ((limit <= 16)); then
  pids=()
  for ((i=0; i<=limit; i++)); do timeout "$TIMEOUT_SECONDS" "$runner_ctl" admit --repo "$fixture_repo" --sha "$candidate" --workflow ci-acceptance/probe-repo/workflow.yml --job slowpoke --attempt 1 >"$out_dir/concurrent-$i.json" 2>"$out_dir/concurrent-$i.stderr" & pids+=("$!"); done
  for pid in "${pids[@]}"; do wait "$pid" || true; done
  for ((i=0; i<=limit; i++)); do evidence_files+=("$TEST_ID/concurrent-$i.json" "$TEST_ID/concurrent-$i.stderr"); done
  refused=$(timeout "$TIMEOUT_SECONDS" jq -s '[.[] | select(.error == "concurrency_limited")] | length' "$out_dir"/concurrent-*.json)
  if ((refused >= 1)); then record concurrency_limit_refusal pass "Admission N+1 refused at least one request with concurrency_limited for N=$limit"; else record concurrency_limit_refusal fail "Admission N+1 produced no concurrency_limited refusal for N=$limit"; fi
  for file in "$out_dir"/concurrent-*.json; do lease=$(timeout 10 jq -r '.lease_id // empty' "$file"); [[ $lease =~ ^[A-Za-z0-9._-]+$ ]] && timeout 10 "$runner_ctl" cancel --lease "$lease" >/dev/null 2>&1 || true; done
else
  record concurrency_limit_refusal fail 'Runner capacity readback did not return a bounded positive concurrency_limit'
fi
emit
exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || [[ " ${statuses[*]} " == *' not_runnable '* ]] && printf 3 || printf 0 )"
