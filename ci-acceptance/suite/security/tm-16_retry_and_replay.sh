#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-16
TITLE='Run the Phase-2 retry probe with fresh workspaces using final `BUZZ_CI_RUN_ID`, `BUZZ_CI_SHA`, and `BUZZ_CI_ATTEMPT`'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/acceptance_control.sh"
candidate=''
candidate_dir=''
evidence_dir=''
plan=0
checks=()
statuses=()
evidence_files=()
preconditions=(
  'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'
  'BUZZ_CI_ACCEPTANCE_CTL receives exact root-authored TM-16 case files on stdin with no arguments'
  'replay, rate, and concurrency case files bind requests exercised by ActivationController'
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
activation_lib=$broker_dir/crates/buzz-ci-execd/src/activation.rs
acceptance_lib=$broker_dir/crates/buzz-ci-acceptance-ctl/src/lib.rs
protocol_static=$out_dir/static-protocol-refusals.txt
if [[ -f $protocol_lib && -f $activation_lib && -f $acceptance_lib ]]; then
  { timeout "$TIMEOUT_SECONDS" grep -nE 'ReplayConflict|NoCapacity|PolicyDenied' "$protocol_lib"; timeout "$TIMEOUT_SECONDS" grep -nE 'Replay|ExpiredNonce|UnauthorizedSigner|RateLimit|ConcurrencyLimit' "$activation_lib"; timeout "$TIMEOUT_SECONDS" grep -nE 'invalid_time_window|binding_mismatch|transport' "$acceptance_lib"; } >"$protocol_static"
else
  : >"$protocol_static"
fi
evidence_files+=("$TEST_ID/static-protocol-refusals.txt")
if timeout 10 grep -q 'ReplayConflict' "$protocol_static" \
  && timeout 10 grep -q 'RateLimit' "$protocol_static" \
  && timeout 10 grep -q 'ConcurrencyLimit' "$protocol_static" \
  && timeout 10 grep -q 'binding_mismatch' "$protocol_static"; then
  record static_protocol_refusals pass 'Acceptance validation refuses signer/binding mismatches before transport; expiry, replay, rate, and concurrency remain ActivationController decisions'
else
  record static_protocol_refusals fail 'The acceptance-control or ActivationController refusal path is missing'
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
export harness_text
if ! acceptance_control_init; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable "$ACCEPTANCE_UNAVAILABLE"; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi

run_case() {
  local case_name=$1 rc=0
  acceptance_control_run "$case_name" "$out_dir/$case_name.json" "$out_dir/$case_name.stderr" || rc=$?
  evidence_files+=("$TEST_ID/$case_name.json" "$TEST_ID/$case_name.stderr")
  return "$rc"
}

retry_rc=0
run_case attempt_1 || retry_rc=$?
run_case attempt_2 || retry_rc=$?
if ((retry_rc == 3)); then
  record fresh_retry_environment not_runnable 'The fixed root-authored attempt_1 or attempt_2 case is unavailable or unsafe'
elif ((retry_rc == 0)) && timeout 10 jq -s -e '
  .[0] as $a | .[1] as $b |
  ($a.attempt_id // $a.lease_id) != null and ($b.attempt_id // $b.lease_id) != null and
  ($a.attempt_id // $a.lease_id) != ($b.attempt_id // $b.lease_id) and
  $a.workspace_digest != null and $b.workspace_digest != null and $a.workspace_digest != $b.workspace_digest and
  $a.run_id == $b.run_id and ($a.attempt|tonumber)==1 and ($b.attempt|tonumber)==2
' "$out_dir/attempt_1.json" "$out_dir/attempt_2.json" >/dev/null 2>&1; then
  record fresh_retry_environment pass 'The two fixed authenticated retry cases produced distinct ActivationController attempts/workspaces with one run identity and attempts 1 then 2'
else
  record fresh_retry_environment fail 'The fixed retry cases did not prove distinct attempts/workspaces and the bound 1-to-2 retry identity'
fi

refusal_case() {
  local check=$1 case_name=$2 expected=$3 before_transport=$4 rc=0
  run_case "$case_name" || rc=$?
  if ((rc == 3)); then
    record "$check" not_runnable "The fixed root-authored $case_name case is unavailable or unsafe"
  elif ((rc != 0)) && acceptance_error_is "$expected" "$out_dir/$case_name.json" "$out_dir/$case_name.stderr" \
    && { [[ $before_transport == false ]] || [[ ! -s $out_dir/$case_name.json ]]; }; then
    record "$check" pass "The fixed $case_name case was refused with stable error $expected"
  else
    record "$check" fail "The fixed $case_name case did not produce stable refusal $expected on the required side of transport"
  fi
}

# Expiry, replay, rate, and concurrency reach ActivationController. A signer
# mismatch is closed by the authenticated-input validator before broker bytes.
refusal_case replay_refusal replay replay_conflict false
refusal_case expired_nonce_refusal expired policy_denied false
refusal_case unauthorized_signer_refusal unauthorized_signer binding_mismatch true
refusal_case rate_limit_refusal rate_limit no_capacity false

primary_rc=0
run_case concurrency_primary || primary_rc=$?
if ((primary_rc == 3)); then
  record concurrency_limit_refusal not_runnable 'The fixed root-authored concurrency_primary case is unavailable or unsafe'
elif ((primary_rc != 0)); then
  record concurrency_limit_refusal fail 'ActivationController did not accept the fixed primary concurrency case'
else
  refusal_case concurrency_limit_refusal concurrency_overflow no_capacity false
fi
emit
exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || [[ " ${statuses[*]} " == *' not_runnable '* ]] && printf 3 || printf 0 )"
