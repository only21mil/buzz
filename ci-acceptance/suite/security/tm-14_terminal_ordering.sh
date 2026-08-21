#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-14
TITLE='Prove the terminal ordering'
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
  'BUZZ_CI_ACCEPTANCE_CTL receives exact root-authored normal and teardown_failure cases on stdin'
  'teardown_failure is the only privileged qualification directive'
  'root readback of lease state requires SUITE_SUDO or passwordless sudo'
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
  elif [[ " ${statuses[*]} " == *' fail '* ]]; then status=fail; summary='At least one terminal-ordering check failed'
  elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then status=not_runnable; summary='Terminal-ordering checks need published isolation wiring and fixed qualification cases'
  else status=pass; pass_json=true; summary='Publication followed complete teardown proof and teardown failure could not produce green'
  fi
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(string_array "${evidence_files[@]}")
  preconditions_json=$(string_array "${preconditions[@]}")
  timeout "$TIMEOUT_SECONDS" jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" \
    --argjson pass "$pass_json" --arg summary "$summary" --argjson checks "$checks_json" \
    --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" \
    '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
}

check_names=(static_teardown_attestation_guard terminal_event_order forced_teardown_failure_no_green)
if ((plan)); then for name in "${check_names[@]}"; do record "$name" plan 'Would inspect the runner guard or exercise terminal ordering'; done; emit; exit 0; fi
[[ -d $candidate_dir ]] || { printf 'candidate directory is not a directory\n' >&2; exit 4; }
out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"
broker_dir=${BUZZ_CI_BROKER_DIR:-$candidate_dir}
runner_lib=$broker_dir/crates/buzz-ci-runner/src/lib.rs
static_file=$out_dir/static-teardown-guard.txt
if [[ -f $runner_lib ]]; then
  timeout "$TIMEOUT_SECONDS" awk 'NR>=117 && NR<=196 {print NR ":" $0}' "$runner_lib" >"$static_file"
else
  : >"$static_file"
fi
evidence_files+=("$TEST_ID/static-teardown-guard.txt")
if timeout "$TIMEOUT_SECONDS" grep -Fq '137:        if receipt.code != buzz_ci_broker_protocol::ResponseCode::Ok' "$static_file" \
  && timeout "$TIMEOUT_SECONDS" grep -Fq '138:            || receipt.broker_state != BrokerState::Terminal' "$static_file" \
  && timeout "$TIMEOUT_SECONDS" grep -Fq '140:            || receipt.teardown_digest == [0; 32]' "$static_file" \
  && timeout "$TIMEOUT_SECONDS" grep -Fq '189:        lease_empty: true' "$static_file"; then
  record static_teardown_attestation_guard pass 'buzz-ci-runner/src/lib.rs:117-196 rejects nonterminal or empty teardown proof before building an attestation'
else
  record static_teardown_attestation_guard fail 'The teardown-attestation guard is missing or moved from the cited runner lines'
fi

dynamic_names=(terminal_event_order forced_teardown_failure_no_green)
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
if ((${#SUDO[@]} == 0)); then for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'Root lease readback requires SUITE_SUDO or passwordless sudo'; done; emit; exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"; fi
harness_text=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat /etc/buzzci/harness.env 2>/dev/null) || { for name in "${dynamic_names[@]}"; do record "$name" fail 'Published harness.env is not root-readable'; done; emit; exit 1; }
export harness_text
lease_root=$(acceptance_env_get BUZZ_CI_LEASE_STATE_ROOT)
if ! acceptance_control_init; then for name in "${dynamic_names[@]}"; do record "$name" not_runnable "$ACCEPTANCE_UNAVAILABLE"; done; emit; exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"; fi
if [[ ! -d $lease_root ]]; then for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'harness.env lacks a readable BUZZ_CI_LEASE_STATE_ROOT'; done; emit; exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"; fi

admit_and_wait() {
  local label=$1 case_name=$2 admit_file=$out_dir/admit-$1.json lease_id lease_dir rc=0
  acceptance_control_run "$case_name" "$admit_file" "$out_dir/admit-$label.stderr" || rc=$?
  ((rc == 0)) || return "$rc"
  lease_id=$(timeout 10 jq -r '.attempt_id // .lease_id // empty' "$admit_file")
  [[ $lease_id =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  lease_dir=$lease_root/$lease_id
  for _ in {1..120}; do
    if timeout 10 "${SUDO[@]}" test -r "$lease_dir/final.json"; then timeout 10 "${SUDO[@]}" cp -- "$lease_dir/final.json" "$out_dir/final-$label.json" 2>"$out_dir/final-$label.stderr" || :; break; fi
    timeout 2 sleep 0.25
  done
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$lease_dir/ordering.jsonl" "$out_dir/ordering-$label.jsonl" 2>/dev/null || :
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$lease_dir/teardown.json" "$out_dir/teardown-$label.json" 2>/dev/null || :
  printf '%s' "$lease_id"
}

normal_rc=0
normal_lease=$(admit_and_wait normal normal) || normal_rc=$?
if ((normal_rc == 0)); then
  evidence_files+=("$TEST_ID/admit-normal.json" "$TEST_ID/admit-normal.stderr" "$TEST_ID/final-normal.json" "$TEST_ID/final-normal.stderr" "$TEST_ID/ordering-normal.jsonl" "$TEST_ID/teardown-normal.json")
  if timeout "$TIMEOUT_SECONDS" jq -s -e '
    map(select(.event as $e | ["stop","finalize_raw_stream","extract","scrub","scan","hash","upload","teardown_proof","publish"] | index($e))) as $x |
    ($x|length)==9 and ([range(1;9)] | all(. as $i; $x[$i].timestamp_unix_ns > $x[$i-1].timestamp_unix_ns)) and
    ($x|map(.event)) == ["stop","finalize_raw_stream","extract","scrub","scan","hash","upload","teardown_proof","publish"] and
    ($x[8].status_event_id|type=="string" and length>0) and ($x[8].verdict_event_id|type=="string" and length>0)
  ' "$out_dir/ordering-normal.jsonl" >/dev/null 2>&1 \
    && timeout 10 jq -e '.cgroup_procs_empty == true and .mounts_removed == true and .dirs_removed == true' "$out_dir/teardown-normal.json" >/dev/null; then
    record terminal_event_order pass "Lease $normal_lease published only after a strictly monotonic teardown proof"
  else
    record terminal_event_order fail 'The normal attempt lacks the required order, publication event IDs, or complete teardown proof'
  fi
else
  if ((normal_rc == 3)); then record terminal_event_order not_runnable 'The fixed root-authored TM-14/normal.json case is unavailable or unsafe'; else record terminal_event_order fail 'Could not admit and observe the normal ordering attempt'; fi
fi

fault_rc=0
fault_lease=$(admit_and_wait teardown-failure teardown_failure) || fault_rc=$?
if ((fault_rc == 0)); then
  evidence_files+=("$TEST_ID/admit-teardown-failure.json" "$TEST_ID/admit-teardown-failure.stderr" "$TEST_ID/final-teardown-failure.json" "$TEST_ID/final-teardown-failure.stderr" "$TEST_ID/ordering-teardown-failure.jsonl" "$TEST_ID/teardown-teardown-failure.json")
  if ! timeout 10 jq -e '.verdict == "green" or .conclusion == "success"' "$out_dir/final-teardown-failure.json" >/dev/null 2>&1 \
    && ! timeout 10 jq -e 'select(.event == "publish")' "$out_dir/ordering-teardown-failure.jsonl" >/dev/null 2>&1; then
    record forced_teardown_failure_no_green pass "Forced teardown failure for lease $fault_lease produced neither green nor publication"
  else
    record forced_teardown_failure_no_green fail 'Forced teardown failure produced a green result or publication event'
  fi
else
  if ((fault_rc == 3)); then record forced_teardown_failure_no_green not_runnable 'The fixed root-authored TM-14/teardown_failure.json case is unavailable or unsafe'; else record forced_teardown_failure_no_green fail 'The authenticated teardown_failure directive could not be admitted and observed'; fi
fi
emit
exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || [[ " ${statuses[*]} " == *' not_runnable '* ]] && printf 3 || printf 0 )"
