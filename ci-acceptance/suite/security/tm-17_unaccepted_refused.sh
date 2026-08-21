#!/usr/bin/env bash
set -euo pipefail

TEST_ID="TM-17"
TITLE="Keep all unaccepted PRs, external forks, and other escalation-triggering jobs refused"
DEFAULT_TIMEOUT=600
TIMEOUT_SECONDS=$DEFAULT_TIMEOUT
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/acceptance_control.sh"
candidate=""
candidate_dir=""
evidence_dir=""
plan=0
checks=()
evidence_files=()
preconditions=(
  "Rust toolchain and candidate broker crates"
  "substrate wiring has published root-owned /etc/buzzci/harness.env"
  "BUZZ_CI_ACCEPTANCE_CTL receives exact root-authored TM-17 case files on stdin with no arguments"
)
saw_fail=0
saw_not_runnable=0

usage() { printf 'usage: %s --candidate <full-sha> --candidate-dir <path> --evidence-dir <path> [--plan]\n' "${0##*/}" >&2; exit 4; }
add_check() {
  local name=$1 status=$2 detail=$3
  checks+=("$(timeout 10 jq -cn --arg name "$name" --arg status "$status" --arg detail "$detail" '{name:$name,status:$status,detail:$detail}')")
  [[ $status != fail ]] || saw_fail=1
  [[ $status != not_runnable ]] || saw_not_runnable=1
}
emit_result() {
  local status=$1 pass_json=$2 summary=$3 rc=$4 checks_json evidence_json preconditions_json
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout 10 jq -sc '.')
  evidence_json=$(printf '%s\n' "${evidence_files[@]}" | timeout 10 jq -Rsc 'split("\n") | map(select(length > 0))')
  preconditions_json=$(printf '%s\n' "${preconditions[@]}" | timeout 10 jq -Rsc 'split("\n") | map(select(length > 0))')
  timeout 10 jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" --argjson pass "$pass_json" \
    --arg summary "$summary" --argjson checks "$checks_json" --argjson evidence_files "$evidence_json" \
    --argjson preconditions "$preconditions_json" \
    '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
  exit "$rc"
}

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
if ((plan)); then
  add_check accepted_reviewed_only plan "Inspect TrustClass decoding and request normalization."
  add_check refusal_unit_tests plan "Run broker-protocol and runner unit tests."
  add_check live_unaccepted_refusal plan "Submit the fixed unaccepted case through qualification validation and require pre-transport unaccepted_trust_class."
  add_check live_external_fork_refusal plan "Submit the fixed external-fork binding through qualification validation and require pre-transport binding_mismatch."
  emit_result plan false "Plan only; no tests, commands, or filesystem writes were performed." 0
fi

timeout_seconds=${SUITE_TIMEOUT_SECONDS:-$DEFAULT_TIMEOUT}
TIMEOUT_SECONDS=$timeout_seconds
export TIMEOUT_SECONDS
[[ $timeout_seconds =~ ^[1-9][0-9]*$ ]] || usage
broker_dir=${BUZZ_CI_BROKER_DIR:-$candidate_dir}
[[ -d $candidate_dir && -d $broker_dir ]] || { printf 'candidate or broker directory missing\n' >&2; exit 4; }
head_sha=$(timeout 15 git -C "$candidate_dir" rev-parse HEAD 2>/dev/null) || { printf 'cannot read candidate HEAD\n' >&2; exit 4; }
[[ $head_sha == "$candidate" ]] || { printf 'candidate directory HEAD does not match --candidate\n' >&2; exit 4; }
protocol_src="$broker_dir/crates/buzz-ci-broker-protocol/src/lib.rs"
acceptance_src="$broker_dir/crates/buzz-ci-acceptance-ctl/src/lib.rs"
[[ -f $protocol_src && -f $acceptance_src ]] || { printf 'broker protocol or acceptance control source missing\n' >&2; exit 4; }
tm_dir="$evidence_dir/$TEST_ID"
timeout 10 mkdir -p -- "$tm_dir"

static_file="$tm_dir/trust-class-source-lines.txt"
{
  timeout "$timeout_seconds" grep -nE 'enum TrustClass|AcceptedReviewed|UnknownEnum' "$protocol_src"
  timeout "$timeout_seconds" grep -nE 'unaccepted_trust_class|UnacceptedTrustClass|transport|validate' "$acceptance_src"
} >"$static_file" 2>&1
evidence_files+=("$TEST_ID/trust-class-source-lines.txt")
accepted_count=$(timeout "$timeout_seconds" grep -Ec '^[[:space:]]*AcceptedReviewed[[:space:]]*=' "$protocol_src")
trust_variant_count=$(timeout "$timeout_seconds" sed -n '/pub enum TrustClass {/,/^}/p' "$protocol_src" | timeout "$timeout_seconds" grep -Ec '^[[:space:]]*[A-Za-z][A-Za-z0-9_]*[[:space:]]*=')
if [[ $accepted_count -eq 1 && $trust_variant_count -eq 1 ]] \
  && timeout "$timeout_seconds" grep -q '1 => Ok(Self::AcceptedReviewed)' "$protocol_src" \
  && timeout "$timeout_seconds" grep -q '_ => Err(DecodeError::UnknownEnum)' "$protocol_src" \
  && timeout "$timeout_seconds" grep -q 'unaccepted_trust_class' "$acceptance_src"; then
  add_check accepted_reviewed_only pass "TrustClass has only AcceptedReviewed, unknown values decode-fail, and qualification input validates trust before transport."
else
  add_check accepted_reviewed_only fail "Static admission paths do not prove accepted/reviewed-only normalization and refusal."
fi

test_file="$tm_dir/cargo-test.log"
set +e
timeout "$timeout_seconds" cargo test -p buzz-ci-acceptance-ctl -p buzz-ci-broker-protocol -p buzz-ci-runner --manifest-path "$broker_dir/Cargo.toml" >"$test_file" 2>&1
test_rc=$?
set -e
evidence_files+=("$TEST_ID/cargo-test.log")
if ((test_rc == 0)) && ! timeout 10 grep -Eq 'test result: FAILED|[1-9][0-9]* failed' "$test_file"; then
  add_check refusal_unit_tests pass "Acceptance-control, runner, and broker-protocol tests completed with zero failures."
else
  add_check refusal_unit_tests fail "Runner or broker-protocol tests failed or timed out."
fi

dynamic_names=(live_unaccepted_refusal live_external_fork_refusal)
if [[ ! -e /etc/buzzci/harness.env ]]; then
  for name in "${dynamic_names[@]}"; do add_check "$name" not_runnable "Substrate wiring has not published /etc/buzzci/harness.env."; done
elif {
  SUDO=()
  if [[ -n ${SUITE_SUDO+x} ]]; then read -r -a SUDO <<<"$SUITE_SUDO"; elif timeout 5 sudo -n true >/dev/null 2>&1; then SUDO=(sudo -n); fi
  ((${#SUDO[@]} == 0)) && [[ ! -r /etc/buzzci/harness.env ]]
}; then
  for name in "${dynamic_names[@]}"; do add_check "$name" not_runnable "harness.env is unreadable without SUITE_SUDO or passwordless sudo."; done
else
  if ((${#SUDO[@]})); then
    harness_text=$(timeout "$timeout_seconds" "${SUDO[@]}" cat /etc/buzzci/harness.env 2>/dev/null) || harness_text=''
  else
    harness_text=$(timeout "$timeout_seconds" cat /etc/buzzci/harness.env 2>/dev/null) || harness_text=''
  fi
  export harness_text
  env_get() {
    local key=$1
    printf '%s\n' "$harness_text" | timeout "$timeout_seconds" awk -F= -v key="$key" '$1==key{print substr($0,index($0,"=")+1); exit}'
  }
  if ! acceptance_control_init; then
    for name in "${dynamic_names[@]}"; do add_check "$name" not_runnable "$ACCEPTANCE_UNAVAILABLE"; done
  else
    live_refusal() {
      local name=$1 case_name=$2 expected=$3 rc=0
      local output=$tm_dir/$name.json error=$tm_dir/$name.stderr
      acceptance_control_run "$case_name" "$output" "$error" || rc=$?
      evidence_files+=("$TEST_ID/$name.json" "$TEST_ID/$name.stderr")
      if ((rc == 3)); then
        add_check "$name" not_runnable "The fixed root-authored $TEST_ID/$case_name.json case is unavailable or unsafe."
      elif ((rc != 0)) && [[ ! -s $output ]] && acceptance_error_is "$expected" "$output" "$error"; then
        add_check "$name" pass "The fixed $case_name case was refused before any broker request bytes with stable error $expected."
      else
        add_check "$name" fail "The fixed $case_name case was not refused before broker transport with stable error $expected."
      fi
    }
    live_refusal live_unaccepted_refusal unaccepted unaccepted_trust_class
    live_refusal live_external_fork_refusal external_fork binding_mismatch
  fi
fi

if ((saw_fail)); then emit_result fail false "Accepted-only admission has a failed static or unit control." 1; fi
if ((saw_not_runnable)); then emit_result not_runnable false "Static and unit refusal controls passed; live broker refusal is not yet runnable." 3; fi
emit_result pass true "Unaccepted and escalation-triggering jobs are refused at every tested admission path." 0
