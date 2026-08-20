#!/usr/bin/env bash
set -euo pipefail

TEST_ID="TM-17"
TITLE="Keep all unaccepted PRs, external forks, and other escalation-triggering jobs refused"
DEFAULT_TIMEOUT=600
candidate=""
candidate_dir=""
evidence_dir=""
plan=0
checks=()
evidence_files=()
preconditions=("Rust toolchain and candidate broker crates" "buzz ci CLI + broker admission path live")
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
  add_check live_unaccepted_refusal plan "Submit unaccepted and external-fork requests through the live CLI and broker."
  emit_result plan false "Plan only; no tests, commands, or filesystem writes were performed." 0
fi

timeout_seconds=${SUITE_TIMEOUT_SECONDS:-$DEFAULT_TIMEOUT}
[[ $timeout_seconds =~ ^[1-9][0-9]*$ ]] || usage
broker_dir=${BUZZ_CI_BROKER_DIR:-$candidate_dir}
[[ -d $candidate_dir && -d $broker_dir ]] || { printf 'candidate or broker directory missing\n' >&2; exit 4; }
head_sha=$(timeout 15 git -C "$candidate_dir" rev-parse HEAD 2>/dev/null) || { printf 'cannot read candidate HEAD\n' >&2; exit 4; }
[[ $head_sha == "$candidate" ]] || { printf 'candidate directory HEAD does not match --candidate\n' >&2; exit 4; }
protocol_src="$broker_dir/crates/buzz-ci-broker-protocol/src/lib.rs"
runner_src="$broker_dir/crates/buzz-ci-runner/src/lib.rs"
[[ -f $protocol_src && -f $runner_src ]] || { printf 'broker protocol or runner source missing\n' >&2; exit 4; }
tm_dir="$evidence_dir/$TEST_ID"
timeout 10 mkdir -p -- "$tm_dir"

static_file="$tm_dir/trust-class-source-lines.txt"
{
  timeout "$timeout_seconds" grep -nE 'enum TrustClass|AcceptedReviewed|UnknownEnum' "$protocol_src"
  timeout "$timeout_seconds" grep -nE 'authorize_request|Unauthorized|normalize_admit_request|trust_class: TrustClass::AcceptedReviewed' "$runner_src"
} >"$static_file" 2>&1
evidence_files+=("$TEST_ID/trust-class-source-lines.txt")
accepted_count=$(timeout "$timeout_seconds" grep -Ec '^[[:space:]]*AcceptedReviewed[[:space:]]*=' "$protocol_src")
trust_variant_count=$(timeout "$timeout_seconds" sed -n '/pub enum TrustClass {/,/^}/p' "$protocol_src" | timeout "$timeout_seconds" grep -Ec '^[[:space:]]*[A-Za-z][A-Za-z0-9_]*[[:space:]]*=')
if [[ $accepted_count -eq 1 && $trust_variant_count -eq 1 ]] \
  && timeout "$timeout_seconds" grep -q '1 => Ok(Self::AcceptedReviewed)' "$protocol_src" \
  && timeout "$timeout_seconds" grep -q '_ => Err(DecodeError::UnknownEnum)' "$protocol_src" \
  && timeout "$timeout_seconds" grep -q 'trust_class: TrustClass::AcceptedReviewed' "$runner_src" \
  && timeout "$timeout_seconds" grep -q 'authorize_request(&request(), &Policy(false))' "$runner_src"; then
  add_check accepted_reviewed_only pass "TrustClass has only AcceptedReviewed; unknown values decode-fail, policy denial is tested, and normalization fixes that class."
else
  add_check accepted_reviewed_only fail "Static admission paths do not prove accepted/reviewed-only normalization and refusal."
fi

test_file="$tm_dir/cargo-test.log"
set +e
timeout "$timeout_seconds" cargo test -p buzz-ci-runner -p buzz-ci-broker-protocol --manifest-path "$broker_dir/Cargo.toml" >"$test_file" 2>&1
test_rc=$?
set -e
evidence_files+=("$TEST_ID/cargo-test.log")
if ((test_rc == 0)) && ! timeout 10 grep -Eq 'test result: FAILED|[1-9][0-9]* failed' "$test_file"; then
  add_check refusal_unit_tests pass "Runner and broker-protocol tests completed with zero failures."
else
  add_check refusal_unit_tests fail "Runner or broker-protocol tests failed or timed out."
fi

add_check live_unaccepted_refusal not_runnable "The buzz ci CLI and live broker admission path are not provisioned."

if ((saw_fail)); then emit_result fail false "Accepted-only admission has a failed static or unit control." 1; fi
if ((saw_not_runnable)); then emit_result not_runnable false "Static and unit refusal controls passed; live broker refusal is not yet runnable." 3; fi
emit_result pass true "Unaccepted and escalation-triggering jobs are refused at every tested admission path." 0
