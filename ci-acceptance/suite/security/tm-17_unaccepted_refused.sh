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
preconditions=(
  "Rust toolchain and candidate broker crates"
  "substrate wiring has published root-owned /etc/buzzci/harness.env"
  "the published runner control admit command supports --acceptance-case unaccepted and external_fork"
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
  add_check live_unaccepted_refusal plan "Submit an unaccepted request through the live runner control and require unaccepted_trust_class."
  add_check live_external_fork_refusal plan "Submit an external-fork request through the live runner control and require unaccepted_trust_class."
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
  env_get() {
    local key=$1
    printf '%s\n' "$harness_text" | timeout "$timeout_seconds" awk -F= -v key="$key" '$1==key{print substr($0,index($0,"=")+1); exit}'
  }
  runner_ctl=$(env_get BUZZ_CI_RUNNER_CTL)
  fixture_repo=$(env_get BUZZ_CI_FIXTURE_REPO)
  if [[ -z $harness_text || ! -x $runner_ctl || -z $fixture_repo ]]; then
    for name in "${dynamic_names[@]}"; do add_check "$name" fail "Published harness.env lacks an executable runner control or fixture coordinate."; done
  else
    help_file=$tm_dir/runner-help.txt
    timeout "$timeout_seconds" "$runner_ctl" admit --help >"$help_file" 2>&1 || true
    evidence_files+=("$TEST_ID/runner-help.txt")
    if ! timeout 10 grep -Fq -- '--acceptance-case' "$help_file"; then
      for name in "${dynamic_names[@]}"; do add_check "$name" not_runnable "The published runner control does not advertise --acceptance-case."; done
    else
      live_refusal() {
        local name=$1 acceptance_case=$2 rc=0
        local output=$tm_dir/$name.json error=$tm_dir/$name.stderr
        timeout "$timeout_seconds" "$runner_ctl" admit --repo "$fixture_repo" --sha "$candidate" \
          --workflow ci-acceptance/probe-repo/workflow.yml --job ok --attempt 1 \
          --acceptance-case "$acceptance_case" >"$output" 2>"$error" || rc=$?
        evidence_files+=("$TEST_ID/$name.json" "$TEST_ID/$name.stderr")
        if ((rc != 0)) && {
          timeout 10 jq -e '.error == "unaccepted_trust_class"' "$output" >/dev/null 2>&1 \
            || timeout 10 jq -e '.error == "unaccepted_trust_class"' "$error" >/dev/null 2>&1
        }; then
          add_check "$name" pass "Live admission refused $acceptance_case with stable error unaccepted_trust_class."
        else
          add_check "$name" fail "Live admission did not refuse $acceptance_case with stable error unaccepted_trust_class."
        fi
      }
      live_refusal live_unaccepted_refusal unaccepted
      live_refusal live_external_fork_refusal external_fork
    fi
  fi
fi

if ((saw_fail)); then emit_result fail false "Accepted-only admission has a failed static or unit control." 1; fi
if ((saw_not_runnable)); then emit_result not_runnable false "Static and unit refusal controls passed; live broker refusal is not yet runnable." 3; fi
emit_result pass true "Unaccepted and escalation-triggering jobs are refused at every tested admission path." 0
