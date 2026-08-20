#!/usr/bin/env bash
set -euo pipefail

TEST_ID="TM-01"
TITLE="Create/update the Buzz project tracking issue before Phase-1 code"
DEFAULT_TIMEOUT=600
REPO_OWNER="9e11cdfbf8df080569fa6e2c785862d015fa70751744a382b9f85690e390b1bb"
REPO_ID="buzz"
EPIC_PREFIX="c93bc162"

candidate=""
candidate_dir=""
evidence_dir=""
plan=0
checks=()
evidence_files=()
preconditions=("buzz relay credentials in env")
saw_fail=0
saw_not_runnable=0

usage() {
  printf 'usage: %s --candidate <full-sha> --candidate-dir <path> --evidence-dir <path> [--plan]\n' "${0##*/}" >&2
  exit 4
}

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
  timeout 10 jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" \
    --argjson pass "$pass_json" --arg summary "$summary" --argjson checks "$checks_json" \
    --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" \
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
  add_check epic_exists plan "Fetch the CI epic from the Buzz issue index."
  add_check frozen_artifact_references plan "Check every frozen design and contract hash."
  add_check wave1_implementation_references plan "Check Wave-1 PR ids and exact candidate SHAs."
  add_check review_gate_residual_risk plan "Check review verdict, gate result, and residual-risk records."
  emit_result plan false "Plan only; no relay reads or filesystem writes were performed." 0
fi

timeout_seconds=${SUITE_TIMEOUT_SECONDS:-$DEFAULT_TIMEOUT}
[[ $timeout_seconds =~ ^[1-9][0-9]*$ ]] || usage
if [[ ! -d $candidate_dir ]]; then
  printf 'candidate directory does not exist: %s\n' "$candidate_dir" >&2
  exit 4
fi
head_sha=$(timeout 15 git -C "$candidate_dir" rev-parse HEAD 2>/dev/null) || { printf 'cannot read candidate HEAD\n' >&2; exit 4; }
[[ $head_sha == "$candidate" ]] || { printf 'candidate directory HEAD does not match --candidate\n' >&2; exit 4; }

tm_dir="$evidence_dir/$TEST_ID"
timeout 10 mkdir -p -- "$tm_dir"

if [[ -z ${BUZZ_RELAY_URL:-} || -z ${BUZZ_PRIVATE_KEY:-} || -z ${BUZZ_AUTH_TAG:-} ]] || ! command -v buzz >/dev/null 2>&1; then
  add_check epic_exists not_runnable "Buzz CLI and relay credentials are required."
  add_check frozen_artifact_references not_runnable "Buzz issue and PR records could not be fetched."
  add_check wave1_implementation_references not_runnable "Buzz issue and PR records could not be fetched."
  add_check review_gate_residual_risk not_runnable "Buzz issue and PR records could not be fetched."
  emit_result not_runnable false "Buzz tracking records were not readable on this host." 3
fi

issues_file="$tm_dir/issues.json"
prs_file="$tm_dir/pull_requests.json"
issues_err="$tm_dir/issues.stderr.log"
prs_err="$tm_dir/pull_requests.stderr.log"
set +e
timeout "$timeout_seconds" buzz issues list --repo-owner "$REPO_OWNER" --repo-id "$REPO_ID" --limit 500 >"$issues_file" 2>"$issues_err"
issues_rc=$?
timeout "$timeout_seconds" buzz pr list --repo-owner "$REPO_OWNER" --repo-id "$REPO_ID" --limit 500 >"$prs_file" 2>"$prs_err"
prs_rc=$?
set -e
evidence_files+=("$TEST_ID/issues.json" "$TEST_ID/issues.stderr.log" "$TEST_ID/pull_requests.json" "$TEST_ID/pull_requests.stderr.log")

if ((issues_rc != 0 || prs_rc != 0)) || ! timeout 10 jq -e 'type == "array"' "$issues_file" >/dev/null 2>&1 || ! timeout 10 jq -e 'type == "array"' "$prs_file" >/dev/null 2>&1; then
  add_check epic_exists not_runnable "Buzz issue or PR fetch failed; see retained stderr logs."
  add_check frozen_artifact_references not_runnable "Complete tracking records are unavailable."
  add_check wave1_implementation_references not_runnable "Complete tracking records are unavailable."
  add_check review_gate_residual_risk not_runnable "Complete tracking records are unavailable."
  emit_result not_runnable false "Buzz tracking records could not be fetched completely." 3
fi

epic_count=$(timeout 10 jq --arg prefix "$EPIC_PREFIX" '[.[] | select((.id // "") | startswith($prefix))] | length' "$issues_file")
if [[ $epic_count == 1 ]]; then
  add_check epic_exists pass "Found one CI epic whose event id starts with $EPIC_PREFIX."
else
  add_check epic_exists fail "Expected one CI epic starting with $EPIC_PREFIX; found $epic_count."
fi

scope_file="$tm_dir/tracking-scope.json"
timeout 10 jq -s --arg epic "$EPIC_PREFIX" --arg blocker "43124185" \
  --argjson prs '["72831546","25ee80f2","27349598","c80c20b8"]' \
  '[.[][] | . as $item | select((($item.id // "") | startswith($epic)) or (($item.id // "") | startswith($blocker)) or any($prs[]; . as $prefix | ($item.id // "") | startswith($prefix)) or any($item.tags[]?; .[0] == "t" and .[1] == "ci"))]' \
  "$issues_file" "$prs_file" >"$scope_file"
evidence_files+=("$TEST_ID/tracking-scope.json")
corpus=$(timeout 10 jq -r 'tostring' "$scope_file")
missing=()
for ref in 094b9a66 306a9631 2f127ef2 8b9715d7 9e4727a5; do
  [[ $corpus == *"$ref"* ]] || missing+=("$ref")
done
if ((${#missing[@]} == 0)); then
  add_check frozen_artifact_references pass "All five frozen artifact hashes are referenced."
else
  add_check frozen_artifact_references fail "Missing frozen artifact references: ${missing[*]}."
fi

missing=()
for ref in 72831546 25ee80f2 27349598 c80c20b8 ab7b72b716dfd9a56c0a582a11f18e330f52ae4c 913755928d3ef4539871e8981d9914a563ac81d1 c3214118c4d26414da00c507e58a229566caba0f; do
  [[ $corpus == *"$ref"* ]] || missing+=("$ref")
done
if ((${#missing[@]} == 0)); then
  add_check wave1_implementation_references pass "All Wave-1 PR ids and exact candidate SHAs are referenced."
else
  add_check wave1_implementation_references fail "Missing Wave-1 references: ${missing[*]}."
fi

corpus_lower=${corpus,,}
verdict_with_sha=$(timeout 10 jq --arg sha1 "ab7b72b716dfd9a56c0a582a11f18e330f52ae4c" --arg sha2 "913755928d3ef4539871e8981d9914a563ac81d1" \
  '[.[] | select(((tostring | contains($sha1)) or (tostring | contains($sha2))) and (tostring | test("VERDICT|PASS|FAIL"; "i")))] | length' "$scope_file")
if [[ $corpus_lower == *review* && $corpus_lower == *gate* && $corpus_lower == *risk* && $verdict_with_sha -gt 0 ]]; then
  add_check review_gate_residual_risk pass "Tracking records include review, gate, residual risk, and a verdict bound to an exact candidate SHA."
else
  add_check review_gate_residual_risk fail "Tracking records lack review, gate-result, residual-risk, or exact-SHA verdict content."
fi

if ((saw_fail)); then
  emit_result fail false "The Buzz tracking record is incomplete." 1
elif ((saw_not_runnable)); then
  emit_result not_runnable false "The Buzz tracking record could not be fully decided." 3
fi
emit_result pass true "The Buzz tracking record contains the required Phase-1 references and review state." 0
