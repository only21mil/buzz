#!/usr/bin/env bash
set -euo pipefail

script_path=${BASH_SOURCE[0]}
script_parent=.
if [[ $script_path == */* ]]; then
  script_parent=${script_path%/*}
fi
script_dir=$(cd -- "$script_parent" && pwd)

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_case() {
  local name=$1
  local expected_rc=$2
  local assertion=$3
  local actual_rc
  local verdict_json

  set +e
  verdict_json=$("$script_dir/aggregate_acceptance.sh" \
    --output - \
    "$script_dir/fixtures/$name.jsonl")
  actual_rc=$?
  set -e

  [[ $actual_rc -eq $expected_rc ]] \
    || fail "$name: expected exit $expected_rc, got $actual_rc"
  jq -e "$assertion" <<<"$verdict_json" >/dev/null \
    || fail "$name: verdict assertion failed"
  printf 'PASS %s exit=%d\n' "$name" "$actual_rc"
}

run_case all-green 0 '
  .candidate_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  .security == {"passed":17,"total":17} and
  .probes == {"passed_runs":12,"total_runs":12} and
  .green == true and .missing == [] and .failed == [] and .sha_conflicts == []
'

run_case one-tm-failure 1 '
  .candidate_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  .security == {"passed":16,"total":17} and
  .probes == {"passed_runs":12,"total_runs":12} and
  .green == false and .missing == [] and .failed == ["TM-05"] and .sha_conflicts == []
'

run_case one-probe-run-2-failure 1 '
  .candidate_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  .security == {"passed":17,"total":17} and
  .probes == {"passed_runs":11,"total_runs":12} and
  .green == false and .missing == [] and .failed == ["P-iv/run-2"] and .sha_conflicts == []
'

run_case candidate-sha-mismatch 1 '
  .candidate_sha == null and
  .security == {"passed":17,"total":17} and
  .probes == {"passed_runs":12,"total_runs":12} and
  .green == false and .missing == [] and .failed == [] and
  .sha_conflicts == ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
'

run_case missing-tm-record 1 '
  .candidate_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  .security == {"passed":16,"total":17} and
  .probes == {"passed_runs":12,"total_runs":12} and
  .green == false and .missing == ["TM-09"] and .failed == [] and .sha_conflicts == []
'

printf 'PASS all 5 acceptance-evidence fixture cases\n'
