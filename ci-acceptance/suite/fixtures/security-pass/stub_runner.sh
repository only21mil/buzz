#!/usr/bin/env bash
set -euo pipefail

FIXTURE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SUITE_DIR="$(cd -- "$FIXTURE_DIR/../.." && pwd -P)"
test_id=${SUITE_FIXTURE_TEST_ID:?fixture test id is required}
candidate=''
candidate_dir=''
evidence_dir=''
plan=false

while (($# > 0)); do
  case "$1" in
    --candidate)
      candidate=$2
      shift 2
      ;;
    --candidate-dir)
      candidate_dir=$2
      shift 2
      ;;
    --evidence-dir)
      evidence_dir=$2
      shift 2
      ;;
    --plan)
      plan=true
      shift
      ;;
    *)
      printf 'fixture usage error\n' >&2
      exit 4
      ;;
  esac
done

title=$(jq -r --arg id "$test_id" '.tests[] | select(.test_id == $id) | .title' \
  "$SUITE_DIR/../evidence/tm_tests.json")
if [[ "$plan" == true ]]; then
  jq -cn --arg id "$test_id" --arg title "$title" \
    '{test_id:$id,title:$title,status:"plan",pass:false,summary:"fixture plan",checks:[{name:"fixture",status:"plan",detail:"fixture does not execute checks in plan mode"}],evidence_files:[],preconditions:["fixture runner selected"]}'
  exit 0
fi

[[ -n "$candidate" && -d "$candidate_dir" && -n "$evidence_dir" ]] || exit 4
mkdir -p -- "$evidence_dir"
printf 'fixture evidence for %s\n' "$test_id" >"$evidence_dir/stub.txt"

case "${SUITE_FIXTURE_CASE:-pass}:${SUITE_FIXTURE_BAD_ID:-}" in
  not_runnable:"$test_id")
    jq -cn --arg id "$test_id" --arg title "$title" \
      '{test_id:$id,title:$title,status:"not_runnable",pass:false,summary:"fixture precondition missing",checks:[{name:"fixture",status:"not_runnable",detail:"fixture requested not-runnable"}],evidence_files:["stub.txt"],preconditions:["fixture case must be pass"]}'
    exit 3
    ;;
  fail:"$test_id")
    jq -cn --arg id "$test_id" --arg title "$title" \
      '{test_id:$id,title:$title,status:"fail",pass:false,summary:"fixture failure",checks:[{name:"fixture",status:"fail",detail:"fixture requested failure"}],evidence_files:["stub.txt"],preconditions:[]}'
    exit 1
    ;;
  garbage:"$test_id")
    printf 'this is not JSON\n'
    exit 0
    ;;
  candidate_mismatch:"$test_id")
    jq -cn --arg id "$test_id" --arg title "$title" \
      '{test_id:$id,title:$title,status:"pass",pass:true,candidate_sha:"ffffffffffffffffffffffffffffffffffffffff",summary:"fixture candidate mismatch",checks:[{name:"fixture",status:"pass",detail:"fixture emitted a mismatched candidate"}],evidence_files:["stub.txt"],preconditions:[]}'
    exit 0
    ;;
esac

jq -cn --arg id "$test_id" --arg title "$title" \
  '{test_id:$id,title:$title,status:"pass",pass:true,summary:"fixture pass",checks:[{name:"fixture",status:"pass",detail:"fixture passed"}],evidence_files:["stub.txt"],preconditions:[]}'
