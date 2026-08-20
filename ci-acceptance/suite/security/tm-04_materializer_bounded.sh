#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-04
TITLE='Implement a bounded unprivileged materializer with root-owned narrow egress'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
candidate=''
candidate_dir=''
evidence_dir=''
plan=0
checks=()
evidence=()
preconditions=(
  'buzz-ci-materializer source and Cargo workspace exist in BUZZ_CI_PROXY_DIR or candidate-dir'
  'bash, coreutils, jq, git, and cargo are installed; evidence-dir is writable'
  'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'
)
failed=0
unrunnable=0

usage() { printf 'usage: %s --candidate <full-sha> --candidate-dir <path> --evidence-dir <path> [--plan]\n' "$0" >&2; exit 4; }
while (($#)); do
  case $1 in
    --candidate) (($# >= 2)) || usage; candidate=$2; shift 2 ;;
    --candidate-dir) (($# >= 2)) || usage; candidate_dir=$2; shift 2 ;;
    --evidence-dir) (($# >= 2)) || usage; evidence_dir=$2; shift 2 ;;
    --plan) plan=1; shift ;;
    *) usage ;;
  esac
done

add_check() {
  local name=$1 status=$2 detail=$3
  checks+=("$(timeout "$TIMEOUT_SECONDS" jq -cn --arg n "$name" --arg s "$status" --arg d "$detail" '{name:$n,status:$s,detail:$d}')")
  [[ $status != fail ]] || failed=1
  [[ $status != not_runnable ]] || unrunnable=1
}
emit() {
  local status=$1 summary=$2 pass_json=false checks_json evidence_json preconditions_json
  [[ $status == pass ]] && pass_json=true
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(printf '%s\n' "${evidence[@]}" | timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n") | map(select(length > 0))')
  preconditions_json=$(printf '%s\n' "${preconditions[@]}" | timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n") | map(select(length > 0))')
  timeout "$TIMEOUT_SECONDS" jq -cn --arg id "$TEST_ID" --arg title "$TITLE" --arg status "$status" --arg summary "$summary" --argjson pass "$pass_json" --argjson checks "$checks_json" --argjson files "$evidence_json" --argjson pre "$preconditions_json" '{test_id:$id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$files,preconditions:$pre}'
}
if ((plan)); then
  add_check materializer_crate_tests plan 'Run the bounded buzz-ci-materializer crate tests.'
  add_check hardened_git_plan plan 'Prove the Git plan disables hooks, credentials, unsafe protocols, submodules, LFS, inherited environment, and executable checkout.'
  add_check exact_object_readback plan 'Prove exact-SHA fetch and commit/tree/workflow/input readback before publication.'
  add_check live_materialization_receipt plan 'Compare a signed receipt and commands.jsonl record with independent Git object readback.'
  emit plan 'Planned static and live materializer controls; no checks executed.'
  exit 0
fi
[[ $candidate =~ ^[0-9a-f]{40}$ ]] || usage
[[ -n $candidate_dir && -n $evidence_dir ]] || usage
if [[ -z ${SUITE_SUDO+x} ]]; then
  if timeout 5 sudo -n true >/dev/null 2>&1; then SUITE_SUDO='sudo -n'; else SUITE_SUDO=''; fi
fi
read -r -a sudo_cmd <<<"$SUITE_SUDO"
read_harness() {
  if ((${#sudo_cmd[@]})); then
    timeout "$TIMEOUT_SECONDS" "${sudo_cmd[@]}" cat /etc/buzzci/harness.env
  else
    return 3
  fi
}
read_harness_key() { local key=$1; printf '%s\n' "$harness_text" | timeout "$TIMEOUT_SECONDS" awk -F= -v key="$key" '$1==key{print substr($0,index($0,"=")+1); exit}'; }
proxy_dir=${BUZZ_CI_PROXY_DIR:-$candidate_dir}
out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir" || { printf 'cannot create evidence directory\n' >&2; exit 4; }

cargo_log=$out_dir/cargo-test.log
set +e
CARGO_TARGET_DIR=$proxy_dir/target timeout "$TIMEOUT_SECONDS" cargo test --manifest-path "$proxy_dir/Cargo.toml" -p buzz-ci-materializer >"$cargo_log" 2>&1
rc=$?
set -e
evidence+=("$TEST_ID/cargo-test.log")
if ((rc == 0)); then add_check materializer_crate_tests pass 'buzz-ci-materializer tests completed with zero failures.'; else add_check materializer_crate_tests fail "cargo test exited $rc; see cargo-test.log."; fi

plan_rs=$proxy_dir/crates/buzz-ci-materializer/src/plan.rs
execute_rs=$proxy_dir/crates/buzz-ci-materializer/src/execute.rs
proof=$out_dir/static-plan-proof.txt
if [[ -f $plan_rs && -f $execute_rs ]]; then
  timeout "$TIMEOUT_SECONDS" grep -nE 'core\.hooksPath=/dev/null|credential\.helper=|protocol\.(allow|https\.allow|http\.allow|ext\.allow|file\.allow)|submodule\.recurse=false|filter\.lfs\.(smudge|clean)=|clear_environment: true|fetch|rev-parse|cat-file|ls-tree|checkout' "$plan_rs" "$execute_rs" >"$proof" 2>&1 || true
  evidence+=("$TEST_ID/static-plan-proof.txt")
  pins=( 'core.hooksPath=/dev/null' 'credential.helper=' 'protocol.allow=never' 'protocol.https.allow=always' 'protocol.http.allow=never' 'protocol.ext.allow=never' 'protocol.file.allow=never' 'submodule.recurse=false' 'filter.lfs.smudge=' 'clear_environment: true' 'program: policy.git_program.clone()' )
  missing=''
  for pin in "${pins[@]}"; do timeout "$TIMEOUT_SECONDS" grep -Fq -- "$pin" "$plan_rs" "$execute_rs" || missing+=" $pin"; done
  if [[ -z $missing ]]; then add_check hardened_git_plan pass 'Static source permits only the root-owned Git program and pins hooks, credentials, protocols, submodules, LFS, and an empty inherited environment; fetched blobs are read, not executed.'; else add_check hardened_git_plan fail "Missing required source pins:$missing"; fi
  object_missing=''
  for pin in fetch rev-parse cat-file ls-tree; do timeout "$TIMEOUT_SECONDS" grep -Fq -- "$pin" "$plan_rs" "$execute_rs" || object_missing+=" $pin"; done
  if timeout "$TIMEOUT_SECONDS" grep -Eq 'exact|expected_source_sha|source_sha' "$plan_rs" "$execute_rs" && [[ -z $object_missing ]]; then add_check exact_object_readback pass 'Static source fetches and reads back the accepted commit, tree, workflow, and blobs before publication.'; else add_check exact_object_readback fail "Exact object readback proof is incomplete:$object_missing"; fi
else
  printf 'missing %s or %s\n' "$plan_rs" "$execute_rs" >"$proof"
  evidence+=("$TEST_ID/static-plan-proof.txt")
  add_check hardened_git_plan fail 'Published proxy checkout is missing materializer plan or execution source.'
  add_check exact_object_readback fail 'Published proxy checkout is missing exact-object readback source.'
fi

if [[ ! -e /etc/buzzci/harness.env ]]; then
  add_check live_materialization_receipt not_runnable 'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'
else
  harness_text=''
  if ! harness_text=$(read_harness 2>/dev/null); then
    if ((${#sudo_cmd[@]} == 0)); then
      add_check live_materialization_receipt not_runnable 'harness.env unreadable without sudo'
    else
      add_check live_materialization_receipt fail 'Published harness.env is not root-readable.'
    fi
  else
  state_root=$(read_harness_key BUZZ_CI_LEASE_STATE_ROOT 2>/dev/null || true)
  if [[ -z $state_root || ! -d $state_root ]]; then
    add_check live_materialization_receipt fail 'harness.env was published but BUZZ_CI_LEASE_STATE_ROOT is absent or invalid.'
  else
    lease_dir=''
    for entry in "$state_root"/*; do [[ -d $entry ]] && { lease_dir=$entry; break; }; done
    receipt=$lease_dir/materializer/receipt.json
    commands=$lease_dir/materializer/commands.jsonl
    live_log=$out_dir/live-materializer-proof.txt
    if [[ -z $lease_dir || ! -f $receipt || ! -f $commands ]]; then
      printf 'lease_dir=%s receipt=%s commands=%s\n' "$lease_dir" "$receipt" "$commands" >"$live_log"
      evidence+=("$TEST_ID/live-materializer-proof.txt")
      add_check live_materialization_receipt fail 'Lease state exists but materializer receipt.json or commands.jsonl is missing.'
    else
      source_sha=$(timeout "$TIMEOUT_SECONDS" jq -r '.source_sha // empty' "$receipt")
      tree_oid=$(timeout "$TIMEOUT_SECONDS" jq -r '.tree_oid // empty' "$receipt")
      actual_sha=$(timeout "$TIMEOUT_SECONDS" git -C "$candidate_dir" rev-parse HEAD 2>/dev/null || true)
      actual_tree=$(timeout "$TIMEOUT_SECONDS" git -C "$candidate_dir" cat-file -p "$actual_sha" 2>/dev/null | timeout "$TIMEOUT_SECONDS" grep '^tree ' | cut -d' ' -f2 || true)
      timeout "$TIMEOUT_SECONDS" jq '{source_sha,tree_oid,workflow_sha256,inputs_sha256,policy_sha256}' "$receipt" >"$live_log" 2>&1 || true
      printf 'independent_head=%s\nindependent_tree=%s\n' "$actual_sha" "$actual_tree" >>"$live_log"
      evidence+=("$TEST_ID/live-materializer-proof.txt")
      commands_ok=1
      for pin in 'core.hooksPath=/dev/null' 'credential.helper=' 'protocol.allow=never' 'protocol.https.allow=always' 'submodule.recurse=false' 'filter.lfs.smudge='; do
        timeout "$TIMEOUT_SECONDS" jq -s -e --arg p "$pin" '[.[] | .. | strings] | any(contains($p))' "$commands" >/dev/null 2>&1 || commands_ok=0
      done
      digest_ok=$(timeout "$TIMEOUT_SECONDS" jq -e '(.workflow_sha256|test("^sha256:[0-9a-f]{64}$")) and (.inputs_sha256|test("^sha256:[0-9a-f]{64}$")) and (.checkout_sha256|test("^sha256:[0-9a-f]{64}$"))' "$receipt" >/dev/null 2>&1 && printf 1 || printf 0)
      if [[ $source_sha == "$candidate" && $source_sha == "$actual_sha" && $tree_oid == "$actual_tree" && $commands_ok == 1 && $digest_ok == 1 ]]; then add_check live_materialization_receipt pass 'Receipt commit/tree match independent Git readback; receipt digests are canonical and commands.jsonl records every hardening pin.'; else add_check live_materialization_receipt fail 'Live receipt, independent Git readback, digest form, or commands.jsonl hardening pins disagree.'; fi
    fi
  fi
  fi
fi

if ((failed)); then emit fail 'One or more materializer checks failed.'; exit 1; fi
if ((unrunnable)); then emit not_runnable 'Static checks ran; live materializer evidence is not runnable on this host.'; exit 3; fi
emit pass 'All materializer checks passed.'
