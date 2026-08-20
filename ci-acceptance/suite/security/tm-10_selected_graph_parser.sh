#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-10
TITLE="Have a broker-owned parser compare \`act\`'s selected graph with the signed canonical manifest"
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
candidate=''; candidate_dir=''; evidence_dir=''; plan=0
checks=(); evidence=(); preconditions=(
  'crates/buzz-relay/src/ci.rs and crates/buzz-relay/src/bin/buzz-ci-graph-reducer.rs exist in the candidate'
  'BUZZ_CI_GRAPH_REDUCER names an executable relay reducer and BUZZ_CI_GRAPH_FIXTURE_DIR names strict JSON fixtures'
  'the materializer commands.jsonl record for a lease contains --concurrent-jobs=1'
)
failed=0; unrunnable=0

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
  checks+=("$(timeout "$TIMEOUT_SECONDS" jq -cn --arg name "$name" --arg status "$status" --arg detail "$detail" '{name:$name,status:$status,detail:$detail}')")
  [[ $status != fail ]] || failed=1
  [[ $status != not_runnable ]] || unrunnable=1
}

json_array() {
  if (($# == 0)); then printf '[]'; else printf '%s\n' "$@" | timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n") | map(select(length > 0))'; fi
}

emit() {
  local status=$1 summary=$2 pass_json=false checks_json evidence_json preconditions_json
  [[ $status == pass ]] && pass_json=true
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(json_array "${evidence[@]}")
  preconditions_json=$(json_array "${preconditions[@]}")
  timeout "$TIMEOUT_SECONDS" jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" \
    --arg summary "$summary" --argjson pass "$pass_json" --argjson checks "$checks_json" \
    --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" \
    '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
}

if ((plan)); then
  add_check reducer_not_in_candidate plan 'Check the relay-owned reducer source and binary entrypoint in the candidate.'
  add_check relay_ci_tests plan 'Run the bounded buzz-relay ci module tests.'
  add_check signed_fixture_reducer plan 'Feed each signed kind-46100 and kind-46102 fixture to the relay reducer and compare expected output or machine error.'
  add_check single_job_concurrency plan 'Check the act-side materializer commands.jsonl record for --concurrent-jobs=1.'
  emit plan 'Plan only; the relay-owned reducer and strict signed-event fixtures were not executed.'
  exit 0
fi

[[ $candidate =~ ^[0-9a-f]{40}$ && -n $candidate_dir && -n $evidence_dir ]] || usage
[[ -d $candidate_dir ]] || { printf 'candidate directory is not a directory\n' >&2; exit 4; }
[[ $TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]] || { printf 'invalid SUITE_TIMEOUT_SECONDS\n' >&2; exit 4; }

out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir" || exit 4
reducer_source=$candidate_dir/crates/buzz-relay/src/bin/buzz-ci-graph-reducer.rs
relay_ci=$candidate_dir/crates/buzz-relay/src/ci.rs
source_log=$out_dir/reducer-source.txt
if [[ -f $reducer_source && -f $relay_ci ]]; then
  printf 'reducer=%s\nci=%s\n' "$reducer_source" "$relay_ci" >"$source_log"
  add_check reducer_not_in_candidate pass 'Relay reducer entrypoint and strict CI input types are present in the candidate.'
  cargo_log=$out_dir/relay-ci-tests.log
  set +e
  CARGO_TARGET_DIR=$candidate_dir/target timeout "$TIMEOUT_SECONDS" cargo test --manifest-path "$candidate_dir/Cargo.toml" -p buzz-relay ci:: >"$cargo_log" 2>&1
  cargo_rc=$?
  set -e
  evidence+=("$TEST_ID/relay-ci-tests.log")
  if ((cargo_rc == 0)); then add_check relay_ci_tests pass 'buzz-relay ci:: tests completed with zero failures.'; else add_check relay_ci_tests fail "cargo test -p buzz-relay ci:: exited $cargo_rc."; fi
else
  printf 'missing reducer=%s or ci=%s\n' "$reducer_source" "$relay_ci" >"$source_log"
  add_check reducer_not_in_candidate fail 'reducer_not_in_candidate: relay-owned graph reducer source is absent from the candidate.'
  add_check relay_ci_tests not_runnable 'buzz-relay ci:: tests require the relay reducer source and CI input types.'
fi
evidence+=("$TEST_ID/reducer-source.txt")

SUDO=()
if [[ -n ${SUITE_SUDO+x} ]]; then read -r -a SUDO <<<"$SUITE_SUDO"
elif timeout 5 sudo -n true >/dev/null 2>&1; then SUDO=(sudo -n)
fi
read_harness() {
  if ((${#SUDO[@]})); then
    timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat /etc/buzzci/harness.env
  else
    return 3
  fi
}
env_get() {
  local key=$1
  printf '%s\n' "$harness_text" | timeout "$TIMEOUT_SECONDS" awk -F= -v key="$key" '$1==key{print substr($0,index($0,"=")+1); exit}'
}

# harness.env state: the act-side concurrency record needs the published seam; the signed-fixture
# reducer check can also run from the process environment or straight from the candidate tree.
harness_text=''; harness_ready=0; harness_state='absent'
if [[ -e /etc/buzzci/harness.env ]]; then
  if harness_text=$(read_harness 2>/dev/null); then harness_ready=1; harness_state='ready'
  elif ((${#SUDO[@]} == 0)); then harness_state='unreadable_nosudo'
  else harness_state='unreadable'
  fi
fi

reducer=''; fixture_dir=''; fixture_source=''
if ((harness_ready)); then
  reducer=$(env_get BUZZ_CI_GRAPH_REDUCER); fixture_dir=$(env_get BUZZ_CI_GRAPH_FIXTURE_DIR); fixture_source='harness.env'
fi
if [[ -z $reducer || -z $fixture_dir ]] && [[ -n ${BUZZ_CI_GRAPH_REDUCER:-} && -n ${BUZZ_CI_GRAPH_FIXTURE_DIR:-} ]]; then
  reducer=$BUZZ_CI_GRAPH_REDUCER; fixture_dir=$BUZZ_CI_GRAPH_FIXTURE_DIR; fixture_source='process environment'
fi
if [[ -z $reducer || -z $fixture_dir ]]; then
  candidate_fixtures=$candidate_dir/crates/buzz-relay/tests/fixtures/ci-graph-reducer
  if [[ -d $candidate_fixtures && -f $reducer_source ]]; then
    build_log=$out_dir/reducer-build.log
    set +e
    CARGO_TARGET_DIR=$candidate_dir/target timeout "$TIMEOUT_SECONDS" cargo build --manifest-path "$candidate_dir/Cargo.toml" -p buzz-relay --bin buzz-ci-graph-reducer >"$build_log" 2>&1
    build_rc=$?
    set -e
    evidence+=("$TEST_ID/reducer-build.log")
    if ((build_rc == 0)) && [[ -x $candidate_dir/target/debug/buzz-ci-graph-reducer ]]; then
      reducer=$candidate_dir/target/debug/buzz-ci-graph-reducer; fixture_dir=$candidate_fixtures; fixture_source='candidate tree'
    fi
  fi
fi

if [[ -z $reducer || ! -x $reducer || -z $fixture_dir || ! -d $fixture_dir ]]; then
  case $harness_state in
    unreadable) add_check signed_fixture_reducer fail 'Published harness.env is not root-readable.' ;;
    unreadable_nosudo) add_check signed_fixture_reducer not_runnable 'harness.env unreadable without sudo' ;;
    *) add_check signed_fixture_reducer not_runnable 'no executable buzz-ci-graph-reducer plus fixture directory from harness.env, the process environment, or the candidate tree (relay reducer seam)' ;;
  esac
else
    mapfile -t fixture_inputs < <(timeout "$TIMEOUT_SECONDS" find "$fixture_dir" -maxdepth 1 -type f -name '*.json' ! -name '*.expected.json' ! -name '*.expected-error.json' -print | sort)
    if ((${#fixture_inputs[@]} == 0)); then
      add_check signed_fixture_reducer not_runnable 'BUZZ_CI_GRAPH_FIXTURE_DIR contains no strict reducer input fixtures.'
    else
      fixture_ok=1
      fixture_index=0
      for input in "${fixture_inputs[@]}"; do
        fixture_index=$((fixture_index + 1))
        stem=${input%.json}
        expected=${stem}.expected.json
        expected_error=${stem}.expected-error.json
        safe_name=${input##*/}
        output=$out_dir/fixture-${fixture_index}-${safe_name}.stdout.json
        stderr=$out_dir/fixture-${fixture_index}-${safe_name}.stderr.log
        set +e
        timeout "$TIMEOUT_SECONDS" "$reducer" <"$input" >"$output" 2>"$stderr"
        reducer_rc=$?
        set -e
        evidence+=("$TEST_ID/${output##*/}" "$TEST_ID/${stderr##*/}")
        if [[ -f $expected ]]; then
          if ((reducer_rc != 0)) || ! timeout "$TIMEOUT_SECONDS" jq -e 'type == "object" and has("selected_job_attempts")' "$output" >/dev/null 2>&1 || ! timeout "$TIMEOUT_SECONDS" jq -n --slurpfile actual "$output" --slurpfile wanted "$expected" '($wanted[0] | keys) as $keys | all($keys[]; $actual[0][.] == $wanted[0][.])' >/dev/null 2>&1; then
            fixture_ok=0
          fi
        elif [[ -f $expected_error ]]; then
          expected_code=$(timeout "$TIMEOUT_SECONDS" jq -r '.error // empty' "$expected_error")
          if ((reducer_rc == 0)) || [[ -z $expected_code ]] || ! timeout "$TIMEOUT_SECONDS" jq -e --arg code "$expected_code" 'select(type == "object" and .error == $code)' "$stderr" >/dev/null 2>&1; then
            fixture_ok=0
          fi
        else
          printf 'missing expected pair for %s\n' "$input" >>"$out_dir/fixture-errors.log"
          evidence+=("$TEST_ID/fixture-errors.log")
          fixture_ok=0
        fi
      done
      if ((fixture_ok)); then add_check signed_fixture_reducer pass "All signed-event reducer fixtures matched selected_job_attempts and expected run coordinates or closed errors (reducer and fixtures from: $fixture_source)."; else add_check signed_fixture_reducer fail "A signed-event reducer fixture did not match its expected output or machine error (reducer and fixtures from: $fixture_source)."; fi
    fi
  fi

if ((harness_ready)); then
  state_root=$(env_get BUZZ_CI_LEASE_STATE_ROOT)
  lease_dir=''
  if [[ -n $state_root && -d $state_root ]]; then
    for entry in "$state_root"/*; do [[ -d $entry ]] && { lease_dir=$entry; break; }; done
  fi
  commands_log=$out_dir/concurrency-commands.txt
  commands_files=()
  if [[ -n $lease_dir ]]; then
    if ((${#SUDO[@]})); then
      mapfile -t commands_files < <(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" find "$lease_dir/materializer" -maxdepth 1 -type f -name commands.jsonl -print 2>/dev/null)
    else
      mapfile -t commands_files < <(timeout "$TIMEOUT_SECONDS" find "$lease_dir/materializer" -maxdepth 1 -type f -name commands.jsonl -print 2>/dev/null)
    fi
  fi
  found=0
  : >"$commands_log"
  for file in "${commands_files[@]}"; do
    if ((${#SUDO[@]})); then timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat "$file" >>"$commands_log" 2>&1 || true
    else timeout "$TIMEOUT_SECONDS" cat "$file" >>"$commands_log" 2>&1 || true
    fi
    if ((${#SUDO[@]})); then timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" jq -s -e '[.[] | .. | strings] | any(. == "--concurrent-jobs=1") or (index("--concurrent-jobs") != null and index("1") != null)' "$file" >/dev/null 2>&1 && found=1 || true
    elif timeout "$TIMEOUT_SECONDS" jq -s -e '[.[] | .. | strings] | any(. == "--concurrent-jobs=1") or (index("--concurrent-jobs") != null and index("1") != null)' "$file" >/dev/null 2>&1; then found=1
    fi
  done
  evidence+=("$TEST_ID/concurrency-commands.txt")
  if ((found)); then add_check single_job_concurrency pass 'A lease materializer commands.jsonl record contains --concurrent-jobs=1.'; else add_check single_job_concurrency fail 'No lease materializer commands.jsonl record contains --concurrent-jobs=1.'; fi
else
  case $harness_state in
    unreadable) add_check single_job_concurrency fail 'Published harness.env is not root-readable.' ;;
    unreadable_nosudo) add_check single_job_concurrency not_runnable 'harness.env unreadable without sudo' ;;
    *) add_check single_job_concurrency not_runnable 'substrate wiring has not published /etc/buzzci/harness.env (relay reducer seam)' ;;
  esac
fi

if ((failed)); then emit fail 'The relay-owned selected-graph reducer acceptance test failed.'; exit 1; fi
if ((unrunnable)); then emit not_runnable 'Static reducer checks passed where present; live signed fixtures or act-side records are not runnable on this host.'; exit 3; fi
emit pass 'The relay-owned graph reducer matched every signed fixture and act-side concurrency record.'
