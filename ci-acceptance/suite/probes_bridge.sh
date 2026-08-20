#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  printf 'Usage: %s --candidate SHA --candidate-dir DIR --evidence-dir DIR --probe-bin PATH [options]\n' \
    "${0##*/}" >&2
}

candidate=''
candidate_dir=''
evidence_dir=''
probe_bin='buzz'
output_path='-'
plan=false
plan_output=''
selftest_mock=false
executor="${SUITE_EXECUTOR:-$(id -un)@$(hostname)}"
host="${SUITE_HOST:-$(hostname)}"
repo_owner="${BUZZ_CI_REPO_OWNER:-probe-owner}"
repo_id="${BUZZ_CI_REPO_ID:-probe-repo}"
workflow="${BUZZ_CI_WORKFLOW:-buzz-ci-phase2-probe-v1}"

while (($# > 0)); do
  case "$1" in
    --candidate)
      (($# >= 2)) || { usage; exit 4; }
      candidate=$2
      shift 2
      ;;
    --candidate-dir)
      (($# >= 2)) || { usage; exit 4; }
      candidate_dir=$2
      shift 2
      ;;
    --evidence-dir)
      (($# >= 2)) || { usage; exit 4; }
      evidence_dir=$2
      shift 2
      ;;
    --probe-bin)
      (($# >= 2)) || { usage; exit 4; }
      probe_bin=$2
      shift 2
      ;;
    --output)
      (($# >= 2)) || { usage; exit 4; }
      output_path=$2
      shift 2
      ;;
    --plan)
      plan=true
      shift
      ;;
    --plan-output)
      (($# >= 2)) || { usage; exit 4; }
      plan_output=$2
      shift 2
      ;;
    --probe-repo-owner)
      (($# >= 2)) || { usage; exit 4; }
      repo_owner=$2
      shift 2
      ;;
    --probe-repo-id)
      (($# >= 2)) || { usage; exit 4; }
      repo_id=$2
      shift 2
      ;;
    --probe-workflow)
      (($# >= 2)) || { usage; exit 4; }
      workflow=$2
      shift 2
      ;;
    --selftest-mock)
      selftest_mock=true
      shift
      ;;
    --executor)
      (($# >= 2)) || { usage; exit 4; }
      executor=$2
      shift 2
      ;;
    --host)
      (($# >= 2)) || { usage; exit 4; }
      host=$2
      shift 2
      ;;
    *)
      usage
      exit 4
      ;;
  esac
done

if ! suite_require_full_oid "$candidate" \
  || [[ -z "$candidate_dir" || ! -d "$candidate_dir" || -z "$evidence_dir" ]]; then
  printf 'candidate-dir must be an existing directory\n' >&2
  exit 4
fi
if [[ "$selftest_mock" == true ]]; then
  executor=selftest-mock
fi

suite_detect_sudo
mkdir -p -- "$evidence_dir"

probe_names=(p1_trigger p2_assignment_monitor p3_headless_logs p4_bounded_rerun p5_dropped_run p6_bounded_retries)
probe_ids=(P-i P-ii P-iii P-iv P-v P-vi)

resolved_probe_bin=''
if resolved_probe_bin=$(suite_resolve_command "$probe_bin" 2>/dev/null); then
  resolved_probe_bin=$(readlink -f -- "$resolved_probe_bin" 2>/dev/null || true)
fi
fixtures_root="$SUITE_ACCEPTANCE_DIR/fixtures"
suite_fixtures_root="$SCRIPT_DIR/fixtures"
if [[ -n "$resolved_probe_bin" ]] \
  && { suite_path_is_under "$fixtures_root" "$resolved_probe_bin" \
    || suite_path_is_under "$suite_fixtures_root" "$resolved_probe_bin"; } \
  && [[ "$selftest_mock" != true ]]; then
  printf 'refusing probe mock under ci-acceptance/fixtures; pass --selftest-mock for a non-production run\n' >&2
  exit 2
fi

plan_mode() {
  local plan_file=${plan_output:-$evidence_dir/probe-plan.json}
  local probe_plan_file="$evidence_dir/.probe-plan.$$.jsonl"
  local index
  : >"$probe_plan_file"
  for index in "${!probe_names[@]}"; do
    jq -cn --arg name "${probe_names[$index]}" --arg id "${probe_ids[$index]}" \
      --arg title "$(suite_probe_title "${probe_ids[$index]}")" \
      --arg run_script "$SUITE_RUN_PROBES" --arg probe_bin "$probe_bin" \
      '{probe:$name,test_id:$id,title:$title,runs:[1,2],status:"plan",runner:$run_script,probe_bin:$probe_bin,preconditions:["the probe binary must be executable for a real run"]}' \
      >>"$probe_plan_file"
  done
  mkdir -p -- "$(dirname -- "$plan_file")"
  jq -cn --arg candidate "$candidate" --arg executor "$executor" --arg host "$host" \
    --arg repo_owner "$repo_owner" --arg repo_id "$repo_id" --arg workflow "$workflow" \
    --slurpfile probes "$probe_plan_file" \
    '{suite:"probe",mode:"plan",candidate_sha:$candidate,executor:$executor,host:$host,repo_owner:$repo_owner,repo_id:$repo_id,workflow:$workflow,probes:$probes}' \
    >"$plan_file"
  rm -f -- "$probe_plan_file"
  printf '%s\n' "$plan_file" >&2
}

if [[ "$plan" == true ]]; then
  plan_mode
  exit 0
fi

if [[ "$output_path" == - ]]; then
  record_file=$(mktemp "$evidence_dir/.probe-records.XXXXXX")
  cleanup_record_file=true
else
  mkdir -p -- "$(dirname -- "$output_path")"
  record_file=$output_path
  cleanup_record_file=false
fi
: >"$record_file"
trap 'if [[ "${cleanup_record_file:-false}" == true ]]; then rm -f -- "$record_file"; fi' EXIT

probe_run_dir="$evidence_dir/probe-run"
mkdir -p -- "$probe_run_dir"
results_file="$probe_run_dir/results.jsonl"
summary_file="$probe_run_dir/summary.json"
run_stdout="$probe_run_dir/run.stdout"
run_stderr="$probe_run_dir/run.stderr"
started=$(suite_now)
malformed=false
run_rc=4

if [[ -z "$resolved_probe_bin" || ! -f "$resolved_probe_bin" || ! -x "$resolved_probe_bin" ]]; then
  printf 'probe binary is not an executable file: %s\n' "$probe_bin" >"$probe_run_dir/error.txt"
else
  suite_run_bounded "$SUITE_TIMEOUT_SECONDS" "$run_stdout" "$run_stderr" env \
    "BUZZ_CI_BIN=$resolved_probe_bin" \
    "BUZZ_CI_SHA=$candidate" \
    "BUZZ_CI_RESULTS_FILE=$results_file" \
    "BUZZ_CI_SUMMARY_FILE=$summary_file" \
    "BUZZ_CI_REPO_OWNER=$repo_owner" \
    "BUZZ_CI_REPO_ID=$repo_id" \
    "BUZZ_CI_WORKFLOW=$workflow" \
    "$SUITE_RUN_PROBES"
  run_rc=$SUITE_LAST_RC
fi
finished=$(suite_now)

summary=''
summary_ok=false
if [[ -f "$summary_file" ]] \
  && summary=$(jq -s -c 'if (length == 1 and (.[0] | type == "object")) then .[0] else empty end' \
    "$summary_file" 2>/dev/null) \
  && [[ -n "$summary" ]] \
  && jq -e '
    (.candidate_sha | type == "string") and
    (.probes | type == "array" and length == 12 and all(.[];
      type == "object" and (.probe | type == "string") and (.run == 1 or .run == 2) and
      (.pass | type == "boolean"))) and
    ([.probes[] | (.probe + "/" + (.run | tostring))] | length == (unique | length)) and
    (.all_pass | type == "boolean")
  ' <<<"$summary" >/dev/null 2>&1; then
  summary_ok=true
else
  malformed=true
  printf 'probe summary was missing or failed its schema checks\n' >"$probe_run_dir/summary_error.txt"
fi

results_ok=false
if [[ -f "$results_file" ]] \
  && jq -e -s 'length > 0 and all(.[]; type == "object" and (.probe | type == "string") and (.run == 1 or .run == 2) and (.pass | type == "boolean"))' \
    "$results_file" >/dev/null 2>&1; then
  results_ok=true
else
  malformed=true
  printf 'probe results were missing or contained malformed JSONL\n' >"$probe_run_dir/results_error.txt"
fi

summary_candidate=''
if [[ "$summary_ok" == true ]]; then
  summary_candidate=$(jq -r '.candidate_sha' <<<"$summary")
  if [[ "$summary_candidate" != "$candidate" ]]; then
    printf 'probe summary candidate SHA differs from the requested candidate\n' \
      >"$probe_run_dir/candidate_sha_error.txt"
  fi
fi

for index in "${!probe_names[@]}"; do
  probe_name=${probe_names[$index]}
  probe_id=${probe_ids[$index]}
  title=$(suite_probe_title "$probe_id")
  for run in 1 2; do
    slice_dir="$evidence_dir/$probe_id"
    slice_file="$slice_dir/run-$run.results.jsonl"
    mkdir -p -- "$slice_dir"
    if [[ "$results_ok" == true ]]; then
      if ! jq -c --arg probe "$probe_name" --argjson run "$run" \
        'select(.probe == $probe and .run == $run)' "$results_file" >"$slice_file"; then
        : >"$slice_file"
      fi
    else
      : >"$slice_file"
    fi
    if [[ ! -s "$slice_file" ]]; then
      jq -cn --arg probe "$probe_name" --argjson run "$run" \
        '{probe:$probe,run:$run,pass:false,detail:"no result slice was emitted"}' >"$slice_file"
    fi

    pair_pass=false
    if [[ "$summary_ok" == true && "$results_ok" == true && "$run_rc" == 0 \
      && "$summary_candidate" == "$candidate" ]]; then
      pair_json=$(jq -c --arg probe "$probe_name" --argjson run "$run" \
        '[.probes[] | select(.probe == $probe and .run == $run)]' <<<"$summary")
      if [[ $(jq -r 'length' <<<"$pair_json") == 1 ]] \
        && jq -e '.[0].pass == true' <<<"$pair_json" >/dev/null 2>&1; then
        pair_pass=true
      fi
    fi
    evidence_ref=$(suite_hash_reference "$slice_file")
    line=$(suite_emit_record probe "$probe_id" "$title" "$candidate" "$pair_pass" \
      "$evidence_ref" "$executor" "$host" "$started" "$finished" "$run")
    printf '%s\n' "$line" >>"$record_file"
  done
done

if [[ "$output_path" == - ]]; then
  cat "$record_file"
fi
if [[ "$malformed" == true ]]; then
  exit 2
fi
if jq -s -e 'length == 12 and all(.[]; .pass == true)' "$record_file" >/dev/null 2>&1; then
  exit 0
fi
exit 1
