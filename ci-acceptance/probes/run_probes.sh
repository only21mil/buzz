#!/usr/bin/env bash
set -euo pipefail

PROBES_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "$PROBES_DIR/.." && pwd -P)"
RESULTS_FILE="${BUZZ_CI_RESULTS_FILE:-$ROOT/results.jsonl}"
SUMMARY_FILE="${BUZZ_CI_SUMMARY_FILE:-$ROOT/summary.json}"

candidate="${BUZZ_CI_SHA:-}"
if [[ -z "$candidate" ]]; then
  candidate="$(git -C "$ROOT/.." rev-parse HEAD 2>/dev/null || true)"
fi
if [[ ! "$candidate" =~ ^[0-9a-f]{40}$ && ! "$candidate" =~ ^[0-9a-f]{64}$ ]]; then
  candidate=1111111111111111111111111111111111111111
fi

state_dir="$(mktemp -d "$ROOT/.probe-state.XXXXXX")"
cleanup() {
  rm -rf -- "$state_dir"
}
trap cleanup EXIT

export BUZZ_CI_SHA="$candidate"
export RESULTS_FILE
export MOCK_STATE_DIR="$state_dir"
export BUZZ_CI_REPO_OWNER="${BUZZ_CI_REPO_OWNER:-probe-owner}"
export BUZZ_CI_REPO_ID="${BUZZ_CI_REPO_ID:-probe-repo}"
export BUZZ_CI_WORKFLOW="${BUZZ_CI_WORKFLOW:-buzz-ci-phase2-probe-v1}"

source "$PROBES_DIR/lib.sh"
: >"$RESULTS_FILE"

probe_scripts=(
  "$PROBES_DIR/p1_trigger.sh"
  "$PROBES_DIR/p2_assignment_monitor.sh"
  "$PROBES_DIR/p3_headless_logs.sh"
  "$PROBES_DIR/p4_bounded_rerun.sh"
  "$PROBES_DIR/p5_dropped_run.sh"
  "$PROBES_DIR/p6_bounded_retries.sh"
)
probe_names=(p1_trigger p2_assignment_monitor p3_headless_logs p4_bounded_rerun p5_dropped_run p6_bounded_retries)

for run in 1 2; do
  for index in "${!probe_scripts[@]}"; do
    probe="${probe_scripts[$index]}"
    name="${probe_names[$index]}"
    set +e
    "$probe" --run "$run"
    rc=$?
    set -e
    if ((rc != 0)); then
      emit_result "$name" "$run" probe_exit false "probe exited $rc"
    fi
  done
done

probes_json="$(jq -cs '
  group_by([.probe,.run])
  | map({probe: .[0].probe, run: .[0].run, pass: all(.[]; .pass == true)})
  | sort_by([.run,.probe])
' "$RESULTS_FILE")"
jq -cn --arg candidate "$candidate" --argjson probes "$probes_json" '{candidate_sha:$candidate,probes:$probes,all_pass:(($probes|length) == 12 and all($probes[]; .pass == true))}' >"$SUMMARY_FILE"

cat "$SUMMARY_FILE"
if jq -e '.all_pass == true' "$SUMMARY_FILE" >/dev/null; then
  exit 0
fi
exit 1
