#!/usr/bin/env bash
set -euo pipefail

SUITE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "$SUITE_DIR/lib.sh"

usage() {
  printf 'Usage: %s --candidate SHA --candidate-dir DIR --evidence-root DIR [options]\n' "${0##*/}" >&2
  printf '  --probe-bin PATH --probe-repo-owner X --probe-repo-id Y --probe-workflow Z\n' >&2
  printf '  --security-only | --probes-only | --plan | --selftest-mock\n' >&2
}

candidate=''
candidate_dir=''
evidence_root=''
probe_bin='buzz'
probe_owner="${BUZZ_CI_REPO_OWNER:-probe-owner}"
probe_id="${BUZZ_CI_REPO_ID:-probe-repo}"
probe_workflow="${BUZZ_CI_WORKFLOW:-buzz-ci-phase2-probe-v1}"
security_only=false
probes_only=false
plan=false
selftest_mock=false
executor="${SUITE_EXECUTOR:-$(id -un)@$(hostname)}"
host="${SUITE_HOST:-$(hostname)}"

while (($# > 0)); do
  case "$1" in
    --candidate)
      (($# >= 2)) || { usage; exit 2; }
      candidate=$2
      shift 2
      ;;
    --candidate-dir)
      (($# >= 2)) || { usage; exit 2; }
      candidate_dir=$2
      shift 2
      ;;
    --evidence-root)
      (($# >= 2)) || { usage; exit 2; }
      evidence_root=$2
      shift 2
      ;;
    --probe-bin)
      (($# >= 2)) || { usage; exit 2; }
      probe_bin=$2
      shift 2
      ;;
    --probe-repo-owner)
      (($# >= 2)) || { usage; exit 2; }
      probe_owner=$2
      shift 2
      ;;
    --probe-repo-id)
      (($# >= 2)) || { usage; exit 2; }
      probe_id=$2
      shift 2
      ;;
    --probe-workflow)
      (($# >= 2)) || { usage; exit 2; }
      probe_workflow=$2
      shift 2
      ;;
    --security-only)
      security_only=true
      shift
      ;;
    --probes-only)
      probes_only=true
      shift
      ;;
    --plan)
      plan=true
      shift
      ;;
    --selftest-mock)
      selftest_mock=true
      shift
      ;;
    --executor)
      (($# >= 2)) || { usage; exit 2; }
      executor=$2
      shift 2
      ;;
    --host)
      (($# >= 2)) || { usage; exit 2; }
      host=$2
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if ! suite_require_full_oid "$candidate" || [[ -z "$candidate_dir" || ! -d "$candidate_dir" ]]; then
  printf 'candidate-dir must be an existing directory\n' >&2
  exit 2
fi
[[ -n "$evidence_root" ]] || {
  printf 'evidence-root is required\n' >&2
  exit 2
}
if [[ "$selftest_mock" == true ]]; then
  executor=selftest-mock
fi

candidate_root="$evidence_root/$candidate"
mkdir -p -- "$candidate_root"
security_dir="${SUITE_SECURITY_DIR:-$SUITE_DIR/security}"
security_runner="$SUITE_DIR/security/run_security.sh"
probe_bridge="$SUITE_DIR/probes_bridge.sh"
aggregator="$SUITE_ACCEPTANCE_DIR/evidence/aggregate_acceptance.sh"

run_security_plan() {
  local output=$1
  local rc
  set +e
  "$security_runner" \
    --candidate "$candidate" \
    --candidate-dir "$candidate_dir" \
    --evidence-dir "$candidate_root/security-plan" \
    --security-dir "$security_dir" \
    --plan --plan-output "$output" \
    --executor "$executor" --host "$host"
  rc=$?
  set -e
  return "$rc"
}

run_probe_plan() {
  local output=$1
  local rc
  local args=(
    --candidate "$candidate"
    --candidate-dir "$candidate_dir"
    --evidence-dir "$candidate_root/probe-plan"
    --probe-bin "$probe_bin"
    --probe-repo-owner "$probe_owner"
    --probe-repo-id "$probe_id"
    --probe-workflow "$probe_workflow"
    --plan
    --plan-output "$output"
    --executor "$executor"
    --host "$host"
  )
  [[ "$selftest_mock" == true ]] && args+=(--selftest-mock)
  set +e
  "$probe_bridge" "${args[@]}"
  rc=$?
  set -e
  return "$rc"
}

if [[ "$plan" == true ]]; then
  security_plan="$candidate_root/security-plan.json"
  probe_plan="$candidate_root/probe-plan.json"
  security_rc=0
  probe_rc=0
  if [[ "$probes_only" != true ]]; then
    run_security_plan "$security_plan" || security_rc=$?
  else
    jq -cn '{suite:"security",mode:"plan",status:"skipped",tests:[]}' >"$security_plan"
  fi
  if [[ "$security_only" != true ]]; then
    run_probe_plan "$probe_plan" || probe_rc=$?
  else
    jq -cn '{suite:"probe",mode:"plan",status:"skipped",probes:[]}' >"$probe_plan"
  fi
  if [[ ! -f "$security_plan" ]]; then
    jq -cn --arg candidate "$candidate" '{suite:"security",mode:"plan",candidate_sha:$candidate,status:"malformed",tests:[]}' >"$security_plan"
  fi
  if [[ ! -f "$probe_plan" ]]; then
    jq -cn --arg candidate "$candidate" '{suite:"probe",mode:"plan",candidate_sha:$candidate,status:"malformed",probes:[]}' >"$probe_plan"
  fi
  jq -cn --arg candidate "$candidate" --arg executor "$executor" --arg host "$host" \
    --argjson security "$(<"$security_plan")" --argjson probes "$(<"$probe_plan")" \
    '{mode:"plan",candidate_sha:$candidate,executor:$executor,host:$host,security:$security,probes:$probes}'
  if ((security_rc == 2 || security_rc == 4 || probe_rc == 2 || probe_rc == 4)); then
    exit 2
  fi
  exit 0
fi

security_file="$candidate_root/security.jsonl"
probe_file="$candidate_root/probe.jsonl"
security_tmp="$candidate_root/.security.$$.jsonl"
probe_tmp="$candidate_root/.probe.$$.jsonl"
schema_tmp="$candidate_root/.schema.$$.tmp"
malformed=false
mkdir -p -- "$schema_tmp"
: >"$security_tmp"
: >"$probe_tmp"
cleanup() {
  rm -f -- "$security_tmp" "$probe_tmp"
  rm -rf -- "$schema_tmp"
}
trap cleanup EXIT

security_rc=0
if [[ "$probes_only" != true ]]; then
  set +e
  "$security_runner" \
    --candidate "$candidate" \
    --candidate-dir "$candidate_dir" \
    --evidence-dir "$candidate_root" \
    --security-dir "$security_dir" \
    --output "$security_tmp" \
    --executor "$executor" --host "$host"
  security_rc=$?
  set -e
else
  : >"$security_tmp"
fi

probe_rc=0
if [[ "$security_only" != true ]]; then
  probe_args=(
    --candidate "$candidate"
    --candidate-dir "$candidate_dir"
    --evidence-dir "$candidate_root"
    --probe-bin "$probe_bin"
    --probe-repo-owner "$probe_owner"
    --probe-repo-id "$probe_id"
    --probe-workflow "$probe_workflow"
    --output "$probe_tmp"
    --executor "$executor"
    --host "$host"
  )
  [[ "$selftest_mock" == true ]] && probe_args+=(--selftest-mock)
  set +e
  "$probe_bridge" "${probe_args[@]}"
  probe_rc=$?
  set -e
else
  : >"$probe_tmp"
fi

if ((security_rc == 2 || security_rc == 4 || probe_rc == 2 || probe_rc == 4)); then
  malformed=true
fi

if ! suite_validate_jsonl "$security_tmp" security "$candidate" "$schema_tmp" \
  || ! suite_validate_jsonl "$probe_tmp" probe "$candidate" "$schema_tmp"; then
  malformed=true
fi

if [[ "$malformed" == true ]]; then
  : >"$security_file"
  : >"$probe_file"
else
  mv -f -- "$security_tmp" "$security_file"
  mv -f -- "$probe_tmp" "$probe_file"
fi

verdict_file="$candidate_root/verdict.json"
aggregate_rc=0
set +e
if [[ "$malformed" == true ]]; then
  malformed_input="$candidate_root/.malformed-input"
  printf '{malformed\n' >"$malformed_input"
  "$aggregator" --output "$verdict_file" "$malformed_input"
  aggregate_rc=$?
  rm -f -- "$malformed_input"
else
  "$aggregator" --output "$verdict_file" "$security_file" "$probe_file"
  aggregate_rc=$?
fi
set -e
cat "$verdict_file"

if [[ "$malformed" == true || "$aggregate_rc" == 2 ]]; then
  exit 2
fi
if ((aggregate_rc == 0)); then
  exit 0
fi
exit 1
