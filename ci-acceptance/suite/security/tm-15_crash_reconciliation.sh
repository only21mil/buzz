#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-15
TITLE='Crash/kill `act`, Podman, proxy, materializer, broker, and host mid-attempt'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/acceptance_control.sh"
candidate=''
candidate_dir=''
evidence_dir=''
plan=0
checks=()
statuses=()
evidence_files=()
preconditions=(
  'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'
  'BUZZ_CI_ACCEPTANCE_CTL receives exact root-authored TM-15 target and reuse cases on stdin'
  'cleanup_adapter_recovery and dns_adapter_recovery must publish clean before-reuse reconciliation and permit a distinct replacement lease/workspace'
  'the accepted fixture repository must expose ci-acceptance/probe-repo/workflow.yml job slowpoke'
  'root kill, systemctl, cgroup, and lease-state access requires SUITE_SUDO or passwordless sudo'
)

usage() { printf 'usage: %s --candidate SHA --candidate-dir DIR --evidence-dir DIR [--plan]\n' "${0##*/}" >&2; exit 4; }
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
[[ $TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]] || { printf 'invalid SUITE_TIMEOUT_SECONDS\n' >&2; exit 4; }
record() { local name=$1 status=$2 detail=$3; checks+=("$(timeout "$TIMEOUT_SECONDS" jq -cn --arg name "$name" --arg status "$status" --arg detail "$detail" '{name:$name,status:$status,detail:$detail}')"); statuses+=("$status"); }
string_array() { if (($# == 0)); then printf '[]'; else printf '%s\n' "$@" | timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n")[:-1]'; fi; }
emit() {
  local status summary pass_json=false checks_json evidence_json preconditions_json
  if ((plan)); then status=plan; summary='Plan only; no checks executed'
  elif [[ " ${statuses[*]} " == *' fail '* ]]; then status=fail; summary='At least one crash-reconciliation check failed'
  elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then status=not_runnable; summary='Crash-reconciliation checks need the published isolation wiring and root access'
  else status=pass; pass_json=true; summary='Generic crash targets reconciled to empty or quarantine; adapter recovery targets reconciled clean before distinct reuse'
  fi
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(string_array "${evidence_files[@]}")
  preconditions_json=$(string_array "${preconditions[@]}")
  timeout "$TIMEOUT_SECONDS" jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" \
    --argjson pass "$pass_json" --arg summary "$summary" --argjson checks "$checks_json" \
    --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" \
    '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
}

generic_targets=(act podman proxy materializer broker simulated_host_crash)
recovery_targets=(cleanup_adapter_recovery dns_adapter_recovery)
targets=("${generic_targets[@]}" "${recovery_targets[@]}")
recovery_contract=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/tm-15_recovery_contract.jq
if ((plan)); then
  record probe_fixture_scripts_parse plan 'Would run bash -n on the probe job scripts used for crash attempts'
  for target in "${generic_targets[@]}"; do record "$target" plan "Would kill $target mid-attempt and verify reconciliation before reuse"; done
  record cleanup_adapter_recovery plan 'Would require clean recovery of the declared non-DNS cleanup resources before a distinct replacement lease/workspace'
  record dns_adapter_recovery plan 'Would require clean network-namespace recovery before a distinct replacement lease/workspace'
  emit
  exit 0
fi
[[ -d $candidate_dir ]] || { printf 'candidate directory is not a directory\n' >&2; exit 4; }
[[ -f $recovery_contract && ! -L $recovery_contract ]] || { printf 'TM-15 recovery contract is missing or linked\n' >&2; exit 4; }
out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"
syntax_file=$out_dir/probe-fixture-syntax.txt
if timeout "$TIMEOUT_SECONDS" bash -n "$candidate_dir"/ci-acceptance/probe-repo/jobs/*.sh >"$syntax_file" 2>&1; then
  record probe_fixture_scripts_parse pass 'All checked-in probe job scripts pass bash -n'
else
  record probe_fixture_scripts_parse fail 'A checked-in probe job script is missing or fails bash -n'
fi
evidence_files+=("$TEST_ID/probe-fixture-syntax.txt")

if [[ ! -e /etc/buzzci/harness.env ]]; then
  for target in "${targets[@]}"; do record "$target" not_runnable 'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi
SUDO=()
if [[ -n ${SUITE_SUDO+x} ]]; then read -r -a SUDO <<<"$SUITE_SUDO"; elif timeout 5 sudo -n true >/dev/null 2>&1; then SUDO=(sudo -n); fi
if ((${#SUDO[@]} == 0)) && [[ ! -r /etc/buzzci/harness.env ]]; then
  for target in "${targets[@]}"; do record "$target" not_runnable 'harness.env unreadable without sudo'; done
  emit
  exit 3
fi
if ((${#SUDO[@]} == 0)); then for target in "${targets[@]}"; do record "$target" not_runnable 'Crash injection and root reconciliation readback require SUITE_SUDO or passwordless sudo'; done; emit; exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"; fi
harness_text=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat /etc/buzzci/harness.env 2>/dev/null) || { for target in "${targets[@]}"; do record "$target" fail 'Published harness.env is not root-readable'; done; emit; exit 1; }
export harness_text
lease_root=$(acceptance_env_get BUZZ_CI_LEASE_STATE_ROOT)
broker_unit=$(acceptance_env_get BUZZ_CI_BROKER_UNIT)
if ! acceptance_control_init; then
  for target in "${targets[@]}"; do record "$target" not_runnable "$ACCEPTANCE_UNAVAILABLE"; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi
if [[ ! -d $lease_root || ! $broker_unit =~ ^buzzci[-A-Za-z0-9_.@]+$ ]]; then
  for target in "${targets[@]}"; do record "$target" not_runnable 'harness.env lacks a readable lease root or constrained buzzci broker unit'; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi

admit_slowpoke() {
  local label=$1 admit_file=$out_dir/admit-$1.json lease_id lease_json rc=0
  acceptance_control_run "$label" "$admit_file" "$out_dir/admit-$label.stderr" || rc=$?
  ((rc == 0)) || return "$rc"
  timeout 10 jq -e '.type == "qualification_result" and .code == "ok"' "$admit_file" >/dev/null 2>&1 || return 1
  lease_id=$(timeout 10 jq -r '.attempt_id // .lease_id // empty' "$admit_file")
  [[ $lease_id =~ ^[0-9a-f]{32}$ && $lease_id != 00000000000000000000000000000000 ]] || return 1
  lease_json=$lease_root/$lease_id/lease.json
  for _ in {1..40}; do timeout 10 "${SUDO[@]}" test -r "$lease_json" && break; timeout 2 sleep 0.25; done
  timeout 10 "${SUDO[@]}" test -r "$lease_json" || return 1
  printf '%s' "$lease_id"
}

check_reconcile_and_no_reuse() {
  local target=$1 old_lease=$2 old_dir=$lease_root/$2 old_workspace reconcile new_lease new_workspace
  reconcile=$old_dir/reconcile.json
  for _ in {1..120}; do [[ -r $reconcile ]] && break; timeout 2 sleep 0.25; done
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$reconcile" "$out_dir/reconcile-$target.json" 2>/dev/null || :
  evidence_files+=("$TEST_ID/reconcile-$target.json")
  old_workspace=$(timeout 10 "${SUDO[@]}" jq -r '.workspace_dir // empty' "$old_dir/lease.json" 2>/dev/null || true)
  local reuse_rc=0
  new_lease=$(admit_slowpoke "reuse-$target") || reuse_rc=$?
  if ((reuse_rc != 0)); then
    if ((reuse_rc == 3)); then record "$target" not_runnable "The fixed root-authored reuse-$target case is unavailable or unsafe"; else record "$target" fail "$target crash did not permit a controlled post-reconciliation admission"; fi
    return
  fi
  new_workspace=$(timeout 10 "${SUDO[@]}" jq -r '.workspace_dir // empty' "$lease_root/$new_lease/lease.json" 2>/dev/null || true)
  evidence_files+=("$TEST_ID/admit-reuse-$target.json" "$TEST_ID/admit-reuse-$target.stderr")
  if timeout 10 jq -e '(.emptied == true or .quarantined == true) and (.before_reuse == true)' "$out_dir/reconcile-$target.json" >/dev/null 2>&1 \
    && [[ $new_lease != "$old_lease" && -n $old_workspace && -n $new_workspace && $new_workspace != "$old_workspace" ]]; then
    record "$target" pass "$target crash produced empty-or-quarantine reconciliation and a distinct replacement lease/workspace"
  else
    record "$target" fail "$target crash lacked before-reuse reconciliation or reused the prior lease/workspace"
  fi
}

check_adapter_recovery() {
  local target=$1 old_lease old_dir old_workspace reconcile new_lease new_workspace
  local admit_rc=0 reuse_rc=0
  old_lease=$(admit_slowpoke "$target") || admit_rc=$?
  if ((admit_rc != 0)); then
    record "$target" fail "The fixed root-authored $target recovery case is unavailable or did not publish its lease"
    return
  fi
  evidence_files+=("$TEST_ID/admit-$target.json" "$TEST_ID/admit-$target.stderr")

  old_dir=$lease_root/$old_lease
  reconcile=$old_dir/reconcile.json
  for _ in {1..120}; do
    timeout 10 "${SUDO[@]}" test -r "$reconcile" && break
    timeout 2 sleep 0.25
  done
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$reconcile" "$out_dir/reconcile-$target.json" 2>/dev/null || :
  evidence_files+=("$TEST_ID/reconcile-$target.json")
  if [[ ! -s $out_dir/reconcile-$target.json ]]; then
    record "$target" fail "$target did not publish recovery reconciliation evidence"
    return
  fi

  old_workspace=$(timeout 10 "${SUDO[@]}" jq -r '.workspace_dir // empty' "$old_dir/lease.json" 2>/dev/null || true)
  new_lease=$(admit_slowpoke "reuse-$target") || reuse_rc=$?
  if ((reuse_rc != 0)); then
    record "$target" fail "The fixed root-authored reuse-$target case is unavailable after recovery"
    return
  fi
  evidence_files+=("$TEST_ID/admit-reuse-$target.json" "$TEST_ID/admit-reuse-$target.stderr")
  new_workspace=$(timeout 10 "${SUDO[@]}" jq -r '.workspace_dir // empty' "$lease_root/$new_lease/lease.json" 2>/dev/null || true)

  if timeout 10 jq -e --arg target "$target" \
    --arg old_lease "$old_lease" --arg new_lease "$new_lease" \
    --arg old_workspace "$old_workspace" --arg new_workspace "$new_workspace" \
    -f "$recovery_contract" "$out_dir/reconcile-$target.json" >/dev/null 2>&1; then
    record "$target" pass "$target published clean before-reuse recovery and a distinct replacement lease/workspace"
  else
    record "$target" fail "$target lacked its required clean resource recovery or reused the prior lease/workspace"
  fi
}

kill_scoped_process() {
  local target=$1 pattern=$2 lease_id lease_json cgroup_path cgroup_dir lease_unit pid='' comm
  local admit_rc=0
  lease_id=$(admit_slowpoke "$target") || admit_rc=$?
  if ((admit_rc != 0)); then
    if ((admit_rc == 3)); then record "$target" not_runnable "The fixed root-authored $target case is unavailable or unsafe"; else record "$target" fail "Could not admit the $target crash attempt"; fi
    return
  fi
  evidence_files+=("$TEST_ID/admit-$target.json" "$TEST_ID/admit-$target.stderr")
  lease_json=$lease_root/$lease_id/lease.json
  cgroup_path=$(timeout 10 "${SUDO[@]}" jq -r '.cgroup_path // empty' "$lease_json")
  lease_unit=$(timeout 10 "${SUDO[@]}" jq -r '.lease_unit // empty' "$lease_json")
  if [[ $cgroup_path != /buzzci.slice/* || -z $lease_unit ]]; then record "$target" fail "Lease $lease_id lacks a confined cgroup_path or exact lease_unit"; return; fi
  cgroup_dir=/sys/fs/cgroup/${cgroup_path#/}
  for _ in {1..40}; do
    while IFS= read -r candidate_pid; do
      [[ $candidate_pid =~ ^[0-9]+$ ]] || continue
      comm=$(timeout 5 "${SUDO[@]}" cat "/proc/$candidate_pid/comm" 2>/dev/null || true)
      if [[ $comm == *"$pattern"* ]]; then pid=$candidate_pid; break; fi
    done < <(timeout 10 "${SUDO[@]}" cat "$cgroup_dir/cgroup.procs" 2>/dev/null || true)
    [[ -n $pid ]] && break
    timeout 2 sleep 0.25
  done
  if [[ -z $pid ]]; then record "$target" fail "No $pattern process appeared in lease $lease_id cgroup.procs"; return; fi
  printf 'lease_id=%s pid=%s comm=%s\n' "$lease_id" "$pid" "$comm" >"$out_dir/killed-$target.txt"
  evidence_files+=("$TEST_ID/killed-$target.txt")
  timeout 10 "${SUDO[@]}" kill -KILL "$pid"
  check_reconcile_and_no_reuse "$target" "$lease_id"
}

kill_scoped_process act act
kill_scoped_process podman podman
kill_scoped_process proxy proxy
kill_scoped_process materializer material

broker_rc=0
broker_lease=$(admit_slowpoke broker) || broker_rc=$?
if ((broker_rc == 0)); then
  evidence_files+=("$TEST_ID/admit-broker.json" "$TEST_ID/admit-broker.stderr")
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" systemctl restart "$broker_unit"
  check_reconcile_and_no_reuse broker "$broker_lease"
else
  if ((broker_rc == 3)); then record broker not_runnable 'The fixed root-authored broker case is unavailable or unsafe'; else record broker fail 'Could not admit the broker-crash attempt'; fi
fi

host_rc=0
host_lease=$(admit_slowpoke simulated_host_crash) || host_rc=$?
if ((host_rc == 0)); then
  evidence_files+=("$TEST_ID/admit-simulated_host_crash.json" "$TEST_ID/admit-simulated_host_crash.stderr")
  host_unit=$(timeout 10 "${SUDO[@]}" jq -r '.lease_unit // empty' "$lease_root/$host_lease/lease.json")
  if [[ -n $host_unit ]]; then
    timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" systemctl kill --kill-whom=all --signal=KILL "$host_unit"
    timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" systemctl restart "$broker_unit"
    check_reconcile_and_no_reuse simulated_host_crash "$host_lease"
  else
    record simulated_host_crash fail 'The simulated host-crash lease did not publish its exact lease_unit'
  fi
else
  if ((host_rc == 3)); then record simulated_host_crash not_runnable 'The fixed root-authored simulated-host-crash case is unavailable or unsafe'; else record simulated_host_crash fail 'Could not admit the simulated host-crash attempt'; fi
fi

for target in "${recovery_targets[@]}"; do
  check_adapter_recovery "$target"
done
emit
exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || [[ " ${statuses[*]} " == *' not_runnable '* ]] && printf 3 || printf 0 )"
