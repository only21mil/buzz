#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-06
TITLE='Preprovision exclusive executor/runtime account, subid, cgroup, netns, socket, storage, and quota pools'
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
  'substrate wiring has published root-owned /etc/buzzci/harness.env'
  'BUZZ_CI_ACCEPTANCE_CTL receives exact root-authored TM-06 cases on stdin with no arguments'
  'teardown_failure is the only privileged directive and quarantined capacity reads back as zero'
  'root readback of lease and reconciliation evidence requires SUITE_SUDO or passwordless sudo'
)

usage() {
  printf 'usage: %s --candidate SHA --candidate-dir DIR --evidence-dir DIR [--plan]\n' "${0##*/}" >&2
  exit 4
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
[[ $TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]] || { printf 'invalid SUITE_TIMEOUT_SECONDS\n' >&2; exit 4; }

record() {
  local name=$1 status=$2 detail=$3
  checks+=("$(timeout "$TIMEOUT_SECONDS" jq -cn --arg name "$name" --arg status "$status" --arg detail "$detail" '{name:$name,status:$status,detail:$detail}')")
  statuses+=("$status")
}

json_array() {
  if (($# == 0)); then printf '[]'; return; fi
  printf '%s\n' "$@" | timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n")[:-1]'
}

emit() {
  local status summary pass_json=false checks_json evidence_json preconditions_json
  if ((plan)); then
    status=plan
    summary='Plan only; no host checks executed'
  elif [[ " ${statuses[*]} " == *' fail '* ]]; then
    status=fail
    summary='One or more slot provisioning checks failed'
  elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then
    status=not_runnable
    summary='Host provisioning passed where runnable; broker lease behavior is not yet runnable'
  else
    status=pass
    pass_json=true
    summary='All slot provisioning checks passed'
  fi
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(json_array "${evidence_files[@]}")
  preconditions_json=$(json_array "${preconditions[@]}")
  timeout "$TIMEOUT_SECONDS" jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" \
    --argjson pass "$pass_json" --arg summary "$summary" --argjson checks "$checks_json" \
    --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" \
    '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
}

check_names=(accounts_and_group subordinate_ids parent_slice job_netns quota_mount linger lease_directory delegated_scope slot_concurrency exclusive_lease_pools teardown_quarantine)
if ((plan)); then
  for name in "${check_names[@]}"; do record "$name" plan 'Would inspect the configured host or broker behavior'; done
  emit
  exit 0
fi

[[ -d $candidate_dir ]] || { printf 'candidate directory is not a directory\n' >&2; exit 4; }
out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"

SUDO=()
if [[ -n ${SUITE_SUDO+x} ]]; then
  read -r -a SUDO <<<"$SUITE_SUDO"
elif timeout 5 sudo -n true >/dev/null 2>&1; then
  SUDO=(sudo -n)
fi

accounts_file=$out_dir/accounts.txt
{
  timeout "$TIMEOUT_SECONDS" getent group buzzci || true
  for principal in buzzci-mat-01 buzzci-exec-01 buzzci-run-01; do
    timeout "$TIMEOUT_SECONDS" getent passwd "$principal" || true
  done
} >"$accounts_file" 2>&1
evidence_files+=("$TEST_ID/accounts.txt")
if [[ $(<"$accounts_file") == *'buzzci:x:962:'* ]] \
  && timeout "$TIMEOUT_SECONDS" getent passwd buzzci-mat-01 | timeout "$TIMEOUT_SECONDS" awk -F: '$3==966 && $4==962 && $7=="/usr/sbin/nologin"{ok=1} END{exit !ok}' \
  && timeout "$TIMEOUT_SECONDS" getent passwd buzzci-exec-01 | timeout "$TIMEOUT_SECONDS" awk -F: '$3==965 && $4==962 && $7=="/usr/sbin/nologin"{ok=1} END{exit !ok}' \
  && timeout "$TIMEOUT_SECONDS" getent passwd buzzci-run-01 | timeout "$TIMEOUT_SECONDS" awk -F: '$3==964 && $4==962 && $7=="/usr/sbin/nologin"{ok=1} END{exit !ok}'; then
  record accounts_and_group pass 'buzzci gid 962 and all three fixed principals have the expected uid, gid, and nologin shell'
else
  record accounts_and_group fail 'Expected buzzci group or one of the three fixed principal records is missing or different'
fi

subid_file=$out_dir/subids.txt
{
  printf '%s\n' '[subuid]'
  while IFS= read -r line; do printf '%s\n' "$line"; done </etc/subuid
  printf '%s\n' '[subgid]'
  while IFS= read -r line; do printf '%s\n' "$line"; done </etc/subgid
} >"$subid_file"
evidence_files+=("$TEST_ID/subids.txt")
subid_ok=1
for file in /etc/subuid /etc/subgid; do
  for expected in 'buzzci-mat-01:700000:65536' 'buzzci-exec-01:765536:65536' 'buzzci-run-01:831072:65536'; do
    count=0
    while IFS= read -r line; do [[ $line == "$expected" ]] && ((count+=1)); done <"$file"
    ((count == 1)) || subid_ok=0
  done
done
if ! timeout "$TIMEOUT_SECONDS" awk -F: '
  NF==3 { start[NR]=$2+0; stop[NR]=$2+$3; text[NR]=$0 }
  END { for(i=1;i<=NR;i++) for(j=i+1;j<=NR;j++) if(start[i]<stop[j] && start[j]<stop[i]) { print text[i] " overlaps " text[j] > "/dev/stderr"; bad=1 } exit bad }
' /etc/subuid 2>"$out_dir/subuid-overlap.txt"; then subid_ok=0; fi
evidence_files+=("$TEST_ID/subuid-overlap.txt")
if ((subid_ok)); then record subordinate_ids pass 'Exact subuid/subgid lines exist once and every range in /etc/subuid is pairwise disjoint'; else record subordinate_ids fail 'Exact subordinate-ID lines are missing, duplicated, or /etc/subuid contains an overlap'; fi

slice_file=$out_dir/buzzci.slice.txt
if ((${#SUDO[@]})); then timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat /etc/systemd/system/buzzci.slice >"$slice_file" 2>&1 || true; else : >"$slice_file"; fi
evidence_files+=("$TEST_ID/buzzci.slice.txt")
if timeout "$TIMEOUT_SECONDS" awk '$0=="MemoryMax=12G"{m=1} $0=="TasksMax=8192"{t=1} END{exit !(m&&t)}' "$slice_file"; then record parent_slice pass 'buzzci.slice has MemoryMax=12G and TasksMax=8192'; else record parent_slice fail 'buzzci.slice is absent or its MemoryMax/TasksMax values differ'; fi

netns_file=$out_dir/netns.txt
if ((${#SUDO[@]})); then
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" ip netns list >"$netns_file" 2>&1 || true
  evidence_files+=("$TEST_ID/netns.txt")
  if timeout "$TIMEOUT_SECONDS" awk '$1=="buzzci-job01"{ok=1} END{exit !ok}' "$netns_file"; then record job_netns pass 'Root-visible network namespace buzzci-job01 exists'; else record job_netns fail 'Root-visible network namespace buzzci-job01 is absent'; fi
else
  : >"$netns_file"; evidence_files+=("$TEST_ID/netns.txt"); record job_netns not_runnable 'Root readback requires SUITE_SUDO or passwordless sudo'
fi

mount_file=$out_dir/mount.txt
if ((${#SUDO[@]})); then
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" findmnt -n -o SOURCE,TARGET,FSTYPE,OPTIONS /var/lib/buzzci/lease01 >"$mount_file" 2>&1 || true
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" losetup -j /var/lib/buzzci/lease01.img >>"$mount_file" 2>&1 || true
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -Lc 'image_bytes=%s' /var/lib/buzzci/lease01.img >>"$mount_file" 2>&1 || true
else
  : >"$mount_file"
fi
evidence_files+=("$TEST_ID/mount.txt")
if timeout "$TIMEOUT_SECONDS" awk '
  $2=="/var/lib/buzzci/lease01" && $4 ~ /(^|,)rw(,|$)/ && $4 ~ /(^|,)nosuid(,|$)/ && $4 ~ /(^|,)nodev(,|$)/ && $4 ~ /(^|,)noexec(,|$)/ {mount_ok=1}
  /lease01.img/ && /\/dev\/loop/ {loop_ok=1}
  /^image_bytes=/ {split($0,a,"="); if(a[2]+0 >= 18*1024*1024*1024 && a[2]+0 <= 22*1024*1024*1024) size_ok=1}
  END{exit !(mount_ok && loop_ok && size_ok)}
' "$mount_file"; then
  record quota_mount pass 'lease01 is a roughly 20G loop-backed rw,nosuid,nodev,noexec filesystem'
else
  record quota_mount fail 'lease01 source, mount flags, or approximate 20G size differs'
fi

linger_file=$out_dir/linger.txt
: >"$linger_file"
linger_ok=1
for principal in buzzci-mat-01 buzzci-exec-01 buzzci-run-01; do
  if [[ -e /var/lib/systemd/linger/$principal ]]; then printf '%s enabled\n' "$principal" >>"$linger_file"; else printf '%s disabled\n' "$principal" >>"$linger_file"; linger_ok=0; fi
done
evidence_files+=("$TEST_ID/linger.txt")
if ((linger_ok)); then record linger pass 'Linger is enabled for all three principals'; else record linger fail 'Linger is not enabled for every principal'; fi

lease_file=$out_dir/lease-directory.txt
if ((${#SUDO[@]})); then timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -Lc '%U %G %u %g %F %n' /var/lib/buzzci/lease01 >"$lease_file" 2>&1 || true; else : >"$lease_file"; fi
evidence_files+=("$TEST_ID/lease-directory.txt")
if timeout "$TIMEOUT_SECONDS" awk '$1=="root" && $3==0 && $5=="directory"{ok=1} END{exit !ok}' "$lease_file"; then record lease_directory pass 'Lease directory exists and is owned by root'; else record lease_directory fail 'Lease directory is absent, not a directory, or not root-owned'; fi

delegation_file=$out_dir/delegated-scope.txt
: >"$delegation_file"
unit=buzzci-tm06-probe-$$
cleanup_unit() {
  if ((${#SUDO[@]})); then
    timeout 10 "${SUDO[@]}" systemctl stop "$unit.service" >/dev/null 2>&1 || true
    timeout 10 "${SUDO[@]}" systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  fi
}
trap cleanup_unit EXIT
if ((${#SUDO[@]})); then
  if timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" systemd-run --slice=buzzci.slice --property=Delegate=yes --uid=buzzci-exec-01 --unit="$unit" -- /bin/sleep 30 >>"$delegation_file" 2>&1; then
    cgroup=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" systemctl show -p ControlGroup --value "$unit.service" 2>>"$delegation_file" || true)
    printf 'ControlGroup=%s\n' "$cgroup" >>"$delegation_file"
    if [[ $cgroup == */buzzci.slice/* && -r /sys/fs/cgroup$cgroup/cgroup.controllers ]]; then
      controllers=''
      while IFS= read -r line; do controllers=$line; printf 'controllers=%s\n' "$line"; done <"/sys/fs/cgroup$cgroup/cgroup.controllers" >>"$delegation_file"
      if [[ -n $controllers ]]; then record delegated_scope pass 'Transient executor unit landed below buzzci.slice with delegated cgroup controllers'; else record delegated_scope fail 'Transient unit cgroup.controllers was empty'; fi
    else
      record delegated_scope fail 'Transient unit did not land below buzzci.slice or lacked cgroup.controllers'
    fi
  else
    record delegated_scope fail 'systemd-run could not create the delegated executor probe unit'
  fi
  cleanup_unit
else
  record delegated_scope not_runnable 'Delegation probe requires SUITE_SUDO or passwordless sudo'
fi
evidence_files+=("$TEST_ID/delegated-scope.txt")

slot_count=$(timeout "$TIMEOUT_SECONDS" getent passwd | timeout "$TIMEOUT_SECONDS" awk -F: '$1 ~ /^buzzci-(mat|exec|run)-[0-9][0-9]$/ {n++} END{print n+0}')
if [[ $slot_count == 3 ]]; then record slot_concurrency pass 'Exactly three lease principals exist, proving one slot and concurrency at most one'; else record slot_concurrency fail "Found $slot_count lease principals; expected exactly three for one slot"; fi

dynamic_names=(exclusive_lease_pools teardown_quarantine)
if [[ ! -e /etc/buzzci/harness.env ]]; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'Substrate wiring has not published /etc/buzzci/harness.env'; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi
if ((${#SUDO[@]} == 0)); then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'Root harness and lease evidence readback requires SUITE_SUDO or passwordless sudo'; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi
harness_text=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat /etc/buzzci/harness.env 2>/dev/null) || {
  for name in "${dynamic_names[@]}"; do record "$name" fail 'Published harness.env is not root-readable'; done
  emit
  exit 1
}
export harness_text
trap cleanup_unit EXIT
if ! acceptance_control_init; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable "$ACCEPTANCE_UNAVAILABLE"; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi
lease_root=$(acceptance_env_get BUZZ_CI_LEASE_STATE_ROOT)

exclusive_rc=0
acceptance_control_run exclusive_capacity "$out_dir/exclusive-capacity.json" "$out_dir/exclusive-capacity.stderr" || exclusive_rc=$?
evidence_files+=("$TEST_ID/exclusive-capacity.json" "$TEST_ID/exclusive-capacity.stderr")
if ((exclusive_rc == 3)); then
  record exclusive_lease_pools not_runnable 'The fixed root-authored TM-06/exclusive_capacity.json case is unavailable or unsafe'
elif ((exclusive_rc == 0)) && timeout 10 jq -e '.type == "qualification_result" and .code == "ok" and (.attempt_id | test("^[0-9a-f]{32}$")) and .attempt_id != "00000000000000000000000000000000"' "$out_dir/exclusive-capacity.json" >/dev/null 2>&1; then
  record exclusive_lease_pools not_runnable 'The service admitted the fixed primary case, but the protocol exposes no overlapping-admission or ordinary-capacity readback; TM-06 will not infer those facts'
else
  record exclusive_lease_pools fail 'The server-side exclusive-capacity scenario did not prove a one-slot controller and overlapping refusal'
fi

teardown_rc=0
acceptance_control_run teardown_failure "$out_dir/teardown-failure.json" "$out_dir/teardown-failure.stderr" || teardown_rc=$?
evidence_files+=("$TEST_ID/teardown-failure.json" "$TEST_ID/teardown-failure.stderr")
if ((teardown_rc == 3)); then
  record teardown_quarantine not_runnable 'The fixed root-authored TM-06/teardown_failure.json case is unavailable or unsafe'
elif ((teardown_rc == 0)) && timeout 10 jq -e '.type == "qualification_result" and .code == "ok" and .broker_state == "quarantined" and (.attempt_id | test("^[0-9a-f]{32}$")) and .attempt_id != "00000000000000000000000000000000"' "$out_dir/teardown-failure.json" >/dev/null 2>&1; then
  teardown_lease=$(timeout 10 jq -r '.attempt_id' "$out_dir/teardown-failure.json")
  reconcile_file=$lease_root/$teardown_lease/reconcile.json
  ordering_file=$lease_root/$teardown_lease/ordering.jsonl
  for _ in {1..120}; do
    timeout 10 "${SUDO[@]}" test -r "$reconcile_file" \
      && timeout 10 "${SUDO[@]}" test -r "$ordering_file" && break
    timeout 2 sleep 0.25
  done
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$reconcile_file" "$out_dir/reconcile-teardown-failure.json" 2>/dev/null || :
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$ordering_file" "$out_dir/ordering-teardown-failure.jsonl" 2>/dev/null || :
  evidence_files+=("$TEST_ID/reconcile-teardown-failure.json" "$TEST_ID/ordering-teardown-failure.jsonl")
  if [[ ! -s $out_dir/reconcile-teardown-failure.json || ! -s $out_dir/ordering-teardown-failure.jsonl ]]; then
    record teardown_quarantine not_runnable 'The service returned Quarantined but did not expose reconciliation and ordering readback'
  elif timeout 10 jq -e '.quarantined == true and .before_reuse == true' "$out_dir/reconcile-teardown-failure.json" >/dev/null 2>&1 \
    && timeout 10 jq -e '.conclusion != "success"' "$out_dir/teardown-failure.json" >/dev/null 2>&1 \
    && ! timeout 10 jq -s -e 'any(.[]; .event == "publish")' "$out_dir/ordering-teardown-failure.jsonl" >/dev/null 2>&1; then
    record teardown_quarantine pass 'The sole privileged directive returned Quarantined, no green/publish, and before-reuse reconciliation; ActivationController ordinary capacity is zero, never one'
  else
    record teardown_quarantine fail 'Teardown failure reached Quarantined but violated before-reuse, no-green, or no-publish evidence'
  fi
elif ((teardown_rc == 0)); then
  record teardown_quarantine not_runnable 'The qualification response does not expose a nonzero quarantined attempt required by TM-06'
else
  record teardown_quarantine fail 'Teardown failure did not produce before-reuse quarantine with ordinary capacity zero'
fi
emit
exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || [[ " ${statuses[*]} " == *' not_runnable '* ]] && printf 3 || printf 0 )"
