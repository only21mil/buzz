#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-06
TITLE='Preprovision exclusive executor/runtime account, subid, cgroup, netns, socket, storage, and quota pools'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
candidate=''
candidate_dir=''
evidence_dir=''
plan=0
checks=()
statuses=()
evidence_files=()
preconditions=(
  'substrate wiring has published root-owned /etc/buzzci/harness.env'
  'the published runner control supports admit, get, cancel, capacity readback, and --fault teardown_failure'
  'the accepted fixture repository exposes ci-acceptance/probe-repo/workflow.yml jobs ok, flaky, and slowpoke'
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
env_get() {
  local key=$1
  printf '%s\n' "$harness_text" | timeout "$TIMEOUT_SECONDS" awk -F= -v key="$key" '$1==key{print substr($0,index($0,"=")+1); exit}'
}
runner_ctl=$(env_get BUZZ_CI_RUNNER_CTL)
lease_root=$(env_get BUZZ_CI_LEASE_STATE_ROOT)
fixture_repo=$(env_get BUZZ_CI_FIXTURE_REPO)
if [[ ! -x $runner_ctl || ! -d $lease_root || -z $fixture_repo ]]; then
  for name in "${dynamic_names[@]}"; do record "$name" fail 'Published runner control, lease root, or fixture coordinate is missing'; done
  emit
  exit 1
fi

active_lease=''
cleanup_lease() {
  if [[ $active_lease =~ ^[A-Za-z0-9._-]+$ ]]; then
    timeout 10 "$runner_ctl" cancel --lease "$active_lease" >/dev/null 2>&1 || true
  fi
}
trap 'cleanup_lease; cleanup_unit' EXIT

capacity_before=$out_dir/capacity-before.json
if timeout "$TIMEOUT_SECONDS" "$runner_ctl" get --capacity >"$capacity_before" 2>"$out_dir/capacity-before.stderr"; then
  concurrency_limit=$(timeout 10 jq -r '.concurrency_limit // 0' "$capacity_before")
else
  concurrency_limit=0
fi
evidence_files+=("$TEST_ID/capacity-before.json" "$TEST_ID/capacity-before.stderr")

exclusive_ok=1
: >"$out_dir/admit-exclusive.json"
: >"$out_dir/admit-exclusive.stderr"
: >"$out_dir/admit-while-leased.json"
: >"$out_dir/admit-while-leased.stderr"
: >"$out_dir/final-exclusive.json"
: >"$out_dir/final-exclusive.stderr"
if [[ $concurrency_limit != 1 ]]; then
  exclusive_ok=0
elif timeout "$TIMEOUT_SECONDS" "$runner_ctl" admit --repo "$fixture_repo" --sha "$candidate" \
    --workflow ci-acceptance/probe-repo/workflow.yml --job slowpoke --attempt 1 >"$out_dir/admit-exclusive.json" 2>"$out_dir/admit-exclusive.stderr"; then
  active_lease=$(timeout 10 jq -r '.lease_id // empty' "$out_dir/admit-exclusive.json")
  [[ $active_lease =~ ^[A-Za-z0-9._-]+$ ]] || exclusive_ok=0
else
  exclusive_ok=0
fi
evidence_files+=("$TEST_ID/admit-exclusive.json" "$TEST_ID/admit-exclusive.stderr")
second_rc=0
if ((exclusive_ok)); then
  timeout "$TIMEOUT_SECONDS" "$runner_ctl" admit --repo "$fixture_repo" --sha "$candidate" \
    --workflow ci-acceptance/probe-repo/workflow.yml --job ok --attempt 1 >"$out_dir/admit-while-leased.json" 2>"$out_dir/admit-while-leased.stderr" || second_rc=$?
  if ((second_rc == 0)) || ! {
    timeout 10 jq -e '.error == "concurrency_limited"' "$out_dir/admit-while-leased.json" >/dev/null 2>&1 \
      || timeout 10 jq -e '.error == "concurrency_limited"' "$out_dir/admit-while-leased.stderr" >/dev/null 2>&1
  }; then
    exclusive_ok=0
  fi
fi
evidence_files+=("$TEST_ID/admit-while-leased.json" "$TEST_ID/admit-while-leased.stderr")
cleanup_lease
exclusive_terminal=0
if [[ -s $out_dir/admit-exclusive.json ]]; then
  exclusive_lease=$(timeout 10 jq -r '.lease_id // empty' "$out_dir/admit-exclusive.json")
  for _ in {1..120}; do
    if timeout 10 "$runner_ctl" get --lease "$exclusive_lease" >"$out_dir/final-exclusive.json" 2>"$out_dir/final-exclusive.stderr" \
      && timeout 10 jq -e '.state == "terminal" or .terminal == true' "$out_dir/final-exclusive.json" >/dev/null 2>&1; then
      exclusive_terminal=1
      break
    fi
    timeout 2 sleep 0.25
  done
fi
evidence_files+=("$TEST_ID/final-exclusive.json" "$TEST_ID/final-exclusive.stderr")
active_lease=''
((exclusive_terminal)) || exclusive_ok=0
if ((exclusive_ok)); then
  record exclusive_lease_pools pass 'Capacity is fixed at one, concurrent admission was refused with concurrency_limited, and cancellation reached terminal state'
else
  record exclusive_lease_pools fail 'Capacity was not one, the first lease failed, concurrent admission was not refused, or cancellation never reached terminal state'
fi

help_file=$out_dir/runner-help.txt
timeout "$TIMEOUT_SECONDS" "$runner_ctl" admit --help >"$help_file" 2>&1 || true
evidence_files+=("$TEST_ID/runner-help.txt")
if ((exclusive_terminal == 0)); then
  record teardown_quarantine not_runnable 'The prior live lease did not reach terminal state, so the teardown-failure probe was not started'
elif ! timeout 10 grep -Fq -- '--fault' "$help_file"; then
  record teardown_quarantine not_runnable 'The published runner control offers no forced teardown-failure operation'
else
  fault_ok=1
  : >"$out_dir/final-teardown-failure.json"
  : >"$out_dir/final-teardown-failure.stderr"
  : >"$out_dir/reconcile-teardown-failure.json"
  : >"$out_dir/capacity-after-quarantine.json"
  : >"$out_dir/capacity-after-quarantine.stderr"
  if timeout "$TIMEOUT_SECONDS" "$runner_ctl" admit --repo "$fixture_repo" --sha "$candidate" \
      --workflow ci-acceptance/probe-repo/workflow.yml --job flaky --attempt 1 --fault teardown_failure \
      >"$out_dir/admit-teardown-failure.json" 2>"$out_dir/admit-teardown-failure.stderr"; then
    fault_lease=$(timeout 10 jq -r '.lease_id // empty' "$out_dir/admit-teardown-failure.json")
    [[ $fault_lease =~ ^[A-Za-z0-9._-]+$ ]] || fault_ok=0
  else
    fault_ok=0
    fault_lease=''
  fi
  evidence_files+=("$TEST_ID/admit-teardown-failure.json" "$TEST_ID/admit-teardown-failure.stderr")
  if ((fault_ok)); then
    for _ in {1..120}; do
      if timeout 10 "$runner_ctl" get --lease "$fault_lease" >"$out_dir/final-teardown-failure.json" 2>"$out_dir/final-teardown-failure.stderr" \
        && timeout 10 jq -e '.state == "terminal" or .terminal == true' "$out_dir/final-teardown-failure.json" >/dev/null 2>&1; then
        break
      fi
      timeout 2 sleep 0.25
    done
    reconcile=$lease_root/$fault_lease/reconcile.json
    for _ in {1..120}; do
      if timeout 10 "${SUDO[@]}" test -r "$reconcile"; then break; fi
      timeout 2 sleep 0.25
    done
    timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat "$reconcile" >"$out_dir/reconcile-teardown-failure.json" 2>/dev/null || fault_ok=0
    timeout "$TIMEOUT_SECONDS" "$runner_ctl" get --capacity >"$out_dir/capacity-after-quarantine.json" 2>"$out_dir/capacity-after-quarantine.stderr" || fault_ok=0
    timeout 10 jq -e '.state == "terminal" or .terminal == true' "$out_dir/final-teardown-failure.json" >/dev/null 2>&1 || fault_ok=0
  fi
  evidence_files+=("$TEST_ID/final-teardown-failure.json" "$TEST_ID/final-teardown-failure.stderr" "$TEST_ID/reconcile-teardown-failure.json" "$TEST_ID/capacity-after-quarantine.json" "$TEST_ID/capacity-after-quarantine.stderr")
  if ((fault_ok)) \
    && timeout 10 jq -e '.quarantined == true and .before_reuse == true and .reuse_allowed == false' "$out_dir/reconcile-teardown-failure.json" >/dev/null \
    && timeout 10 jq -e '.concurrency_limit == 1' "$out_dir/capacity-after-quarantine.json" >/dev/null; then
    record teardown_quarantine pass 'Forced incomplete teardown published a before-reuse quarantine with reuse disallowed, alongside live fixed-capacity readback'
  else
    record teardown_quarantine fail 'Forced incomplete teardown lacked terminal quarantine evidence, before-reuse proof, reuse refusal, or fixed-capacity readback'
  fi
fi
emit
exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || [[ " ${statuses[*]} " == *' not_runnable '* ]] && printf 3 || printf 0 )"
