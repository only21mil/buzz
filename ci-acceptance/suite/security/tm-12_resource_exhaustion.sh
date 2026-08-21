#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-12
TITLE='Exhaust CPU, RAM, PIDs, disk, log bytes/rate, wall time, and artifact count/size'
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
  'BUZZ_CI_ACCEPTANCE_CTL receives one exact root-authored case per exhaustion job on stdin'
  'root readback of lease state and cgroup v2 requires SUITE_SUDO or passwordless sudo'
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

string_array() {
  if (($# == 0)); then printf '[]'; else printf '%s\n' "$@" | timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n")[:-1]'; fi
}

emit() {
  local status summary pass_json=false checks_json evidence_json preconditions_json
  if ((plan)); then status=plan; summary='Plan only; no checks executed'
  elif [[ " ${statuses[*]} " == *' fail '* ]]; then status=fail; summary='At least one resource-exhaustion check failed'
  elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then status=not_runnable; summary='Resource-exhaustion checks need the published isolation wiring'
  else status=pass; pass_json=true; summary='Every exhaustion case stopped within bounds and the host remained healthy'
  fi
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(string_array "${evidence_files[@]}")
  preconditions_json=$(string_array "${preconditions[@]}")
  timeout "$TIMEOUT_SECONDS" jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" \
    --argjson pass "$pass_json" --arg summary "$summary" --argjson checks "$checks_json" \
    --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" \
    '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
}

static_checks=(fixture_scripts_parse every_job_has_outer_timeout)
jobs=(cpu-burn memory-balloon pid-fork-storm disk-fill log-flood wall-time-overrun artifact-overrun)
if ((plan)); then
  for name in "${static_checks[@]}"; do record "$name" plan 'Would validate the checked-in exhaustion fixture'; done
  for job in "${jobs[@]}"; do record "${job//-/_}" plan "Would admit $job and verify cgroup limits, deadline, ordering, and teardown"; done
  record host_health plan 'Would compare host load, free memory, and systemd state before and after all cases'
  emit
  exit 0
fi

[[ -d $candidate_dir ]] || { printf 'candidate directory is not a directory\n' >&2; exit 4; }
out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"
fixture=$candidate_dir/ci-acceptance/suite/fixtures/tm-12-exhaustion-repo
syntax_log=$out_dir/fixture-syntax.txt
if [[ -d $fixture/jobs ]] && timeout "$TIMEOUT_SECONDS" bash -n "$fixture"/jobs/*.sh >"$syntax_log" 2>&1; then
  record fixture_scripts_parse pass 'All seven exhaustion job scripts pass bash -n'
else
  record fixture_scripts_parse fail 'The exhaustion fixture is missing or a job script fails bash -n'
fi
evidence_files+=("$TEST_ID/fixture-syntax.txt")

timeout_log=$out_dir/fixture-timeouts.txt
: >"$timeout_log"
timeout_ok=1
for script in "$fixture"/jobs/*.sh; do
  if [[ -f $script ]] && timeout "$TIMEOUT_SECONDS" awk 'BEGIN{ok=0} /^[[:space:]]*timeout[[:space:]]+[0-9]+([[:space:]]|$)/{ok=1} END{exit !ok}' "$script"; then
    printf '%s outer-timeout=yes\n' "${script##*/}" >>"$timeout_log"
  else
    printf '%s outer-timeout=no\n' "${script##*/}" >>"$timeout_log"
    timeout_ok=0
  fi
done
if ((timeout_ok)) && [[ $(timeout "$TIMEOUT_SECONDS" find "$fixture/jobs" -maxdepth 1 -type f -name '*.sh' -print | timeout "$TIMEOUT_SECONDS" wc -l) -eq 7 ]]; then
  record every_job_has_outer_timeout pass 'Every exhaustion job has a literal outer timeout and exactly seven job scripts exist'
else
  record every_job_has_outer_timeout fail 'One or more exhaustion jobs lacks a literal outer timeout or the fixture job count differs'
fi
evidence_files+=("$TEST_ID/fixture-timeouts.txt")

dynamic_names=()
for job in "${jobs[@]}"; do dynamic_names+=("${job//-/_}"); done
dynamic_names+=(host_health)
if [[ ! -e /etc/buzzci/harness.env ]]; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi

SUDO=()
if [[ -n ${SUITE_SUDO+x} ]]; then read -r -a SUDO <<<"$SUITE_SUDO"
elif timeout 5 sudo -n true >/dev/null 2>&1; then SUDO=(sudo -n)
fi
if ((${#SUDO[@]} == 0)) && [[ ! -r /etc/buzzci/harness.env ]]; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'harness.env unreadable without sudo'; done
  emit
  exit 3
fi
if ((${#SUDO[@]} == 0)); then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'Root lease and cgroup readback requires SUITE_SUDO or passwordless sudo'; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi

harness_text=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat /etc/buzzci/harness.env 2>/dev/null) || { for name in "${dynamic_names[@]}"; do record "$name" fail 'Published harness.env is not root-readable'; done; emit; exit 1; }
export harness_text
lease_root=$(acceptance_env_get BUZZ_CI_LEASE_STATE_ROOT)
if ! acceptance_control_init; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable "$ACCEPTANCE_UNAVAILABLE"; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi
if [[ ! -d $lease_root ]]; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'harness.env lacks a readable BUZZ_CI_LEASE_STATE_ROOT'; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi

host_before=$out_dir/host-before.txt
{ timeout 10 cat /proc/loadavg; timeout 10 free -b; timeout 10 systemctl is-system-running || true; } >"$host_before" 2>&1
evidence_files+=("$TEST_ID/host-before.txt")

run_job() {
  local job=$1 safe=${1//-/_} admit_file lease_id lease_dir lease_json cgroup_path cgroup_dir rc=0
  admit_file=$out_dir/admit-$job.json
  acceptance_control_run "$job" "$admit_file" "$out_dir/admit-$job.stderr" || rc=$?
  evidence_files+=("$TEST_ID/admit-$job.json" "$TEST_ID/admit-$job.stderr")
  if ((rc == 3)); then
    record "$safe" not_runnable "The fixed root-authored $TEST_ID/$job.json case is unavailable or unsafe"
    return
  elif ((rc != 0)); then
    record "$safe" fail "The authenticated $job case was refused"
    return
  fi
  lease_id=$(timeout "$TIMEOUT_SECONDS" jq -r '.attempt_id // .lease_id // empty' "$admit_file")
  if [[ ! $lease_id =~ ^[A-Za-z0-9._-]+$ ]]; then record "$safe" not_runnable "Qualification response for $job exposes no safe attempt identifier"; return; fi
  lease_dir=$lease_root/$lease_id
  lease_json=$lease_dir/lease.json
  for _ in {1..20}; do timeout 10 "${SUDO[@]}" test -r "$lease_json" && break; timeout 2 sleep 0.25; done
  if ! timeout 10 "${SUDO[@]}" test -r "$lease_json"; then record "$safe" not_runnable "Attempt $lease_id did not expose lease.json readback"; return; fi
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$lease_json" "$out_dir/lease-$job.json"
  evidence_files+=("$TEST_ID/lease-$job.json")
  cgroup_path=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" jq -r '.cgroup_path // empty' "$lease_json")
  cgroup_dir=/sys/fs/cgroup/${cgroup_path#/}
  limits_file=$out_dir/cgroup-$job.txt
  : >"$limits_file"
  for field in cpu.max memory.max memory.swap.max pids.max memory.events; do
    if [[ -r $cgroup_dir/$field ]]; then printf '%s=' "$field" >>"$limits_file"; timeout 10 "${SUDO[@]}" cat "$cgroup_dir/$field" >>"$limits_file"; fi
  done
  evidence_files+=("$TEST_ID/cgroup-$job.txt")
  for _ in {1..80}; do
    if timeout 10 "${SUDO[@]}" test -r "$lease_dir/final.json"; then
      timeout 10 "${SUDO[@]}" cp -- "$lease_dir/final.json" "$out_dir/final-$job.json" 2>"$out_dir/final-$job.stderr" || :
      break
    fi
    if [[ $job == memory-balloon && -r $cgroup_dir/memory.events ]]; then timeout 10 "${SUDO[@]}" cat "$cgroup_dir/memory.events" >"$out_dir/memory-events-$job.txt"; fi
    timeout 2 sleep 0.25
  done
  evidence_files+=("$TEST_ID/final-$job.json" "$TEST_ID/final-$job.stderr")
  if [[ -r $cgroup_dir/cgroup.procs ]]; then timeout 10 "${SUDO[@]}" cat "$cgroup_dir/cgroup.procs" >"$out_dir/cgroup-procs-$job.txt"; else : >"$out_dir/cgroup-procs-$job.txt"; fi
  evidence_files+=("$TEST_ID/cgroup-procs-$job.txt")
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$lease_dir/ordering.jsonl" "$out_dir/ordering-$job.jsonl" 2>/dev/null || :
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$lease_dir/teardown.json" "$out_dir/teardown-$job.json" 2>/dev/null || :
  evidence_files+=("$TEST_ID/ordering-$job.jsonl" "$TEST_ID/teardown-$job.json")
  local limits_ok=0 terminal_ok=0 ordering_ok=0 teardown_ok=0 oom_ok=1 reason_ok=0 expected_reason
  if timeout 10 awk -F= '$1=="cpu.max" && $2!="max"{c=1} $1=="memory.max" && $2!="max"{m=1} $1=="memory.swap.max" && $2!="max"{s=1} $1=="pids.max" && $2!="max"{p=1} END{exit !(c&&m&&s&&p)}' "$limits_file"; then limits_ok=1; fi
  if timeout 10 jq -e '(.state == "terminal" or .terminal == true) and ((.conclusion // .result // "failure") != "success")' "$out_dir/final-$job.json" >/dev/null 2>&1; then terminal_ok=1; fi
  if timeout 10 jq -s --slurpfile lease "$out_dir/lease-$job.json" -e '
    map(select(.event as $e | ["stop","teardown_proof","publish"] | index($e))) as $x |
    ($x|length)==3 and $x[0].event=="stop" and $x[1].event=="teardown_proof" and $x[2].event=="publish" and
    $x[0].timestamp_unix_ns < $x[1].timestamp_unix_ns and $x[1].timestamp_unix_ns < $x[2].timestamp_unix_ns and
    (($lease[0].limits.wall_deadline | tonumber) as $d | $x[0].timestamp_unix_ns <= (if $d < 1000000000000000 then $d*1000000000 else $d end))
  ' "$out_dir/ordering-$job.jsonl" >/dev/null 2>&1; then ordering_ok=1; fi
  if timeout 10 jq -e '.cgroup_procs_empty == true and .mounts_removed == true and .dirs_removed == true' "$out_dir/teardown-$job.json" >/dev/null 2>&1 \
    && [[ ! -s $out_dir/cgroup-procs-$job.txt ]]; then teardown_ok=1; fi
  if [[ $job == memory-balloon ]]; then
    oom_ok=0
    if [[ -f $out_dir/memory-events-$job.txt ]] && timeout 10 awk '$1=="oom_kill" && $2>0{ok=1} END{exit !ok}' "$out_dir/memory-events-$job.txt"; then oom_ok=1; fi
  fi
  case $job in
    cpu-burn) expected_reason='cpu|timeout|deadline|cancel' ;;
    memory-balloon) expected_reason='oom|memory' ;;
    pid-fork-storm) expected_reason='pid|process|task' ;;
    disk-fill) expected_reason='disk|quota|space' ;;
    log-flood) expected_reason='log|output|rate|byte' ;;
    wall-time-overrun) expected_reason='wall|timeout|deadline' ;;
    artifact-overrun) expected_reason='artifact|count|size|quota' ;;
  esac
  if timeout 10 jq -er '(.terminal_reason // .reason // .error // "") | tostring | ascii_downcase' "$out_dir/final-$job.json" 2>/dev/null | timeout 10 grep -Eq "$expected_reason"; then reason_ok=1; fi
  if ((limits_ok && terminal_ok && ordering_ok && teardown_ok && oom_ok && reason_ok)); then
    record "$safe" pass "$job hit its bounded terminal path with finite cgroup limits and complete teardown"
  else
    record "$safe" fail "$job lacked its expected exhaustion reason, finite limit, deadline order, required OOM kill, or empty teardown proof"
  fi
}

for job in "${jobs[@]}"; do run_job "$job"; done
host_after=$out_dir/host-after.txt
{ timeout 10 cat /proc/loadavg; timeout 10 free -b; timeout 10 systemctl is-system-running || true; } >"$host_after" 2>&1
evidence_files+=("$TEST_ID/host-after.txt")
if timeout 10 tail -n 1 "$host_after" | timeout 10 grep -Eq '^(running|degraded)$'; then
  record host_health pass 'systemd remained running or degraded after all bounded exhaustion cases; before/after load and memory are retained'
else
  record host_health fail 'systemd did not report running or degraded after the exhaustion cases'
fi
emit
exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || [[ " ${statuses[*]} " == *' not_runnable '* ]] && printf 3 || printf 0 )"
