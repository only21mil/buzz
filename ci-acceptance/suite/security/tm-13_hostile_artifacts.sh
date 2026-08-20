#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-13
TITLE='Attempt cache collision/poisoning, symlink/hardlink/path traversal, device/FIFO/socket archive entries, decompression bomb, ANSI/OSC terminal injection, and encoded secret patterns'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
candidate=''
candidate_dir=''
evidence_dir=''
plan=0
checks=()
statuses=()
evidence_files=()
preconditions=(
  'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'
  'the published runner control entrypoint must support admit and get'
  'lease.json or teardown.json must name sanitized artifact and log publication paths'
  'root readback of lease state and publication stores requires SUITE_SUDO or passwordless sudo'
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

record() {
  local name=$1 status=$2 detail=$3
  checks+=("$(timeout "$TIMEOUT_SECONDS" jq -cn --arg name "$name" --arg status "$status" --arg detail "$detail" '{name:$name,status:$status,detail:$detail}')")
  statuses+=("$status")
}
string_array() { if (($# == 0)); then printf '[]'; else printf '%s\n' "$@" | timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n")[:-1]'; fi; }
emit() {
  local status summary pass_json=false checks_json evidence_json preconditions_json
  if ((plan)); then status=plan; summary='Plan only; no checks executed'
  elif [[ " ${statuses[*]} " == *' fail '* ]]; then status=fail; summary='At least one hostile-artifact check failed'
  elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then status=not_runnable; summary='Hostile-artifact checks need the published isolation wiring'
  else status=pass; pass_json=true; summary='No hostile artifact or raw log payload crossed quarantine'
  fi
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(string_array "${evidence_files[@]}")
  preconditions_json=$(string_array "${preconditions[@]}")
  timeout "$TIMEOUT_SECONDS" jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" \
    --argjson pass "$pass_json" --arg summary "$summary" --argjson checks "$checks_json" \
    --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" \
    '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
}

check_names=(fixture_script_parse fixture_payload_manifest artifact_quarantine log_scrubbing cache_poisoning terminal_artifact_order)
if ((plan)); then
  for name in "${check_names[@]}"; do record "$name" plan 'Would validate the fixture or run the hostile-artifact publication check'; done
  emit
  exit 0
fi
[[ -d $candidate_dir ]] || { printf 'candidate directory is not a directory\n' >&2; exit 4; }
out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"
fixture=$candidate_dir/ci-acceptance/suite/fixtures/tm-13-hostile-artifacts-repo
syntax_log=$out_dir/fixture-syntax.txt
if [[ -f $fixture/jobs/hostile-artifacts.sh ]] && timeout "$TIMEOUT_SECONDS" bash -n "$fixture/jobs/hostile-artifacts.sh" >"$syntax_log" 2>&1; then
  record fixture_script_parse pass 'The hostile-artifact job script passes bash -n'
else
  record fixture_script_parse fail 'The hostile-artifact fixture is missing or fails bash -n'
fi
evidence_files+=("$TEST_ID/fixture-syntax.txt")

manifest_log=$out_dir/fixture-payloads.txt
: >"$manifest_log"
payload_ok=1
for pattern in 'ln -s' 'ln ' 'mkfifo' 'socket-entry' 'device-node.request' '../escape' '/dev/zero' '2097152' '\033[31m' '\033]0;' 'ghp_' 'AKIA' 'base64' 'cache-poison-attempt' 'timeout 30'; do
  if timeout "$TIMEOUT_SECONDS" grep -Fq -- "$pattern" "$fixture/jobs/hostile-artifacts.sh"; then printf '%s present\n' "$pattern" >>"$manifest_log"; else printf '%s missing\n' "$pattern" >>"$manifest_log"; payload_ok=0; fi
done
if ((payload_ok)); then record fixture_payload_manifest pass 'The fixture carries every required hostile payload and a 30-second outer bound'; else record fixture_payload_manifest fail 'The fixture omits one or more required hostile payload markers'; fi
evidence_files+=("$TEST_ID/fixture-payloads.txt")

dynamic_names=(artifact_quarantine log_scrubbing cache_poisoning terminal_artifact_order)
if [[ ! -e /etc/buzzci/harness.env ]]; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi
SUDO=()
if [[ -n ${SUITE_SUDO+x} ]]; then read -r -a SUDO <<<"$SUITE_SUDO"; elif timeout 5 sudo -n true >/dev/null 2>&1; then SUDO=(sudo -n); fi
if ((${#SUDO[@]} == 0)) && [[ ! -r /etc/buzzci/harness.env ]]; then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'harness.env unreadable without sudo'; done
  emit
  exit 3
fi
if ((${#SUDO[@]} == 0)); then
  for name in "${dynamic_names[@]}"; do record "$name" not_runnable 'Root lease and publication-store readback requires SUITE_SUDO or passwordless sudo'; done
  emit
  exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || printf 3 )"
fi
harness_text=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat /etc/buzzci/harness.env 2>/dev/null) || { for name in "${dynamic_names[@]}"; do record "$name" fail 'Published harness.env is not root-readable'; done; emit; exit 1; }
env_get() { local key=$1; printf '%s\n' "$harness_text" | timeout "$TIMEOUT_SECONDS" awk -F= -v key="$key" '$1==key{print substr($0,index($0,"=")+1); exit}'; }
runner_ctl=$(env_get BUZZ_CI_RUNNER_CTL)
lease_root=$(env_get BUZZ_CI_LEASE_STATE_ROOT)
fixture_repo=$(env_get BUZZ_CI_FIXTURE_REPO)
if [[ ! -x $runner_ctl || ! -d $lease_root || -z $fixture_repo ]]; then
  for name in "${dynamic_names[@]}"; do record "$name" fail 'Published runner control, lease state root, or fixture coordinate is missing'; done
  emit
  exit 1
fi

admit_file=$out_dir/admit.json
if ! timeout "$TIMEOUT_SECONDS" "$runner_ctl" admit --repo "$fixture_repo" --sha "$candidate" \
    --workflow ci-acceptance/suite/fixtures/tm-13-hostile-artifacts-repo/workflow.yml --job hostile-artifacts --attempt 1 >"$admit_file" 2>"$out_dir/admit.stderr"; then
  evidence_files+=("$TEST_ID/admit.json" "$TEST_ID/admit.stderr")
  for name in "${dynamic_names[@]}"; do record "$name" fail 'The hostile-artifact attempt was not admitted'; done
  emit
  exit 1
fi
evidence_files+=("$TEST_ID/admit.json" "$TEST_ID/admit.stderr")
lease_id=$(timeout "$TIMEOUT_SECONDS" jq -r '.lease_id // empty' "$admit_file")
if [[ ! $lease_id =~ ^[A-Za-z0-9._-]+$ ]]; then for name in "${dynamic_names[@]}"; do record "$name" fail 'Admission returned no safe lease_id'; done; emit; exit 1; fi
lease_dir=$lease_root/$lease_id
for _ in {1..120}; do
  if timeout 10 "$runner_ctl" get --lease "$lease_id" >"$out_dir/final.json" 2>"$out_dir/final.stderr" \
    && timeout 10 jq -e '.state == "terminal" or .terminal == true' "$out_dir/final.json" >/dev/null; then break; fi
  timeout 2 sleep 0.25
done
evidence_files+=("$TEST_ID/final.json" "$TEST_ID/final.stderr")
for name in lease.json teardown.json ordering.jsonl; do timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$lease_dir/$name" "$out_dir/$name" 2>/dev/null || :; evidence_files+=("$TEST_ID/$name"); done

paths_file=$out_dir/publication-paths.txt
timeout "$TIMEOUT_SECONDS" jq -r '.. | objects | to_entries[] | select(.key|test("((published|sanitized|content_addressed).*(artifact|log)|(artifact|log).*(published|sanitized|content_addressed|store_path))";"i")) | .value | select(type=="string")' \
  "$out_dir/lease.json" "$out_dir/teardown.json" 2>/dev/null | timeout "$TIMEOUT_SECONDS" awk 'NF && !seen[$0]++' >"$paths_file"
evidence_files+=("$TEST_ID/publication-paths.txt")
if [[ ! -s $paths_file ]]; then
  record artifact_quarantine fail 'Lease metadata names no sanitized artifact or log publication paths'
  record log_scrubbing fail 'Lease metadata names no sanitized log publication path'
  record cache_poisoning fail 'Lease metadata names no publication store to check for the cache-poison marker'
else
  unsafe_count=0
  log_bad=0
  poison_count=0
  scan_file=$out_dir/publication-scan.txt
  : >"$scan_file"
  while IFS= read -r published; do
    if [[ ! $published == /* || ! -e $published ]]; then printf 'missing_or_relative=%s\n' "$published" >>"$scan_file"; unsafe_count=$((unsafe_count + 1)); continue; fi
    special=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" find "$published" -xdev \( -type l -o -type p -o -type s -o -type b -o -type c \) -print 2>/dev/null | timeout "$TIMEOUT_SECONDS" wc -l)
    traversal=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" find "$published" -xdev -print 2>/dev/null | timeout "$TIMEOUT_SECONDS" awk 'index($0,"../") || $0 ~ /(^|\/)escape($|\/)/{n++} END{print n+0}')
    oversized=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" find "$published" -xdev -type f -size +2M -print 2>/dev/null | timeout "$TIMEOUT_SECONDS" wc -l)
    poison=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" find "$published" -xdev -name '*cache-poison*' -print 2>/dev/null | timeout "$TIMEOUT_SECONDS" wc -l)
    hostile_names=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" find "$published" -xdev \( -iname '*symlink*' -o -iname '*hardlink*' -o -iname '*traversal*' -o -iname '*device-entry*' -o -iname '*fifo*' -o -iname '*socket*' -o -iname '*bomb*' \) -print 2>/dev/null | timeout "$TIMEOUT_SECONDS" wc -l)
    archive_bad=0
    while IFS= read -r archive; do
      if timeout 10 "${SUDO[@]}" tar -tf "$archive" 2>/dev/null | timeout 10 grep -Eq '(^|/)\.\.?/|(^|/)(device|fifo|socket|symlink|hardlink|escape|bomb)(-|/|$)'; then archive_bad=$((archive_bad + 1)); fi
    done < <(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" find "$published" -xdev -type f \( -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' \) -print 2>/dev/null)
    controls=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" grep -rIl $'\033\|ghp_[[:alnum:]]\{36\}\|AKIA[[:alnum:]]\{16\}\|Z2hwXw\|QUtJQQ' "$published" 2>/dev/null | timeout "$TIMEOUT_SECONDS" wc -l)
    printf 'path=%s special=%s traversal=%s oversized=%s hostile_names=%s hostile_archives=%s poison=%s unsafe_log_files=%s\n' "$published" "$special" "$traversal" "$oversized" "$hostile_names" "$archive_bad" "$poison" "$controls" >>"$scan_file"
    unsafe_count=$((unsafe_count + special + traversal + oversized + hostile_names + archive_bad))
    poison_count=$((poison_count + poison))
    log_bad=$((log_bad + controls))
  done <"$paths_file"
  evidence_files+=("$TEST_ID/publication-scan.txt")
  if ((unsafe_count == 0)); then record artifact_quarantine pass 'Published paths contain no links, special files, traversal markers, or files beyond the bomb cap'; else record artifact_quarantine fail 'A published path contains a hostile entry, missing path, or file beyond the bomb cap'; fi
  if ((log_bad == 0)); then record log_scrubbing pass 'Published copies contain no ANSI/OSC bytes or fake secret patterns'; else record log_scrubbing fail 'A published copy retains ANSI/OSC bytes or a fake secret pattern'; fi
  if ((poison_count == 0)) && [[ ! -e ${lease_dir%/*}/tm13-cache-poison-attempt ]]; then record cache_poisoning pass 'No cache-poison marker appears in lease state or published output'; else record cache_poisoning fail 'The cache-poison marker escaped its workspace or entered published output'; fi
fi

if timeout "$TIMEOUT_SECONDS" jq -s -e '
  map(select(.event as $e | ["stop","finalize_raw_stream","extract","scrub","scan","hash","upload","teardown_proof","publish"] | index($e))) as $x |
  ($x|length)==9 and ([range(1;9)] | all(. as $i; $x[$i].timestamp_unix_ns > $x[$i-1].timestamp_unix_ns)) and
  ($x|map(.event)) == ["stop","finalize_raw_stream","extract","scrub","scan","hash","upload","teardown_proof","publish"]
' "$out_dir/ordering.jsonl" >/dev/null 2>&1; then
  record terminal_artifact_order pass 'Extraction, scrubbing, scanning, hashing, and upload followed stop and preceded teardown proof and publication'
else
  record terminal_artifact_order fail 'ordering.jsonl lacks the required strictly ordered terminal artifact sequence'
fi
emit
exit "$( [[ " ${statuses[*]} " == *' fail '* ]] && printf 1 || [[ " ${statuses[*]} " == *' not_runnable '* ]] && printf 3 || printf 0 )"
