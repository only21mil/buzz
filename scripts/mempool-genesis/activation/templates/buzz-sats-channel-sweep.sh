#!/usr/bin/env bash
# Keep every Sats agent in every live open Buzz channel, maintain the named
# channel admins, and add the full Sats set to Victor-visible private channels.
# Mempool and Genesis are a fixed public-key roster. The owner adds them only to
# open channels. Their private keys are never loaded here, and their kind:10100
# records remain self-published rather than owned by directory-sync automation.
#
# Keys and auth tags come only from the sanctioned secrets file and reach Buzz
# through its environment. The script never prints either value.
# Skip list: one channel UUID per line in ~/.config/sats/buzz-channel-sweep.skip
set -euo pipefail
umask 077
secret_file=${SATS_SECRET_FILE:-/home/victor/.config/sats/secrets.env}
skip_file=${SATS_SKIP_FILE:-/home/victor/.config/sats/buzz-channel-sweep.skip}
log=${SATS_SWEEP_LOG:-/home/victor/.local/state/sats/buzz-channel-sweep.log}
tools_dir=${SATS_TOOLS_DIR:-/home/victor/.agents/tools}
BUZZ_BIN=${BUZZ_BIN:-/home/victor/work/buzz-agents/bin/buzz}
export BUZZ_RELAY_URL=${BUZZ_RELAY_URL:-wss://framework-desktop.tail69757d.ts.net:38443}
unset BUZZ_AUTH_TAG BUZZ_PRIVATE_KEY
if [[ ! -f $secret_file || -L $secret_file ]] \
  || [[ $(stat -c '%U %a' -- "$secret_file") != "$(id -un) 600" ]] \
  || [[ $(stat -c '%U %a' -- "$(dirname -- "$secret_file")") != "$(id -un) 700" ]]; then
  echo "secrets file failed safety checks" >&2
  exit 1
fi
set -a
# shellcheck disable=SC1090,SC1091
. "$secret_file"
set +a
mg_mode=full
case ${1:-} in
  "") ;;
  --check) mg_mode=check ;;
  --dry-run) mg_mode=dry-run ;;
  --mempool-genesis-apply) mg_mode=apply ;;
  --directory-dry-run)
    exec python3 "$tools_dir/buzz-sats-directory-sync.py" --dry-run
    ;;
  *)
    printf '%s\n' 'usage: buzz-sats-channel-sweep.sh [--check|--dry-run|--mempool-genesis-apply|--directory-dry-run]' >&2
    exit 64
    ;;
esac

ts() { date -u +%FT%TZ; }
logline() { printf '%s %s\n' "$(ts)" "$*" | tee -a "$log"; }
statusline() {
  if [[ $mg_mode == check || $mg_mode == dry-run ]]; then
    printf '%s\n' "$*"
  else
    logline "$*"
  fi
}
sanitize() {
  if [[ ${1:-} == archimedes ]]; then
    python3 -c '
import re,sys
channel_id = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
for raw in sys.stdin:
    line = raw.rstrip("\n")
    if re.fullmatch(r"Archimedes (Hermes|Codex): joined=[0-9]+ channels=[0-9]+ directory=(in sync|published and verified)", line):
        print(line)
        continue
    match = re.match(r"^Archimedes private blocked (" + channel_id.pattern + r")", line)
    if match:
        print(f"Archimedes private blocked {match.group(1)}")
        continue
    match = re.match(r"^Archimedes private: channels=([0-9]+) private_added=([0-9]+) private_blocked=([0-9]+)", line)
    if match:
        print(
            f"Archimedes private: channels={match.group(1)} "
            f"private_added={match.group(2)} private_blocked={match.group(3)}"
        )
        continue
    if line.startswith("Archimedes private: ERROR"):
        match = channel_id.search(line)
        suffix = f" channel={match.group(0)}" if match else ""
        print(f"Archimedes private: ERROR{suffix}")
        continue
    match = re.match(r"^(Archimedes (Hermes|Codex)): ERROR", line)
    if match:
        print(f"{match.group(1)}: ERROR")
'
    return
  fi
  tr -d '\n' | sed -E 's/nsec1[^[:space:]]+/<nsec>/g; s/[0-9a-fA-F]{64}/<hex>/g' | cut -c1-200
}
buzz_as() {
  local key=$1 tag=$2
  shift 2
  if [[ -n $tag ]]; then
    BUZZ_PRIVATE_KEY=$key BUZZ_AUTH_TAG=$tag "$BUZZ_BIN" "$@"
  else
    env -u BUZZ_AUTH_TAG BUZZ_PRIVATE_KEY="$key" "$BUZZ_BIN" "$@"
  fi
}
derive_pubkey() {
  PYTHONPATH=$tools_dir BUZZ_PRIVATE_KEY=$1 python3 -c '
import os,re
from nostr_min import pubkey_xonly
raw = os.environ["BUZZ_PRIVATE_KEY"].strip()
if not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
    raise SystemExit("private key has invalid format")
print(pubkey_xonly(bytes.fromhex(raw)).hex())
'
}

list_live_channels() {
  local visibility=$1 key=$2 tag=$3 member_only=${4:-false}
  local listed rows cid encoded_name state
  local -a list_args=(channels list --visibility "$visibility")
  [[ $member_only == true ]] && list_args+=(--member)
  listed=$(buzz_as "$key" "$tag" "${list_args[@]}") || return 1
  rows=$(python3 -c '
import base64,json,sys
for channel in json.load(sys.stdin):
    cid = channel.get("channel_id", "")
    name = channel.get("name", "")
    if not cid or not name:
        continue
    if channel.get("archived") or channel.get("archived_at") is not None:
        state = "archived"
    elif "archived" in channel or "archived_at" in channel:
        state = "live"
    else:
        state = "unknown"
    encoded = base64.b64encode(name.encode()).decode()
    print(cid, encoded, state, sep="\t")
' <<<"$listed") || return 1
  while IFS=$'\t' read -r cid encoded_name state; do
    [[ -n $cid ]] || continue
    # The relay projection exposes no archive fields to this CLI. The relay
    # itself rejects writes to archived channels with an 'archived' error and
    # every write path below classifies that rejection, so unknown means live.
    [[ $state == unknown ]] && state=live
    [[ $state == archived ]] && continue
    printf '%s\t%s\n' "$cid" "$encoded_name"
  done <<<"$rows"
}

skips=()
[[ -f $skip_file ]] && mapfile -t skips < <(grep -E '^[0-9a-f-]{36}' "$skip_file" | cut -c1-36)
in_skips() { local c; for c in "${skips[@]:-}"; do [[ $c == "$1" ]] && return 0; done; return 1; }

owner_key=${BUZZ_OWNER_PRIVATE_KEY:-}
[[ ${#owner_key} -ge 32 ]] || { echo "BUZZ_OWNER_PRIVATE_KEY is empty" >&2; exit 1; }
owner_pubkey=$(derive_pubkey "$owner_key")
expected_owner_pubkey=4a34c131ec5cb5dd9a200bac619bbd103c0793e068fad278d1de59203d05b97d
[[ $owner_pubkey == "$expected_owner_pubkey" ]] || {
  echo "BUZZ_OWNER_PRIVATE_KEY does not authenticate Victor" >&2
  exit 1
}

mg_labels=("Mempool" "Genesis")
mg_pubkeys=(
  "__MEMPOOL_PUBLIC_KEY__"
  "__GENESIS_PUBLIC_KEY__"
)
mg_reserved_pubkeys=(
  "4a34c131ec5cb5dd9a200bac619bbd103c0793e068fad278d1de59203d05b97d"
  "7806a7beb69ba4fd3b6e9b86d56931a446b62666e9794533f87fb2d1b956684f"
  "73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812"
  "aefa6783cdf2f33f9aa3705b41e5ae3ec214318c64db48f1410fc77db015f2ec"
  "db965b1f484ec4ebd3b0041091e890e2cd28e64732d9be53fd07ba640255af61"
)

joined=0
admin_writes=0
private_writes=0
private_not_admin=0
archimedes_private_writes=0
archimedes_private_blocked=0
failed=0
archived_rejected=0
admin_blocked=0
mg_planned=0
mg_writes=0
mg_already=0
mg_blocked=0

member_role() {
  local target=$1
  TARGET_PUBKEY=$target python3 -c '
import json,os,sys
target = os.environ["TARGET_PUBKEY"]
print(next((member.get("role", "") for member in json.load(sys.stdin) if member.get("pubkey") == target), ""))
'
}

validate_mg_roster() {
  local key reserved
  [[ ${#mg_pubkeys[@]} -eq 2 ]]
  [[ ${mg_pubkeys[0]} != "${mg_pubkeys[1]}" ]]
  for key in "${mg_pubkeys[@]}"; do
    [[ $key =~ ^[0-9a-f]{64}$ ]] || {
      statusline "Mempool/Genesis roster has an unresolved or invalid public key"
      return 1
    }
    for reserved in "${mg_reserved_pubkeys[@]}"; do
      [[ $key != "$reserved" ]] || {
        statusline "Mempool/Genesis roster reuses a responder public key"
        return 1
      }
    done
  done
}

reconcile_mg_open_channels() {
  local action=$1 cid members owner_role target label role out verified
  validate_mg_roster || {
    mg_blocked=$((mg_blocked + 1))
    return 1
  }
  while IFS=$'\t' read -r cid _encoded_name; do
    [[ -n $cid ]] || continue
    if ! members=$(buzz_as "$owner_key" "" channels members --channel "$cid" 2>/dev/null); then
      statusline "owner: Mempool/Genesis member read FAILED $cid"
      mg_blocked=$((mg_blocked + 1))
      continue
    fi
    owner_role=$(member_role "$expected_owner_pubkey" <<<"$members")
    if [[ $owner_role != owner ]]; then
      statusline "owner: Mempool/Genesis owner authority UNMET $cid"
      mg_blocked=$((mg_blocked + 1))
      continue
    fi
    for i in "${!mg_pubkeys[@]}"; do
      target=${mg_pubkeys[$i]}
      label=${mg_labels[$i]}
      role=$(member_role "$target" <<<"$members")
      if [[ -n $role ]]; then
        mg_already=$((mg_already + 1))
        continue
      fi
      mg_planned=$((mg_planned + 1))
      if [[ $action == dry-run ]]; then
        printf 'PLAN owner add-member channel=%s label=%s pubkey=%s role=member\n' "$cid" "$label" "$target"
      fi
      [[ $action == apply ]] || continue
      if out=$(buzz_as "$owner_key" "" channels add-member --channel "$cid" --pubkey "$target" --role member 2>&1); then
        if ! python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("accepted") is True else 1)' <<<"$out"; then
          statusline "$label owner add-member FAILED $cid: $(sanitize <<<"$out")"
          failed=$((failed + 1))
          continue
        fi
        if ! verified=$(buzz_as "$owner_key" "" channels members --channel "$cid" 2>/dev/null); then
          statusline "$label owner add-member verify read FAILED $cid"
          failed=$((failed + 1))
          continue
        fi
        role=$(member_role "$target" <<<"$verified")
        if [[ $role != member ]]; then
          statusline "$label owner add-member verification FAILED $cid"
          failed=$((failed + 1))
          continue
        fi
        statusline "$label joined open $cid by owner add-member"
        mg_writes=$((mg_writes + 1))
      elif grep -qi 'archived' <<<"$out"; then
        statusline "$label owner add-member skipped archived $cid"
        archived_rejected=$((archived_rejected + 1))
      else
        statusline "$label owner add-member FAILED $cid: $(sanitize <<<"$out")"
        failed=$((failed + 1))
      fi
    done
  done <<<"$open_channels"
  statusline "Mempool/Genesis open-channel roster: planned=$mg_planned writes=$mg_writes already=$mg_already blocked=$mg_blocked"
  [[ $mg_blocked -eq 0 && $failed -eq 0 ]]
}

if ! open_channels=$(list_live_channels open "$owner_key" "" 2>/dev/null); then
  statusline "owner: live open channel list failed or relay unreachable"
  failed=$((failed + 1))
  open_channels=
fi
[[ -n $open_channels ]] || { statusline "owner: live open channel list empty"; failed=$((failed + 1)); }

case $mg_mode in
  check)
    reconcile_mg_open_channels check
    printf '%s\n' "PREFLIGHT OK: read-only Mempool/Genesis reconciliation can proceed"
    exit 0
    ;;
  dry-run)
    reconcile_mg_open_channels dry-run
    printf '%s\n' "DRY RUN OK: no channel writes performed"
    exit 0
    ;;
  apply)
    reconcile_mg_open_channels apply
    exit 0
    ;;
  full)
    reconcile_mg_open_channels apply || failed=$((failed + 1))
    ;;
esac

mapfile -t key_vars < <(
  compgen -v \
    | grep -E '^BUZZ_SATS_[A-Z0-9_]+_PRIVATE_KEY$' \
    | grep -vE '^BUZZ_SATS_(MEMPOOL|GENESIS)_PRIVATE_KEY$' \
    | sort \
    || true
)
[[ ${#key_vars[@]} -gt 0 ]] || { echo "no BUZZ_SATS_*_PRIVATE_KEY variables found" >&2; exit 1; }
declare -a agent_names agent_keys agent_tags agent_pubkeys
for var in "${key_vars[@]}"; do
  agent=${var#BUZZ_SATS_}
  agent=${agent%_PRIVATE_KEY}
  key=${!var}
  tagvar=BUZZ_SATS_${agent}_AUTH_TAG
  tag=${!tagvar:-}
  [[ ${#key} -ge 32 ]] || { echo "$agent key is empty" >&2; exit 1; }
  pubkey=$(derive_pubkey "$key")
  agent_names+=("$agent")
  agent_keys+=("$key")
  agent_tags+=("$tag")
  agent_pubkeys+=("$pubkey")
done

for i in "${!agent_names[@]}"; do
  agent=${agent_names[$i]}
  key=${agent_keys[$i]}
  tag=${agent_tags[$i]}
  if ! mine=$(buzz_as "$key" "$tag" channels list --visibility open --member 2>/dev/null | python3 -c 'import sys,json; [print(c["channel_id"]) for c in json.load(sys.stdin)]' 2>/dev/null); then
    logline "$agent: membership list failed or relay unreachable"
    failed=$((failed + 1))
    continue
  fi
  while IFS=$'\t' read -r cid encoded_name; do
    [[ -n $cid ]] || continue
    grep -qxF "$cid" <<<"$mine" && continue
    in_skips "$cid" && continue
    cname=$(printf '%s' "$encoded_name" | base64 -d)
    if out=$(buzz_as "$key" "$tag" channels join --channel "$cid" 2>&1); then
      if grep -q '"accepted":true' <<<"$out"; then
        logline "$agent joined $cid ($cname)"
        joined=$((joined + 1))
      else
        logline "$agent FAILED join $cid ($cname): $(sanitize <<<"$out")"
        failed=$((failed + 1))
      fi
    elif grep -qi 'archived' <<<"$out"; then
      logline "$agent archived join rejected $cid ($cname)"
      archived_rejected=$((archived_rejected + 1))
    else
      logline "$agent FAILED join $cid ($cname): $(sanitize <<<"$out")"
      failed=$((failed + 1))
    fi
  done <<<"$open_channels"
done

admin_labels=("Sats Codex" "Sats Codex-2" "Archimedes Codex")
admin_pubkeys=(
  "73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812"
  "aefa6783cdf2f33f9aa3705b41e5ae3ec214318c64db48f1410fc77db015f2ec"
  "db965b1f484ec4ebd3b0041091e890e2cd28e64732d9be53fd07ba640255af61"
)
while IFS=$'\t' read -r cid _encoded_name; do
  [[ -n $cid ]] || continue
  in_skips "$cid" && continue
  if ! members=$(buzz_as "$owner_key" "" channels members --channel "$cid" 2>/dev/null); then
    logline "owner: member read FAILED $cid"
    failed=$((failed + 1))
    continue
  fi
  for i in "${!admin_pubkeys[@]}"; do
    target=${admin_pubkeys[$i]}
    label=${admin_labels[$i]}
    role=$(TARGET_PUBKEY=$target python3 -c '
import json,os,sys
target = os.environ["TARGET_PUBKEY"]
print(next((member.get("role", "") for member in json.load(sys.stdin) if member.get("pubkey") == target), ""))
' <<<"$members")
    [[ $role == admin || $role == owner ]] && continue
    if out=$(buzz_as "$owner_key" "" channels add-member --channel "$cid" --pubkey "$target" --role admin 2>&1); then
      logline "$label elevated $cid to admin"
      admin_writes=$((admin_writes + 1))
    elif grep -qi 'archived' <<<"$out"; then
      logline "$label admin skipped archived $cid"
      archived_rejected=$((archived_rejected + 1))
    elif grep -qiE 'only owners/admins|not authorized|forbidden' <<<"$out"; then
      logline "$label admin BLOCKED $cid: $(sanitize <<<"$out")"
      admin_blocked=$((admin_blocked + 1))
    else
      logline "$label admin FAILED $cid: $(sanitize <<<"$out")"
      failed=$((failed + 1))
    fi
  done
done <<<"$open_channels"

if ! private_channels=$(list_live_channels private "$owner_key" "" true 2>/dev/null); then
  logline "owner: private channel list failed or relay unreachable"
  failed=$((failed + 1))
  private_channels=
fi
while IFS=$'\t' read -r cid _encoded_name; do
  [[ -n $cid ]] || continue
  in_skips "$cid" && continue
  if ! members=$(buzz_as "$owner_key" "" channels members --channel "$cid" 2>/dev/null); then
    logline "owner: private member read FAILED $cid"
    failed=$((failed + 1))
    continue
  fi
  owner_role=$(TARGET_PUBKEY=$owner_pubkey python3 -c '
import json,os,sys
target = os.environ["TARGET_PUBKEY"]
print(next((member.get("role", "") for member in json.load(sys.stdin) if member.get("pubkey") == target), ""))
' <<<"$members")
  if [[ $owner_role != owner && $owner_role != admin ]]; then
    private_not_admin=$((private_not_admin + 1))
    continue
  fi
  for i in "${!agent_pubkeys[@]}"; do
    target=${agent_pubkeys[$i]}
    agent=${agent_names[$i]}
    if TARGET_PUBKEY=$target python3 -c '
import json,os,sys
target = os.environ["TARGET_PUBKEY"]
raise SystemExit(0 if any(member.get("pubkey") == target for member in json.load(sys.stdin)) else 1)
' <<<"$members"; then
      continue
    fi
    if out=$(buzz_as "$owner_key" "" channels add-member --channel "$cid" --pubkey "$target" --role member 2>&1); then
      logline "$agent joined private $cid"
      joined=$((joined + 1))
      private_writes=$((private_writes + 1))
    elif grep -qi 'archived' <<<"$out"; then
      logline "$agent private join skipped archived $cid"
      archived_rejected=$((archived_rejected + 1))
    else
      logline "$agent private join FAILED $cid"
      failed=$((failed + 1))
    fi
  done
done <<<"$private_channels"

# Keep kind:10100 channel_ids in step for the pre-existing directory-managed
# roster only. Mempool and Genesis are deliberately absent from this writer;
# each agent publishes and refreshes its own record.
if out=$(BUZZ_RELAY_URL=$BUZZ_RELAY_URL python3 "$tools_dir/buzz-sats-directory-sync.py" 2>&1); then
  while read -r line; do [[ -n $line ]] && logline "directory: $line"; done < <(grep -E "republished|ERROR" <<<"$out" || true)
else
  logline "directory sync FAILED: $(sanitize <<<"$out")"
  failed=$((failed + 1))
fi
if out=$(sudo -n -u sats /home/sats/buzz-agents/tools/buzz-archimedes-channel-sync.py 2>&1); then
  safe_out=$(sanitize archimedes <<<"$out")
  while read -r line; do [[ -n $line ]] && logline "archimedes: $line"; done <<<"$safe_out"
  archimedes_private_writes=$(sed -nE 's/.*private_added=([0-9]+).*/\1/p' <<<"$safe_out" | tail -n 1)
  archimedes_private_writes=${archimedes_private_writes:-0}
  archimedes_private_blocked=$(sed -nE 's/.*private_blocked=([0-9]+).*/\1/p' <<<"$safe_out" | tail -n 1)
  archimedes_private_blocked=${archimedes_private_blocked:-0}
else
  safe_out=$(sanitize archimedes <<<"$out")
  while read -r line; do [[ -n $line ]] && logline "archimedes: $line"; done <<<"$safe_out"
  logline "archimedes sync FAILED"
  failed=$((failed + 1))
fi
logline "sweep done: joined=$joined mg_planned=$mg_planned mg_writes=$mg_writes mg_already=$mg_already mg_blocked=$mg_blocked admin_writes=$admin_writes private_writes=$private_writes private_not_admin=$private_not_admin archimedes_private_writes=$archimedes_private_writes archimedes_private_blocked=$archimedes_private_blocked failed=$failed archived_rejected=$archived_rejected admin_blocked=$admin_blocked agents=${#key_vars[@]}"
# Keep the log bounded.
tail -n 500 "$log" > "$log.tmp" && mv "$log.tmp" "$log"
[[ $failed -eq 0 ]]
