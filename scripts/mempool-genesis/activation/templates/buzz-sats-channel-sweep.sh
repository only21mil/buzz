#!/usr/bin/env bash
# Keep every Sats agent in every live open Buzz channel, maintain the named
# channel admins, and add the full Sats set to Victor-visible private channels.
# Mempool and Genesis are a fixed public-key roster. Victor adds them to every
# open and eligible Sats/Victor private channel where Codex-R is a member. Their
# private keys are never loaded here, and their kind:10100
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
sudo_bin=${SATS_SUDO_BIN:-sudo}
archimedes_sync=${SATS_ARCHIMEDES_SYNC:-/home/sats/buzz-agents/tools/buzz-archimedes-channel-sync.py}
transaction_tool=${SATS_ACTIVATION_TRANSACTION_TOOL:-/usr/local/libexec/buzz/mempool-genesis-activation-transaction}
activation_root=${SATS_ACTIVATION_ROOT:-/}
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
mg_mode=check
mg_agent=all
activation_state=
case ${1:-} in
  "") ;;
  --check) mg_mode=check ;;
  --dry-run) mg_mode=dry-run ;;
  --mempool-genesis-apply)
    printf '%s\n' 'combined Mempool/Genesis mutation is disabled; use the selective transaction modes' >&2
    exit 64
    ;;
  --mempool-apply|--genesis-apply)
    mg_mode=apply
    mg_agent=${1#--}
    mg_agent=${mg_agent%-apply}
    activation_state=${2:-}
    [[ -n $activation_state ]] || { echo 'activation transaction state is required' >&2; exit 64; }
    ;;
  --mempool-complete|--genesis-complete)
    mg_mode=complete
    mg_agent=${1#--}
    mg_agent=${mg_agent%-complete}
    activation_state=${2:-}
    phase_gate_receipt=${3:-}
    [[ -n $activation_state && -n $phase_gate_receipt ]] || {
      echo 'activation transaction state and phase gate receipt are required' >&2
      exit 64
    }
    ;;
  --activation-rollback)
    mg_mode=rollback
    activation_state=${2:-}
    [[ -n $activation_state ]] || { echo 'activation transaction state is required' >&2; exit 64; }
    ;;
  --full) mg_mode=full ;;
  --directory-dry-run)
    exec python3 "$tools_dir/buzz-sats-directory-sync.py" --dry-run
    ;;
  *)
    printf '%s\n' 'usage: buzz-sats-channel-sweep.sh [--check|--dry-run|--mempool-apply STATE|--mempool-complete STATE GATE|--genesis-apply STATE|--genesis-complete STATE GATE|--activation-rollback STATE|--full|--directory-dry-run]' >&2
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
activation_transaction() {
  "$transaction_tool" "$@" >/dev/null
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

skips=(
  # Stable policy exclusions: the first channel has no owner authority; the
  # second is archived but remains visible in the relay projection.
  "9f7d9f1d-df0f-490f-8e32-1e3dbf261f1f"
  "446dba03-c038-4e8c-b05e-245deb1d5ac5"
)
external_skips=()
[[ -f $skip_file ]] && mapfile -t external_skips < <(grep -E '^[0-9a-f-]{36}' "$skip_file" | cut -c1-36)
skips+=("${external_skips[@]}")
in_skips() { local c; for c in "${skips[@]:-}"; do [[ $c == "$1" ]] && return 0; done; return 1; }

owner_key=${BUZZ_OWNER_PRIVATE_KEY:-}
[[ ${#owner_key} -ge 32 ]] || { echo "BUZZ_OWNER_PRIVATE_KEY is empty" >&2; exit 1; }
owner_pubkey=$(derive_pubkey "$owner_key")
expected_owner_pubkey=4a34c131ec5cb5dd9a200bac619bbd103c0793e068fad278d1de59203d05b97d
rachel_pubkey=7806a7beb69ba4fd3b6e9b86d56931a446b62666e9794533f87fb2d1b956684f
[[ $owner_pubkey == "$expected_owner_pubkey" ]] || {
  echo "BUZZ_OWNER_PRIVATE_KEY does not authenticate Victor" >&2
  exit 1
}
codexr_key=${BUZZ_SATS_CODEX_R_PRIVATE_KEY:-}
[[ ${#codexr_key} -ge 32 ]] || { echo "BUZZ_SATS_CODEX_R_PRIVATE_KEY is empty" >&2; exit 1; }
codexr_pubkey=$(derive_pubkey "$codexr_key")

mg_labels=("Mempool" "Genesis")
mg_pubkeys=(
  "__MEMPOOL_PUBLIC_KEY__"
  "__GENESIS_PUBLIC_KEY__"
)
mg_channel_allowlist=(
__MG_CHANNEL_ALLOWLIST__
)
mg_authority_exclusions=(
__MG_AUTHORITY_EXCLUSIONS__
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
members = json.load(sys.stdin)
if not isinstance(members, list) or any(
    not isinstance(member, dict)
    or not isinstance(member.get("pubkey"), str)
    or not isinstance(member.get("role"), str)
    for member in members
):
    raise SystemExit(1)
print(next((member["role"] for member in members if member["pubkey"] == target), ""))
'
}

mg_member_projection() {
  local owner=$1 first=$2 second=$3
  MG_OWNER_PUBKEY=$owner MG_FIRST_PUBKEY=$first MG_SECOND_PUBKEY=$second python3 -c '
import json,os,sys
members = json.load(sys.stdin)
if not isinstance(members, list) or any(
    not isinstance(member, dict)
    or not isinstance(member.get("pubkey"), str)
    or not isinstance(member.get("role"), str)
    for member in members
):
    raise SystemExit(1)
def role(target):
    return next((member["role"] for member in members if member["pubkey"] == target), "")
print("\t".join((
    "owner" if role(os.environ["MG_OWNER_PUBKEY"]) == "owner" else "unmet",
    "present" if role(os.environ["MG_FIRST_PUBKEY"]) else "absent",
    "present" if role(os.environ["MG_SECOND_PUBKEY"]) else "absent",
)))
'
}

bound_sweep_log() {
  if ! tail -n 500 "$log" > "$log.tmp"; then
    rm -f -- "$log.tmp"
    return 1
  fi
  if ! mv "$log.tmp" "$log"; then
    rm -f -- "$log.tmp"
    return 1
  fi
}

validate_mg_roster() {
  local key reserved stripped
  [[ ${#mg_pubkeys[@]} -eq 2 ]] || {
    statusline "Mempool/Genesis roster must contain exactly two public keys"
    return 1
  }
  [[ ${mg_pubkeys[0]} != "${mg_pubkeys[1]}" ]] || {
    statusline "Mempool/Genesis roster public keys must be distinct"
    return 1
  }
  [[ $codexr_pubkey =~ ^[0-9a-f]{64}$ ]] || {
    statusline "Codex-R reference identity is invalid"
    return 1
  }
  for key in "${mg_pubkeys[@]}"; do
    [[ $key =~ ^[0-9a-f]{64}$ ]] || {
      statusline "Mempool/Genesis roster has an unresolved or invalid public key"
      return 1
    }
    stripped=${key//${key:0:1}/}
    [[ -n $stripped ]] || {
      statusline "Mempool/Genesis roster contains a repeated-nibble placeholder"
      return 1
    }
    PUBKEY=$key python3 -c '
import os
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
x = int(os.environ["PUBKEY"], 16)
if x >= p:
    raise SystemExit(1)
value = (pow(x, 3, p) + 7) % p
raise SystemExit(0 if pow(value, (p - 1) // 2, p) == 1 else 1)
' || {
      statusline "Mempool/Genesis roster contains an invalid secp256k1 x-only public key"
      return 1
    }
    for reserved in "${mg_reserved_pubkeys[@]}"; do
      [[ $key != "$reserved" ]] || {
        statusline "Mempool/Genesis roster reuses a responder public key"
        return 1
      }
    done
    [[ $key != "$codexr_pubkey" ]] || {
      statusline "Mempool/Genesis roster reuses the Codex-R reference identity"
      return 1
    }
  done
}

in_mg_allowlist() {
  local allowed
  for allowed in "${mg_channel_allowlist[@]}"; do
    [[ $allowed == "$1" ]] && return 0
  done
  return 1
}

in_mg_exclusions() {
  local record cid
  for record in "${mg_authority_exclusions[@]}"; do
    IFS='|' read -r cid _ <<<"$record"
    [[ $cid == "$1" ]] && return 0
  done
  return 1
}

verify_mg_authority_exclusions() {
  local record cid required_actor expected_actor expected_reference approval
  local open_match members actor_role reference_role first_role second_role
  [[ ${#mg_authority_exclusions[@]} -eq 1 ]] || {
    statusline "Mempool/Genesis authority exclusion inventory INVALID"
    return 1
  }
  for record in "${mg_authority_exclusions[@]}"; do
    IFS='|' read -r cid required_actor expected_actor expected_reference approval <<<"$record"
    [[ -n $cid && $required_actor == owner && $expected_actor == member && \
       $expected_reference == bot && -n $approval ]] || {
      statusline "Mempool/Genesis authority exclusion contract INVALID"
      return 1
    }
    in_mg_allowlist "$cid" && {
      statusline "Mempool/Genesis authority exclusion overlaps candidate allowlist $cid"
      return 1
    }
    open_match=$(awk -F '\t' -v wanted="$cid" '$1 == wanted { count++ } END { print count+0 }' <<<"$open_channels")
    [[ $open_match -eq 1 ]] || {
      statusline "Mempool/Genesis authority exclusion visibility/archive drift $cid"
      return 1
    }
    members=$(buzz_as "$owner_key" "" channels members --channel "$cid" 2>/dev/null) || {
      statusline "Mempool/Genesis authority exclusion member read FAILED $cid"
      return 1
    }
    if ! actor_role=$(member_role "$expected_owner_pubkey" <<<"$members") \
      || ! reference_role=$(member_role "$codexr_pubkey" <<<"$members") \
      || ! first_role=$(member_role "${mg_pubkeys[0]}" <<<"$members") \
      || ! second_role=$(member_role "${mg_pubkeys[1]}" <<<"$members"); then
      statusline "Mempool/Genesis authority exclusion member projection INVALID $cid"
      return 1
    fi
    [[ $actor_role == "$expected_actor" && $actor_role != "$required_actor" ]] || {
      statusline "Mempool/Genesis authority exclusion actor-role drift $cid"
      return 1
    }
    [[ $reference_role == "$expected_reference" ]] || {
      statusline "Mempool/Genesis authority exclusion Codex-R drift $cid"
      return 1
    }
    [[ -z $first_role && -z $second_role ]] || {
      statusline "Mempool/Genesis authority exclusion candidate-presence drift $cid"
      return 1
    }
  done
}

reconcile_mg_channels() {
  local action=$1 visibility=$2 channel_rows=$3 i=$4
  local cid members projection owner_role first_presence second_presence presence
  local rachel_role codexr_role target label role out verified
  validate_mg_roster || {
    mg_blocked=$((mg_blocked + 1))
    return 1
  }
  while IFS=$'\t' read -r cid _encoded_name; do
    [[ -n $cid ]] || continue
    in_mg_exclusions "$cid" && continue
    in_mg_allowlist "$cid" || continue
    if ! members=$(buzz_as "$owner_key" "" channels members --channel "$cid" 2>/dev/null); then
      statusline "owner: Mempool/Genesis member read FAILED $cid"
      mg_blocked=$((mg_blocked + 1))
      continue
    fi
    if ! projection=$(mg_member_projection "$expected_owner_pubkey" "${mg_pubkeys[0]}" "${mg_pubkeys[1]}" <<<"$members"); then
      statusline "owner: Mempool/Genesis member projection INVALID $cid"
      mg_blocked=$((mg_blocked + 1))
      continue
    fi
    IFS=$'\t' read -r owner_role first_presence second_presence <<<"$projection"
    if [[ $owner_role != owner ]]; then
      statusline "owner: Mempool/Genesis owner authority UNMET $cid"
      mg_blocked=$((mg_blocked + 1))
      continue
    fi
    rachel_role=$(member_role "$rachel_pubkey" <<<"$members")
    if [[ $visibility == private && $rachel_role == owner ]]; then
      statusline "owner: Mempool/Genesis skipped Rachel/Archimedes private $cid"
      continue
    fi
    codexr_role=$(member_role "$codexr_pubkey" <<<"$members")
    if [[ -z $codexr_role ]]; then
      statusline "owner: Mempool/Genesis skipped non-Codex-R channel $cid"
      continue
    fi
    target=${mg_pubkeys[$i]}
    label=${mg_labels[$i]}
    if [[ $i -eq 0 ]]; then
      presence=$first_presence
    else
      presence=$second_presence
    fi
    if [[ $presence == present ]]; then
      mg_already=$((mg_already + 1))
      continue
    fi
    mg_planned=$((mg_planned + 1))
    if [[ $action == dry-run ]]; then
      printf 'PLAN owner add-member visibility=%s channel=%s label=%s pubkey=%s role=member\n' "$visibility" "$cid" "$label" "$target"
    fi
    [[ $action == apply ]] || continue
    if ! activation_transaction plan-membership --state-dir "$activation_state" \
      --slug "${mg_labels[$i],,}" --channel-id "$cid" --pubkey "$target"; then
      statusline "$label transaction journal FAILED before membership write $cid"
      failed=$((failed + 1))
      continue
    fi
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
        if ! role=$(member_role "$target" <<<"$verified"); then
          statusline "$label owner add-member verification FAILED $cid"
          failed=$((failed + 1))
          continue
        fi
        if [[ $role != member && $role != bot ]]; then
          statusline "$label owner add-member verification FAILED $cid"
          failed=$((failed + 1))
          continue
        fi
        if ! activation_transaction confirm-membership --state-dir "$activation_state" \
          --slug "${mg_labels[$i],,}" --channel-id "$cid" --pubkey "$target"; then
          statusline "$label transaction confirmation FAILED $cid"
          failed=$((failed + 1))
          continue
        fi
        statusline "$label joined $visibility $cid by owner add-member"
        mg_writes=$((mg_writes + 1))
      elif grep -qi 'archived' <<<"$out"; then
        statusline "$label owner add-member skipped archived $cid"
        archived_rejected=$((archived_rejected + 1))
      else
        statusline "$label owner add-member FAILED $cid: $(sanitize <<<"$out")"
        failed=$((failed + 1))
      fi
  done <<<"$channel_rows"
  statusline "${mg_labels[$i]} $visibility roster: planned=$mg_planned writes=$mg_writes already=$mg_already blocked=$mg_blocked"
  [[ $mg_blocked -eq 0 && $failed -eq 0 ]]
}

if ! open_channels=$(list_live_channels open "$owner_key" "" 2>/dev/null); then
  statusline "owner: live open channel list failed or relay unreachable"
  failed=$((failed + 1))
  open_channels=
elif [[ -z $open_channels ]]; then
  statusline "owner: live open channel list empty"
  failed=$((failed + 1))
fi
if ! mg_private_channels=$(list_live_channels private "$owner_key" "" true 2>/dev/null); then
  statusline "owner: private channel list failed or relay unreachable"
  failed=$((failed + 1))
  mg_private_channels=
fi

reconcile_mg_parity() {
  local action=$1 i
  local -a indices=(0 1)
  validate_mg_roster || {
    mg_blocked=$((mg_blocked + 1))
    return 1
  }
  verify_mg_authority_exclusions || {
    mg_blocked=$((mg_blocked + 1))
    return 1
  }
  [[ $mg_agent == mempool ]] && indices=(0)
  [[ $mg_agent == genesis ]] && indices=(1)
  for i in "${indices[@]}"; do
    reconcile_mg_channels "$action" open "$open_channels" "$i"
    reconcile_mg_channels "$action" private "$mg_private_channels" "$i"
  done
}

rollback_mg_activation() {
  local plan slug cid target confirmed members role out verified
  activation_transaction begin-rollback --state-dir "$activation_state" --root "$activation_root"
  plan=$("$transaction_tool" rollback-plan --state-dir "$activation_state") || return 1
  mapfile -t rollback_rows < <(python3 -c '
import json,re,sys
channel = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
pubkey = re.compile(r"^[0-9a-f]{64}$")
for item in json.load(sys.stdin):
    if item.get("slug") not in {"mempool","genesis"} or not channel.fullmatch(item.get("channel_id","")) or not pubkey.fullmatch(item.get("pubkey","")):
        raise SystemExit("invalid rollback membership plan")
    if not isinstance(item.get("confirmed"), bool):
        raise SystemExit("invalid rollback confirmation state")
    print(item["slug"], item["channel_id"], item["pubkey"], str(item["confirmed"]).lower(), sep="\t")
' <<<"$plan") || return 1
  for row in "${rollback_rows[@]}"; do
    IFS=$'\t' read -r slug cid target confirmed <<<"$row"
    members=$(buzz_as "$owner_key" "" channels members --channel "$cid" 2>/dev/null) || {
      statusline "$slug membership rollback read FAILED $cid"
      return 1
    }
    role=$(member_role "$target" <<<"$members")
    if [[ -z $role ]]; then
      activation_transaction mark-membership-rolled-back --state-dir "$activation_state" \
        --slug "$slug" --channel-id "$cid" --pubkey "$target"
      continue
    fi
    if [[ $confirmed != true ]]; then
      statusline "$slug unconfirmed membership intent blocks destructive rollback $cid"
      return 1
    fi
    if [[ $role != member ]]; then
      statusline "$slug membership drift blocks rollback $cid"
      return 1
    fi
    out=$(buzz_as "$owner_key" "" channels remove-member --channel "$cid" --pubkey "$target" 2>&1) || {
      statusline "$slug owner remove-member FAILED $cid: $(sanitize <<<"$out")"
      return 1
    }
    python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("accepted") is True else 1)' <<<"$out" || {
      statusline "$slug owner remove-member rejected $cid"
      return 1
    }
    verified=$(buzz_as "$owner_key" "" channels members --channel "$cid" 2>/dev/null) || return 1
    [[ -z $(member_role "$target" <<<"$verified") ]] || {
      statusline "$slug membership rollback verification FAILED $cid"
      return 1
    }
    activation_transaction mark-membership-rolled-back --state-dir "$activation_state" \
      --slug "$slug" --channel-id "$cid" --pubkey "$target"
  done
  activation_transaction finish-rollback --state-dir "$activation_state" --root "$activation_root"
  statusline "Mempool/Genesis activation rollback complete"
}

case $mg_mode in
  check)
    if ! reconcile_mg_parity check; then
      exit 1
    fi
    printf '%s\n' "PREFLIGHT OK: read-only Mempool/Genesis reconciliation can proceed"
    exit 0
    ;;
  dry-run)
    if ! reconcile_mg_parity dry-run; then
      exit 1
    fi
    printf '%s\n' "DRY RUN OK: no channel writes performed"
    exit 0
    ;;
  apply)
    activation_transaction begin-phase --state-dir "$activation_state" --slug "$mg_agent"
    apply_status=0
    if ! reconcile_mg_parity apply; then
      apply_status=1
    fi
    if ! bound_sweep_log; then
      exit 1
    fi
    exit "$apply_status"
    ;;
  complete)
    activation_transaction complete-phase --state-dir "$activation_state" \
      --slug "$mg_agent" --gate-receipt "$phase_gate_receipt"
    printf '%s\n' "$mg_agent activation phase complete"
    exit 0
    ;;
  rollback)
    rollback_mg_activation
    exit 0
    ;;
  full)
    reconcile_mg_parity check || failed=$((failed + 1))
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
if out=$("$sudo_bin" -n -u sats "$archimedes_sync" 2>&1); then
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
if ! bound_sweep_log; then
  exit 1
fi
[[ $failed -eq 0 ]]
