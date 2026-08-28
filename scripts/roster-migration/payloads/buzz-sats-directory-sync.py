#!/usr/bin/env python3
"""Keep BUZZ_SATS_* kind:10100 records aligned with live memberships.

The script updates channel_ids, creates missing records from a fixed Sats
configuration table, and fills missing mention-eligibility fields. It preserves
existing fields and never prints private keys or auth tags.

This script is the sole writer for these agents' kind:10100 records until
buzz-acp publishes its own directory updates. Retire this timer step when that
writer lands instead of running both writers concurrently.
"""
import argparse
import asyncio
import json
import os
import re
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INSTALLED_TOOL_DIR = "/home/victor/.agents/tools"
sys.path.insert(0, SCRIPT_DIR)
if SCRIPT_DIR != INSTALLED_TOOL_DIR:
    sys.path.insert(0, INSTALLED_TOOL_DIR)
import websockets

from nostr_min import finish_event, pubkey_xonly


RELAY = os.environ.get(
    "BUZZ_RELAY_URL", "wss://framework-desktop.tail69757d.ts.net:38443"
)
VICTOR = "4a34c131ec5cb5dd9a200bac619bbd103c0793e068fad278d1de59203d05b97d"
RACHEL = "7806a7beb69ba4fd3b6e9b86d56931a446b62666e9794533f87fb2d1b956684f"
MASON = "1a536702f3eb8db5cd9cbb661cc2bdbf863ff011ddf2fc652309e1c225fd8a19"

CONFIG = {
    "CLAUDE": ("claude", None, "owner_only", [VICTOR, RACHEL, MASON]),
    "CLAUDE_R": ("claude", None, "owner_only", [VICTOR, RACHEL, MASON]),
    "CODEX": ("codex", None, "owner_only", [VICTOR, RACHEL, MASON]),
    "CODEX_R": ("codex", None, "owner_only", [VICTOR]),
    "CODEX2": ("codex", "UTXO", "owner_only", [VICTOR, RACHEL, MASON]),
    "DSV4F": ("qwen", "Knots", "anyone", [VICTOR, RACHEL, MASON]),
    "GLM": ("glm", "Segwit", "anyone", [VICTOR, RACHEL, MASON]),
    "GLM52": ("glm", "Ledger", "anyone", [VICTOR, RACHEL, MASON]),
}
PREVIOUS_DISPLAY_NAMES = {
    "CODEX2": "Sats Codex-2",
    "DSV4F": "Sats DSV4F",
    "GLM": "Sats GLM5.2.1",
    "GLM52": "Sats GLM5.2",
}


async def connect_as(sk, auth_tag):
    ws = await websockets.connect(RELAY, open_timeout=10)
    await ws.send(json.dumps(["REQ", "warm", {"kinds": [10100], "limit": 1}]))
    while True:
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        if msg[0] == "AUTH":
            tags = [["relay", RELAY], ["challenge", msg[1]]]
            if auth_tag:
                tags.append(auth_tag)
            ev = {
                "kind": 22242,
                "created_at": int(time.time()),
                "content": "",
                "tags": tags,
            }
            finish_event(ev, sk)
            await ws.send(json.dumps(["AUTH", ev]))
        elif msg[0] == "OK":
            if not msg[2]:
                raise RuntimeError("relay authentication rejected")
            return ws
        elif msg[0] == "EOSE":
            return ws


async def req(ws, sub, flt):
    await ws.send(json.dumps(["REQ", sub, flt]))
    out = []
    while True:
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=15))
        if msg[0] == "EVENT" and msg[1] == sub:
            out.append(msg[2])
        elif msg[0] in ("EOSE", "CLOSED") and msg[1] == sub:
            await ws.send(json.dumps(["CLOSE", sub]))
            if msg[0] == "CLOSED":
                raise RuntimeError("relay closed query")
            return out


def tagmap(ev):
    result = {}
    for tag in ev.get("tags", []):
        if tag:
            result.setdefault(tag[0], []).append(tag[1:])
    return result


def latest(events):
    return max(events, key=lambda event: (event.get("created_at", 0), event.get("id", "")))


def record_version(event):
    if event is None:
        return None
    return event.get("id"), event.get("created_at")


def auth_owner(tag):
    if not tag or tag[0] != "auth" or len(tag) < 2 or not tag[1]:
        raise ValueError("invalid auth tag")
    return tag[1]


def profile_field_state(profile, field):
    if field not in profile:
        return {"present": False}
    value = profile[field]
    if not isinstance(value, str):
        raise ValueError(f"kind:0 {field} must be a string when present")
    return {"present": True, "value": value}


def apply_profile_field_state(profile, field, state):
    if not isinstance(state, dict) or state.get("present") not in (True, False):
        raise ValueError(f"invalid kind:0 {field} state")
    if state["present"]:
        if set(state) != {"present", "value"} or not isinstance(state["value"], str):
            raise ValueError(f"invalid present kind:0 {field} state")
        profile[field] = state["value"]
    elif state != {"present": False}:
        raise ValueError(f"invalid absent kind:0 {field} state")
    else:
        profile.pop(field, None)


def preserved_auth_tags(tags, env_auth):
    stored_auths = [tag for tag in tags if tag and tag[0] == "auth"]
    if len(stored_auths) > 1:
        raise RuntimeError("event has multiple auth tags")
    stored_auth = stored_auths[0] if stored_auths else None
    if stored_auth and env_auth and auth_owner(stored_auth) != auth_owner(env_auth):
        raise RuntimeError("refusing to change auth owner")
    chosen_auth = env_auth or stored_auth
    new_tags = [tag for tag in tags if not tag or tag[0] != "auth"]
    if chosen_auth:
        new_tags.append(chosen_auth)
    return new_tags


async def publish_kind0(ws, current, content, tags, env_auth, sk):
    previous = current.get("created_at", 0)
    raw_content = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
    prepublish_events = await req(ws, "profile-prepublish", {"kinds": [0], "authors": [current["pubkey"]]})
    prepublish = latest(prepublish_events) if prepublish_events else None
    if record_version(prepublish) != record_version(current):
        raise RuntimeError("kind:0 changed during sync; deferred to next cycle")
    event = {
        "kind": 0,
        "created_at": max(int(time.time()), previous + 1),
        "content": raw_content,
        "tags": preserved_auth_tags(tags, env_auth),
    }
    finish_event(event, sk)
    await ws.send(json.dumps(["EVENT", event]))
    while True:
        message = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        if message[0] == "OK" and message[1] == event["id"]:
            if not message[2]:
                raise RuntimeError("relay rejected kind:0")
            break
    readback_events = await req(ws, "profile-readback", {"kinds": [0], "authors": [current["pubkey"]]})
    if not readback_events:
        raise RuntimeError("kind:0 readback is empty")
    readback = latest(readback_events)
    if readback.get("id") != event["id"] or readback.get("content") != raw_content:
        raise RuntimeError("kind:0 readback mismatch")


async def handle(prefix, dry_run=False, sync_kind0=False, restore_kind0=None):
    short = prefix.removeprefix("SATS_")
    if short not in CONFIG:
        raise RuntimeError("missing fixed configuration")
    agent_type, configured_display_name, new_policy, allowlist = CONFIG[short]
    raw_key = os.environ[f"BUZZ_{prefix}_PRIVATE_KEY"].strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", raw_key):
        raise ValueError("private key has invalid format")
    sk = bytes.fromhex(raw_key)
    pk = pubkey_xonly(sk).hex()
    raw_tag = os.environ.get(f"BUZZ_{prefix}_AUTH_TAG", "").strip()
    env_auth = json.loads(raw_tag) if raw_tag else None
    if env_auth:
        auth_owner(env_auth)

    ws = await connect_as(sk, env_auth)
    try:
        metas = await req(ws, "meta", {"kinds": [39000]})
        members = await req(ws, "members", {"kinds": [39002]})
        current_events = await req(ws, "current", {"kinds": [10100], "authors": [pk]})
        profiles = await req(ws, "profile", {"kinds": [0], "authors": [pk]})

        info = {}
        for event in metas:
            tags = tagmap(event)
            channel_id = tags.get("d", [[""]])[0][0]
            if channel_id:
                info[channel_id] = {
                    "name": tags.get("name", [[""]])[0][0],
                    "type": tags.get("t", [[""]])[0][0],
                    "archived": tags.get("archived", [[]])[0][:1] == ["true"],
                }
        mine = set()
        for event in members:
            tags = tagmap(event)
            channel_id = tags.get("d", [[""]])[0][0]
            if channel_id and any(tag and tag[0] == pk for tag in tags.get("p", [])):
                mine.add(channel_id)
        wanted = sorted(
            channel_id
            for channel_id in mine
            if channel_id in info
            and info[channel_id]["type"] != "dm"
            and not info[channel_id]["archived"]
        )
        if not wanted:
            raise RuntimeError("live channel membership is empty")

        current = latest(current_events) if current_events else None
        if current:
            content = json.loads(current["content"])
            if not isinstance(content, dict):
                raise ValueError("kind:10100 content is not an object")
            tags = [list(tag) for tag in current.get("tags", [])]
        else:
            content = {}
            tags = []

        profile_event = latest(profiles) if profiles else None
        if profile_event is None:
            raise RuntimeError("kind:0 profile is missing")
        profile = json.loads(profile_event["content"])
        if not isinstance(profile, dict):
            raise ValueError("kind:0 profile content is not an object")
        original_name = profile_field_state(profile, "name")
        profile_changed = False
        if restore_kind0 is not None:
            if not isinstance(restore_kind0, dict) or set(restore_kind0) != {"name", "display_name"}:
                raise ValueError("invalid kind:0 restore snapshot")
            before = json.dumps(profile, sort_keys=True)
            apply_profile_field_state(profile, "name", restore_kind0["name"])
            apply_profile_field_state(profile, "display_name", restore_kind0["display_name"])
            profile_changed = json.dumps(profile, sort_keys=True) != before
        elif sync_kind0:
            if not configured_display_name:
                raise RuntimeError("kind:0 sync requires a configured display name")
            if profile.get("display_name") != configured_display_name:
                profile["display_name"] = configured_display_name
                profile_changed = True
        if profile_field_state(profile, "name") != original_name and restore_kind0 is None:
            raise RuntimeError("kind:0 name preservation failed")
        if profile_changed and not dry_run:
            await publish_kind0(
                ws,
                profile_event,
                profile,
                [list(tag) for tag in profile_event.get("tags", [])],
                env_auth,
                sk,
            )
        display_name = configured_display_name or (
            profile.get("display_name")
            or profile.get("name")
            or content.get("display_name")
            or content.get("name")
        )
        if not display_name:
            raise RuntimeError("kind:0 profile has no display name")

        changed = False

        def set_if_missing(key, value):
            nonlocal changed
            if not content.get(key):
                content[key] = value
                changed = True

        for key, value in (
            ("display_name", display_name),
            ("name", display_name),
            ("agent_type", agent_type),
        ):
            if content.get(key) != value:
                content[key] = value
                changed = True
        if current is None:
            content.update(
                {
                    "respond_to": "allowlist",
                    "respond_to_allowlist": allowlist,
                    "channel_add_policy": new_policy,
                    "status": "online",
                }
            )
            changed = True
        elif not content.get("respond_to"):
            content["respond_to"] = "allowlist"
            content["respond_to_allowlist"] = allowlist
            changed = True
        elif content.get("respond_to") == "allowlist" and not content.get("respond_to_allowlist"):
            content["respond_to_allowlist"] = allowlist
            changed = True

        have = sorted(content.get("channel_ids", []) or [])
        wanted_names = [info[channel_id]["name"] for channel_id in wanted]
        if have != wanted or content.get("channels") != wanted_names:
            content["channel_ids"] = wanted
            content["channels"] = wanted_names
            changed = True

        new_tags = preserved_auth_tags(tags, env_auth)
        if new_tags != tags:
            changed = True

        if not changed:
            return f"{prefix}: in sync ({len(wanted)} channels)"
        if dry_run:
            return f"{prefix}: would republish ({len(wanted)} channels)"

        previous = current.get("created_at", 0) if current else 0
        raw_content = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
        prepublish_events = await req(
            ws, "prepublish", {"kinds": [10100], "authors": [pk]}
        )
        prepublish = latest(prepublish_events) if prepublish_events else None
        if record_version(prepublish) != record_version(current):
            raise RuntimeError("kind:10100 changed during sync; deferred to next cycle")
        event = {
            "kind": 10100,
            "created_at": max(int(time.time()), previous + 1),
            "content": raw_content,
            "tags": new_tags,
        }
        finish_event(event, sk)
        await ws.send(json.dumps(["EVENT", event]))
        while True:
            message = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
            if message[0] == "OK" and message[1] == event["id"]:
                if not message[2]:
                    raise RuntimeError("relay rejected kind:10100")
                break

        readback_events = await req(
            ws, "readback", {"kinds": [10100], "authors": [pk]}
        )
        if not readback_events:
            raise RuntimeError("kind:10100 readback is empty")
        readback = latest(readback_events)
        if readback.get("id") != event["id"] or readback.get("content") != raw_content:
            raise RuntimeError("kind:10100 readback mismatch")
        return f"{prefix}: republished {len(have)}->{len(wanted)} channels and verified readback"
    finally:
        await ws.close()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--prefix", action="append", default=[])
    parser.add_argument("--previous-names", action="store_true")
    parser.add_argument("--sync-kind0", action="store_true")
    parser.add_argument("--restore-kind0-stdin", action="store_true")
    parser.add_argument("--preflight-owner", action="store_true")
    args = parser.parse_args()
    if args.preflight_owner:
        raw_key = sys.stdin.read().strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", raw_key):
            print("owner key preflight failed", file=sys.stderr)
            return 1
        if pubkey_xonly(bytes.fromhex(raw_key)).hex() != VICTOR:
            print("owner key preflight failed", file=sys.stderr)
            return 1
        print(json.dumps({"owner": VICTOR, "status": "pass"}, sort_keys=True))
        return 0
    if args.sync_kind0 and args.restore_kind0_stdin:
        print("kind:0 sync and restore modes are mutually exclusive", file=sys.stderr)
        return 1
    prefixes = sorted(
        match.group(1)
        for variable in os.environ
        for match in [re.match(r"^BUZZ_(SATS_[A-Z0-9_]+)_PRIVATE_KEY$", variable)]
        if match
    )
    if not prefixes:
        print("no BUZZ_SATS_* keys in environment", file=sys.stderr)
        return 1
    if args.prefix:
        wanted_prefixes = set(args.prefix)
        unknown = wanted_prefixes - set(prefixes)
        if unknown:
            print("requested prefix is not present", file=sys.stderr)
            return 1
        prefixes = [prefix for prefix in prefixes if prefix in wanted_prefixes]
    if args.previous_names:
        for short, display_name in PREVIOUS_DISPLAY_NAMES.items():
            agent_type, _, policy, allowlist = CONFIG[short]
            CONFIG[short] = (agent_type, display_name, policy, allowlist)
    restore_snapshots = None
    if args.restore_kind0_stdin:
        try:
            restore_snapshots = json.loads(sys.stdin.read())
        except json.JSONDecodeError:
            print("invalid kind:0 restore JSON", file=sys.stderr)
            return 1
        if not isinstance(restore_snapshots, dict) or set(restore_snapshots) != set(prefixes):
            print("kind:0 restore inventory mismatch", file=sys.stderr)
            return 1
    rc = 0
    for prefix in prefixes:
        try:
            print(await handle(
                prefix,
                args.dry_run,
                sync_kind0=args.sync_kind0,
                restore_kind0=restore_snapshots.get(prefix) if restore_snapshots else None,
            ))
        except Exception as error:
            rc = 1
            print(f"{prefix}: ERROR {type(error).__name__}: {str(error)[:160]}")
    return rc


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
