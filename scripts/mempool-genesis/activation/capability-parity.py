#!/usr/bin/env python3
"""Build and compare secret-safe Codex-R capability parity manifests."""

from __future__ import annotations

import argparse
import copy
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time
import tomllib
from typing import Any

OBSERVATION_SCHEMA = "buzz-agent-capability-observation-v1"
MANIFEST_SCHEMA = "buzz-agent-capability-manifest-v1"
POLICY_SCHEMA = "buzz-agent-capability-parity-policy-v2"
RECEIPT_SCHEMA = "buzz-agent-capability-parity-receipt-v2"
SEALED_RECEIPT_SCHEMA = "buzz-agent-capability-parity-sealed-receipt-v1"
SIGNATURE_SCHEMA = "buzz-agent-capability-parity-signature-v1"
BINDING_SCHEMA = "buzz-agent-activation-binding-v1"
SIGNER_TARGET_NAME = "buzz-parity-owner-signer"
VERIFIER_TARGET_NAME = "buzz-parity-owner-verifier"
ROOT_VERIFIER_TARGET = "/usr/local/libexec/buzz/buzz-agent-key-handoff"
CAPTURE_SCHEMA = "buzz-agent-capability-capture-spec-v1"
CANONICAL_JSON_CONTRACT = "buzz-canonical-json-ascii-v1"
AUTHORITY_RECEIPT_SCHEMA = "buzz-agent-capability-authority-receipt-v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX_PREFIX = re.compile(r"^[0-9a-f]{12,16}$")
ROLE_SLUGS = {"reference": None, "mempool": "mempool", "genesis": "genesis"}
ROOT_KEYS = {
    "home", "codex_home", "xdg_config", "xdg_cache", "xdg_state", "temporary",
    "runtime", "state", "environment", "prompt", "credential", "profile_event",
    "directory_event", "acceptance", "claim", "install_receipt", "rollback_receipt",
    "backup", "activation_receipt",
}
RUNTIME_KEYS = {
    "model", "reasoning_effort", "agent_command", "mcp_command", "codex_config",
    "memory", "agents", "subscribe", "multiple_event_handling", "context_message_limit",
    "idle_timeout", "max_turn_duration", "turn_liveness_secs", "permission_mode",
    "environment_keys", "closure",
}
COMMON_CLOSURE = {
    "launcher", "codex_cli", "codex_acp", "codex_code_mode_host", "mcp", "node",
    "wrapper", "buzz_acp",
}
CLOSURE_KEYS = COMMON_CLOSURE | {"service_unit"}
EXPECTED_CANDIDATE_CLOSURE_PATHS = {
    "launcher": "/usr/local/libexec/buzz/run-buzz-agent",
    "codex_cli": "/usr/local/libexec/buzz/codex",
    "codex_acp": "/usr/local/libexec/buzz/codex-acp",
    "codex_code_mode_host": "/usr/local/libexec/buzz/codex-code-mode-host",
    "mcp": "/usr/local/libexec/buzz/buzz-dev-mcp",
    "node": "/usr/local/libexec/buzz/node",
    "wrapper": "/usr/local/libexec/buzz/verify-installed-agent",
    "buzz_acp": "/usr/local/libexec/buzz/buzz-acp",
}
REQUIRED_HARDENING = {
    "UMask": "0077",
    "NoNewPrivileges": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "read-only",
    "PrivateDevices": "yes",
    "PrivateTmp": "yes",
    "CapabilityBoundingSet": [],
    "AmbientCapabilities": [],
}
ALLOWED_SCOPES = {"open", "sats-victor-private"}
CHANNEL_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
BENIGN_TOKEN_FIELDS = re.compile(
    r"^(?:tool_output_token_limit|max_output_tokens|token_(?:budget|count|limit|usage))$"
)
HARD_SENSITIVE_KEY_FIELDS = re.compile(
    r"(^|_)(?:private_key|secret_key|api_key|access_key|signing_key|encryption_key|"
    r"cookie|oauth|client_secret|auth_tag_payload|secret_value)($|_)"
)
SENSITIVE_KEY_FIELDS = re.compile(
    r"(^|_)(?:private_key|secret_key|api_key|access_key|signing_key|encryption_key|"
    r"token|access_token|refresh_token|api_token|bearer_token|session_token|id_token|"
    r"cookie|oauth|client_secret|auth_tag_payload|secret_value)($|_)"
)


class ParityError(ValueError):
    pass


def _validate_canonical_json(value: object, where: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if type(value) is int:
        if -(1 << 63) <= value <= (1 << 63) - 1:
            return
        raise ParityError(f"{where} integer is outside signed 64-bit range")
    if isinstance(value, str):
        if all(0x20 <= ord(character) <= 0x7E for character in value):
            return
        raise ParityError(f"{where} string is outside printable ASCII")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_canonical_json(item, f"{where}/{index}")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key or not all(
                0x20 <= ord(character) <= 0x7E for character in key
            ):
                raise ParityError(f"{where} object key is outside printable ASCII")
            _validate_canonical_json(item, f"{where}/{key}")
        return
    raise ParityError(f"{where} has unsupported canonical JSON type")


def canonical_json(value: object) -> bytes:
    _validate_canonical_json(value)
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def exact_keys(value: object, expected: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ParityError(f"{where} has wrong fields")
    return value


def regular_json(path: Path, *, owner_only: bool = True) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ParityError(f"unsafe JSON input: {path}")
    if owner_only and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ParityError(f"JSON input is not owner-only: {path}")
    value = json.loads(path.read_bytes(), object_pairs_hook=_reject_duplicates)
    if not isinstance(value, dict):
        raise ParityError(f"JSON input is not an object: {path}")
    return value


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ParityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def write_private(path: Path, value: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
    )
    try:
        payload = canonical_json(value)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while writing parity artifact")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def secret_bearing_key(key: str) -> bool:
    normalized = key.lower()
    if HARD_SENSITIVE_KEY_FIELDS.search(normalized):
        return True
    if BENIGN_TOKEN_FIELDS.fullmatch(normalized):
        return False
    return SENSITIVE_KEY_FIELDS.search(normalized) is not None


def reject_secret_values(value: object, where: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            descriptor_role = where.endswith("/secret_files") and key == "buzz_private_key"
            if secret_bearing_key(key) and not descriptor_role:
                raise ParityError(f"secret-bearing field is forbidden at {where}/{key}")
            reject_secret_values(child, f"{where}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_values(child, f"{where}/{index}")
    elif isinstance(value, str):
        if re.search(r"(?:nsec1|sk-[A-Za-z0-9_-]{16}|eyJ[a-zA-Z0-9_-]{16})", value):
            raise ParityError(f"secret-looking value is forbidden at {where}")


def validate_secret_descriptor(value: object, where: str) -> dict[str, Any]:
    descriptor = exact_keys(
        value,
        {
            "path_class", "present", "file_type", "character_class", "length", "mode", "owner",
            "group", "nlink", "device", "inode", "sha256_prefix",
        },
        where,
    )
    if descriptor["present"] is not True or descriptor["file_type"] != "regular":
        raise ParityError(f"{where} is not a present regular file")
    if not isinstance(descriptor["path_class"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._:-]{2,127}", descriptor["path_class"]
    ):
        raise ParityError(f"{where} path class is invalid")
    if descriptor["mode"] != "0600" or descriptor["nlink"] != 1:
        raise ParityError(f"{where} mode or link count is unsafe")
    if not isinstance(descriptor["length"], int) or descriptor["length"] <= 0:
        raise ParityError(f"{where} has invalid length")
    if not isinstance(descriptor["device"], int) or not isinstance(descriptor["inode"], int):
        raise ParityError(f"{where} has invalid inode identity")
    if descriptor["device"] < 0 or descriptor["inode"] <= 0:
        raise ParityError(f"{where} has invalid inode identity")
    if not all(isinstance(descriptor[key], str) and descriptor[key] for key in ("owner", "group")):
        raise ParityError(f"{where} has invalid ownership")
    if descriptor["character_class"] not in {
        "lowercase-hex", "bech32", "utf8-json", "utf8-ascii", "utf8", "binary",
    }:
        raise ParityError(f"{where} has invalid character class")
    if not isinstance(descriptor["sha256_prefix"], str) or not HEX_PREFIX.fullmatch(
        descriptor["sha256_prefix"]
    ):
        raise ParityError(f"{where} has invalid truncated SHA-256")
    return descriptor


def validate_policy(value: object) -> dict[str, Any]:
    policy = exact_keys(
        value,
        {
            "schema", "canonical_json_contract", "owner_pubkey", "reserved_pubkeys",
            "allowed_identity_differences", "response_policy", "reference_channels",
            "eligible_channels", "authority_exclusions", "approved_exceptions",
            "forbidden_path_prefixes",
        },
        "policy",
    )
    if (
        policy["schema"] != POLICY_SCHEMA
        or policy["canonical_json_contract"] != CANONICAL_JSON_CONTRACT
        or not HEX64.fullmatch(policy["owner_pubkey"])
    ):
        raise ParityError("policy schema or owner is invalid")
    if not isinstance(policy["reserved_pubkeys"], list) or not all(
        isinstance(item, str) and HEX64.fullmatch(item) for item in policy["reserved_pubkeys"]
    ):
        raise ParityError("policy reserved identities are invalid")
    if not isinstance(policy["allowed_identity_differences"], list) or not all(
        isinstance(item, str) and item.startswith("/")
        for item in policy["allowed_identity_differences"]
    ) or len(set(policy["allowed_identity_differences"])) != len(policy["allowed_identity_differences"]):
        raise ParityError("policy allowed identity differences are invalid")
    response = exact_keys(
        policy["response_policy"],
        {"respond_to", "allowed_respond_to", "responder_allowlist", "owner_pubkey"},
        "policy/response_policy",
    )
    if response != {
        "respond_to": "allowlist",
        "allowed_respond_to": "allowlist",
        "responder_allowlist": [policy["owner_pubkey"]],
        "owner_pubkey": policy["owner_pubkey"],
    }:
        raise ParityError("policy response policy does not match Codex-R")
    reference_channels = policy["reference_channels"]
    eligible_channels = policy["eligible_channels"]
    if not isinstance(reference_channels, list) or len(reference_channels) != 26:
        raise ParityError("policy must bind exactly 26 reference channels")
    if not isinstance(eligible_channels, list) or len(eligible_channels) != 25:
        raise ParityError("policy must bind exactly 25 eligible channels")

    def validate_channels(channels: list[object], label: str, roles: set[str]) -> list[str]:
        channel_ids: list[str] = []
        for raw in channels:
            channel = exact_keys(
                raw, {"channel_id", "visibility", "scope", "role"}, f"policy/{label}_channel"
            )
            channel_id = channel["channel_id"]
            if not isinstance(channel_id, str) or not CHANNEL_ID.fullmatch(channel_id):
                raise ParityError(f"policy {label} channel ID is invalid")
            if channel["scope"] not in ALLOWED_SCOPES:
                raise ParityError(f"policy {label} channel scope is invalid")
            visibility = "open" if channel["scope"] == "open" else "private"
            if channel["visibility"] != visibility or channel["role"] not in roles:
                raise ParityError(f"policy {label} channel permissions are invalid")
            channel_ids.append(channel_id)
        if channel_ids != sorted(set(channel_ids)):
            raise ParityError(f"policy {label} channel IDs are not sorted and unique")
        return channel_ids

    reference_ids = validate_channels(reference_channels, "reference", {"member", "bot"})
    eligible_ids = validate_channels(eligible_channels, "eligible", {"member"})
    exclusions = policy["authority_exclusions"]
    if not isinstance(exclusions, list) or len(exclusions) != 1:
        raise ParityError("policy must bind exactly one authority exclusion")
    exclusion_ids: list[str] = []
    for raw in exclusions:
        exclusion = exact_keys(
            raw,
            {
                "channel_id", "visibility", "scope", "archived", "required_actor_role",
                "expected_actor_role", "reference", "expected_reference_role",
                "expected_reference_present", "expected_candidates_absent", "reason",
                "disposition", "approval_id",
            },
            "policy/authority_exclusion",
        )
        channel_id = exclusion["channel_id"]
        if not isinstance(channel_id, str) or not CHANNEL_ID.fullmatch(channel_id):
            raise ParityError("policy authority exclusion channel ID is invalid")
        expected = {
            "visibility": "open", "scope": "open", "archived": False,
            "required_actor_role": "owner", "expected_actor_role": "member",
            "reference": "codex-r", "expected_reference_role": "bot",
            "expected_reference_present": True,
            "expected_candidates_absent": ["genesis", "mempool"],
            "reason": "victor-not-channel-owner",
            "disposition": "exclude-from-membership",
            "approval_id": "victor-2026-08-27-buzz-mgact-authority-exclusion-9f7d9f1d",
        }
        if any(exclusion[key] != value for key, value in expected.items()):
            raise ParityError("policy authority exclusion contract is invalid")
        exclusion_ids.append(channel_id)
    if exclusion_ids != sorted(set(exclusion_ids)):
        raise ParityError("policy authority exclusion IDs are not sorted and unique")
    if set(eligible_ids) & set(exclusion_ids):
        raise ParityError("eligible and authority-excluded channels overlap")
    if set(reference_ids) != set(eligible_ids) | set(exclusion_ids):
        raise ParityError("reference channels are not the exact eligible/exclusion union")
    reference_by_id = {item["channel_id"]: item for item in reference_channels}
    for exclusion in exclusions:
        reference = reference_by_id[exclusion["channel_id"]]
        if reference["role"] != exclusion["expected_reference_role"]:
            raise ParityError("authority exclusion reference role does not match reference set")
    exceptions = exact_keys(policy["approved_exceptions"], {"mempool", "genesis"}, "exceptions")
    for slug in ("mempool", "genesis"):
        entry = exact_keys(exceptions[slug], {"host_access", "address_families"}, f"exceptions/{slug}")
        if not isinstance(entry["host_access"], list) or not isinstance(entry["address_families"], list):
            raise ParityError(f"exceptions/{slug} has invalid lists")
        if any(family != "AF_NETLINK" for family in entry["address_families"]):
            raise ParityError(f"exceptions/{slug} has an invalid address-family exception")
        seen: set[str] = set()
        for access in entry["host_access"]:
            record = exact_keys(
                access,
                {"path", "mode", "purpose", "owner", "expires_at", "approval"},
                f"exceptions/{slug}/host_access",
            )
            if not isinstance(record["path"], str) or not record["path"].startswith("/") or record["path"] in seen:
                raise ParityError(f"exceptions/{slug} has an invalid or duplicate host path")
            seen.add(record["path"])
            if record["mode"] not in {"ro", "rw"} or not all(
                isinstance(record[key], str) and record[key]
                for key in ("purpose", "owner", "expires_at", "approval")
            ):
                raise ParityError(f"exceptions/{slug} host-access justification is incomplete")
    return policy


def validate_authority_receipt(
    value: object,
    policy: dict[str, Any],
    manifests: dict[str, dict[str, Any]],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    receipt = exact_keys(
        value,
        {
            "schema", "canonical_json_contract", "captured_at", "expires_at", "relay",
            "source_commit", "source_tree", "package_digest", "policy_sha256",
            "reference_channels", "reference_channels_sha256", "eligible_channels",
            "eligible_channels_sha256", "authority_exclusions",
            "authority_exclusions_sha256", "candidate_pubkeys", "observations",
            "payload_sha256",
        },
        "authority receipt",
    )
    if (
        receipt["schema"] != AUTHORITY_RECEIPT_SCHEMA
        or receipt["canonical_json_contract"] != CANONICAL_JSON_CONTRACT
    ):
        raise ParityError("authority receipt schema or canonical contract mismatch")
    captured_at = receipt["captured_at"]
    expires_at = receipt["expires_at"]
    current = int(time.time()) if now is None else now
    if (
        type(captured_at) is not int
        or type(expires_at) is not int
        or captured_at > current
        or expires_at < current
        or expires_at - captured_at > 300
    ):
        raise ParityError("authority receipt is stale or has invalid freshness")
    if not isinstance(receipt["relay"], str) or not receipt["relay"].startswith("wss://"):
        raise ParityError("authority receipt relay binding is invalid")
    for field in ("source_commit", "source_tree"):
        if not isinstance(receipt[field], str) or not re.fullmatch(r"[0-9a-f]{40}", receipt[field]):
            raise ParityError(f"authority receipt {field} is invalid")
    if not isinstance(receipt["package_digest"], str) or not HEX64.fullmatch(
        receipt["package_digest"]
    ):
        raise ParityError("authority receipt package digest is invalid")
    expected_lists = {
        "reference_channels": policy["reference_channels"],
        "eligible_channels": policy["eligible_channels"],
        "authority_exclusions": policy["authority_exclusions"],
    }
    if receipt["policy_sha256"] != digest(policy):
        raise ParityError("authority receipt policy digest mismatch")
    for field, expected in expected_lists.items():
        if receipt[field] != expected or receipt[f"{field}_sha256"] != digest(expected):
            raise ParityError(f"authority receipt {field} binding mismatch")
    candidate_pubkeys = exact_keys(
        receipt["candidate_pubkeys"], {"mempool", "genesis"}, "authority candidate pubkeys"
    )
    if any(
        not isinstance(candidate_pubkeys[slug], str)
        or not HEX64.fullmatch(candidate_pubkeys[slug])
        or candidate_pubkeys[slug] != manifests[slug]["identity"]["pubkey"]
        for slug in ("mempool", "genesis")
    ):
        raise ParityError("authority receipt candidate identities are unbound or mismatched")
    observations = receipt["observations"]
    if not isinstance(observations, list) or len(observations) != len(
        policy["authority_exclusions"]
    ):
        raise ParityError("authority receipt observation inventory mismatch")
    expected_observations = [
        {
            "channel_id": exclusion["channel_id"],
            "visibility": exclusion["visibility"],
            "archived": exclusion["archived"],
            "actor_role": exclusion["expected_actor_role"],
            "reference_present": exclusion["expected_reference_present"],
            "reference_role": exclusion["expected_reference_role"],
            "candidate_presence": {"genesis": "absent", "mempool": "absent"},
        }
        for exclusion in policy["authority_exclusions"]
    ]
    if observations != expected_observations:
        raise ParityError("authority receipt observation drift")
    unsigned = copy.deepcopy(receipt)
    recorded = unsigned.pop("payload_sha256")
    if not isinstance(recorded, str) or not HEX64.fullmatch(recorded) or digest(unsigned) != recorded:
        raise ParityError("authority receipt payload digest mismatch")
    return receipt


def validate_manifest(value: object, role: str, policy: dict[str, Any]) -> dict[str, Any]:
    if role not in ROLE_SLUGS:
        raise ParityError(f"unsupported comparison role: {role}")
    reject_secret_values(value)
    manifest = exact_keys(
        value,
        {
            "schema", "captured_at", "slug", "display_name", "identity", "roots", "runtime",
            "response_policy", "channels", "profile", "directory", "systemd", "secret_files", "prompt",
            "receipts",
        },
        role,
    )
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ParityError(f"{role} manifest schema mismatch")
    slug = manifest["slug"]
    expected_slug = ROLE_SLUGS[role]
    if role == "reference" and slug != "codex-r":
        raise ParityError("reference manifest is not Codex-R")
    if expected_slug is not None and slug != expected_slug:
        raise ParityError(f"{role} manifest has wrong slug")
    identity = exact_keys(
        manifest["identity"],
        {"pubkey", "owner_pubkey", "unix_user", "unix_group", "profile_author_pubkey", "auth_tag"},
        f"{role}/identity",
    )
    pubkey = identity["pubkey"]
    if not isinstance(pubkey, str) or not HEX64.fullmatch(pubkey):
        raise ParityError(f"{role} pubkey is invalid")
    if identity["owner_pubkey"] != policy["owner_pubkey"] or identity["profile_author_pubkey"] != pubkey:
        raise ParityError(f"{role} pubkey owner or profile author mismatch")
    auth = exact_keys(
        identity["auth_tag"],
        {"present", "type", "owner_pubkey", "subject_pubkey", "character_class", "length", "sha256_prefix"},
        f"{role}/auth_tag",
    )
    if auth["present"] is not True or auth["type"] != "nip-oa":
        raise ParityError(f"{role} auth tag is absent or wrong type")
    if auth["owner_pubkey"] != policy["owner_pubkey"] or auth["subject_pubkey"] != pubkey:
        raise ParityError(f"{role} auth tag owner or subject mismatch")
    if not HEX_PREFIX.fullmatch(str(auth["sha256_prefix"])):
        raise ParityError(f"{role} auth tag digest is invalid")
    if not isinstance(auth["length"], int) or auth["length"] <= 0:
        raise ParityError(f"{role} auth tag length is invalid")
    if not isinstance(auth["character_class"], str) or not auth["character_class"]:
        raise ParityError(f"{role} auth tag character class is invalid")
    if expected_slug is not None:
        expected_user = f"buzz-{slug}"
        if identity["unix_user"] != expected_user or identity["unix_group"] != expected_user:
            raise ParityError(f"{role} Unix identity mismatch")

    roots = exact_keys(manifest["roots"], ROOT_KEYS, f"{role}/roots")
    for key, path in roots.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise ParityError(f"{role} root {key} is not absolute")
    if expected_slug is not None:
        home = f"/home/buzz-{slug}"
        exact_roots = {
            "home": home,
            "codex_home": f"{home}/.codex",
            "xdg_config": f"{home}/.config",
            "xdg_cache": f"{home}/.cache",
            "xdg_state": f"{home}/.local/state",
            "temporary": f"{home}/.tmp",
            "runtime": f"/run/buzz-agents-{slug}",
            "state": f"{home}/.local/state/buzz-acp",
            "environment": f"/etc/buzz-agents/{slug}.env",
            "prompt": f"/etc/buzz-agents/prompts/{slug}.md",
            "credential": f"/etc/buzz-agents/credentials/{slug}.key",
        }
        for key, expected in exact_roots.items():
            if roots[key] != expected:
                raise ParityError(f"{role} root {key} mismatch")

    runtime = exact_keys(manifest["runtime"], RUNTIME_KEYS, f"{role}/runtime")
    if runtime["model"] != "gpt-5.6-sol" or runtime["reasoning_effort"] != "high":
        raise ParityError(f"{role} model profile is not gpt-5.6-sol high")
    expected_runtime = {
        "memory": True, "agents": 1, "subscribe": "mentions", "multiple_event_handling": "steer",
        "permission_mode": "bypass-permissions",
    }
    for key, expected in expected_runtime.items():
        if runtime[key] != expected:
            raise ParityError(f"{role} runtime setting {key} mismatch")
    if not isinstance(runtime["environment_keys"], list) or runtime["environment_keys"] != sorted(
        set(runtime["environment_keys"])
    ):
        raise ParityError(f"{role} environment key names are not sorted and unique")
    closure = exact_keys(runtime["closure"], CLOSURE_KEYS, f"{role}/runtime/closure")
    for component, record in closure.items():
        item = exact_keys(record, {"path", "sha256", "mode", "owner", "group"}, f"closure/{component}")
        if not isinstance(item["path"], str) or not item["path"].startswith("/"):
            raise ParityError(f"{role} closure path is invalid")
        if not isinstance(item["sha256"], str) or not HEX64.fullmatch(item["sha256"]):
            raise ParityError(f"{role} closure digest is invalid")
        if expected_slug is not None:
            expected_path = EXPECTED_CANDIDATE_CLOSURE_PATHS.get(component)
            if expected_path is not None and item["path"] != expected_path:
                raise ParityError(f"{role} closure path mismatch: {component}")
            expected_mode = "0644" if component == "service_unit" else "0755"
            if item["mode"] != expected_mode or item["owner"] != "root" or item["group"] != "root":
                raise ParityError(f"{role} closure metadata mismatch: {component}")
    if runtime["agent_command"] != closure["codex_acp"]["path"]:
        raise ParityError(f"{role} agent command is outside its captured closure")
    if runtime["mcp_command"] != closure["mcp"]["path"]:
        raise ParityError(f"{role} MCP command is outside its captured closure")

    response = exact_keys(
        manifest["response_policy"],
        {"respond_to", "allowed_respond_to", "responder_allowlist", "owner_pubkey"},
        f"{role}/response_policy",
    )
    if response != policy["response_policy"]:
        raise ParityError(f"{role} response policy does not match Codex-R")

    if not isinstance(manifest["channels"], list):
        raise ParityError(f"{role} channels are invalid")
    reviewed_channels = (
        policy["reference_channels"] if expected_slug is None else policy["eligible_channels"]
    )
    policy_channels = {
        item["channel_id"]: (item["visibility"], item["scope"], item["role"])
        for item in reviewed_channels
    }
    seen_channels: set[str] = set()
    live_members: set[str] = set()
    for channel in manifest["channels"]:
        item = exact_keys(
            channel, {"channel_id", "visibility", "scope", "role", "archived", "eligible"},
            f"{role}/channel",
        )
        cid = item["channel_id"]
        if not isinstance(cid, str) or not cid or cid in seen_channels:
            raise ParityError(f"{role} channel identity is invalid or duplicated")
        seen_channels.add(cid)
        if item["eligible"] and not item["archived"]:
            if item["scope"] not in ALLOWED_SCOPES:
                raise ParityError(f"{role} has ineligible private-channel reach")
            expected_visibility = "open" if item["scope"] == "open" else "private"
            if item["visibility"] != expected_visibility:
                raise ParityError(f"{role} channel scope and visibility mismatch")
            if expected_slug is not None and item["role"] != "member":
                raise ParityError(f"{role} channel role is not member")
            if policy_channels.get(cid) != (item["visibility"], item["scope"], item["role"]):
                raise ParityError(f"{role} channel is outside its reviewed channel set")
            live_members.add(cid)
        if item["archived"] and item["eligible"]:
            raise ParityError(f"{role} archived channel cannot be eligible")

    directory = exact_keys(
        manifest["directory"],
        {
            "self_published", "author_pubkey", "agent_type", "respond_to", "allowed_respond_to",
            "responder_allowlist", "channel_ids", "auth_owner_pubkey", "auth_subject_pubkey", "event_id",
        },
        f"{role}/directory",
    )
    if directory["self_published"] is not True or directory["author_pubkey"] != pubkey:
        raise ParityError(f"{role} directory record is not self-published")
    directory_response = {
        "respond_to": directory["respond_to"],
        "allowed_respond_to": directory["allowed_respond_to"],
        "responder_allowlist": directory["responder_allowlist"],
        "owner_pubkey": policy["owner_pubkey"],
    }
    if directory["agent_type"] != "codex" or directory_response != policy["response_policy"]:
        raise ParityError(f"{role} directory policy does not match Codex-R")
    if directory["auth_owner_pubkey"] != policy["owner_pubkey"] or directory["auth_subject_pubkey"] != pubkey:
        raise ParityError(f"{role} directory auth binding mismatch")
    if not isinstance(directory["event_id"], str) or not HEX64.fullmatch(directory["event_id"]):
        raise ParityError(f"{role} directory event id is invalid")
    if directory["channel_ids"] != sorted(live_members):
        raise ParityError(f"{role} directory channels do not equal live membership")
    if role == "reference" and live_members != set(policy_channels):
        raise ParityError("reference channels do not equal the reviewed 26-channel allowlist")

    profile = exact_keys(
        manifest["profile"],
        {"author_pubkey", "display_name", "event_id", "auth_owner_pubkey", "auth_subject_pubkey"},
        f"{role}/profile",
    )
    if profile["author_pubkey"] != pubkey or profile["display_name"] != manifest["display_name"]:
        raise ParityError(f"{role} profile identity mismatch")
    if profile["auth_owner_pubkey"] != policy["owner_pubkey"] or profile["auth_subject_pubkey"] != pubkey:
        raise ParityError(f"{role} profile auth binding mismatch")
    if not isinstance(profile["event_id"], str) or not HEX64.fullmatch(profile["event_id"]):
        raise ParityError(f"{role} profile event id is invalid")

    systemd = exact_keys(
        manifest["systemd"],
        {"properties", "read_write_paths", "read_only_paths", "address_families", "executable_paths", "host_access"},
        f"{role}/systemd",
    )
    if expected_slug is not None:
        for key, expected in REQUIRED_HARDENING.items():
            if systemd["properties"].get(key) != expected:
                raise ParityError(f"{role} systemd hardening mismatch: {key}")
        if "AF_NETLINK" in systemd["address_families"] and "AF_NETLINK" not in policy["approved_exceptions"][slug]["address_families"]:
            raise ParityError(f"{role} has unapproved AF_NETLINK access")
        if systemd["host_access"] != policy["approved_exceptions"][slug]["host_access"]:
            raise ParityError(f"{role} host-access exception mismatch")
        if systemd["address_families"] != ["AF_UNIX", "AF_INET", "AF_INET6"]:
            raise ParityError(f"{role} address-family set is not the approved narrow set")
        allowed_writable = {
            roots["codex_home"], roots["xdg_config"], roots["xdg_cache"], roots["xdg_state"],
            roots["temporary"], roots["runtime"], roots["state"],
        }
        if not set(systemd["read_write_paths"]) <= allowed_writable:
            raise ParityError(f"{role} has an unapproved writable path")
    all_paths = list(systemd["read_write_paths"]) + list(systemd["read_only_paths"])
    all_paths += [entry["path"] for entry in systemd["host_access"]]
    for path in all_paths:
        if not isinstance(path, str) or not path.startswith("/"):
            raise ParityError(f"{role} systemd path is invalid")
        approved_host_paths = {entry["path"] for entry in policy["approved_exceptions"].get(slug, {"host_access": []})["host_access"]} if expected_slug is not None else set()
        if expected_slug is not None and (
            path == "/home/victor"
            or (path.startswith("/home/victor/") and path not in approved_host_paths)
            or any(path.startswith(prefix) for prefix in policy["forbidden_path_prefixes"])
        ):
            raise ParityError(f"{role} has forbidden host access: {path}")

    secret_files = exact_keys(manifest["secret_files"], {"buzz_private_key", "codex_auth"}, f"{role}/secret_files")
    for name, descriptor in secret_files.items():
        checked = validate_secret_descriptor(descriptor, f"{role}/secret_files/{name}")
        if expected_slug is not None:
            if name == "buzz_private_key" and (
                checked["path_class"] != f"{slug}:buzz-private-key"
                or checked["owner"] != "root"
                or checked["group"] != "root"
                or checked["length"] != 64
                or checked["character_class"] != "lowercase-hex"
            ):
                raise ParityError(f"{role} private-key descriptor mismatch")
            if name == "codex_auth" and (
                checked["path_class"] != f"{slug}:codex-auth"
                or checked["owner"] != identity["unix_user"]
                or checked["group"] != identity["unix_group"]
            ):
                raise ParityError(f"{role} Codex auth descriptor mismatch")
    prompt = exact_keys(
        manifest["prompt"], {"sha256", "policy_sha256", "identity", "mission", "session_title"},
        f"{role}/prompt",
    )
    if not HEX64.fullmatch(str(prompt["sha256"])) or not HEX64.fullmatch(str(prompt["policy_sha256"])):
        raise ParityError(f"{role} prompt digest is invalid")
    if not isinstance(manifest["receipts"], list) or not all(
        isinstance(path, str) and path.startswith("/") for path in manifest["receipts"]
    ):
        raise ParityError(f"{role} receipt paths are invalid")
    if expected_slug is not None and set(manifest["receipts"]) != {
        roots["acceptance"], roots["claim"], roots["install_receipt"], roots["rollback_receipt"],
        roots["backup"], roots["activation_receipt"],
    }:
        raise ParityError(f"{role} receipt set is incomplete or shared")
    return manifest


def build_manifest(observation: dict[str, Any], role: str, policy: dict[str, Any]) -> dict[str, Any]:
    if observation.get("schema") != OBSERVATION_SCHEMA:
        raise ParityError("observation schema mismatch")
    manifest = copy.deepcopy(observation)
    manifest["schema"] = MANIFEST_SCHEMA
    return validate_manifest(manifest, role, policy)


def normalize(value: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(value)
    slug = normalized["slug"]
    identity = normalized["identity"]
    replacements = {
        slug: "<agent>",
        normalized["display_name"]: "<Agent>",
        identity["pubkey"]: "<agent-pubkey>",
        identity["unix_user"]: "<agent-user>",
        identity["unix_group"]: "<agent-group>",
        normalized["roots"]["home"]: "/home/<agent>",
        normalized["roots"]["runtime"]: "/run/<agent>",
    }

    def walk(item: object) -> object:
        if isinstance(item, dict):
            return {key: walk(child) for key, child in item.items()}
        if isinstance(item, list):
            return [walk(child) for child in item]
        if isinstance(item, str):
            result = item
            for old, new in sorted(replacements.items(), key=lambda pair: len(pair[0]), reverse=True):
                result = result.replace(old, new)
            return result
        return item

    normalized = walk(normalized)
    assert isinstance(normalized, dict)
    normalized["captured_at"] = "<capture-time>"
    normalized["slug"] = "<agent>"
    normalized["display_name"] = "<Agent>"
    normalized["runtime"]["agent_command"] = "<codex-acp>"
    normalized["runtime"]["mcp_command"] = "<buzz-dev-mcp>"
    normalized["identity"]["auth_tag"]["sha256_prefix"] = "<identity-secret>"
    for descriptor in normalized["secret_files"].values():
        descriptor["device"] = "<identity-device>"
        descriptor["inode"] = "<identity-inode>"
        descriptor["sha256_prefix"] = "<identity-secret>"
    normalized["prompt"]["sha256"] = "<identity-prompt>"
    normalized["prompt"]["identity"] = "<identity>"
    normalized["prompt"]["mission"] = "<mission>"
    normalized["prompt"]["session_title"] = "<session-title>"
    normalized["directory"]["event_id"] = "<directory-event>"
    normalized["profile"]["event_id"] = "<profile-event>"
    normalized["receipts"] = [f"<receipt-{index}>" for index, _ in enumerate(normalized["receipts"])]
    normalized["runtime"]["closure"]["service_unit"]["sha256"] = "<service-unit>"
    normalized["systemd"]["host_access"] = "<approved-host-access>"
    normalized["systemd"]["properties"].pop("User", None)
    normalized["systemd"]["properties"].pop("Group", None)
    normalized["systemd"]["properties"].pop("WorkingDirectory", None)
    return normalized


def json_differences(reference: object, candidate: object, path: str = "") -> list[str]:
    if type(reference) is not type(candidate):
        return [path or "/"]
    if isinstance(reference, dict):
        keys = sorted(set(reference) | set(candidate))
        return [difference for key in keys for difference in json_differences(reference.get(key), candidate.get(key), f"{path}/{key}")]
    if isinstance(reference, list):
        if len(reference) != len(candidate):
            return [path or "/"]
        return [difference for index, item in enumerate(reference) for difference in json_differences(item, candidate[index], f"{path}/{index}")]
    return [] if reference == candidate else [path or "/"]


def allowed_identity_difference(path: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        expression = re.escape(pattern).replace(r"\*", "[^/]+")
        if re.fullmatch(expression, path):
            return True
    return False


def compare_set(
    reference: dict[str, Any],
    mempool: dict[str, Any],
    genesis: dict[str, Any],
    policy: dict[str, Any],
    authority_receipt: dict[str, Any],
) -> dict[str, Any]:
    policy = validate_policy(policy)
    manifests = {
        "reference": validate_manifest(reference, "reference", policy),
        "mempool": validate_manifest(mempool, "mempool", policy),
        "genesis": validate_manifest(genesis, "genesis", policy),
    }
    authority_receipt = validate_authority_receipt(authority_receipt, policy, manifests)
    pubkeys = [value["identity"]["pubkey"] for value in manifests.values()]
    if len(set(pubkeys)) != 3:
        raise ParityError("reference, Mempool, and Genesis pubkeys must be unique")
    if any(key in policy["reserved_pubkeys"] for key in pubkeys[1:]):
        raise ParityError("Mempool or Genesis reuses a reserved responder identity")
    users = [value["identity"]["unix_user"] for value in manifests.values()]
    homes = [value["roots"]["home"] for value in manifests.values()]
    states = [value["roots"]["state"] for value in manifests.values()]
    prompts = [value["roots"]["prompt"] for value in manifests.values()]
    prompt_hashes = [value["prompt"]["sha256"] for value in manifests.values()]
    directory_events = [value["directory"]["event_id"] for value in manifests.values()]
    profile_events = [value["profile"]["event_id"] for value in manifests.values()]
    for label, values in (
        ("Unix users", users), ("homes", homes), ("state roots", states),
        ("prompt paths", prompts), ("prompts", prompt_hashes),
        ("directory events", directory_events), ("profile events", profile_events),
    ):
        if len(set(values)) != 3:
            raise ParityError(f"{label} are not identity-local and unique")
    receipt_paths = [path for value in manifests.values() for path in value["receipts"]]
    if len(set(receipt_paths)) != len(receipt_paths):
        raise ParityError("receipt, claim, or backup paths are shared")
    auth_hashes = [value["identity"]["auth_tag"]["sha256_prefix"] for value in manifests.values()]
    if len(set(auth_hashes)) != 3:
        raise ParityError("auth tags are not unique")
    inode_pairs: list[tuple[int, int]] = []
    secret_paths: list[str] = []
    secret_hashes: list[str] = []
    for value in manifests.values():
        for descriptor in value["secret_files"].values():
            inode_pairs.append((descriptor["device"], descriptor["inode"]))
            secret_paths.append(descriptor["path_class"])
            secret_hashes.append(descriptor["sha256_prefix"])
    if len(set(inode_pairs)) != len(inode_pairs):
        raise ParityError("secret files reuse an inode")
    if len(set(secret_paths)) != len(secret_paths):
        raise ParityError("secret files reuse a path class")
    if len(set(secret_hashes)) != len(secret_hashes):
        raise ParityError("secret files reuse secret material")

    expected_channels = {
        item["channel_id"]: (item["visibility"], item["scope"], item["role"])
        for item in policy["eligible_channels"]
    }
    unexplained: dict[str, list[str]] = {}
    for slug in ("mempool", "genesis"):
        candidate = manifests[slug]
        candidate_channels = {
            item["channel_id"]: (item["visibility"], item["scope"], item["role"])
            for item in candidate["channels"] if item["eligible"] and not item["archived"]
        }
        differences: list[str] = []
        if candidate_channels != expected_channels:
            differences.append("/channels")
        for component in COMMON_CLOSURE:
            if candidate["runtime"]["closure"][component]["sha256"] != reference["runtime"]["closure"][component]["sha256"]:
                differences.append(f"/runtime/closure/{component}/sha256")
        if candidate["prompt"]["policy_sha256"] != reference["prompt"]["policy_sha256"]:
            differences.append("/prompt/policy_sha256")
        normalized_diff = json_differences(normalize(reference), normalize(candidate))
        differences.extend(
            path for path in normalized_diff
            if not path.startswith("/channels")
            and path != "/directory/channel_ids"
            and not allowed_identity_difference(path, policy["allowed_identity_differences"])
        )
        unexplained[slug] = sorted(set(differences))
    flat = [f"{slug}:{path}" for slug, paths in unexplained.items() for path in paths]
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "canonical_json_contract": CANONICAL_JSON_CONTRACT,
        "status": "PASS" if not flat else "BLOCKED",
        "manifest_sha256": {role: digest(value) for role, value in manifests.items()},
        "policy_sha256": digest(policy),
        "reference_channels": policy["reference_channels"],
        "reference_channels_sha256": digest(policy["reference_channels"]),
        "eligible_channels": policy["eligible_channels"],
        "eligible_channels_sha256": digest(policy["eligible_channels"]),
        "authority_exclusions": policy["authority_exclusions"],
        "authority_exclusions_sha256": digest(policy["authority_exclusions"]),
        "authority_receipt": authority_receipt,
        "authority_receipt_sha256": digest(authority_receipt),
        "allowed_identity_differences": policy["allowed_identity_differences"],
        "approved_exceptions": policy["approved_exceptions"],
        "checks": {
            "unique_pubkeys": True,
            "unique_auth_tags": True,
            "unique_secret_inodes_paths_and_material": True,
            "codex_r_response_policy": True,
            "runtime_closure": not any("/runtime/closure" in item for item in flat),
            "channel_and_member_parity": not any("/channels" in item for item in flat),
            "self_published_directory": True,
            "systemd_hardening_and_host_scope": True,
        },
        "systemd_comparison": {
            slug: {
                "reference_sha256": digest(manifests["reference"]["systemd"]),
                "candidate_sha256": digest(manifests[slug]["systemd"]),
                "required_hardening": True,
                "approved_exceptions": policy["approved_exceptions"][slug],
            }
            for slug in ("mempool", "genesis")
        },
        "unexplained_differences": unexplained,
    }
    receipt["payload_sha256"] = digest(receipt)
    return receipt


def regular_bytes(path: Path, max_bytes: int = 4 * 1024 * 1024) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ParityError(f"unsafe capture source: {path}")
        if metadata.st_size > max_bytes:
            raise ParityError(f"capture source is too large: {path}")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise ParityError(f"capture source is too large: {path}")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks), metadata


def regular_sha256(
    path: Path, max_bytes: int = 1024 * 1024 * 1024
) -> tuple[str, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ParityError(f"unsafe executable source: {path}")
        if metadata.st_size > max_bytes:
            raise ParityError(f"executable source is too large: {path}")
        observed = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise ParityError(f"executable source is too large: {path}")
            observed.update(chunk)
    finally:
        os.close(descriptor)
    return observed.hexdigest(), metadata


def character_class(payload: bytes) -> str:
    if re.fullmatch(rb"[0-9a-f]+", payload):
        return "lowercase-hex"
    if re.fullmatch(rb"[a-z0-9]+1[02-9ac-hj-np-z]+", payload):
        return "bech32"
    try:
        text = payload.decode()
    except UnicodeDecodeError:
        return "binary"
    try:
        json.loads(text)
        return "utf8-json"
    except json.JSONDecodeError:
        return "utf8-ascii" if text.isascii() else "utf8"


def describe_secret(path: Path, path_class: str) -> dict[str, object]:
    raw, metadata = regular_bytes(path)
    payload = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        owner = pwd.getpwuid(metadata.st_uid).pw_name
        group = grp.getgrgid(metadata.st_gid).gr_name
    except KeyError as error:
        raise ParityError(f"secret descriptor has unresolved ownership: {path_class}") from error
    return {
        "path_class": path_class,
        "present": True,
        "file_type": "regular",
        "character_class": character_class(payload),
        "length": len(payload),
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "owner": owner,
        "group": group,
        "nlink": metadata.st_nlink,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "sha256_prefix": hashlib.sha256(raw).hexdigest()[:12],
    }


def describe_value(value: str) -> dict[str, object]:
    payload = value.encode()
    return {
        "present": True,
        "type": "nip-oa",
        "character_class": character_class(payload),
        "length": len(payload),
        "sha256_prefix": hashlib.sha256(payload).hexdigest()[:12],
    }


def parse_environment(path: Path) -> dict[str, str]:
    raw, _metadata = regular_bytes(path)
    try:
        text = raw.decode()
    except UnicodeDecodeError as error:
        raise ParityError("environment file is not UTF-8") from error
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
            raise ParityError("environment file has an invalid or duplicate key")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def normalized_toml_digest(path: Path, replacements: dict[str, str]) -> str:
    raw, _metadata = regular_bytes(path)
    try:
        value = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ParityError("Codex config is not valid UTF-8 TOML") from error
    reject_secret_values(value)

    def normalize(item: object) -> object:
        if isinstance(item, dict):
            return {key: normalize(child) for key, child in sorted(item.items())}
        if isinstance(item, list):
            return [normalize(child) for child in item]
        if isinstance(item, str):
            result = item
            for old, new in sorted(replacements.items(), key=lambda pair: len(pair[0]), reverse=True):
                result = result.replace(old, new)
            return result
        return item

    return f"sha256:{digest(normalize(value))}"


def safe_command(argv: object, stdin_payload: bytes | None = None) -> bytes:
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        raise ParityError("capture command must be a nonempty string array")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise ParityError("capture command executable must be absolute")
    metadata = executable.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not (metadata.st_mode & 0o111)
    ):
        raise ParityError("capture command executable is unsafe")
    for argument in argv[1:]:
        if len(argument) > 512 or re.search(r"(?:nsec1|sk-[A-Za-z0-9_-]{16}|eyJ[a-zA-Z0-9_-]{16})", argument):
            raise ParityError("capture command argument is unsafe")
    completed = subprocess.run(
        argv,
        input=stdin_payload,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    if completed.returncode != 0:
        raise ParityError(f"capture command failed with exit {completed.returncode}")
    if len(completed.stdout) > 4 * 1024 * 1024:
        raise ParityError("capture command output is too large")
    return completed.stdout


def json_source(source: object, where: str) -> object:
    if not isinstance(source, dict) or source.get("kind") not in {"file", "command"}:
        raise ParityError(f"{where} source is invalid")
    if source["kind"] == "file":
        exact_keys(source, {"kind", "path"}, where)
        raw, _metadata = regular_bytes(Path(source["path"]))
    else:
        exact_keys(source, {"kind", "argv"}, where)
        raw = safe_command(source["argv"])
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ParityError(f"{where} source is not valid JSON") from error
    reject_secret_values(value, where)
    return value


def systemd_capture(source: object) -> dict[str, object]:
    if not isinstance(source, dict) or source.get("kind") not in {"file", "live"}:
        raise ParityError("systemd source is invalid")
    if source["kind"] == "file":
        exact_keys(source, {"kind", "path"}, "systemd source")
        value = json_source(source, "systemd")
        return exact_keys(
            value,
            {"properties", "read_write_paths", "read_only_paths", "address_families", "executable_paths"},
            "systemd fixture",
        )
    exact_keys(source, {"kind", "scope", "unit", "executable_paths"}, "systemd source")
    scope = source["scope"]
    if scope not in {"system", "user"}:
        raise ParityError("systemd scope is invalid")
    unit = source["unit"]
    if not isinstance(unit, str) or not re.fullmatch(r"[a-zA-Z0-9_.@:-]+\.service", unit):
        raise ParityError("systemd unit name is invalid")
    property_names = (
        "UMask", "NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateDevices",
        "PrivateTmp", "CapabilityBoundingSet", "AmbientCapabilities", "User", "Group",
        "WorkingDirectory", "ReadWritePaths", "ReadOnlyPaths", "RestrictAddressFamilies",
    )
    observed: dict[str, str] = {}
    for name in property_names:
        argv = ["/usr/bin/systemctl"]
        if scope == "user":
            argv.append("--user")
        argv.extend(["show", "--no-pager", f"--property={name}", "--value", unit])
        raw = safe_command(argv)
        observed[name] = raw.decode().strip()
    properties: dict[str, object] = {
        name: ([] if name in {"CapabilityBoundingSet", "AmbientCapabilities"} and not value else value)
        for name, value in observed.items()
        if name not in {"ReadWritePaths", "ReadOnlyPaths", "RestrictAddressFamilies"}
    }
    return {
        "properties": properties,
        "read_write_paths": observed["ReadWritePaths"].split(),
        "read_only_paths": observed["ReadOnlyPaths"].split(),
        "address_families": observed["RestrictAddressFamilies"].split(),
        "executable_paths": source["executable_paths"],
    }


def closure_record(path: Path) -> dict[str, object]:
    sha256, metadata = regular_sha256(path)
    try:
        owner = pwd.getpwuid(metadata.st_uid).pw_name
        group = grp.getgrgid(metadata.st_gid).gr_name
    except KeyError as error:
        raise ParityError(f"closure path has unresolved ownership: {path}") from error
    return {
        "path": str(path),
        "sha256": sha256,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "owner": owner,
        "group": group,
    }


def capture_closure(sources: object, role: str) -> dict[str, dict[str, Any]]:
    closure_sources = exact_keys(sources, CLOSURE_KEYS, "capture closure")
    closure: dict[str, dict[str, Any]] = {}
    for component, path in closure_sources.items():
        record = closure_record(Path(path))
        if role != "reference" and component in EXPECTED_CANDIDATE_CLOSURE_PATHS:
            record["path"] = EXPECTED_CANDIDATE_CLOSURE_PATHS[component]
        closure[component] = record
    return closure


def auth_tag_from_source(source: object) -> str:
    if not isinstance(source, dict) or source.get("kind") not in {"file", "environment"}:
        raise ParityError("auth-tag source is invalid")
    if source["kind"] == "file":
        exact_keys(source, {"kind", "path"}, "auth-tag source")
        raw, _metadata = regular_bytes(Path(source["path"]))
        return raw.decode().strip()
    exact_keys(source, {"kind", "path", "key"}, "auth-tag source")
    values = parse_environment(Path(source["path"]))
    key = source["key"]
    if not isinstance(key, str) or key not in values:
        raise ParityError("auth-tag environment key is absent")
    return values[key]


def capture_manifest(spec: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    policy = validate_policy(policy)
    spec = exact_keys(
        spec,
        {
            "schema", "role", "captured_at", "slug", "display_name", "identity", "roots",
            "sources", "prompt", "receipts",
        },
        "capture spec",
    )
    if spec["schema"] != CAPTURE_SCHEMA or spec["role"] not in ROLE_SLUGS:
        raise ParityError("capture spec schema or role mismatch")
    identity = exact_keys(
        spec["identity"],
        {"pubkey", "owner_pubkey", "unix_user", "unix_group", "profile_author_pubkey"},
        "capture identity",
    )
    roots = exact_keys(spec["roots"], ROOT_KEYS, "capture roots")
    sources = exact_keys(
        spec["sources"],
        {
            "environment_file", "prompt_file", "prompt_policy_file", "codex_config_file",
            "buzz_private_key", "codex_auth", "auth_tag", "systemd", "channels", "profile",
            "directory", "closure",
        },
        "capture sources",
    )
    environment_path = Path(sources["environment_file"])
    environment = parse_environment(environment_path)
    model_value = environment.get("BUZZ_ACP_MODEL", "")
    match = re.fullmatch(r"(gpt-5\.6-sol)(?:\[(high)\])?", model_value)
    if match is None:
        raise ParityError("captured model is not gpt-5.6-sol high")
    reasoning = match.group(2) or environment.get("BUZZ_ACP_REASONING_EFFORT", "")
    if reasoning != "high":
        raise ParityError("captured reasoning effort is not high")

    def required_env(name: str) -> str:
        value = environment.get(name)
        if value is None:
            raise ParityError(f"captured environment misses {name}")
        return value

    auth_value = auth_tag_from_source(sources["auth_tag"])
    auth_descriptor = describe_value(auth_value)
    auth_descriptor.update(
        {
            "owner_pubkey": identity["owner_pubkey"],
            "subject_pubkey": identity["pubkey"],
        }
    )
    prompt_raw, _prompt_metadata = regular_bytes(Path(sources["prompt_file"]))
    policy_raw, _policy_metadata = regular_bytes(Path(sources["prompt_policy_file"]))
    replacements = {
        str(identity["pubkey"]): "<agent-pubkey>",
        str(identity["unix_user"]): "<agent-user>",
        str(roots["home"]): "/home/<agent>",
        str(roots["runtime"]): "/run/<agent>",
        str(spec["slug"]): "<agent>",
        str(spec["display_name"]): "<Agent>",
    }
    codex_config = normalized_toml_digest(Path(sources["codex_config_file"]), replacements)
    systemd = systemd_capture(sources["systemd"])
    approved_access = policy["approved_exceptions"].get(spec["slug"], {"host_access": []})[
        "host_access"
    ]
    approved_by_path = {entry["path"]: entry for entry in approved_access}
    identity_paths = {
        roots["codex_home"], roots["xdg_config"], roots["xdg_cache"], roots["xdg_state"],
        roots["temporary"], roots["runtime"], roots["state"],
    }
    raw_writable = list(systemd["read_write_paths"])
    unclassified = set(raw_writable) - identity_paths - set(approved_by_path)
    if spec["role"] != "reference" and unclassified:
        raise ParityError("captured systemd has an unapproved writable path")
    host_access = [entry for entry in approved_access if entry["path"] in raw_writable]
    channels = json_source(sources["channels"], "channels")
    if not isinstance(channels, list):
        raise ParityError("channel capture is not a list")
    channels = sorted(channels, key=lambda item: str(item.get("channel_id", "")) if isinstance(item, dict) else "")
    profile = json_source(sources["profile"], "profile")
    directory = json_source(sources["directory"], "directory")
    address_family_order = {name: index for index, name in enumerate(
        ("AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK")
    )}
    observed_families = set(systemd["address_families"])
    if spec["role"] != "reference" and not observed_families <= set(address_family_order):
        raise ParityError("captured systemd has an unknown address family")
    ordered_families = (
        sorted(observed_families)
        if spec["role"] == "reference"
        else sorted(observed_families, key=address_family_order.__getitem__)
    )
    closure = capture_closure(sources["closure"], spec["role"])
    private_source = exact_keys(sources["buzz_private_key"], {"path", "path_class"}, "private-key source")
    codex_source = exact_keys(sources["codex_auth"], {"path", "path_class"}, "Codex-auth source")
    prompt = exact_keys(spec["prompt"], {"identity", "mission", "session_title"}, "capture prompt")
    observed = {
        "schema": MANIFEST_SCHEMA,
        "captured_at": spec["captured_at"],
        "slug": spec["slug"],
        "display_name": spec["display_name"],
        "identity": {
            **identity,
            "auth_tag": auth_descriptor,
        },
        "roots": roots,
        "runtime": {
            "model": match.group(1),
            "reasoning_effort": reasoning,
            "agent_command": required_env("BUZZ_ACP_AGENT_COMMAND"),
            "mcp_command": required_env("BUZZ_ACP_MCP_COMMAND"),
            "codex_config": codex_config,
            "memory": required_env("BUZZ_ACP_MEMORY").lower() == "true",
            "agents": int(required_env("BUZZ_ACP_AGENTS")),
            "subscribe": required_env("BUZZ_ACP_SUBSCRIBE"),
            "multiple_event_handling": required_env("BUZZ_ACP_MULTIPLE_EVENT_HANDLING"),
            "context_message_limit": int(required_env("BUZZ_ACP_CONTEXT_MESSAGE_LIMIT")),
            "idle_timeout": int(required_env("BUZZ_ACP_IDLE_TIMEOUT")),
            "max_turn_duration": int(required_env("BUZZ_ACP_MAX_TURN_DURATION")),
            "turn_liveness_secs": int(required_env("BUZZ_ACP_TURN_LIVENESS_SECS")),
            "permission_mode": required_env("BUZZ_ACP_PERMISSION_MODE"),
            "environment_keys": sorted(environment),
            "closure": closure,
        },
        "response_policy": {
            "respond_to": required_env("BUZZ_ACP_RESPOND_TO"),
            "allowed_respond_to": required_env("BUZZ_ACP_ALLOWED_RESPOND_TO"),
            "responder_allowlist": [
                item for item in environment.get("BUZZ_ACP_RESPOND_TO_ALLOWLIST", "").split(",") if item
            ],
            "owner_pubkey": required_env("BUZZ_ACP_AGENT_OWNER"),
        },
        "channels": channels,
        "profile": profile,
        "directory": directory,
        "systemd": {
            "properties": systemd["properties"],
            "read_write_paths": sorted(set(path for path in raw_writable if path not in approved_by_path)),
            "read_only_paths": sorted(set(systemd["read_only_paths"])),
            "address_families": ordered_families,
            "executable_paths": sorted(set(systemd["executable_paths"])),
            "host_access": host_access,
        },
        "secret_files": {
            "buzz_private_key": describe_secret(
                Path(private_source["path"]), str(private_source["path_class"])
            ),
            "codex_auth": describe_secret(Path(codex_source["path"]), str(codex_source["path_class"])),
        },
        "prompt": {
            "sha256": hashlib.sha256(prompt_raw).hexdigest(),
            "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
            **prompt,
        },
        "receipts": spec["receipts"],
    }
    return validate_manifest(observed, spec["role"], policy)


def validate_receipt_digest(receipt: dict[str, Any]) -> None:
    recorded = receipt.get("payload_sha256")
    payload = dict(receipt)
    payload.pop("payload_sha256", None)
    if not isinstance(recorded, str) or not HEX64.fullmatch(recorded) or digest(payload) != recorded:
        raise ParityError("parity receipt payload digest mismatch")
    if receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("status") != "PASS":
        raise ParityError("only a passing parity receipt may be sealed")


def manifest_bound_command_record(
    argv: list[str], manifest: dict[str, Any], target_name: str
) -> dict[str, object]:
    ops_targets = manifest.get("ops_targets")
    if not isinstance(ops_targets, list):
        raise ParityError("bundle manifest ops target inventory is absent")
    matches = [
        item for item in ops_targets
        if isinstance(item, dict) and Path(str(item.get("target", ""))).name == target_name
    ]
    if len(matches) != 1:
        raise ParityError(f"bundle manifest has no unique {target_name} ops target")
    bound = exact_keys(
        matches[0], {"target", "source", "mode", "uid", "gid", "sha256", "scope"},
        f"bundle manifest {target_name}",
    )
    if argv[0] != bound["target"] or not Path(argv[0]).is_absolute():
        raise ParityError(f"{target_name} command path is not manifest-bound")
    executable = Path(argv[0])
    sha256, metadata = regular_sha256(executable)
    observed_mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
    if (
        bound["mode"] != "0700"
        or observed_mode != bound["mode"]
        or metadata.st_uid != bound["uid"]
        or metadata.st_gid != bound["gid"]
        or sha256 != bound["sha256"]
    ):
        raise ParityError(f"{target_name} executable metadata or digest is not manifest-bound")
    return {
        "argv_sha256": digest(argv),
        "executable": str(executable),
        "executable_sha256": sha256,
        "mode": observed_mode,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "ops_record_sha256": digest(bound),
    }


def validate_persisted_ops_record(
    record: object, manifest: dict[str, Any], target_name: str
) -> None:
    ops_targets = manifest.get("ops_targets")
    if not isinstance(ops_targets, list):
        raise ParityError("bundle manifest ops target inventory is absent")
    matches = [
        item for item in ops_targets
        if isinstance(item, dict) and Path(str(item.get("target", ""))).name == target_name
    ]
    if len(matches) != 1:
        raise ParityError(f"bundle manifest has no unique {target_name} ops target")
    bound = exact_keys(
        matches[0], {"target", "source", "mode", "uid", "gid", "sha256", "scope"},
        f"bundle manifest {target_name}",
    )
    persisted = exact_keys(
        record,
        {
            "argv_sha256", "executable", "executable_sha256", "mode", "uid", "gid",
            "ops_record_sha256",
        },
        f"persisted {target_name}",
    )
    expected = {
        "executable": bound["target"],
        "executable_sha256": bound["sha256"],
        "mode": bound["mode"],
        "uid": bound["uid"],
        "gid": bound["gid"],
        "ops_record_sha256": digest(bound),
    }
    if not isinstance(persisted["argv_sha256"], str) or not HEX64.fullmatch(
        persisted["argv_sha256"]
    ):
        raise ParityError(f"persisted {target_name} command digest is invalid")
    if any(persisted[field] != value for field, value in expected.items()):
        raise ParityError(f"persisted {target_name} is not manifest-bound")


def open_sealed_runtime_verifier(
    path: Path, manifest: dict[str, Any], root: Path = Path("/")
) -> int:
    expected_path = root / ROOT_VERIFIER_TARGET.lstrip("/")
    if path != expected_path:
        raise ParityError("root verifier path is not the reviewed runtime target")
    runtime_targets = manifest.get("runtime_targets")
    if not isinstance(runtime_targets, list):
        raise ParityError("bundle manifest runtime target inventory is absent")
    matches = [
        item for item in runtime_targets
        if isinstance(item, dict) and item.get("target") == ROOT_VERIFIER_TARGET
    ]
    if len(matches) != 1:
        raise ParityError("bundle manifest has no unique root verifier runtime target")
    bound = exact_keys(
        matches[0], {"target", "source", "mode", "uid", "gid", "sha256"},
        "bundle manifest root verifier",
    )
    if (
        bound["mode"] != "0755"
        or bound["uid"] != 0
        or bound["gid"] != 0
        or not isinstance(bound["sha256"], str)
        or not HEX64.fullmatch(bound["sha256"])
    ):
        raise ParityError("root verifier manifest ownership, mode, or digest is unsafe")

    source = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    sealed = -1
    try:
        metadata = os.fstat(source)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or metadata.st_uid != 0
            or metadata.st_gid != 0
        ):
            raise ParityError("installed root verifier metadata is unsafe")
        sealed = os.memfd_create(
            "buzz-parity-runtime-verifier", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        )
        observed = hashlib.sha256()
        while chunk := os.read(source, 1024 * 1024):
            observed.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(sealed, view)
                if written <= 0:
                    raise OSError("short write while freezing root verifier")
                view = view[written:]
        if observed.hexdigest() != bound["sha256"]:
            raise ParityError("installed root verifier digest is not manifest-bound")
        os.fchmod(sealed, 0o500)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
        fcntl.fcntl(sealed, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(sealed, fcntl.F_GET_SEALS) & seals != seals:
            raise ParityError("root verifier memfd is not fully sealed")
        os.lseek(sealed, 0, os.SEEK_SET)
        return sealed
    except Exception:
        if sealed >= 0:
            os.close(sealed)
        raise
    finally:
        os.close(source)


def run_runtime_verifier(
    path: Path, manifest: dict[str, Any], owner_pubkey: str, envelope: dict[str, Any],
    root: Path = Path("/"),
) -> None:
    descriptor = open_sealed_runtime_verifier(path, manifest, root)
    try:
        completed = subprocess.run(
            [
                f"/proc/self/fd/{descriptor}",
                "verify-parity-envelope",
                "--owner-pubkey",
                owner_pubkey,
            ],
            input=canonical_json(envelope),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=60,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            pass_fds=(descriptor,),
        )
        if completed.returncode != 0:
            raise ParityError(
                f"root-owned sealed parity verifier failed with exit {completed.returncode}"
            )
        if completed.stdout:
            raise ParityError("root-owned sealed parity verifier emitted unexpected output")
    finally:
        os.close(descriptor)


def activation_binding(bundle_manifest: dict[str, Any]) -> dict[str, object]:
    required = {
        "source_commit": re.compile(r"^[0-9a-f]{40}$"),
        "source_tree": re.compile(r"^[0-9a-f]{40}$"),
        "package_digest": HEX64,
        "runtime_artifact_fingerprint": HEX64,
    }
    values: dict[str, str] = {}
    for field, pattern in required.items():
        value = bundle_manifest.get(field)
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise ParityError(f"bundle manifest {field} is invalid")
        values[field] = value
    return {
        "schema": BINDING_SCHEMA,
        **values,
        "bundle_manifest_sha256": digest(bundle_manifest),
    }


def bind_receipt(
    receipt: dict[str, Any], bundle_manifest: dict[str, Any]
) -> dict[str, Any]:
    validate_receipt_digest(receipt)
    bound = copy.deepcopy(receipt)
    if "activation_binding" in bound:
        raise ParityError("parity receipt is already activation-bound")
    authority = bound.get("authority_receipt")
    if not isinstance(authority, dict) or any(
        authority.get(field) != bundle_manifest.get(field)
        for field in ("source_commit", "source_tree", "package_digest")
    ):
        raise ParityError("authority receipt source/package binding mismatch")
    parity_contract = bundle_manifest.get("capability_parity")
    if not isinstance(parity_contract, dict) or any(
        parity_contract.get(field) != bound.get(field)
        for field in (
            "reference_channels_sha256", "eligible_channels_sha256",
            "authority_exclusions_sha256",
        )
    ):
        raise ParityError("authority receipt channel set binding mismatch")
    if parity_contract.get("canonical_json_contract") != CANONICAL_JSON_CONTRACT:
        raise ParityError("bundle canonical JSON contract mismatch")
    bound.pop("payload_sha256")
    bound["activation_binding"] = activation_binding(bundle_manifest)
    bound["payload_sha256"] = digest(bound)
    return bound


def seal_receipt(
    receipt: dict[str, Any], policy: dict[str, Any], signer_argv: list[str],
    verifier_argv: list[str], bundle_manifest: dict[str, Any]
) -> dict[str, Any]:
    receipt = bind_receipt(receipt, bundle_manifest)
    signer_record = manifest_bound_command_record(
        signer_argv, bundle_manifest, SIGNER_TARGET_NAME
    )
    verifier_record = manifest_bound_command_record(
        verifier_argv, bundle_manifest, VERIFIER_TARGET_NAME
    )
    signature_raw = safe_command(signer_argv, f"{receipt['payload_sha256']}\n".encode())
    try:
        signature = json.loads(signature_raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ParityError("signer output is not valid JSON") from error
    signature = exact_keys(
        signature,
        {"schema", "algorithm", "signer_pubkey", "payload_sha256", "signature", "signed_at"},
        "signature",
    )
    if signature["schema"] != SIGNATURE_SCHEMA or signature["algorithm"] != "schnorr-secp256k1":
        raise ParityError("signature schema or algorithm mismatch")
    if signature["signer_pubkey"] != policy["owner_pubkey"] or signature["payload_sha256"] != receipt["payload_sha256"]:
        raise ParityError("signature owner or payload binding mismatch")
    if not isinstance(signature["signature"], str) or not re.fullmatch(r"[0-9a-f]{128}", signature["signature"]):
        raise ParityError("signature encoding is invalid")
    if not isinstance(signature["signed_at"], str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", signature["signed_at"]
    ):
        raise ParityError("signature time is invalid")
    envelope = {
        "schema": SEALED_RECEIPT_SCHEMA,
        "receipt": receipt,
        "signature": signature,
        "signer": signer_record,
        "verifier": verifier_record,
        "verified": False,
    }
    safe_command(verifier_argv, canonical_json(envelope))
    envelope["verified"] = True
    envelope["sealed_sha256"] = digest(envelope)
    safe_command(verifier_argv, canonical_json(envelope))
    return envelope


def verify_sealed_receipt(
    envelope: dict[str, Any], policy: dict[str, Any], bundle_manifest: dict[str, Any],
    runtime_verifier: Path, root: Path = Path("/"),
) -> dict[str, Any]:
    envelope = exact_keys(
        envelope,
        {"schema", "receipt", "signature", "signer", "verifier", "verified", "sealed_sha256"},
        "sealed receipt",
    )
    if envelope["schema"] != SEALED_RECEIPT_SCHEMA or envelope["verified"] is not True:
        raise ParityError("sealed parity receipt is not persistently verified")
    recorded_seal = envelope["sealed_sha256"]
    unsigned_envelope = copy.deepcopy(envelope)
    unsigned_envelope.pop("sealed_sha256")
    if not isinstance(recorded_seal, str) or not HEX64.fullmatch(recorded_seal):
        raise ParityError("sealed parity receipt digest is invalid")
    if digest(unsigned_envelope) != recorded_seal:
        raise ParityError("sealed parity receipt digest mismatch")
    receipt = envelope["receipt"]
    if not isinstance(receipt, dict):
        raise ParityError("sealed parity receipt payload is invalid")
    validate_receipt_digest(receipt)
    if receipt.get("activation_binding") != activation_binding(bundle_manifest):
        raise ParityError("sealed parity receipt source/package binding mismatch")
    if receipt.get("policy_sha256") != digest(policy):
        raise ParityError("sealed parity receipt policy binding mismatch")
    signature = exact_keys(
        envelope["signature"],
        {"schema", "algorithm", "signer_pubkey", "payload_sha256", "signature", "signed_at"},
        "persisted signature",
    )
    if (
        signature["schema"] != SIGNATURE_SCHEMA
        or signature["algorithm"] != "schnorr-secp256k1"
        or signature["signer_pubkey"] != policy["owner_pubkey"]
        or signature["payload_sha256"] != receipt["payload_sha256"]
        or not isinstance(signature["signature"], str)
        or not re.fullmatch(r"[0-9a-f]{128}", signature["signature"])
        or not isinstance(signature["signed_at"], str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", signature["signed_at"])
    ):
        raise ParityError("persisted signature binding mismatch")
    for label, target_name in (("signer", SIGNER_TARGET_NAME), ("verifier", VERIFIER_TARGET_NAME)):
        validate_persisted_ops_record(envelope[label], bundle_manifest, target_name)
    run_runtime_verifier(
        runtime_verifier, bundle_manifest, policy["owner_pubkey"], envelope, root
    )
    return envelope


def command_argv(path: Path) -> list[str]:
    spec = exact_keys(regular_json(path), {"schema", "argv"}, "command spec")
    if spec["schema"] != "buzz-agent-capability-command-v1":
        raise ParityError("command spec schema mismatch")
    argv = spec["argv"]
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        raise ParityError("command spec argv is invalid")
    return argv


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--role", choices=ROLE_SLUGS, required=True)
    build.add_argument("--observation", required=True)
    build.add_argument("--policy", required=True)
    build.add_argument("--output", required=True)
    compare = subparsers.add_parser("compare-set")
    compare.add_argument("--reference", required=True)
    compare.add_argument("--mempool", required=True)
    compare.add_argument("--genesis", required=True)
    compare.add_argument("--authority-receipt", required=True)
    compare.add_argument("--policy", required=True)
    compare.add_argument("--output", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--spec", required=True)
    capture.add_argument("--policy", required=True)
    capture.add_argument("--output", required=True)
    seal = subparsers.add_parser("seal-receipt")
    seal.add_argument("--receipt", required=True)
    seal.add_argument("--policy", required=True)
    seal.add_argument("--signer-command", required=True)
    seal.add_argument("--verifier-command", required=True)
    seal.add_argument("--bundle-manifest", required=True)
    seal.add_argument("--output", required=True)
    verify = subparsers.add_parser("verify-sealed")
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--policy", required=True)
    verify.add_argument("--bundle-manifest", required=True)
    verify.add_argument("--runtime-verifier", required=True)
    args = parser.parse_args()
    policy = validate_policy(regular_json(Path(args.policy).resolve(strict=True), owner_only=False))
    if args.command == "verify-sealed":
        result = verify_sealed_receipt(
            regular_json(Path(args.receipt).resolve(strict=True)),
            policy,
            regular_json(Path(args.bundle_manifest).resolve(strict=True)),
            Path(args.runtime_verifier),
        )
        print(json.dumps({"status": "PASS", "sealed_sha256": result["sealed_sha256"]}, sort_keys=True))
        return
    output = Path(args.output).absolute()
    if args.command == "build":
        observation = regular_json(Path(args.observation).resolve(strict=True))
        result = build_manifest(observation, args.role, policy)
    elif args.command == "compare-set":
        result = compare_set(
            regular_json(Path(args.reference).resolve(strict=True)),
            regular_json(Path(args.mempool).resolve(strict=True)),
            regular_json(Path(args.genesis).resolve(strict=True)),
            policy,
            regular_json(Path(args.authority_receipt).resolve(strict=True)),
        )
    elif args.command == "capture":
        capture_spec = regular_json(Path(args.spec).resolve(strict=True))
        result = capture_manifest(capture_spec, policy)
    else:
        receipt = regular_json(Path(args.receipt).resolve(strict=True))
        result = seal_receipt(
            receipt,
            policy,
            command_argv(Path(args.signer_command).resolve(strict=True)),
            command_argv(Path(args.verifier_command).resolve(strict=True)),
            regular_json(Path(args.bundle_manifest).resolve(strict=True)),
        )
    write_private(output, result)
    print(json.dumps({"status": result.get("status", "MANIFEST_WRITTEN"), "output": str(output)}, sort_keys=True))
    if result.get("status") == "BLOCKED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
