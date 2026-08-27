#!/usr/bin/env python3
"""Build and compare secret-safe Codex-R capability parity manifests."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

OBSERVATION_SCHEMA = "buzz-agent-capability-observation-v1"
MANIFEST_SCHEMA = "buzz-agent-capability-manifest-v1"
POLICY_SCHEMA = "buzz-agent-capability-parity-policy-v1"
RECEIPT_SCHEMA = "buzz-agent-capability-parity-receipt-v1"
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
SENSITIVE_KEYS = re.compile(r"(^|_)(private_key|token|cookie|oauth|auth_tag_payload|secret_value)($|_)")


class ParityError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


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


def reject_secret_values(value: object, where: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            descriptor_role = where.endswith("/secret_files") and key == "buzz_private_key"
            if SENSITIVE_KEYS.search(key) and not descriptor_role:
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
            "path", "present", "file_type", "character_class", "length", "mode", "owner",
            "group", "nlink", "device", "inode", "sha256_prefix",
        },
        where,
    )
    if descriptor["present"] is not True or descriptor["file_type"] != "regular":
        raise ParityError(f"{where} is not a present regular file")
    if not isinstance(descriptor["path"], str) or not descriptor["path"].startswith("/"):
        raise ParityError(f"{where} path is not absolute")
    if descriptor["mode"] != "0600" or descriptor["nlink"] != 1:
        raise ParityError(f"{where} mode or link count is unsafe")
    if not isinstance(descriptor["length"], int) or descriptor["length"] <= 0:
        raise ParityError(f"{where} has invalid length")
    if not isinstance(descriptor["device"], int) or not isinstance(descriptor["inode"], int):
        raise ParityError(f"{where} has invalid inode identity")
    if not isinstance(descriptor["sha256_prefix"], str) or not HEX_PREFIX.fullmatch(
        descriptor["sha256_prefix"]
    ):
        raise ParityError(f"{where} has invalid truncated SHA-256")
    return descriptor


def validate_policy(value: object) -> dict[str, Any]:
    policy = exact_keys(
        value,
        {
            "schema", "owner_pubkey", "reserved_pubkeys", "allowed_identity_differences",
            "approved_exceptions", "forbidden_path_prefixes",
        },
        "policy",
    )
    if policy["schema"] != POLICY_SCHEMA or not HEX64.fullmatch(policy["owner_pubkey"]):
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


def validate_manifest(value: object, role: str, policy: dict[str, Any]) -> dict[str, Any]:
    if role not in ROLE_SLUGS:
        raise ParityError(f"unsupported comparison role: {role}")
    reject_secret_values(value)
    manifest = exact_keys(
        value,
        {
            "schema", "captured_at", "slug", "display_name", "identity", "roots", "runtime",
            "response_policy", "channels", "directory", "systemd", "secret_files", "prompt",
            "receipts",
        },
        role,
    )
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ParityError(f"{role} manifest schema mismatch")
    slug = manifest["slug"]
    expected_slug = ROLE_SLUGS[role]
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

    response = exact_keys(
        manifest["response_policy"],
        {"respond_to", "allowed_respond_to", "responder_allowlist", "owner_pubkey"},
        f"{role}/response_policy",
    )
    if response != {
        "respond_to": "owner-only",
        "allowed_respond_to": "owner-only",
        "responder_allowlist": [],
        "owner_pubkey": policy["owner_pubkey"],
    }:
        raise ParityError(f"{role} response policy is not owner-only")

    if not isinstance(manifest["channels"], list):
        raise ParityError(f"{role} channels are invalid")
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
            if expected_slug is not None and item["role"] != "member":
                raise ParityError(f"{role} channel role is not member")
            live_members.add(cid)

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
    if directory["agent_type"] != "codex" or directory["respond_to"] != "owner-only" or directory["allowed_respond_to"] != "owner-only" or directory["responder_allowlist"] != []:
        raise ParityError(f"{role} directory policy mismatch")
    if directory["auth_owner_pubkey"] != policy["owner_pubkey"] or directory["auth_subject_pubkey"] != pubkey:
        raise ParityError(f"{role} directory auth binding mismatch")
    if directory["channel_ids"] != sorted(live_members):
        raise ParityError(f"{role} directory channels do not equal live membership")

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
                checked["path"] != roots["credential"]
                or checked["owner"] != "root"
                or checked["group"] != "root"
                or checked["length"] != 64
                or checked["character_class"] != "lowercase-hex"
            ):
                raise ParityError(f"{role} private-key descriptor mismatch")
            if name == "codex_auth" and (
                not checked["path"].startswith(f"{roots['codex_home']}/")
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


def compare_set(reference: dict[str, Any], mempool: dict[str, Any], genesis: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    policy = validate_policy(policy)
    manifests = {
        "reference": validate_manifest(reference, "reference", policy),
        "mempool": validate_manifest(mempool, "mempool", policy),
        "genesis": validate_manifest(genesis, "genesis", policy),
    }
    pubkeys = [value["identity"]["pubkey"] for value in manifests.values()]
    if len(set(pubkeys)) != 3:
        raise ParityError("reference, Mempool, and Genesis pubkeys must be unique")
    if any(key in policy["reserved_pubkeys"] for key in pubkeys[1:]):
        raise ParityError("Mempool or Genesis reuses a reserved responder identity")
    auth_hashes = [value["identity"]["auth_tag"]["sha256_prefix"] for value in manifests.values()]
    if len(set(auth_hashes)) != 3:
        raise ParityError("auth tags are not unique")
    inode_pairs: list[tuple[int, int]] = []
    secret_paths: list[str] = []
    secret_hashes: list[str] = []
    for value in manifests.values():
        for descriptor in value["secret_files"].values():
            inode_pairs.append((descriptor["device"], descriptor["inode"]))
            secret_paths.append(descriptor["path"])
            secret_hashes.append(descriptor["sha256_prefix"])
    if len(set(inode_pairs)) != len(inode_pairs):
        raise ParityError("secret files reuse an inode")
    if len(set(secret_paths)) != len(secret_paths):
        raise ParityError("secret files reuse a path")
    if len(set(secret_hashes)) != len(secret_hashes):
        raise ParityError("secret files reuse secret material")

    reference_channels = {
        item["channel_id"]: (item["visibility"], item["scope"], item["role"])
        for item in reference["channels"] if item["eligible"] and not item["archived"]
    }
    unexplained: dict[str, list[str]] = {}
    for slug in ("mempool", "genesis"):
        candidate = manifests[slug]
        candidate_channels = {
            item["channel_id"]: (item["visibility"], item["scope"], item["role"])
            for item in candidate["channels"] if item["eligible"] and not item["archived"]
        }
        expected_channels = {
            cid: (visibility, scope, "member")
            for cid, (visibility, scope, _role) in reference_channels.items()
            if scope in ALLOWED_SCOPES
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
        ignored_prefixes = (
            "/channels", "/runtime/closure", "/systemd", "/roots", "/secret_files",
            "/identity", "/prompt", "/directory", "/receipts",
        )
        differences.extend(path for path in normalized_diff if not path.startswith(ignored_prefixes))
        unexplained[slug] = sorted(set(differences))
    flat = [f"{slug}:{path}" for slug, paths in unexplained.items() for path in paths]
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "PASS" if not flat else "BLOCKED",
        "manifest_sha256": {role: digest(value) for role, value in manifests.items()},
        "policy_sha256": digest(policy),
        "allowed_identity_differences": policy["allowed_identity_differences"],
        "approved_exceptions": policy["approved_exceptions"],
        "checks": {
            "unique_pubkeys": True,
            "unique_auth_tags": True,
            "unique_secret_inodes_paths_and_material": True,
            "owner_only_response_policy": True,
            "runtime_closure": not any("/runtime/closure" in item for item in flat),
            "channel_and_member_parity": not any("/channels" in item for item in flat),
            "self_published_directory": True,
            "systemd_hardening_and_host_scope": True,
        },
        "unexplained_differences": unexplained,
    }


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
    compare.add_argument("--policy", required=True)
    compare.add_argument("--output", required=True)
    args = parser.parse_args()
    policy = validate_policy(regular_json(Path(args.policy).resolve(strict=True), owner_only=False))
    output = Path(args.output).absolute()
    if args.command == "build":
        observation = regular_json(Path(args.observation).resolve(strict=True))
        result = build_manifest(observation, args.role, policy)
    else:
        result = compare_set(
            regular_json(Path(args.reference).resolve(strict=True)),
            regular_json(Path(args.mempool).resolve(strict=True)),
            regular_json(Path(args.genesis).resolve(strict=True)),
            policy,
        )
    write_private(output, result)
    print(json.dumps({"status": result.get("status", "MANIFEST_WRITTEN"), "output": str(output)}, sort_keys=True))
    if result.get("status") == "BLOCKED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
