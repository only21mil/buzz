#!/usr/bin/env python3
"""Shared validation and descriptor-safe I/O for Buzz CI activation packages."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any
from urllib.parse import urlsplit

MANIFEST_SCHEMA = "buzz-ci-capacity-one-activation-package-v1"
DRAFT_SCHEMA = "buzz-ci-capacity-one-activation-draft-v1"
RECEIPT_SCHEMA = "buzz-ci-capacity-one-activation-receipt-v1"
PROVENANCE_SCHEMA = "buzz-ci-binary-provenance-v1"
MAX_JSON_BYTES = 1024 * 1024
MAX_ASSET_BYTES = 4 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
ASSET = re.compile(r"^assets/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
UNIT = re.compile(r"^[a-z0-9][a-z0-9@_.-]+\.(?:service|socket|target)$")

COMPONENTS = {
    "runner": ("/usr/libexec/buzz-ci-runner", "buzz-ci-runner.service"),
    "controld": ("/usr/libexec/buzz-ci-controld", "buzz-ci-controld.service"),
    "execd": ("/usr/libexec/buzz-ci-execd", "buzz-ci-execd.service"),
    "keyholder": ("/usr/libexec/buzz-ci-keyholder", "buzz-ci-keyholder.service"),
    "qualification": ("/usr/libexec/buzz-ci-acceptance-ctl", None),
    "executor": ("/usr/libexec/buzz-ci-executor", None),
    "acceptance_canary": ("/usr/libexec/buzz-ci-capacity-one-canary", None),
    "acceptance_driver": ("/usr/libexec/buzz-ci-capacity-one-driver", None),
    "acceptance_control": ("/usr/libexec/buzz-ci-acceptance-control", "buzz-ci-acceptance-control.service"),
}

INSTALLABLE_COMPONENT_ROLES = {
    "acceptance_canary_binary": "acceptance_canary",
    "acceptance_driver_binary": "acceptance_driver",
    "acceptance_control_binary": "acceptance_control",
}
TRACKED_INSTALL_ROLES = {
    "activation_controller": (0o500, 0o755),
    "activation_package_module": (0o500, 0o644),
}

IDENTITIES = {
    "runner": "buzzci-runner",
    "controld": "buzzci-controld",
    "keyholder": "buzzci-keyholder",
    "qualification": "buzzci-ctl",
}
IDENTITY_HOMES = {
    "runner": "/var/lib/buzzci/runner",
    "controld": "/var/lib/buzzci/controld",
    "keyholder": "/var/lib/buzzci/keyholder",
    "qualification": "/var/lib/buzzci/ctl",
}
ACCESS_GROUP_NAME = "buzzci-execd"
ACCESS_GROUP_MEMBERS = ["buzzci-ctl", "buzzci-runner"]
ACCEPTANCE_BINDING_PATH = "/var/lib/buzzci/activation-controller/controld-acceptance-v1.json"
ACCEPTANCE_BINDING_SCHEMA = "buzz-ci-controld-acceptance-binding/v1"
ACTIVATION_CONTROLLER_PATH = "/usr/libexec/buzz-ci-activation-controller"
ACTIVATION_PACKAGE_MODULE_PATH = "/usr/libexec/buzz_ci_activation_package.py"
FIXED_PACKAGE_PATH = "/var/lib/buzzci/activation-controller/package"

CONFIG_TARGETS = {
    "runner_config": "/etc/buzzci/runner-v1.json",
    "controld_config": "/etc/buzzci/controld-v1.json",
    "keyholder_config": "/etc/buzzci/keyholder-v1.json",
}

START_ORDER = [
    "buzz-ci-controld-acceptance.socket",
    "buzz-ci-acceptance-control.socket",
    "buzz-ci-acceptance-control.service",
    "buzz-ci-keyholder.socket",
    "buzz-ci-execd.socket",
    "buzz-ci-runner.socket",
    "buzz-ci-controld.service",
]
STOP_ORDER = [
    "buzz-ci-controld-acceptance.socket",
    "buzz-ci-controld.service",
    "buzz-ci-acceptance-control.socket",
    "buzz-ci-acceptance-control.service",
    "buzz-ci-runner.service",
    "buzz-ci-runner.socket",
    "buzz-ci-execd.service",
    "buzz-ci-execd.socket",
    "buzz-ci-keyholder.service",
    "buzz-ci-keyholder.socket",
]
STAGED_ZERO_UNITS = [
    "buzz-ci-controld-acceptance.socket",
    "buzz-ci-controld.service",
    "buzz-ci-acceptance-control.socket",
    "buzz-ci-acceptance-control.service",
]
PERSISTENT_UNIT = "buzz-ci-capacity-one.target"

SOCKET_POLICY = {
    "acceptance_control": {
        "unit": "buzz-ci-acceptance-control.socket",
        "path": "/run/buzzci/acceptance-control.sock",
        "descriptor_name": "buzz-ci-acceptance-control",
        "user": "root",
        "group": "buzzci-ctl",
        "mode": "0620",
    },
    "controld_acceptance": {
        "unit": "buzz-ci-controld-acceptance.socket",
        "path": "/run/buzzci/controld-acceptance.sock",
        "descriptor_name": "buzz-ci-controld-acceptance",
        "user": "root",
        "group": "buzzci-ctl",
        "mode": "0620",
    },
    "keyholder": {
        "unit": "buzz-ci-keyholder.socket",
        "path": "/run/buzzci/keyholder.sock",
        "descriptor_name": "buzz-ci-keyholder-control",
        "user": "buzzci-keyholder",
        "group": "buzzci-controld",
        "mode": "0620",
    },
    "execd": {
        "unit": "buzz-ci-execd.socket",
        "path": "/run/buzzci/execd.sock",
        "descriptor_name": "buzz-ci-execd",
        "user": "root",
        "group": ACCESS_GROUP_NAME,
        "mode": "0620",
    },
    "runner": {
        "unit": "buzz-ci-runner.socket",
        "path": "/run/buzzci/runner-control.sock",
        "descriptor_name": "buzz-ci-runner-control",
        "user": "buzzci-runner",
        "group": "buzzci-controld",
        "mode": "0620",
    },
}

STATIC_TARGETS = {
    "sysusers": "/usr/lib/sysusers.d/buzzci-activation.conf",
    "tmpfiles": "/usr/lib/tmpfiles.d/buzzci-activation.conf",
    "capacity_target": "/etc/systemd/system/buzz-ci-capacity-one.target",
    "controld_acceptance_socket": "/etc/systemd/system/buzz-ci-controld-acceptance.socket",
    "acceptance_control_socket": "/etc/systemd/system/buzz-ci-acceptance-control.socket",
    "acceptance_control_service": "/etc/systemd/system/buzz-ci-acceptance-control.service",
    "acceptance_tmpfiles": "/usr/lib/tmpfiles.d/buzzci-acceptance.conf",
    "acceptance_canary_binary": COMPONENTS["acceptance_canary"][0],
    "acceptance_driver_binary": COMPONENTS["acceptance_driver"][0],
    "acceptance_control_binary": COMPONENTS["acceptance_control"][0],
    "activation_controller": ACTIVATION_CONTROLLER_PATH,
    "activation_package_module": ACTIVATION_PACKAGE_MODULE_PATH,
    "execd_socket_dropin": "/etc/systemd/system/buzz-ci-execd.socket.d/20-capacity-one.conf",
    "runner_service_dropin": "/etc/systemd/system/buzz-ci-runner.service.d/20-capacity-one.conf",
    "controld_service_dropin": "/etc/systemd/system/buzz-ci-controld.service.d/20-capacity-one.conf",
    "keyholder_socket_dropin": "/etc/systemd/system/buzz-ci-keyholder.socket.d/20-capacity-one.conf",
}


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_fd(path: Path, limit: int = MAX_ASSET_BYTES) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe regular file: {path}")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, min(1024 * 1024, limit + 1 - total)):
            total += len(chunk)
            if total > limit:
                raise ValueError(f"file exceeds byte limit: {path}")
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(fd)


def read_fd_at(parent_fd: int, name: str, limit: int = MAX_ASSET_BYTES) -> tuple[bytes, os.stat_result]:
    if not name or "/" in name or name in {".", ".."}:
        raise ValueError("unsafe descriptor-relative filename")
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe regular file: {name}")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, min(1024 * 1024, limit + 1 - total)):
            total += len(chunk)
            if total > limit:
                raise ValueError(f"file exceeds byte limit: {name}")
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(fd)


def parse_json(path: Path, limit: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes, os.stat_result]:
    raw, metadata = read_fd(path, limit)
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value, raw, metadata


def parse_mode(value: object) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0[4567][0-7]{2}", value):
        raise ValueError("mode must be a four-digit octal string")
    return int(value, 8)


def require_keys(value: dict[str, Any], expected: set[str], where: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unknown = sorted(set(value) - expected)
        raise ValueError(f"{where} keys differ: missing={missing}, unknown={unknown}")


def require_u32(value: object, where: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 0xFFFFFFFF:
        raise ValueError(f"{where} must be a {'nonzero ' if not allow_zero else ''}u32")
    return value


def require_absolute(value: object, where: str) -> str:
    if not isinstance(value, str) or "\0" in value:
        raise ValueError(f"{where} must be an absolute normalized path")
    path = PurePosixPath(value)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts) or str(path) != value:
        raise ValueError(f"{where} must be an absolute normalized path")
    return value


def require_asset(value: object, where: str) -> str:
    if not isinstance(value, str) or not ASSET.fullmatch(value):
        raise ValueError(f"{where} must name one flat assets/ file")
    return value


def _validate_identity(role: str, value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"identity {role} must be an object")
    require_keys(value, {"user", "group", "uid", "gid", "home", "shell", "supplementary_groups"}, f"identity {role}")
    expected_name = IDENTITIES[role]
    if value["user"] != expected_name or value["group"] != expected_name:
        raise ValueError(f"identity {role} has the wrong fixed name")
    require_u32(value["uid"], f"identity {role} uid")
    require_u32(value["gid"], f"identity {role} gid")
    expected_groups = [ACCESS_GROUP_NAME] if role in {"runner", "qualification"} else []
    if value["supplementary_groups"] != expected_groups:
        raise ValueError(f"identity {role} supplementary groups differ from the fixed plan")
    if value["home"] != IDENTITY_HOMES[role] or value["shell"] != "/usr/sbin/nologin":
        raise ValueError(f"identity {role} home or shell differs from the fixed plan")
    return value


def _validate_component(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("component must be an object")
    require_keys(
        value,
        {"name", "binary_path", "binary_sha256", "source_commit", "provenance_source", "provenance_sha256", "uid", "gid", "mode", "unit"},
        "component",
    )
    name = value["name"]
    if name not in COMPONENTS:
        raise ValueError("unknown component")
    expected_path, expected_unit = COMPONENTS[name]
    if value["binary_path"] != expected_path or value["unit"] != expected_unit:
        raise ValueError(f"component {name} path or unit differs from the fixed plan")
    if not isinstance(value["binary_sha256"], str) or not SHA256.fullmatch(value["binary_sha256"]):
        raise ValueError(f"component {name} binary digest is invalid")
    if not isinstance(value["source_commit"], str) or not GIT_OID.fullmatch(value["source_commit"]):
        raise ValueError(f"component {name} source commit is invalid")
    require_asset(value["provenance_source"], f"component {name} provenance")
    if not isinstance(value["provenance_sha256"], str) or not SHA256.fullmatch(value["provenance_sha256"]):
        raise ValueError(f"component {name} provenance digest is invalid")
    require_u32(value["uid"], f"component {name} uid", allow_zero=True)
    require_u32(value["gid"], f"component {name} gid", allow_zero=True)
    if value["uid"] != 0 or value["gid"] != 0:
        raise ValueError(f"component {name} binary must be root owned")
    if parse_mode(value["mode"]) != 0o755:
        raise ValueError(f"component {name} binary mode must be 0755")
    return value


def _validate_entry(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("entry must be an object")
    allowed = {"role", "source", "source_mode", "sha256", "target", "install_mode", "uid", "gid", "active_source", "active_source_mode", "active_sha256"}
    if not set(value) <= allowed:
        raise ValueError("entry contains unknown keys")
    required = {"role", "source", "source_mode", "sha256", "target", "install_mode", "uid", "gid"}
    if not required <= set(value):
        raise ValueError("entry is incomplete")
    role = value["role"]
    if role not in set(CONFIG_TARGETS) | set(STATIC_TARGETS):
        raise ValueError("entry role is unknown")
    expected_target = CONFIG_TARGETS.get(role, STATIC_TARGETS.get(role))
    if value["target"] != expected_target:
        raise ValueError(f"entry {role} target differs from the fixed plan")
    require_asset(value["source"], f"entry {role} source")
    if not isinstance(value["sha256"], str) or not SHA256.fullmatch(value["sha256"]):
        raise ValueError(f"entry {role} digest is invalid")
    parse_mode(value["source_mode"])
    parse_mode(value["install_mode"])
    require_u32(value["uid"], f"entry {role} uid", allow_zero=True)
    require_u32(value["gid"], f"entry {role} gid", allow_zero=True)
    active = {"active_source", "active_source_mode", "active_sha256"}
    if role in {"runner_config", "controld_config"}:
        if not active <= set(value):
            raise ValueError(f"entry {role} requires a distinct active payload")
        require_asset(value["active_source"], f"entry {role} active source")
        parse_mode(value["active_source_mode"])
        if not isinstance(value["active_sha256"], str) or not SHA256.fullmatch(value["active_sha256"]):
            raise ValueError(f"entry {role} active digest is invalid")
        if value["sha256"] == value["active_sha256"]:
            raise ValueError(f"entry {role} staged and active payloads must differ")
    elif role == "keyholder_config":
        if active & set(value):
            raise ValueError("keyholder configuration is provisioned while its separate socket remains dormant")
    elif active & set(value):
        raise ValueError(f"static entry {role} cannot have an active payload")
    return value


def validate_manifest(manifest: dict[str, Any], *, require_digest: bool = True) -> dict[str, Any]:
    expected = {
        "schema", "activation_id", "source_commit", "default_state", "identities", "components", "entries",
        "access_group", "systemd", "socket_policy", "qualification", "package_uid", "package_gid", "package_digest",
    }
    if not require_digest:
        expected -= {"activation_id", "package_digest"}
    require_keys(manifest, expected, "activation manifest")
    expected_schema = MANIFEST_SCHEMA if require_digest else DRAFT_SCHEMA
    if manifest["schema"] != expected_schema:
        raise ValueError("activation manifest schema is unsupported")
    source_commit = manifest["source_commit"]
    if not isinstance(source_commit, str) or not GIT_OID.fullmatch(source_commit):
        raise ValueError("activation source commit is invalid")
    if manifest["default_state"] != {"capacity": 0, "enabled": False, "active": False, "provisioned": False}:
        raise ValueError("activation package must remain dormant by default")
    if manifest["package_uid"] != 0 or manifest["package_gid"] != 0:
        raise ValueError("activation package must be root owned")

    identities = manifest["identities"]
    if not isinstance(identities, dict) or set(identities) != set(IDENTITIES):
        raise ValueError("activation identities are incomplete")
    for role in IDENTITIES:
        _validate_identity(role, identities[role])
    uids = [identities[role]["uid"] for role in IDENTITIES]
    gids = [identities[role]["gid"] for role in IDENTITIES]
    if len(set(uids)) != len(uids) or len(set(gids)) != len(gids):
        raise ValueError("activation service UIDs and GIDs must be distinct")
    access_group = manifest["access_group"]
    if not isinstance(access_group, dict):
        raise ValueError("execd access group must be an object")
    require_keys(access_group, {"group", "gid", "members"}, "execd access group")
    require_u32(access_group["gid"], "execd access group gid")
    if access_group["group"] != ACCESS_GROUP_NAME or access_group["members"] != ACCESS_GROUP_MEMBERS:
        raise ValueError("execd access group differs from the fixed membership plan")
    if access_group["gid"] in gids:
        raise ValueError("execd access group GID must be distinct")

    components = manifest["components"]
    if not isinstance(components, list) or len(components) != len(COMPONENTS):
        raise ValueError("activation components are incomplete")
    validated_components = [_validate_component(item) for item in components]
    if {item["name"] for item in validated_components} != set(COMPONENTS):
        raise ValueError("activation components must be unique and complete")

    entries = manifest["entries"]
    expected_roles = set(CONFIG_TARGETS) | set(STATIC_TARGETS)
    if not isinstance(entries, list) or len(entries) != len(expected_roles):
        raise ValueError("activation entries are incomplete")
    validated_entries = [_validate_entry(item) for item in entries]
    if {item["role"] for item in validated_entries} != expected_roles:
        raise ValueError("activation entry roles must be unique and complete")
    targets = [item["target"] for item in validated_entries]
    sources = [item["source"] for item in validated_entries]
    sources.extend(item["active_source"] for item in validated_entries if "active_source" in item)
    if len(set(targets)) != len(targets) or len(set(sources)) != len(sources):
        raise ValueError("activation entry targets and assets must be unique")
    entries_by_role = {item["role"]: item for item in validated_entries}
    for role, identity_role in (("runner_config", "runner"), ("controld_config", "controld"), ("keyholder_config", "keyholder")):
        if entries_by_role[role]["uid"] != identities[identity_role]["uid"] or entries_by_role[role]["gid"] != identities[identity_role]["gid"]:
            raise ValueError(f"entry {role} ownership differs from its service identity")
    for role in STATIC_TARGETS:
        if entries_by_role[role]["uid"] != 0 or entries_by_role[role]["gid"] != 0:
            raise ValueError(f"static entry {role} must be root owned")
    components_by_name = {item["name"]: item for item in validated_components}
    for role, component_name in INSTALLABLE_COMPONENT_ROLES.items():
        entry = entries_by_role[role]
        component = components_by_name[component_name]
        if (
            entry["sha256"] != component["binary_sha256"]
            or parse_mode(entry["install_mode"]) != 0o755
            or parse_mode(entry["source_mode"]) != 0o500
        ):
            raise ValueError(f"installable component entry differs from component provenance: {component_name}")
    for role, (source_mode, install_mode) in TRACKED_INSTALL_ROLES.items():
        entry = entries_by_role[role]
        if parse_mode(entry["source_mode"]) != source_mode or parse_mode(entry["install_mode"]) != install_mode:
            raise ValueError(f"tracked activation program entry mode differs: {role}")

    systemd = manifest["systemd"]
    require_keys(systemd, {"start_order", "stop_order", "persistent_unit", "stage_capacity", "active_capacity"}, "systemd plan")
    if systemd != {
        "start_order": START_ORDER,
        "stop_order": STOP_ORDER,
        "persistent_unit": PERSISTENT_UNIT,
        "stage_capacity": 0,
        "active_capacity": 1,
    }:
        raise ValueError("systemd activation order differs from the fixed plan")
    if manifest["socket_policy"] != SOCKET_POLICY:
        raise ValueError("socket permission plan differs from the fixed plan")

    qualification = manifest["qualification"]
    if not isinstance(qualification, dict):
        raise ValueError("qualification must be an object")
    require_keys(
        qualification,
        {"program", "principal", "request_source", "request_sha256", "expected_response_sha256", "timeout_seconds", "terminate_grace_seconds"},
        "qualification",
    )
    if qualification["program"] != COMPONENTS["qualification"][0] or qualification["principal"] != "qualification":
        raise ValueError("qualification must use the fixed acceptance controller")
    require_asset(qualification["request_source"], "qualification request")
    for field in ("request_sha256", "expected_response_sha256"):
        if not isinstance(qualification[field], str) or not SHA256.fullmatch(qualification[field]):
            raise ValueError(f"qualification {field} is invalid")
    timeout = qualification["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        raise ValueError("qualification timeout must be between 1 and 300 seconds")
    if qualification["terminate_grace_seconds"] != 2:
        raise ValueError("qualification termination grace must be two seconds")
    all_sources = sources + [item["provenance_source"] for item in validated_components] + [qualification["request_source"]]
    if len(all_sources) != len(set(all_sources)):
        raise ValueError("activation assets must not share source names")

    if require_digest:
        package_digest = manifest["package_digest"]
        activation_id = manifest["activation_id"]
        if not isinstance(package_digest, str) or not SHA256.fullmatch(package_digest):
            raise ValueError("activation package digest is invalid")
        if activation_id != f"buzz-ci-capacity-one-{source_commit[:12]}-{package_digest[:12]}":
            raise ValueError("activation id is not bound to commit and package digest")
        unsigned = dict(manifest)
        del unsigned["activation_id"]
        del unsigned["package_digest"]
        unsigned["schema"] = DRAFT_SCHEMA
        if digest(canonical_json(unsigned)) != package_digest:
            raise ValueError("activation package digest does not match canonical content")
    return manifest


def _json_payload(payload: bytes, where: str) -> dict[str, Any]:
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{where} must be valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be a JSON object")
    return value


def _contains_private_field(value: object) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = key.lower()
            if any(word in lowered for word in ("secret", "private", "seed", "credential", "token")):
                return True
            if _contains_private_field(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_private_field(item) for item in value)
    return False


def validate_phase_configs(manifest: dict[str, Any], payloads: dict[str, bytes]) -> None:
    entries = {entry["role"]: entry for entry in manifest["entries"]}
    for role in CONFIG_TARGETS:
        entry = entries[role]
        for source_field in ("source", "active_source"):
            source = entry.get(source_field)
            if source is not None and len(payloads[source]) > 64 * 1024:
                raise ValueError(f"configuration exceeds 64 KiB: {role}")
    runner = entries["runner_config"]
    runner_staged = _json_payload(payloads[runner["source"]], "staged runner configuration")
    runner_active = _json_payload(payloads[runner["active_source"]], "active runner configuration")
    if set(runner_staged) != {"schema_version", "controld_uid"} or set(runner_active) != {"schema_version", "controld_uid", "host"}:
        raise ValueError("runner capacity flip must add one complete host block")
    if runner_staged["schema_version"] != 1:
        raise ValueError("runner configuration schema must remain version one")
    if runner_staged.get("schema_version") != runner_active.get("schema_version") or runner_staged.get("controld_uid") != runner_active.get("controld_uid"):
        raise ValueError("runner staged and active identity binding differs")
    if runner_staged.get("controld_uid") != manifest["identities"]["controld"]["uid"]:
        raise ValueError("runner configuration is not bound to the controld UID")
    host = runner_active["host"]
    host_fields = {
        "owner_pubkey", "manifest_verification_key", "relay_signer", "broker_socket", "broker_uid",
        "executor_program", "evidence_directory", "journal_directory", "max_argv_items", "max_argv_bytes",
        "max_environment_items", "max_environment_bytes", "max_output_bytes",
    }
    if not isinstance(host, dict) or set(host) != host_fields:
        raise ValueError("runner active host block is incomplete")
    for field in ("owner_pubkey", "manifest_verification_key", "relay_signer"):
        if not isinstance(host[field], str) or not SHA256.fullmatch(host[field]):
            raise ValueError(f"runner active host identity is invalid: {field}")
    if host.get("broker_socket") != SOCKET_POLICY["execd"]["path"] or host.get("broker_uid") != 0:
        raise ValueError("runner active configuration does not bind the root execd peer")
    if host["executor_program"] != COMPONENTS["executor"][0]:
        raise ValueError("runner executor program is not bound to the packaged executor component")
    if host["evidence_directory"] != "/var/lib/buzzci/runner/evidence" or host["journal_directory"] != "/var/lib/buzzci/runner/journal":
        raise ValueError("runner active state directories differ from the frozen interface")
    for field, maximum in (
        ("max_argv_items", 256),
        ("max_argv_bytes", 65_536),
        ("max_environment_items", 256),
        ("max_environment_bytes", 65_536),
        ("max_output_bytes", 16_777_216),
    ):
        value = host[field]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise ValueError(f"runner active bound is invalid: {field}")

    controld = entries["controld_config"]
    controld_staged = _json_payload(payloads[controld["source"]], "staged controld configuration")
    controld_active = _json_payload(payloads[controld["active_source"]], "active controld configuration")
    staged_fields = {"schema_version", "capacity", "store_root", "acceptance_binding"}
    if set(controld_staged) != staged_fields:
        raise ValueError("staged controld configuration differs from the frozen closed interface")
    if controld_staged.get("capacity") != 0 or controld_active.get("capacity") != 1:
        raise ValueError("controld configuration must flip from capacity zero to one")
    if controld_staged.get("schema_version") != 1 or controld_active.get("schema_version") != 1:
        raise ValueError("controld schema changes during activation")
    if controld_staged.get("store_root") != "/var/lib/buzzci/controld" or controld_active.get("store_root") != "/var/lib/buzzci/controld":
        raise ValueError("controld store root changes during activation")
    active_fields = {
        "schema_version", "capacity", "store_root", "relay_url", "runner_socket", "keyholder_socket",
        "keyholder_uid", "keyholder_gid", "keyholder_selectors", "keyholder_timeout_millis",
        "keyholder_transport_attempts", "acceptance_binding",
    }
    if set(controld_active) != active_fields:
        raise ValueError("active controld configuration differs from the strict interface")
    if (
        controld_staged["acceptance_binding"] != ACCEPTANCE_BINDING_PATH
        or controld_active["acceptance_binding"] != ACCEPTANCE_BINDING_PATH
    ):
        raise ValueError("controld acceptance binding path differs from the fixed interface")
    if not isinstance(controld_active["relay_url"], str) or not controld_active["relay_url"].startswith("wss://"):
        raise ValueError("controld relay URL must use wss")
    if controld_active.get("runner_socket") != SOCKET_POLICY["runner"]["path"]:
        raise ValueError("controld active configuration does not bind the runner socket")
    if controld_active.get("keyholder_socket") != SOCKET_POLICY["keyholder"]["path"]:
        raise ValueError("controld active configuration does not bind the separate keyholder socket")
    keyholder_identity = manifest["identities"]["keyholder"]
    if (
        controld_active["keyholder_uid"] != keyholder_identity["uid"]
        or controld_active["keyholder_gid"] != keyholder_identity["gid"]
    ):
        raise ValueError("controld keyholder peer credentials differ from the manifest")
    for field, maximum in (("keyholder_timeout_millis", 60_000), ("keyholder_transport_attempts", 16)):
        value = controld_active[field]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise ValueError(f"controld keyholder bound is invalid: {field}")
    controld_encoded = canonical_json(controld_active)
    if SOCKET_POLICY["execd"]["path"].encode() in controld_encoded or COMPONENTS["execd"][0].encode() in controld_encoded:
        raise ValueError("controld configuration must not bypass the runner to reach execd")

    keyholder = entries["keyholder_config"]
    keyholder_value = _json_payload(payloads[keyholder["source"]], "keyholder configuration")
    if any(_contains_private_field(value) for value in (runner_staged, runner_active, controld_staged, controld_active, keyholder_value)):
        raise ValueError("activation packages cannot contain secrets or credentials")
    if set(keyholder_value) != {"schema_version", "peer", "selectors", "nip98_origin"}:
        raise ValueError("keyholder configuration differs from the daemon interface")
    if keyholder_value.get("schema_version") != 1:
        raise ValueError("keyholder configuration schema must be version one")
    expected_peer = {
        "uid": manifest["identities"]["controld"]["uid"],
        "gid": manifest["identities"]["controld"]["gid"],
    }
    if keyholder_value["peer"] != expected_peer:
        raise ValueError("keyholder peer credentials differ from the controld principal")
    selectors = keyholder_value["selectors"]
    if not isinstance(selectors, dict) or set(selectors) != {"ci_event", "nip98", "manifest"}:
        raise ValueError("keyholder selectors are incomplete")
    for name, selector in selectors.items():
        if not isinstance(selector, dict) or set(selector) != {"public_key", "generation"}:
            raise ValueError(f"keyholder selector is invalid: {name}")
        if not isinstance(selector["public_key"], str) or not SHA256.fullmatch(selector["public_key"]):
            raise ValueError(f"keyholder selector public key is invalid: {name}")
        generation = selector["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or not 1 <= generation <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"keyholder selector generation is invalid: {name}")
    origin = keyholder_value["nip98_origin"]
    if not isinstance(origin, str) or "\0" in origin:
        raise ValueError("keyholder NIP-98 origin must use https")
    parsed_origin = urlsplit(origin)
    if (
        parsed_origin.scheme != "https"
        or not parsed_origin.hostname
        or parsed_origin.username is not None
        or parsed_origin.password is not None
        or parsed_origin.path not in {"", "/"}
        or parsed_origin.query
        or parsed_origin.fragment
    ):
        raise ValueError("keyholder NIP-98 origin must be one HTTPS origin")
    if controld_active["keyholder_selectors"] != selectors:
        raise ValueError("controld keyholder selectors differ from the daemon configuration")
    keyholder_encoded = canonical_json(keyholder_value)
    if SOCKET_POLICY["execd"]["path"].encode() in keyholder_encoded or COMPONENTS["execd"][0].encode() in keyholder_encoded:
        raise ValueError("keyholder configuration must not reach execd")


def validate_payloads(manifest: dict[str, Any], payloads: dict[str, bytes]) -> None:
    validate_phase_configs(manifest, payloads)
    request_source = manifest["qualification"]["request_source"]
    if len(payloads[request_source]) > 64 * 1024:
        raise ValueError("qualification request exceeds 64 KiB")


def rooted(root: Path, target: str) -> Path:
    require_absolute(target, "target")
    root = Path(os.path.abspath(root))
    if Path(os.path.realpath(root)) != root:
        raise ValueError("root must be a real absolute directory")
    return root / target.lstrip("/")


def open_parent_fd(root: Path, target: str, *, create: bool = False) -> tuple[int, str]:
    """Open a target parent one no-follow directory descriptor at a time."""
    require_absolute(target, "target")
    root = Path(os.path.abspath(root))
    current_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        parts = PurePosixPath(target).parts[1:]
        if not parts:
            raise ValueError("target must not be the filesystem root")
        for part in parts[:-1]:
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o755, dir_fd=current_fd)
                os.fsync(current_fd)
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
            metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_fd)
                raise ValueError(f"target parent is not a directory: {part}")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd, parts[-1]
    except BaseException:
        if current_fd >= 0:
            os.close(current_fd)
        raise
