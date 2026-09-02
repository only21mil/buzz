#!/usr/bin/env python3
"""Shared validation and descriptor-safe I/O for Buzz CI activation packages."""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any
from urllib.parse import urlsplit
import uuid

MANIFEST_SCHEMA = "buzz-ci-capacity-one-activation-package-v2"
DRAFT_SCHEMA = "buzz-ci-capacity-one-activation-draft-v2"
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
    "qualification": ("/usr/libexec/buzz-ci-production-qualification", None),
    "executor": ("/usr/libexec/buzz-ci-executor", None),
    "acceptance_canary": ("/usr/libexec/buzz-ci-capacity-one-canary", None),
    "acceptance_driver": ("/usr/libexec/buzz-ci-capacity-one-driver", None),
    "acceptance_control": ("/usr/libexec/buzz-ci-acceptance-control", "buzz-ci-acceptance-control.service"),
    "receipt_verifier": ("/usr/libexec/buzz-ci-verify-acceptance-receipt", None),
}

INSTALLABLE_COMPONENT_ROLES = {
    "qualification_binary": "qualification",
    "acceptance_canary_binary": "acceptance_canary",
    "acceptance_driver_binary": "acceptance_driver",
    "acceptance_control_binary": "acceptance_control",
    "receipt_verifier_binary": "receipt_verifier",
    "executor_binary": "executor",
}
TRACKED_INSTALL_ROLES = {
    "activation_controller": (0o500, 0o755),
    "activation_package_module": (0o500, 0o644),
    "receipt_verifier_binary": (0o500, 0o755),
    "receipt_verifier_expected_stages": (0o400, 0o644),
    "fixture_manifest": (0o400, 0o444),
    "fixture_input": (0o400, 0o444),
    "fixture_script": (0o500, 0o555),
    "execd_service": (0o400, 0o644),
    "execd_socket": (0o400, 0o644),
    "executor_service": (0o400, 0o644),
    "executor_socket": (0o400, 0o644),
}

IDENTITIES = {
    "runner": "buzzci-runner",
    "controld": "buzzci-controld",
    "keyholder": "buzzci-keyholder",
    "qualification": "buzzci-ctl",
    "job": "buzzci-job",
}
IDENTITY_HOMES = {
    "runner": "/var/lib/buzzci/runner",
    "controld": "/var/lib/buzzci/controld",
    "keyholder": "/var/lib/buzzci/keyholder",
    "qualification": "/var/lib/buzzci/principals/ctl",
    "job": "/var/empty",
}
QUALIFICATION_UID = 961
QUALIFICATION_GID = 961
ACCESS_GROUP_NAME = "buzzci-execd"
ACCESS_GROUP_MEMBERS = ["buzzci-ctl", "buzzci-runner"]
ACCEPTANCE_BINDING_PATH = "/var/lib/buzzci/activation-controller/controld-acceptance-v2.json"
ACCEPTANCE_BINDING_SCHEMA = "buzz-ci-activation-acceptance-binding/v2"
ACTIVATION_CONTROLLER_PATH = "/usr/libexec/buzz-ci-activation-controller"
ACTIVATION_PACKAGE_MODULE_PATH = "/usr/libexec/buzz_ci_activation_package.py"
FIXED_PACKAGE_PATH = "/var/lib/buzzci/activation-controller/package"

CONFIG_TARGETS = {
    "runner_config": "/etc/buzzci/runner-v2.json",
    "execd_config": "/etc/buzzci/execd-v2.json",
    "controld_config": "/etc/buzzci/controld-v2.json",
}
KEYHOLDER_CONFIG_PATH = "/etc/buzzci/keyholder-v2.json"
KEYHOLDER_ALLOWED_OPERATIONS = [
    "describe", "sign_ci_event", "nip98_authorize", "sign_manifest",
    "describe_acceptance", "sign_acceptance_mutation",
]

START_ORDER = [
    "buzz-ci-controld-acceptance.socket",
    "buzz-ci-acceptance-control.socket",
    "buzz-ci-acceptance-control.service",
    "buzz-ci-keyholder.socket",
    "buzz-ci-executor.socket",
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
    "buzz-ci-executor.service",
    "buzz-ci-executor.socket",
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

EXECD_V2_PROTOCOL = 2
REGISTER_JOB_INTENT_OPERATION = 9
EXECD_INTENT_ROOT = "/var/lib/buzzci/execd-v2/intents"
EXECD_BINDING_ROOT = "/var/lib/buzzci/execd-v2/bindings"
EXECD_EVIDENCE_ROOT = "/var/lib/buzzci/execd-v2/evidence"
EXECD_TEARDOWN_ROOT = "/var/lib/buzzci/execd-v2/teardown"
EXECD_ATTEMPT_ROOT = "/var/lib/buzzci/execd-v2/attempts"
EXECD_QUALIFICATION_ROOT = "/var/lib/buzzci/execd-v2/qualification"
EXECD_DYNAMIC_DIGEST_PLACEHOLDER = "0" * 64
EXECUTION_SCHEMA_VERSION = 1
EXECUTION_DIGEST_DOMAIN = b"buzz-ci-execd:static-execution:v1\0"
FIXTURE_MANIFEST_SHA256 = "f204b8fba64e972408f5a0ea1c0bb3140cfa696289903d96a8cb07d602af6b23"
FIXTURE_INPUT_SHA256 = "967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6"
FIXTURE_SCRIPT_SHA256 = "d081e43ebfde3ee67c3cd8d852d58410a79ad799bbfa2cf98d5e2ef7b8bed3b1"
FIXTURE_MANIFEST_PATH = "/usr/share/buzzci/execd-v2/fixture/fixture-manifest.json"
FIXTURE_INPUT_PATH = "/usr/share/buzzci/execd-v2/fixture/input.txt"
FIXTURE_SCRIPT_PATH = "/usr/libexec/buzz-ci-capacity-one-fixture"
EXECUTOR_SOCKET_PATH = "/run/buzzci/executor.sock"
RUNNER_REPLAY_JOURNAL = "/var/lib/buzzci/runner/v2-replay.json"
SECCOMP_PROFILE_DIGEST = "2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4"
SECCOMP_PROFILE_PATH = f"/var/lib/buzzci/seccomp/v1/sha256/{SECCOMP_PROFILE_DIGEST}.json"
RECEIPT_VERIFIER_EXPECTED_STAGES_SHA256 = "c8addbb42bace522e99fc8fe00603c9245db61ac8a599ef5762c2744267189cd"
QUALIFICATION_SOURCE_COMMIT = "564e41fda889f25b094b79524b3fb409121794c7"
LANE_MANIFEST_DIGEST_DOMAIN = b"buzz-ci:lane-activation-manifest:v1\0"

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
    "executor": {
        "unit": "buzz-ci-executor.socket",
        "path": EXECUTOR_SOCKET_PATH,
        "descriptor_name": "buzz-ci-executor",
        "user": "root",
        "group": "root",
        "mode": "0600",
    },
}

STATIC_TARGETS = {
    "sysusers": "/usr/lib/sysusers.d/buzzci-activation.conf",
    "tmpfiles": "/usr/lib/tmpfiles.d/buzzci-activation.conf",
    "capacity_target": "/etc/systemd/system/buzz-ci-capacity-one.target",
    "acceptance_control_socket": "/etc/systemd/system/buzz-ci-acceptance-control.socket",
    "acceptance_control_service": "/etc/systemd/system/buzz-ci-acceptance-control.service",
    "acceptance_tmpfiles": "/usr/lib/tmpfiles.d/buzzci-acceptance.conf",
    "acceptance_canary_binary": COMPONENTS["acceptance_canary"][0],
    "acceptance_driver_binary": COMPONENTS["acceptance_driver"][0],
    "acceptance_control_binary": COMPONENTS["acceptance_control"][0],
    "receipt_verifier_binary": COMPONENTS["receipt_verifier"][0],
    "receipt_verifier_expected_stages": "/usr/libexec/buzz-ci-acceptance-expected-stages.json",
    "qualification_binary": COMPONENTS["qualification"][0],
    "executor_binary": COMPONENTS["executor"][0],
    "fixture_manifest": FIXTURE_MANIFEST_PATH,
    "fixture_input": FIXTURE_INPUT_PATH,
    "fixture_script": FIXTURE_SCRIPT_PATH,
    "execd_service": "/usr/lib/systemd/system/buzz-ci-execd.service",
    "execd_socket": "/usr/lib/systemd/system/buzz-ci-execd.socket",
    "executor_service": "/usr/lib/systemd/system/buzz-ci-executor.service",
    "executor_socket": "/usr/lib/systemd/system/buzz-ci-executor.socket",
    "activation_controller": ACTIVATION_CONTROLLER_PATH,
    "activation_package_module": ACTIVATION_PACKAGE_MODULE_PATH,
    "execd_socket_dropin": "/etc/systemd/system/buzz-ci-execd.socket.d/20-capacity-one.conf",
    "runner_service_dropin": "/etc/systemd/system/buzz-ci-runner.service.d/20-capacity-one.conf",
    "controld_service_dropin": "/etc/systemd/system/buzz-ci-controld.service.d/20-capacity-one.conf",
    "keyholder_socket_dropin": "/etc/systemd/system/buzz-ci-keyholder.socket.d/20-capacity-one.conf",
}
COMPONENT_PACKAGE_NAMES = ("runner", "controld")
COMPONENT_TMPFILES_TARGETS = {
    "runner": "/usr/lib/tmpfiles.d/buzzci-runner.conf",
    "controld": "/usr/lib/tmpfiles.d/buzzci-controld.conf",
}

PACKAGE_UNIT_ROLES = {
    PERSISTENT_UNIT: "capacity_target",
    "buzz-ci-acceptance-control.socket": "acceptance_control_socket",
    "buzz-ci-acceptance-control.service": "acceptance_control_service",
    "buzz-ci-execd.service": "execd_service",
    "buzz-ci-execd.socket": "execd_socket",
    "buzz-ci-executor.service": "executor_service",
    "buzz-ci-executor.socket": "executor_socket",
}
DEPENDENCY_UNITS = sorted(
    set(START_ORDER + STOP_ORDER) - set(PACKAGE_UNIT_ROLES)
)

PLATFORM_SYSTEMD = {
    "schema_version": "buzz-ci-systemd-platform-binding/v1",
    "platform_id": "fedora-44-systemd-259",
    "service_drop_ins": [{
        "owner": "platform",
        "path": "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
        "sha256": "ae6b234f92bc22f1201a7572b59b454c9809f33c80d13f361b9674e1801acc37",
    }],
}


def systemd_drop_in_order(paths: list[str]) -> list[str]:
    """Return systemd's bytewise basename order, rejecting ambiguous overrides."""
    basenames: dict[bytes, str] = {}
    for path in paths:
        if not isinstance(path, str):
            raise ValueError("systemd drop-in path must be text")
        basename = PurePosixPath(path).name.encode("utf-8")
        if not basename or basename in basenames:
            raise ValueError("systemd drop-in basename collision is ambiguous")
        basenames[basename] = path
    return [basenames[basename] for basename in sorted(basenames)]


def _service_drop_ins(*records: dict[str, str]) -> list[dict[str, str]]:
    combined = [
        *records,
        *[
            {"owner": item["owner"], "path": item["path"]}
            for item in PLATFORM_SYSTEMD["service_drop_ins"]
        ],
    ]
    by_path = {item["path"]: item for item in combined}
    return [
        by_path[path]
        for path in systemd_drop_in_order([item["path"] for item in combined])
    ]

SYSTEMD_UNIT_LAYOUT = {
    "buzz-ci-capacity-one.target": {
        "fragment": {"owner": "activation", "path": "/etc/systemd/system/buzz-ci-capacity-one.target"},
        "drop_ins": [],
    },
    "buzz-ci-controld-acceptance.socket": {
        "fragment": {"owner": "controld", "path": "/etc/systemd/system/buzz-ci-controld-acceptance.socket"},
        "drop_ins": [],
    },
    "buzz-ci-acceptance-control.socket": {
        "fragment": {"owner": "activation", "path": "/etc/systemd/system/buzz-ci-acceptance-control.socket"},
        "drop_ins": [],
    },
    "buzz-ci-acceptance-control.service": {
        "fragment": {"owner": "activation", "path": "/etc/systemd/system/buzz-ci-acceptance-control.service"},
        "drop_ins": _service_drop_ins(),
    },
    "buzz-ci-runner.service": {
        "fragment": {"owner": "runner", "path": "/etc/systemd/system/buzz-ci-runner.service"},
        "drop_ins": _service_drop_ins(
            {"owner": "activation", "path": "/etc/systemd/system/buzz-ci-runner.service.d/20-capacity-one.conf"},
        ),
    },
    "buzz-ci-runner.socket": {
        "fragment": {"owner": "runner", "path": "/etc/systemd/system/buzz-ci-runner.socket"},
        "drop_ins": [],
    },
    "buzz-ci-controld.service": {
        "fragment": {"owner": "controld", "path": "/etc/systemd/system/buzz-ci-controld.service"},
        "drop_ins": _service_drop_ins(
            {"owner": "activation", "path": "/etc/systemd/system/buzz-ci-controld.service.d/20-capacity-one.conf"},
        ),
    },
    "buzz-ci-keyholder.service": {
        "fragment": {"owner": "keyholder", "path": "/etc/systemd/system/buzz-ci-keyholder.service"},
        "drop_ins": _service_drop_ins(
            {"owner": "keyholder", "path": "/etc/systemd/system/buzz-ci-keyholder.service.d/20-acceptance-actor.conf"},
        ),
    },
    "buzz-ci-keyholder.socket": {
        "fragment": {"owner": "keyholder", "path": "/etc/systemd/system/buzz-ci-keyholder.socket"},
        "drop_ins": [
            {"owner": "activation", "path": "/etc/systemd/system/buzz-ci-keyholder.socket.d/20-capacity-one.conf"},
        ],
    },
    "buzz-ci-execd.service": {
        "fragment": {"owner": "activation", "path": "/usr/lib/systemd/system/buzz-ci-execd.service"},
        "drop_ins": _service_drop_ins(),
    },
    "buzz-ci-execd.socket": {
        "fragment": {"owner": "activation", "path": "/usr/lib/systemd/system/buzz-ci-execd.socket"},
        "drop_ins": [
            {"owner": "activation", "path": "/etc/systemd/system/buzz-ci-execd.socket.d/20-capacity-one.conf"},
        ],
    },
    "buzz-ci-executor.service": {
        "fragment": {"owner": "activation", "path": "/usr/lib/systemd/system/buzz-ci-executor.service"},
        "drop_ins": _service_drop_ins(),
    },
    "buzz-ci-executor.socket": {
        "fragment": {"owner": "activation", "path": "/usr/lib/systemd/system/buzz-ci-executor.socket"},
        "drop_ins": [],
    },
}

SYSTEMD_ENTRY_ROLES = {
    target: role
    for role, target in STATIC_TARGETS.items()
    if target.startswith(("/etc/systemd/system/", "/usr/lib/systemd/system/"))
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
    base_fields = {
        "name", "binary_path", "binary_sha256", "source_commit", "provenance_source",
        "provenance_sha256", "uid", "gid", "mode", "unit",
    }
    package_manifest_fields = {
        "package_manifest_source", "package_manifest_sha256", "package_digest",
    }
    name = value.get("name")
    require_keys(
        value,
        base_fields | (package_manifest_fields if name in COMPONENT_PACKAGE_NAMES else set()),
        "component",
    )
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
    if name in COMPONENT_PACKAGE_NAMES:
        require_asset(value["package_manifest_source"], f"{name} package manifest")
        for field in ("package_manifest_sha256", "package_digest"):
            if not isinstance(value[field], str) or not SHA256.fullmatch(value[field]):
                raise ValueError(f"{name} {field} is invalid")
    return value


def _validate_effective_systemd(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(SYSTEMD_UNIT_LAYOUT):
        raise ValueError("effective systemd inventory is incomplete")
    result: list[dict[str, Any]] = []
    observed_units: set[str] = set()
    observed_paths: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("effective systemd item must be an object")
        require_keys(item, {"unit", "fragment", "drop_ins"}, "effective systemd item")
        unit = item["unit"]
        if not isinstance(unit, str) or unit not in SYSTEMD_UNIT_LAYOUT or unit in observed_units:
            raise ValueError("effective systemd unit is unknown or duplicated")
        observed_units.add(unit)
        layout = SYSTEMD_UNIT_LAYOUT[unit]
        fragment = item["fragment"]
        if not isinstance(fragment, dict):
            raise ValueError(f"effective systemd fragment is invalid: {unit}")
        require_keys(fragment, {"owner", "path", "sha256"}, f"effective systemd fragment {unit}")
        if {key: fragment[key] for key in ("owner", "path")} != layout["fragment"]:
            raise ValueError(f"effective systemd fragment owner or path differs: {unit}")
        if not isinstance(fragment["sha256"], str) or not SHA256.fullmatch(fragment["sha256"]):
            raise ValueError(f"effective systemd fragment digest is invalid: {unit}")
        require_absolute(fragment["path"], f"effective systemd fragment path {unit}")
        if fragment["path"] in observed_paths:
            raise ValueError("effective systemd path is duplicated")
        observed_paths.add(fragment["path"])
        drop_ins = item["drop_ins"]
        if not isinstance(drop_ins, list) or len(drop_ins) != len(layout["drop_ins"]):
            raise ValueError(f"effective systemd drop-in inventory differs: {unit}")
        for index, (drop_in, expected) in enumerate(zip(drop_ins, layout["drop_ins"], strict=True)):
            if not isinstance(drop_in, dict):
                raise ValueError(f"effective systemd drop-in is invalid: {unit}")
            require_keys(drop_in, {"owner", "path", "sha256"}, f"effective systemd drop-in {unit}")
            if {key: drop_in[key] for key in ("owner", "path")} != expected:
                raise ValueError(f"effective systemd drop-in owner, path, or order differs: {unit} index {index}")
            if not isinstance(drop_in["sha256"], str) or not SHA256.fullmatch(drop_in["sha256"]):
                raise ValueError(f"effective systemd drop-in digest is invalid: {unit}")
            require_absolute(drop_in["path"], f"effective systemd drop-in path {unit}")
            if drop_in["path"] in observed_paths and drop_in["owner"] != "platform":
                raise ValueError("effective systemd path is duplicated")
            if drop_in["owner"] != "platform":
                observed_paths.add(drop_in["path"])
        result.append(item)
    if observed_units != set(SYSTEMD_UNIT_LAYOUT):
        raise ValueError("effective systemd units are incomplete")
    if [item["unit"] for item in result] != sorted(SYSTEMD_UNIT_LAYOUT):
        raise ValueError("effective systemd units must use bytewise name order")
    return result


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
    if role in {"runner_config", "execd_config", "controld_config"}:
        if not active <= set(value):
            raise ValueError(f"entry {role} requires a distinct active payload")
        require_asset(value["active_source"], f"entry {role} active source")
        parse_mode(value["active_source_mode"])
        if not isinstance(value["active_sha256"], str) or not SHA256.fullmatch(value["active_sha256"]):
            raise ValueError(f"entry {role} active digest is invalid")
        if value["sha256"] == value["active_sha256"]:
            raise ValueError(f"entry {role} staged and active payloads must differ")
    elif active & set(value):
        raise ValueError(f"static entry {role} cannot have an active payload")
    return value


def validate_manifest(manifest: dict[str, Any], *, require_digest: bool = True) -> dict[str, Any]:
    expected = {
        "schema", "activation_id", "source_commit", "default_state", "identities", "components", "entries",
        "access_group", "acceptance_template", "systemd", "platform_systemd", "effective_systemd", "socket_policy", "qualification", "package_uid",
        "package_gid", "package_digest",
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
    if manifest["platform_systemd"] != PLATFORM_SYSTEMD:
        raise ValueError("systemd platform binding differs from the fixed plan")

    identities = manifest["identities"]
    if not isinstance(identities, dict) or set(identities) != set(IDENTITIES):
        raise ValueError("activation identities are incomplete")
    for role in IDENTITIES:
        _validate_identity(role, identities[role])
    qualification_identity = identities["qualification"]
    if (
        qualification_identity["uid"] != QUALIFICATION_UID
        or qualification_identity["gid"] != QUALIFICATION_GID
    ):
        raise ValueError("qualification identity must preserve the installed buzzci-ctl UID and GID")
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
    validate_acceptance_template(manifest["acceptance_template"])

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
    for role, identity_role in (("runner_config", "runner"), ("controld_config", "controld")):
        if entries_by_role[role]["uid"] != identities[identity_role]["uid"] or entries_by_role[role]["gid"] != identities[identity_role]["gid"]:
            raise ValueError(f"entry {role} ownership differs from its service identity")
    if entries_by_role["execd_config"]["uid"] != 0 or entries_by_role["execd_config"]["gid"] != 0:
        raise ValueError("execd v2 configuration must be root owned")
    for role in STATIC_TARGETS:
        if entries_by_role[role]["uid"] != 0 or entries_by_role[role]["gid"] != 0:
            raise ValueError(f"static entry {role} must be root owned")
    if entries_by_role["receipt_verifier_expected_stages"]["sha256"] != RECEIPT_VERIFIER_EXPECTED_STAGES_SHA256:
        raise ValueError("receipt verifier expected stages digest differs from the frozen contract")
    for role, expected in (
        ("fixture_manifest", FIXTURE_MANIFEST_SHA256),
        ("fixture_input", FIXTURE_INPUT_SHA256),
        ("fixture_script", FIXTURE_SCRIPT_SHA256),
    ):
        if entries_by_role[role]["sha256"] != expected:
            raise ValueError(f"capacity-one fixture digest differs: {role}")
    components_by_name = {item["name"]: item for item in validated_components}
    if components_by_name["qualification"]["source_commit"] != QUALIFICATION_SOURCE_COMMIT:
        raise ValueError("production-v2 qualification client source commit differs from the frozen ABI")
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

    effective_systemd = _validate_effective_systemd(manifest["effective_systemd"])
    platform_records = {
        item["path"]: item for item in manifest["platform_systemd"]["service_drop_ins"]
    }
    for unit in effective_systemd:
        for record in (unit["fragment"], *unit["drop_ins"]):
            role = SYSTEMD_ENTRY_ROLES.get(record["path"])
            if record["owner"] == "activation":
                if role is None or entries_by_role[role]["sha256"] != record["sha256"]:
                    raise ValueError(f"activation effective systemd bytes differ: {record['path']}")
            elif record["owner"] == "platform":
                if role is not None or platform_records.get(record["path"]) != record:
                    raise ValueError(f"platform effective systemd binding differs: {record['path']}")
            elif role is not None:
                raise ValueError(f"non-activation systemd path is activation-owned: {record['path']}")

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
        {"program", "principal", "request_validity_seconds", "timeout_seconds", "terminate_grace_seconds"},
        "qualification",
    )
    if qualification["program"] != COMPONENTS["qualification"][0] or qualification["principal"] != "qualification":
        raise ValueError("qualification must use the fixed production-v2 client")
    if qualification["request_validity_seconds"] != 60:
        raise ValueError("qualification request lifetime must be sixty seconds")
    timeout = qualification["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        raise ValueError("qualification timeout must be between 1 and 300 seconds")
    if qualification["terminate_grace_seconds"] != 2:
        raise ValueError("qualification termination grace must be two seconds")
    all_sources = sources + [item["provenance_source"] for item in validated_components]
    all_sources.extend(
        components_by_name[name]["package_manifest_source"]
        for name in COMPONENT_PACKAGE_NAMES
    )
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


def _nonzero_sha256(value: object, where: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value) or value == "0" * 64:
        raise ValueError(f"{where} must be a nonzero lowercase SHA-256")
    return value


def _positive_integer(value: object, maximum: int, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(f"{where} is outside its fixed bound")
    return value


def production_acceptance_template(
    *, actor_public_key: str, actor_generation: int, ci_signer_public_key: str,
    candidate_sha: str, workflow_id: str, workflow_digest: str, job_id: str,
    time_reference: int,
) -> dict[str, Any]:
    """Build the one canonical public Run/Grant/Rerun/Tombstone authority set.

    The set is static: its event ids are bound by digest into the keyholder
    signing policy, the controld acceptance authority, the scenario fixture,
    and the acceptance binding receipt. Its request windows therefore hang off
    ``time_reference``, the package's bound time reference recorded at freeze
    and carried in the manifest, and the runner judges every admission and
    cancel window against that same value as a static activation coordinate
    (``acceptance_time_reference``), never against the wall clock.
    """
    actor = _nonzero_sha256(actor_public_key, "public acceptance actor")
    signer = _nonzero_sha256(ci_signer_public_key, "public CI signer")
    _positive_integer(actor_generation, 0xFFFFFFFFFFFFFFFF, "public acceptance actor generation")
    if not GIT_OID.fullmatch(candidate_sha):
        raise ValueError("production acceptance candidate must be a full SHA-1 object id")
    if not isinstance(workflow_id, str) or not workflow_id or len(workflow_id.encode("utf-8")) > 64:
        raise ValueError("production acceptance workflow id is invalid")
    _nonzero_sha256(workflow_digest, "production acceptance workflow digest")
    if not isinstance(job_id, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", job_id) is None:
        raise ValueError("production acceptance job id is invalid")

    channel = "12345678-1234-4abc-8def-123456789abc"
    run_id = "13131313-1313-4313-8313-131313131313"
    target_repo = f"30617:{'22' * 32}:buzz"
    pr_event = "33" * 32
    issued_at = _positive_integer(
        time_reference, 0xFFFFFFFFFFFFFFFF - 601, "public acceptance time reference",
    )

    def request(*, request_type: str, attempt: int, idempotency_key: str) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": 1,
            "request_type": request_type,
            "target_repo_a": target_repo,
            "pr_root_event_id": pr_event,
            "source_clone_url": "https://relay.example.invalid/git/buzz",
            "immutable_source_ref": "refs/nostr/source",
            "tip_oid": candidate_sha,
            "source_branch": "acceptance/capacity-one",
            "base_ref": "refs/heads/main",
            "base_oid": candidate_sha,
            "workflow_id": workflow_id,
            "workflow_digest": workflow_digest,
            "job_ids": [job_id],
            "run_id": run_id,
            "attempt": attempt,
        }
        if request_type == "rerun":
            value.update({"parent_attempt": 1, "parent_run_id": run_id})
        value.update({
            "trigger_event_id": pr_event,
            "actor": actor,
            "timeout_seconds": 120,
            "idempotency_key": idempotency_key,
            # Every request is issued at the reference: the runner and execd
            # judge issued_at <= reference < expires_at for the run and the
            # rerun alike (H9 clean host: a rerun issued at reference + 10 was
            # refused as issued after the package time reference).
            "issued_at": issued_at,
            "expires_at": issued_at + (300 if attempt == 1 else 310),
        })
        return value

    run = request(
        request_type="run", attempt=1,
        idempotency_key="12121212-1212-4212-8212-121212121212",
    )
    rerun = request(
        request_type="rerun", attempt=2,
        idempotency_key="14141414-1414-4414-8414-141414141414",
    )

    def request_event(envelope: dict[str, Any]) -> list[object]:
        attempt = str(envelope["attempt"])
        tags = [
            ["h", channel], ["a", target_repo], ["run", run_id],
            ["workflow", workflow_id], ["c", candidate_sha], ["attempt", attempt],
        ]
        return [
            0, actor, envelope["issued_at"], 46_100, tags,
            json.dumps(envelope, ensure_ascii=False, separators=(",", ":")),
        ]

    run_event = request_event(run)
    rerun_event = request_event(rerun)
    grant = {
        "schema_version": 1,
        "target_repo_a": target_repo,
        "signer_pubkey": signer,
        "valid_from": issued_at + 1,
        "valid_until": issued_at + 601,
    }
    grant_event = [
        0, actor, issued_at + 1, 46_107, [["h", channel]],
        json.dumps(grant, ensure_ascii=False, separators=(",", ":")),
    ]
    rerun_event_id = digest(json.dumps(
        rerun_event, ensure_ascii=False, separators=(",", ":"),
    ).encode())
    return validate_acceptance_template({
        "actor": {"public_key": actor, "generation": actor_generation},
        "time_reference": issued_at,
        "run_event": run_event,
        "grant_event": grant_event,
        "rerun_event": rerun_event,
        "tombstone_event": [0, actor, issued_at + 20, 5, [["e", rerun_event_id]], ""],
    })


def production_activation_draft(
    *, source_commit: str, identities: dict[str, Any], access_group: dict[str, Any],
    components: list[dict[str, Any]], entries: list[dict[str, Any]],
    effective_systemd: list[dict[str, Any]], actor_public_key: str,
    actor_generation: int, ci_signer_public_key: str, workflow_id: str,
    workflow_digest: str, job_id: str, time_reference: int,
) -> dict[str, Any]:
    """Materialize a new closed activation draft from explicit ready inputs.

    ``time_reference`` is the freeze-time value the acceptance template is
    issued at; the materializer records it once and the manifest carries it.
    """
    def detached(value: object) -> Any:
        return json.loads(canonical_json(value), object_pairs_hook=reject_duplicates)

    draft = {
        "schema": DRAFT_SCHEMA,
        "source_commit": source_commit,
        "default_state": {
            "capacity": 0, "enabled": False, "active": False, "provisioned": False,
        },
        "identities": detached(identities),
        "access_group": detached(access_group),
        "components": detached(components),
        "acceptance_template": production_acceptance_template(
            actor_public_key=actor_public_key,
            actor_generation=actor_generation,
            ci_signer_public_key=ci_signer_public_key,
            candidate_sha=source_commit,
            workflow_id=workflow_id,
            workflow_digest=workflow_digest,
            job_id=job_id,
            time_reference=time_reference,
        ),
        "entries": detached(entries),
        "effective_systemd": detached(effective_systemd),
        "platform_systemd": detached(PLATFORM_SYSTEMD),
        "socket_policy": detached(SOCKET_POLICY),
        "systemd": {
            "start_order": list(START_ORDER),
            "stop_order": list(STOP_ORDER),
            "persistent_unit": PERSISTENT_UNIT,
            "stage_capacity": 0,
            "active_capacity": 1,
        },
        "qualification": {
            "program": "/usr/libexec/buzz-ci-production-qualification",
            "request_validity_seconds": 60,
            "timeout_seconds": 5,
            "terminate_grace_seconds": 2,
            "principal": "qualification",
        },
        "package_uid": 0,
        "package_gid": 0,
    }
    return validate_manifest(draft, require_digest=False)


def validate_acceptance_template(value: object) -> dict[str, Any]:
    fields = {"actor", "time_reference", "run_event", "grant_event", "rerun_event", "tombstone_event"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("public acceptance template shape differs")
    actor = value["actor"]
    if not isinstance(actor, dict) or set(actor) != {"public_key", "generation"}:
        raise ValueError("public acceptance actor shape differs")
    public_key = _nonzero_sha256(actor["public_key"], "public acceptance actor")
    _positive_integer(actor["generation"], 0xFFFFFFFFFFFFFFFF, "public acceptance actor generation")
    time_reference = _positive_integer(
        value["time_reference"], 0xFFFFFFFFFFFFFFFF, "public acceptance time reference",
    )
    expected_kinds = {
        "run_event": 46_100,
        "grant_event": 46_107,
        "rerun_event": 46_100,
        "tombstone_event": 5,
    }
    encoded: set[bytes] = set()
    for name, kind in expected_kinds.items():
        event = value[name]
        if (
            not isinstance(event, list) or len(event) != 6 or event[0] != 0
            or event[1] != public_key
            or isinstance(event[2], bool) or not isinstance(event[2], int)
            or not 0 <= event[2] <= 0xFFFFFFFFFFFFFFFF
            or isinstance(event[3], bool) or event[3] != kind
            or not isinstance(event[4], list) or not isinstance(event[5], str)
        ):
            raise ValueError(f"public acceptance event template is invalid: {name}")
        raw = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode()
        if len(raw) > 64 * 1024 or raw in encoded:
            raise ValueError("public acceptance event templates are oversized or duplicate")
        encoded.add(raw)
    run_event = value["run_event"]
    try:
        run = json.loads(run_event[5], object_pairs_hook=reject_duplicates)
    except (TypeError, ValueError) as error:
        raise ValueError("public acceptance run template envelope is invalid") from error
    if (
        run_event[2] != time_reference
        or not isinstance(run, dict)
        or run.get("issued_at") != time_reference
        or isinstance(run.get("expires_at"), bool)
        or not isinstance(run.get("expires_at"), int)
        or run["expires_at"] <= time_reference
    ):
        raise ValueError("public acceptance run template is not issued at the time reference")
    rerun_event = value["rerun_event"]
    try:
        rerun = json.loads(rerun_event[5], object_pairs_hook=reject_duplicates)
    except (TypeError, ValueError) as error:
        raise ValueError("public acceptance rerun template envelope is invalid") from error
    if (
        rerun_event[2] != time_reference
        or not isinstance(rerun, dict)
        or rerun.get("issued_at") != time_reference
        or isinstance(rerun.get("expires_at"), bool)
        or not isinstance(rerun.get("expires_at"), int)
        or rerun["expires_at"] <= time_reference
    ):
        raise ValueError("public acceptance rerun template is not issued at the time reference")
    return value


def validate_external_keyholder_config(
    value: object, manifest: dict[str, Any], expected_selectors: object | None = None,
    expected_nip98_origin: object | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "peer", "selectors", "nip98_origin", "acceptance"}:
        raise ValueError("external keyholder configuration shape differs")
    if isinstance(value["schema_version"], bool) or value["schema_version"] != 2:
        raise ValueError("external keyholder configuration schema differs")
    peer = value["peer"]
    expected_peer = {
        "uid": manifest["identities"]["controld"]["uid"],
        "gid": manifest["identities"]["controld"]["gid"],
        "allowed_operations": KEYHOLDER_ALLOWED_OPERATIONS,
    }
    if peer != expected_peer:
        raise ValueError("external keyholder peer contract differs")
    selectors = value["selectors"]
    if not isinstance(selectors, dict) or set(selectors) != {"ci_event", "nip98", "manifest"}:
        raise ValueError("external keyholder selectors are incomplete")
    for name, selector in selectors.items():
        if not isinstance(selector, dict) or set(selector) != {"public_key", "generation"}:
            raise ValueError(f"external keyholder selector is invalid: {name}")
        _nonzero_sha256(selector["public_key"], f"external keyholder selector {name}")
        _positive_integer(selector["generation"], 0xFFFFFFFFFFFFFFFF, f"external keyholder generation {name}")
    selector_keys = {selector["public_key"] for selector in selectors.values()}
    if len(selector_keys) != 3:
        raise ValueError("external keyholder selector public keys are not distinct")
    if manifest["acceptance_template"]["actor"]["public_key"] in selector_keys:
        raise ValueError("public acceptance actor collides with a keyholder selector")
    if expected_selectors is not None and selectors != expected_selectors:
        raise ValueError("external keyholder selectors differ from active controld")
    origin = value["nip98_origin"]
    parsed = urlsplit(origin if isinstance(origin, str) else "")
    if (
        parsed.scheme != "https" or not parsed.hostname or len(origin) > 2048 or parsed.path != ""
        or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
    ):
        raise ValueError("external keyholder NIP-98 origin is invalid")
    if expected_nip98_origin is not None and origin.removesuffix("/") != str(expected_nip98_origin).removesuffix("/"):
        raise ValueError("external keyholder NIP-98 origin differs from active controld")
    if value["acceptance"] != {
        "binding_receipt_path": ACCEPTANCE_BINDING_PATH,
        "credential_selector": "acceptance-actor.key",
    }:
        raise ValueError("external keyholder acceptance receipt contract differs")
    return value


def lane_manifest_digest(value: object) -> str:
    fields = {
        "schema_version", "lane_id", "lane_epoch", "admission_verifying_key",
        "admission_key_generation", "broker_build_identity", "host_profile_digest",
        "suite_identity", "isolation_profile_digest", "not_before", "expires_at",
        "max_wall_timeout_seconds",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("execd lane manifest shape differs from production v2")
    if isinstance(value["schema_version"], bool) or value["schema_version"] != 1:
        raise ValueError("execd lane manifest schema must be version one")
    lane_epoch = _positive_integer(value["lane_epoch"], 0xFFFFFFFFFFFFFFFF, "execd lane epoch")
    key_generation = _positive_integer(
        value["admission_key_generation"], 0xFFFFFFFFFFFFFFFF, "execd admission key generation",
    )
    not_before = _positive_integer(value["not_before"], 0xFFFFFFFFFFFFFFFF, "execd lane not-before")
    expires_at = _positive_integer(value["expires_at"], 0xFFFFFFFFFFFFFFFF, "execd lane expiry")
    if not_before >= expires_at:
        raise ValueError("execd lane validity window is empty")
    wall_timeout = _positive_integer(
        value["max_wall_timeout_seconds"], 0xFFFFFFFF, "execd maximum wall timeout",
    )
    encoded = bytearray(LANE_MANIFEST_DIGEST_DOMAIN)
    encoded.extend(struct.pack(">H", value["schema_version"]))
    encoded.extend(bytes.fromhex(_nonzero_sha256(value["lane_id"], "execd lane id")))
    encoded.extend(struct.pack(">Q", lane_epoch))
    encoded.append(1)  # AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256
    for field in (
        "admission_verifying_key", "broker_build_identity", "host_profile_digest",
        "suite_identity", "isolation_profile_digest",
    ):
        if field == "admission_verifying_key":
            encoded.extend(bytes.fromhex(_nonzero_sha256(value[field], f"execd {field}")))
            encoded.extend(struct.pack(">Q", key_generation))
        else:
            encoded.extend(bytes.fromhex(_nonzero_sha256(value[field], f"execd {field}")))
    encoded.extend(struct.pack(">Q", not_before))
    encoded.extend(struct.pack(">Q", expires_at))
    encoded.extend(struct.pack(">I", wall_timeout))
    return digest(bytes(encoded))


def _wire_text64(value: object, where: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{where} must be ASCII text")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"{where} must be ASCII text") from error
    if not 1 <= len(raw) <= 64:
        raise ValueError(f"{where} must contain one through sixty-four ASCII bytes")
    return bytes([len(raw)]) + raw.ljust(64, b"\0")


def validate_execution_declaration(value: object, *, allow_placeholder: bool) -> dict[str, Any]:
    fields = {
        "schema_version", "declaration_digest", "workflow_id", "workflow_digest", "job_id", "artifact",
        "fixture_manifest_sha256", "fixture_input_sha256", "fixture_script_sha256", "max_stdout_bytes",
        "max_stderr_bytes", "max_memory_bytes", "max_processes", "max_wall_seconds",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("execd execution declaration shape differs from production")
    if isinstance(value["schema_version"], bool) or value["schema_version"] != EXECUTION_SCHEMA_VERSION:
        raise ValueError("execd execution declaration schema differs")
    declaration_digest = value["declaration_digest"]
    if allow_placeholder and declaration_digest == EXECD_DYNAMIC_DIGEST_PLACEHOLDER:
        pass
    else:
        _nonzero_sha256(declaration_digest, "execd execution declaration digest")
    _wire_text64(value["workflow_id"], "execd workflow id")
    _nonzero_sha256(value["workflow_digest"], "execd workflow digest")
    if value["job_id"] != "capacity-one-fixture":
        raise ValueError("execd execution job id differs from the fixed fixture")
    artifact = value["artifact"]
    expected_artifact = {
        "artifact_id": "result", "name": "result.json", "media_type": "application/json",
        "relative_name": "result.json", "max_bytes": 32_768,
    }
    if artifact != expected_artifact:
        raise ValueError("execd execution artifact differs from the fixed fixture")
    for field, expected in (
        ("fixture_manifest_sha256", FIXTURE_MANIFEST_SHA256),
        ("fixture_input_sha256", FIXTURE_INPUT_SHA256),
        ("fixture_script_sha256", FIXTURE_SCRIPT_SHA256),
    ):
        if value[field] != expected:
            raise ValueError(f"execd execution source digest differs: {field}")
    expected_limits = {
        "max_stdout_bytes": 32_768,
        "max_stderr_bytes": 32_768,
        "max_memory_bytes": 134_217_728,
        "max_processes": 16,
        "max_wall_seconds": 120,
    }
    if any(value[field] != expected for field, expected in expected_limits.items()):
        raise ValueError("execd execution resource limits differ")
    return value


def execution_declaration_digest(
    source_commit: str, package_digest: str, lane_manifest: object, execution: object,
) -> str:
    if not isinstance(source_commit, str) or not GIT_OID.fullmatch(source_commit):
        raise ValueError("execution candidate must be a full SHA-1 object id")
    package_digest = _nonzero_sha256(package_digest, "execution activation package digest")
    declaration = validate_execution_declaration(execution, allow_placeholder=True)
    lane_digest = lane_manifest_digest(lane_manifest)
    isolation_digest = _nonzero_sha256(
        lane_manifest["isolation_profile_digest"] if isinstance(lane_manifest, dict) else None,
        "execution isolation profile digest",
    )
    encoded = bytearray(EXECUTION_DIGEST_DOMAIN)
    encoded.append(0x01)
    encoded.extend(bytes.fromhex(source_commit))
    encoded.extend(bytes.fromhex(package_digest))
    encoded.extend(bytes.fromhex(lane_digest))
    encoded.extend(bytes.fromhex(isolation_digest))
    encoded.extend(_wire_text64(declaration["workflow_id"], "execd workflow id"))
    encoded.extend(bytes.fromhex(_nonzero_sha256(declaration["workflow_digest"], "execd workflow digest")))
    encoded.extend(_wire_text64(declaration["job_id"], "execd job id"))
    artifact = declaration["artifact"]
    for field in ("artifact_id", "name", "media_type", "relative_name"):
        encoded.extend(_wire_text64(artifact[field], f"execd artifact {field}"))
    encoded.extend(struct.pack(">I", artifact["max_bytes"]))
    for field in ("fixture_manifest_sha256", "fixture_input_sha256", "fixture_script_sha256"):
        encoded.extend(bytes.fromhex(declaration[field]))
    encoded.extend(struct.pack(">I", declaration["max_stdout_bytes"]))
    encoded.extend(struct.pack(">I", declaration["max_stderr_bytes"]))
    encoded.extend(struct.pack(">Q", declaration["max_memory_bytes"]))
    encoded.extend(struct.pack(">I", declaration["max_processes"]))
    encoded.extend(struct.pack(">I", declaration["max_wall_seconds"]))
    return digest(bytes(encoded))


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
    staged_runner_fields = {"schema_version", "controld_uid", "controld_gid", "mode"}
    active_runner_fields = staged_runner_fields | {
        "execd_socket", "execd_uid", "execd_gid", "replay_journal", "connect_timeout_millis",
        "io_timeout_millis", "transport_attempts", "retry_delay_millis", "lane_manifest_digest",
        "lane_epoch", "admission_key_generation", "isolation_profile_digest", "audience_digest",
        "acceptance_time_reference",
    }
    if set(runner_staged) != staged_runner_fields or set(runner_active) != active_runner_fields:
        raise ValueError("runner capacity flip must select the complete v2 proxy contract")
    if (
        isinstance(runner_staged["schema_version"], bool)
        or isinstance(runner_active["schema_version"], bool)
        or runner_staged["schema_version"] != 2
        or runner_active["schema_version"] != 2
    ):
        raise ValueError("runner configuration schema must remain version two")
    if runner_staged["mode"] != "dormant" or runner_active["mode"] != "v2_proxy":
        raise ValueError("runner activation must flip dormant to v2_proxy")
    if (
        runner_staged["controld_uid"] != runner_active["controld_uid"]
        or runner_staged["controld_gid"] != runner_active["controld_gid"]
    ):
        raise ValueError("runner staged and active identity binding differs")
    controld_identity = manifest["identities"]["controld"]
    if (
        runner_staged["controld_uid"] != controld_identity["uid"]
        or runner_staged["controld_gid"] != controld_identity["gid"]
    ):
        raise ValueError("runner configuration is not bound to the controld principal")
    if (
        runner_active["execd_socket"] != SOCKET_POLICY["execd"]["path"]
        or runner_active["execd_uid"] != 0
        or runner_active["execd_gid"] != 0
        or runner_active["replay_journal"] != RUNNER_REPLAY_JOURNAL
    ):
        raise ValueError("runner v2 proxy does not bind the fixed root execd transport")
    for field, maximum, allow_zero in (
        ("connect_timeout_millis", 30_000, False),
        ("io_timeout_millis", 30_000, False),
        ("transport_attempts", 5, False),
        ("retry_delay_millis", 5_000, True),
    ):
        value = runner_active[field]
        minimum = 0 if allow_zero else 1
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"runner v2 proxy bound is invalid: {field}")
    for field in ("lane_manifest_digest", "isolation_profile_digest", "audience_digest"):
        _nonzero_sha256(runner_active[field], f"runner {field}")
    for field in ("lane_epoch", "admission_key_generation"):
        _positive_integer(runner_active[field], 9_007_199_254_740_991, f"runner {field}")
    _positive_integer(
        runner_active["acceptance_time_reference"], 0xFFFFFFFFFFFFFFFF, "runner acceptance_time_reference",
    )
    if runner_active["acceptance_time_reference"] != manifest["acceptance_template"]["time_reference"]:
        raise ValueError("runner v2 proxy time reference differs from the frozen acceptance template")

    execd = entries["execd_config"]
    if "active_source" not in execd:
        raise ValueError("execd v2 configuration requires staged and active templates")
    execd_staged = _json_payload(payloads[execd["source"]], "staged execd v2 configuration template")
    execd_active = _json_payload(payloads[execd["active_source"]], "active execd v2 configuration template")
    execd_fields = {
        "schema_version", "enabled_protocol", "capacity", "identities", "paths",
        "lane_manifest", "lane_manifest_digest", "executor", "qualification", "execution",
        "acceptance_time_reference",
    }
    if set(execd_staged) != execd_fields or set(execd_active) != execd_fields:
        raise ValueError("execd v2 configuration shape differs from production")
    for phase, value in (("staged", execd_staged), ("active", execd_active)):
        _positive_integer(
            value["acceptance_time_reference"], 0xFFFFFFFFFFFFFFFF, f"execd {phase} acceptance_time_reference",
        )
        if value["acceptance_time_reference"] != manifest["acceptance_template"]["time_reference"]:
            raise ValueError("execd v2 time reference differs from the frozen acceptance template")
    if (
        any(isinstance(value[field], bool) for value in (execd_staged, execd_active) for field in ("schema_version", "enabled_protocol", "capacity"))
        or execd_staged["schema_version"] != 2
        or execd_active["schema_version"] != 2
        or execd_staged["enabled_protocol"] != EXECD_V2_PROTOCOL
        or execd_active["enabled_protocol"] != EXECD_V2_PROTOCOL
        or execd_staged["capacity"] != 0
        or execd_active["capacity"] != 1
        or REGISTER_JOB_INTENT_OPERATION != 9
    ):
        raise ValueError("execd configuration templates do not select closed-zero then capacity-one protocol v2")
    for field in execd_fields - {"capacity"}:
        if execd_staged[field] != execd_active[field]:
            raise ValueError(f"execd configuration template field changes across capacity: {field}")
    identities = execd_staged["identities"]
    expected_execd_identities = {
        "execd_uid": 0,
        "execd_gid": 0,
        "runner_uid": manifest["identities"]["runner"]["uid"],
        "runner_gid": manifest["identities"]["runner"]["gid"],
        "control_uid": manifest["identities"]["qualification"]["uid"],
        "control_gid": manifest["identities"]["qualification"]["gid"],
        "control_user": "buzzci-ctl",
        "control_group": "buzzci-ctl",
        "control_home": "/var/lib/buzzci/principals/ctl",
        "control_shell": "/usr/sbin/nologin",
        "control_supplementary_groups": [ACCESS_GROUP_NAME],
        "job_uid": manifest["identities"]["job"]["uid"],
        "job_gid": manifest["identities"]["job"]["gid"],
        "access_group": ACCESS_GROUP_NAME,
        "access_group_gid": manifest["access_group"]["gid"],
        "access_group_members": ACCESS_GROUP_MEMBERS,
    }
    if identities != expected_execd_identities:
        raise ValueError("execd v2 peer and job identities differ from the activation manifest")
    expected_paths = {
        "intent_root": EXECD_INTENT_ROOT,
        "binding_root": EXECD_BINDING_ROOT,
        "evidence_root": EXECD_EVIDENCE_ROOT,
        "teardown_root": EXECD_TEARDOWN_ROOT,
        "attempt_root": EXECD_ATTEMPT_ROOT,
        "qualification_root": EXECD_QUALIFICATION_ROOT,
        "executor_socket": EXECUTOR_SOCKET_PATH,
    }
    if execd_staged["paths"] != expected_paths:
        raise ValueError("execd v2 intent, evidence, teardown, or executor path differs")
    lane_digest = lane_manifest_digest(execd_staged["lane_manifest"])
    if execd_staged["lane_manifest_digest"] != lane_digest:
        raise ValueError("execd v2 lane manifest digest differs from the Rust contract")
    executor_component = next(item for item in manifest["components"] if item["name"] == "executor")
    if executor_component["source_commit"] != manifest["source_commit"]:
        raise ValueError("execd executor source commit differs from the integrated candidate")
    expected_executor = {
        "path": COMPONENTS["executor"][0],
        "sha256": executor_component["binary_sha256"],
        "source_commit": executor_component["source_commit"],
        "uid": 0,
        "gid": 0,
        "mode": 0o755,
    }
    if execd_staged["executor"] != expected_executor:
        raise ValueError("execd v2 executor provenance differs from the packaged component")
    qualification_template = execd_staged["qualification"]
    if qualification_template != {
        "integrated_candidate_sha": manifest["source_commit"],
        "activation_package_digest": EXECD_DYNAMIC_DIGEST_PLACEHOLDER,
        "fixture_digest": EXECD_DYNAMIC_DIGEST_PLACEHOLDER,
        "controller_generation": 1,
        "runner_generation": 1,
    }:
        raise ValueError("execd qualification template is not the fixed post-freeze placeholder")
    execution_template = validate_execution_declaration(execd_staged["execution"], allow_placeholder=True)
    if execution_template["declaration_digest"] != EXECD_DYNAMIC_DIGEST_PLACEHOLDER:
        raise ValueError("execd execution declaration must be post-freeze bound")
    lane_manifest = execd_staged["lane_manifest"]
    if (
        runner_active["lane_manifest_digest"] != lane_digest
        or runner_active["lane_epoch"] != lane_manifest["lane_epoch"]
        or runner_active["admission_key_generation"] != lane_manifest["admission_key_generation"]
        or runner_active["isolation_profile_digest"] != lane_manifest["isolation_profile_digest"]
    ):
        raise ValueError("runner v2 proxy authority differs from the execd lane manifest")

    controld = entries["controld_config"]
    controld_staged = _json_payload(payloads[controld["source"]], "staged controld configuration")
    controld_active = _json_payload(payloads[controld["active_source"]], "active controld configuration")
    staged_fields = {"schema_version", "capacity", "store_root", "acceptance_binding"}
    if set(controld_staged) != staged_fields:
        raise ValueError("staged controld configuration differs from the frozen closed interface")
    if (
        isinstance(controld_staged.get("capacity"), bool)
        or isinstance(controld_active.get("capacity"), bool)
        or controld_staged.get("capacity") != 0
        or controld_active.get("capacity") != 1
    ):
        raise ValueError("controld configuration must flip from capacity zero to one")
    if (
        isinstance(controld_staged.get("schema_version"), bool)
        or isinstance(controld_active.get("schema_version"), bool)
        or controld_staged.get("schema_version") != 2
        or controld_active.get("schema_version") != 2
    ):
        raise ValueError("controld schema changes during activation")
    if controld_staged.get("store_root") != "/var/lib/buzzci/controld" or controld_active.get("store_root") != "/var/lib/buzzci/controld":
        raise ValueError("controld store root changes during activation")
    active_fields = staged_fields | {
        "relay_url", "relay_http_origin", "channel_id", "poll_interval_millis",
        "runner_socket", "runner_uid", "runner_gid", "runner_connect_timeout_millis",
        "runner_io_timeout_millis", "runner_transport_attempts", "lane_manifest_digest",
        "lane_epoch", "audience_digest", "isolation_profile_digest", "workflow_id",
        "workflow_digest", "jobs", "keyholder_socket", "keyholder_uid", "keyholder_gid",
        "keyholder_selectors", "keyholder_timeout_millis", "keyholder_transport_attempts",
    }
    if set(controld_active) != active_fields:
        raise ValueError("active controld configuration differs from the strict interface")
    if (
        controld_staged["acceptance_binding"] != ACCEPTANCE_BINDING_PATH
        or controld_active["acceptance_binding"] != ACCEPTANCE_BINDING_PATH
    ):
        raise ValueError("controld acceptance binding path differs from the fixed interface")
    relay = urlsplit(controld_active["relay_url"] if isinstance(controld_active["relay_url"], str) else "")
    origin = urlsplit(controld_active["relay_http_origin"] if isinstance(controld_active["relay_http_origin"], str) else "")
    if (
        relay.scheme != "wss" or not relay.hostname or relay.path not in {"", "/"}
        or relay.username is not None or relay.password is not None or relay.query or relay.fragment
        or origin.scheme != "https" or origin.hostname != relay.hostname or origin.port != relay.port
        or origin.path not in {"", "/"} or origin.username is not None or origin.password is not None
        or origin.query or origin.fragment
    ):
        raise ValueError("controld relay URL and HTTP origin differ from one secure authority")
    try:
        channel = uuid.UUID(controld_active["channel_id"])
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("controld channel id is not a canonical UUID") from error
    if str(channel) != controld_active["channel_id"]:
        raise ValueError("controld channel id is not a canonical UUID")
    if controld_active.get("runner_socket") != SOCKET_POLICY["runner"]["path"]:
        raise ValueError("controld active configuration does not bind the runner socket")
    runner_identity = manifest["identities"]["runner"]
    if (controld_active["runner_uid"], controld_active["runner_gid"]) != (
        runner_identity["uid"], runner_identity["gid"],
    ):
        raise ValueError("controld runner peer credentials differ from the manifest")
    if controld_active.get("keyholder_socket") != SOCKET_POLICY["keyholder"]["path"]:
        raise ValueError("controld active configuration does not bind the separate keyholder socket")
    keyholder_identity = manifest["identities"]["keyholder"]
    if (
        controld_active["keyholder_uid"] != keyholder_identity["uid"]
        or controld_active["keyholder_gid"] != keyholder_identity["gid"]
    ):
        raise ValueError("controld keyholder peer credentials differ from the manifest")
    for field, maximum in (
        ("poll_interval_millis", 60_000),
        ("runner_connect_timeout_millis", 5_000),
        ("runner_io_timeout_millis", 30_000),
        ("runner_transport_attempts", 8),
        ("keyholder_timeout_millis", 5_000),
        ("keyholder_transport_attempts", 8),
    ):
        value = controld_active[field]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise ValueError(f"controld bounded field is invalid: {field}")
    for field in ("lane_manifest_digest", "audience_digest", "isolation_profile_digest", "workflow_digest"):
        _nonzero_sha256(controld_active[field], f"controld {field}")
    _positive_integer(controld_active["lane_epoch"], 9_007_199_254_740_991, "controld lane epoch")
    if not isinstance(controld_active["workflow_id"], str) or not controld_active["workflow_id"] or "\0" in controld_active["workflow_id"]:
        raise ValueError("controld workflow id is invalid")
    if (
        controld_active["lane_manifest_digest"] != runner_active["lane_manifest_digest"]
        or controld_active["lane_epoch"] != runner_active["lane_epoch"]
        or controld_active["audience_digest"] != runner_active["audience_digest"]
        or controld_active["isolation_profile_digest"] != runner_active["isolation_profile_digest"]
    ):
        raise ValueError("controld runner authority differs from the runner v2 proxy")
    jobs = controld_active["jobs"]
    if not isinstance(jobs, list) or len(jobs) != 1 or not isinstance(jobs[0], dict):
        raise ValueError("controld capacity one requires exactly one static job")
    job = jobs[0]
    if set(job) != {"job_id", "name", "required", "skip_policy", "selected_job_instance", "also_reruns", "artifacts"}:
        raise ValueError("controld static job shape differs")
    for field in ("job_id", "name", "selected_job_instance"):
        if not isinstance(job[field], str) or not job[field] or "\0" in job[field]:
            raise ValueError(f"controld static job field is invalid: {field}")
    if not isinstance(job["required"], bool) or job["skip_policy"] not in {"forbid", "allow"}:
        raise ValueError("controld static job policy is invalid")
    reruns = job["also_reruns"]
    if not isinstance(reruns, list) or any(not isinstance(item, str) or not item or "\0" in item for item in reruns) or len(set(reruns)) != len(reruns):
        raise ValueError("controld static job reruns are invalid")
    artifacts = job["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 1 or not isinstance(artifacts[0], dict):
        raise ValueError("controld capacity one requires exactly one artifact")
    artifact = artifacts[0]
    if set(artifact) != {"artifact_id", "name", "media_type", "relative_name", "max_bytes"}:
        raise ValueError("controld artifact shape differs")
    identifier = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
    for field in ("artifact_id", "name", "relative_name"):
        if not isinstance(artifact[field], str) or not identifier.fullmatch(artifact[field]) or artifact[field] in {".", ".."}:
            raise ValueError(f"controld artifact field is invalid: {field}")
    media_type = artifact["media_type"]
    if not isinstance(media_type, str) or len(media_type) > 64 or not re.fullmatch(r"[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+", media_type):
        raise ValueError("controld artifact media type is invalid")
    if isinstance(artifact["max_bytes"], bool) or not isinstance(artifact["max_bytes"], int) or not 1 <= artifact["max_bytes"] <= 32_768:
        raise ValueError("controld artifact byte bound is invalid")
    if (
        execution_template["workflow_id"] != controld_active["workflow_id"]
        or execution_template["workflow_digest"] != controld_active["workflow_digest"]
        or execution_template["job_id"] != job["job_id"]
        or execution_template["artifact"] != artifact
    ):
        raise ValueError("execd execution declaration differs from active controld workflow")
    selectors = controld_active["keyholder_selectors"]
    if not isinstance(selectors, dict) or set(selectors) != {"ci_event", "nip98", "manifest"}:
        raise ValueError("controld keyholder selectors are incomplete")
    for name, selector in selectors.items():
        if not isinstance(selector, dict) or set(selector) != {"public_key", "generation"}:
            raise ValueError(f"controld keyholder selector is invalid: {name}")
        _nonzero_sha256(selector["public_key"], f"controld keyholder selector {name}")
        _positive_integer(selector["generation"], 9_007_199_254_740_991, f"controld keyholder generation {name}")
    # The keyholder's manifest selector is the one source of the admission key
    # and its generation: keyholder signs admissions with that key at that
    # generation, controld derives admission_key_generation from this selector,
    # execd verifies against the lane manifest, and the runner's static
    # coordinates copy the lane manifest (checked above). All must agree.
    manifest_selector = selectors["manifest"]
    if (
        lane_manifest["admission_verifying_key"] != manifest_selector["public_key"]
        or lane_manifest["admission_key_generation"] != manifest_selector["generation"]
    ):
        raise ValueError("execd lane manifest admission key differs from the keyholder manifest selector")
    controld_encoded = canonical_json(controld_active)
    if SOCKET_POLICY["execd"]["path"].encode() in controld_encoded or COMPONENTS["execd"][0].encode() in controld_encoded:
        raise ValueError("controld configuration must not bypass the runner to reach execd")

    if any(_contains_private_field(value) for value in (runner_staged, runner_active, execd_staged, execd_active, controld_staged, controld_active)):
        raise ValueError("activation packages cannot contain secrets or credentials")


def _validate_component_package_manifest(
    manifest: dict[str, Any], payload: bytes, name: str,
) -> dict[str, Any]:
    if name not in COMPONENT_PACKAGE_NAMES:
        raise ValueError("component package manifest name is unsupported")
    component = next(item for item in manifest["components"] if item["name"] == name)
    if digest(payload) != component["package_manifest_sha256"]:
        raise ValueError(f"{name} package manifest bytes differ")
    package = _json_payload(payload, f"{name} package manifest")
    if canonical_json(package) != payload:
        raise ValueError(f"{name} package manifest is not canonical")
    special_field = "peer_policy" if name == "runner" else "daemon_contract"
    identity_field = "identities" if name == "runner" else "identity"
    required = {
        "schema", "package_id", "source_commit", "binary_provenance_sha256",
        "default_state", special_field, "package_uid", "package_gid",
        identity_field, "directories", "entries", "package_digest",
    }
    if set(package) != required:
        raise ValueError(f"{name} package manifest fields differ")
    if type(package["package_uid"]) is not int or type(package["package_gid"]) is not int:
        raise ValueError(f"{name} package ownership types differ")
    expected_schema = f"buzz-ci-{name}-install-package-v2"
    expected_id = f"buzz-ci-{name}-{component['source_commit'][:12]}-{component['binary_sha256'][:12]}"
    if package["schema"] != expected_schema or package["package_id"] != expected_id:
        raise ValueError(f"{name} package manifest identity differs")
    package_digest = package["package_digest"]
    unsigned = dict(package)
    unsigned.pop("package_digest", None)
    if (
        package["source_commit"] != component["source_commit"]
        or package_digest != component["package_digest"]
        or not isinstance(package_digest, str)
        or not SHA256.fullmatch(package_digest)
        or digest(canonical_json(unsigned)) != package_digest
    ):
        raise ValueError(f"{name} package manifest digest or source differs")
    if (
        package["binary_provenance_sha256"] != component["provenance_sha256"]
        or package["package_uid"] != 0
        or package["package_gid"] != 0
    ):
        raise ValueError(f"{name} package provenance or ownership differs")
    identities = manifest["identities"]
    if name == "runner":
        if (
            type(package["default_state"].get("capacity")) is not int
            or type(package["default_state"].get("host_block")) is not bool
            or any(type(package["default_state"].get(field)) is not bool for field in ("enabled", "active", "provisioned"))
            or type(package["peer_policy"].get("broker_socket", {}).get("expected_uid")) is not int
            or type(package["peer_policy"].get("broker_socket", {}).get("managed_by_package")) is not bool
        ):
            raise ValueError("runner package numeric or boolean types differ")
        if package["default_state"] != {
            "enabled": False, "active": False, "provisioned": False,
            "capacity": 0, "host_block": False,
        }:
            raise ValueError("runner package default state differs")
        expected_identity = {
            role: {
                "user": identities[role]["user"], "group": identities[role]["group"],
                "uid": identities[role]["uid"], "gid": identities[role]["gid"],
            }
            for role in ("runner", "controld")
        }
        if package["identities"] != expected_identity:
            raise ValueError("runner package identities differ")
        if any(
            type(package["identities"][role][field]) is not int
            for role in ("runner", "controld") for field in ("uid", "gid")
        ):
            raise ValueError("runner package identity types differ")
        peer = package["peer_policy"]
        if (
            not isinstance(peer, dict)
            or set(peer) != {"runner_control_socket", "broker_socket"}
            or peer["runner_control_socket"] != {
                "path": SOCKET_POLICY["runner"]["path"],
                "descriptor_name": "buzz-ci-runner-control",
                "user": "buzzci-runner", "group": "buzzci-controld",
                "mode": "0620", "directory_mode": "0711",
            }
            or peer["broker_socket"] != {
                "path": SOCKET_POLICY["execd"]["path"], "expected_uid": 0,
                "owner": "root", "group": ACCESS_GROUP_NAME, "mode": "0620",
                "supplementary_members": ["buzzci-runner", "buzzci-ctl"],
                "managed_by_package": False,
            }
        ):
            raise ValueError("runner package peer policy differs")
    else:
        if (
            type(package["default_state"].get("capacity")) is not int
            or type(package["default_state"].get("providers_wired")) is not bool
            or any(type(package["default_state"].get(field)) is not bool for field in ("enabled", "active", "provisioned"))
            or any(
                type(package["daemon_contract"].get(field)) is not int
                for field in ("default_capacity", "maximum_capacity", "runner_protocol")
            )
            or type(package["daemon_contract"].get("providers_fail_closed")) is not bool
        ):
            raise ValueError("controld package numeric or boolean types differ")
        if package["default_state"] != {
            "enabled": False, "active": False, "provisioned": False,
            "capacity": 0, "providers_wired": False,
        }:
            raise ValueError("controld package default state differs")
        expected_identity = {
            "user": identities["controld"]["user"],
            "group": identities["controld"]["group"],
            "uid": identities["controld"]["uid"],
            "gid": identities["controld"]["gid"],
        }
        if package["identity"] != expected_identity:
            raise ValueError("controld package identity differs")
        if any(type(package["identity"][field]) is not int for field in ("uid", "gid")):
            raise ValueError("controld package identity types differ")
        if package["daemon_contract"] != {
            "service_user": "buzzci-controld",
            "config_path": CONFIG_TARGETS["controld_config"],
            "acceptance_binding": ACCEPTANCE_BINDING_PATH,
            "store_root": "/var/lib/buzzci/controld",
            "default_capacity": 0,
            "maximum_capacity": 1,
            "providers_fail_closed": True,
            "runner_protocol": 2,
            "acceptance_socket": "/run/buzzci/controld-acceptance.sock",
        }:
            raise ValueError("controld package daemon contract differs")
    expected_directories = [
        {"target": "/etc/buzzci", "mode": "0755", "uid": 0, "gid": 0},
        {"target": f"/usr/share/doc/buzz-ci-{name}", "mode": "0755", "uid": 0, "gid": 0},
    ]
    if package["directories"] != expected_directories:
        raise ValueError(f"{name} package directories differ")
    if any(
        not isinstance(item, dict)
        or type(item.get("uid")) is not int
        or type(item.get("gid")) is not int
        for item in package["directories"]
    ):
        raise ValueError(f"{name} package directory ownership types differ")
    entries = package["entries"]
    if not isinstance(entries, list) or len(entries) != 6:
        raise ValueError(f"{name} package entry inventory differs")
    by_target: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"role", "source", "target", "source_mode", "install_mode", "uid", "gid", "sha256"}
            or not isinstance(entry.get("target"), str)
            or not isinstance(entry.get("source"), str)
            or not isinstance(entry.get("sha256"), str)
            or not SHA256.fullmatch(entry["sha256"])
            or type(entry.get("uid")) is not int
            or type(entry.get("gid")) is not int
        ):
            raise ValueError(f"{name} package entry is invalid")
        if entry["target"] in by_target:
            raise ValueError(f"{name} package target is duplicated")
        by_target[entry["target"]] = entry
    if entries != sorted(entries, key=lambda item: item["target"].encode()):
        raise ValueError(f"{name} package entries are not bytewise target ordered")
    socket_role = "socket" if name == "runner" else "acceptance_socket"
    expected_targets = {
        "binary": COMPONENTS[name][0],
        "config": CONFIG_TARGETS[f"{name}_config"],
        "service": f"/etc/systemd/system/buzz-ci-{name}.service",
        socket_role: (
            "/etc/systemd/system/buzz-ci-runner.socket"
            if name == "runner"
            else "/etc/systemd/system/buzz-ci-controld-acceptance.socket"
        ),
        "tmpfiles": COMPONENT_TMPFILES_TARGETS[name],
        "documentation": f"/usr/share/doc/buzz-ci-{name}/README.md",
    }
    by_role = {entry["role"]: entry for entry in entries}
    if set(by_role) != set(expected_targets) or any(
        by_role[role]["target"] != target for role, target in expected_targets.items()
    ):
        raise ValueError(f"{name} package role or target inventory differs")
    expected_sources = {
        "binary": f"assets/buzz-ci-{name}",
        "config": f"assets/{name}-v2.json",
        "service": f"assets/buzz-ci-{name}.service",
        socket_role: f"assets/buzz-ci-{name}{'-acceptance' if name == 'controld' else ''}.socket",
        "tmpfiles": f"assets/buzzci-{name}.conf",
        "documentation": "assets/README.md",
    }
    if any(by_role[role]["source"] != source for role, source in expected_sources.items()):
        raise ValueError(f"{name} package source inventory differs")
    for role, entry in by_role.items():
        expected_source_mode = "0500" if role == "binary" else "0400"
        expected_install_mode = "0755" if role == "binary" else ("0600" if role == "config" else "0644")
        expected_owner = identities[name] if role == "config" else {"uid": 0, "gid": 0}
        if (
            entry["source_mode"] != expected_source_mode
            or entry["install_mode"] != expected_install_mode
            or entry["uid"] != expected_owner["uid"]
            or entry["gid"] != expected_owner["gid"]
        ):
            raise ValueError(f"{name} package entry metadata differs: {role}")
    if by_role["binary"]["sha256"] != component["binary_sha256"]:
        raise ValueError(f"{name} package binary binding differs")
    activation_config = next(item for item in manifest["entries"] if item["role"] == f"{name}_config")
    packaged_config = by_role["config"]
    if (
        any(
            packaged_config.get(package_field) != activation_config[activation_field]
            for package_field, activation_field in (
                ("sha256", "sha256"),
                ("install_mode", "install_mode"),
                ("uid", "uid"),
                ("gid", "gid"),
            )
        )
    ):
        raise ValueError(f"{name} package staged config binding differs")
    effective = {item["unit"]: item for item in manifest["effective_systemd"]}
    for unit, role in (
        (f"buzz-ci-{name}.service", "service"),
        (("buzz-ci-runner.socket" if name == "runner" else "buzz-ci-controld-acceptance.socket"), socket_role),
    ):
        fragment = effective[unit]["fragment"]
        entry = by_target.get(fragment["path"])
        if (
            not isinstance(entry, dict)
            or entry.get("sha256") != fragment["sha256"]
            or entry.get("install_mode") != "0644"
            or entry.get("uid") != 0
            or entry.get("gid") != 0
        ):
            raise ValueError(f"{name} package effective unit binding differs: {unit}")
    return package


def _validate_controld_package_manifest(manifest: dict[str, Any], payload: bytes) -> None:
    _validate_component_package_manifest(manifest, payload, "controld")


def component_tmpfiles_plan(
    manifest: dict[str, Any], payloads: dict[str, bytes],
) -> tuple[dict[str, object], ...]:
    components = {item["name"]: item for item in manifest["components"]}
    result: list[dict[str, object]] = []
    for name in COMPONENT_PACKAGE_NAMES:
        component = components[name]
        package = _validate_component_package_manifest(
            manifest, payloads[component["package_manifest_source"]], name,
        )
        entry = next(item for item in package["entries"] if item["role"] == "tmpfiles")
        result.append({
            "component": name, "target": entry["target"], "sha256": entry["sha256"],
            "mode": entry["install_mode"], "uid": entry["uid"], "gid": entry["gid"],
        })
    return tuple(result)


def tmpfiles_plan(
    manifest: dict[str, Any], payloads: dict[str, bytes],
) -> tuple[dict[str, object], ...]:
    entries = {item["role"]: item for item in manifest["entries"]}
    result = [
        {
            "component": "activation", "target": entries[role]["target"],
            "sha256": entries[role]["sha256"], "mode": entries[role]["install_mode"],
            "uid": entries[role]["uid"], "gid": entries[role]["gid"],
        }
        for role in ("tmpfiles", "acceptance_tmpfiles")
    ]
    result.extend(component_tmpfiles_plan(manifest, payloads))
    return tuple(result)


def validate_payloads(manifest: dict[str, Any], payloads: dict[str, bytes]) -> None:
    validate_phase_configs(manifest, payloads)
    component_tmpfiles_plan(manifest, payloads)


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
