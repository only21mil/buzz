#!/usr/bin/python3
"""Preflight, stage, qualify, persist, or roll back Buzz CI capacity one."""

from __future__ import annotations

import argparse
import base64
import ctypes
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import resource
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from typing import Any

if __name__ == "__main__":
    sys.dont_write_bytecode = True

controller_path = Path(__file__).resolve()
if controller_path.name == "controller.py":
    import package as activation_package
elif controller_path.name == "buzz-ci-activation-controller":
    if (
        controller_path.parent.name == "assets"
        and controller_path.parent.parent.name == "package"
    ):
        fixed_assets = controller_path.parent
    else:
        fixed_assets = (
            controller_path.parents[2]
            / "var/lib/buzzci/activation-controller/package/assets"
        )
    sys.path.insert(0, str(fixed_assets))
    import buzz_ci_activation_package as activation_package
else:
    raise ModuleNotFoundError("activation package module path is not fixed")

RECEIPT_PATH = "/var/lib/buzzci/activation-controller/receipt-v1.json"
OPERATOR_LOCK_PATH = "/var/lib/buzzci/activation-controller/operator.lock"
ROLLBACK_CLEANUP_PATH = "/var/lib/buzzci/activation-controller/rollback-cleanup-v1.json"
ROLLBACK_CLEANUP_SCHEMA = "buzz-ci-activation-rollback-cleanup-v1"
ROLLBACK_RETIREMENT_PATH = "/var/lib/buzzci/activation-controller/rollback-retirement-v1.json"
ROLLBACK_RETIREMENT_SCHEMA = "buzz-ci-activation-rollback-retirement-v1"
ROLLBACK_ARCHIVE_ROOT = "/var/lib/buzzci/activation-controller/rollback-archive"
ROLLBACK_ARCHIVE_SCHEMA = "buzz-ci-activation-rollback-archive-v1"
ROLLBACK_RECOVERY_ROLES = frozenset({"activation_controller", "activation_package_module"})
ACCEPTANCE_BINDING_PATH = activation_package.ACCEPTANCE_BINDING_PATH
CONTROLD_ACCEPTANCE_LEDGER_PATH = "/var/lib/buzzci/controld/acceptance-operation-ledger-v1.json"
FIXED_PACKAGE_PATH = activation_package.FIXED_PACKAGE_PATH
ZERO_REQUEST_SCHEMA = "buzz-ci-activation-qualification-zero-request/v1"
ZERO_RESPONSE_SCHEMA = "buzz-ci-activation-qualification-zero-response/v1"
ZERO_SEQUENCE_SCHEMA = "buzz-ci-activation-qualification-zero-state/v1"
CAPACITY_ONE_REQUEST_SCHEMA = "buzz-ci-activation-capacity-one-request/v1"
CAPACITY_ONE_RESPONSE_SCHEMA = "buzz-ci-activation-capacity-one-response/v1"
CAPACITY_ONE_SEQUENCE_SCHEMA = "buzz-ci-activation-capacity-one-state/v1"
PERSISTENT_AUTHORIZATION_SCHEMA = "buzz-ci-persistent-capacity-one-authorization/v1"
PERSISTENT_CAPACITY_ONE_ACTION = "persist-capacity-one"
PERSISTENT_OPERATION_DOMAIN = b"buzz-ci:persistent-capacity-one:v1\0"
MAX_ZERO_REQUEST_BYTES = 64 * 1024
MAX_CAPACITY_ONE_ATTEMPTS = 3
MAX_SCENARIO_BYTES = 256 * 1024
SYSTEMCTL = "/usr/bin/systemctl"
SYSUSERS = "/usr/bin/systemd-sysusers"
TMPFILES = "/usr/bin/systemd-tmpfiles"
MAX_COMMAND_OUTPUT = 256 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
EXECD_BINARY_PATH = "/usr/libexec/buzz-ci-execd"
EXECD_PACKAGE_RECEIPT_PATH = "/var/lib/buzzci/execd-v2/package/receipt-v1.json"
EXECD_PACKAGE_PREIMAGE_PATH = "/var/lib/buzzci/execd-v2/package/preimage-v1.bin"
EXECD_PACKAGE_ROLLBACK_PATH = "/var/lib/buzzci/execd-v2/package/rollback-v1.json"
QUALIFICATION_REQUEST_SCHEMA = "buzz-ci-production-qualification-request/v2"
QUALIFICATION_RESPONSE_SCHEMA = "buzz-ci-production-qualification-response/v2"
QUALIFICATION_STATE_SCHEMA = "buzz-ci-production-qualification-state/v3"
QUALIFICATION_MAX_ATTEMPTS = 3
QUALIFICATION_PRINCIPAL_DOMAIN = b"buzz-ci-execd:production-qualification-principal:v1\0"
QUALIFICATION_EXECUTOR_DOMAIN = b"buzz-ci-execd:production-qualification-executor-provenance:v1\0"

CAPACITY_ONE_FRAGMENT_PATHS = {
    "buzz-ci-capacity-one.target": "/etc/systemd/system/buzz-ci-capacity-one.target",
    "buzz-ci-controld.service": "/etc/systemd/system/buzz-ci-controld.service",
    "buzz-ci-runner.socket": "/etc/systemd/system/buzz-ci-runner.socket",
    "buzz-ci-execd.service": "/usr/lib/systemd/system/buzz-ci-execd.service",
    "buzz-ci-execd.socket": "/usr/lib/systemd/system/buzz-ci-execd.socket",
    "buzz-ci-executor.service": "/usr/lib/systemd/system/buzz-ci-executor.service",
    "buzz-ci-executor.socket": "/usr/lib/systemd/system/buzz-ci-executor.socket",
    "buzz-ci-keyholder.socket": "/etc/systemd/system/buzz-ci-keyholder.socket",
}
CAPACITY_ONE_PROCESS_UNITS = (
    "buzz-ci-keyholder.service",
    "buzz-ci-executor.service",
    "buzz-ci-execd.service",
    "buzz-ci-runner.service",
    "buzz-ci-controld.service",
)
CAPACITY_ONE_START_ORDER = (
    "buzz-ci-keyholder.socket",
    "buzz-ci-keyholder.service",
    "buzz-ci-executor.socket",
    "buzz-ci-executor.service",
    "buzz-ci-execd.socket",
    "buzz-ci-execd.service",
    "buzz-ci-runner.socket",
    "buzz-ci-runner.service",
    "buzz-ci-controld-acceptance.socket",
    "buzz-ci-controld.service",
    "buzz-ci-capacity-one.target",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _metadata_dict(metadata: os.stat_result) -> dict[str, int]:
    return {
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def _read_target(root: Path, target: str, limit: int = activation_package.MAX_ASSET_BYTES) -> tuple[bytes, os.stat_result] | None:
    try:
        parent_fd, name = activation_package.open_parent_fd(root, target)
    except FileNotFoundError:
        return None
    try:
        return activation_package.read_fd_at(parent_fd, name, limit)
    except FileNotFoundError:
        return None
    finally:
        os.close(parent_fd)


def _physical_ids(root: Path, uid: int, gid: int) -> tuple[int, int]:
    if root != Path("/") and os.geteuid() != 0:
        return os.geteuid(), os.getegid()
    return uid, gid


def _execd_package_json(root: Path, target: str) -> dict[str, Any] | None:
    opened = _read_target(root, target, MAX_SCENARIO_BYTES)
    if opened is None:
        return None
    payload, metadata = opened
    uid, gid = _physical_ids(root, 0, 0)
    if (
        metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError(f"execd package receipt metadata differs: {target}")
    try:
        value = json.loads(payload, object_pairs_hook=activation_package.reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"execd package receipt is invalid: {target}") from error
    if not isinstance(value, dict) or activation_package.canonical_json(value) != payload:
        raise ValueError(f"execd package receipt is noncanonical: {target}")
    return value


def _bind_execd_install_receipt(
    manifest: dict[str, Any], root: Path, value: dict[str, Any]
) -> dict[str, Any]:
    component = next(item for item in manifest["components"] if item["name"] == "execd")
    root_uid, root_gid = _physical_ids(root, 0, 0)
    expected_keys = {
        "schema", "state", "package_id", "package_digest", "source_commit",
        "binary_sha256", "binary_target", "binary_mode", "binary_uid", "binary_gid",
        "activation_id", "activation_package_digest", "activation_manifest_sha256",
        "activation_owned_entries_sha256", "seccomp_source_sha256", "enabled", "active",
        "capacity", "prior",
    }
    prior = value.get("prior")
    if (
        set(value) != expected_keys
        or value.get("schema") != "buzz-ci-execd-install-receipt-v1"
        or value.get("state") != "installed"
        or value.get("source_commit") != component["source_commit"]
        or value.get("binary_sha256") != component["binary_sha256"]
        or value.get("binary_target") != EXECD_BINARY_PATH
        or value.get("binary_mode") != 0o755
        or value.get("binary_uid") != root_uid
        or value.get("binary_gid") != root_gid
        or value.get("activation_id") != manifest["activation_id"]
        or value.get("activation_package_digest") != manifest["package_digest"]
        or value.get("activation_manifest_sha256")
        != activation_package.digest(activation_package.canonical_json(manifest))
        or value.get("enabled") is not False
        or value.get("active") is not False
        or value.get("capacity") != 0
        or not isinstance(value.get("package_id"), str)
        or not re.fullmatch(r"buzz-ci-execd-[0-9a-f]{12}-[0-9a-f]{12}", value["package_id"])
        or not isinstance(value.get("package_digest"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["package_digest"])
        or not isinstance(value.get("activation_owned_entries_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["activation_owned_entries_sha256"])
        or not isinstance(value.get("seccomp_source_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["seccomp_source_sha256"])
        or not isinstance(prior, dict)
    ):
        raise ValueError("execd package receipt belongs to a different candidate")
    if prior == {"state": "absent", "binary": None, "preimage": None}:
        return prior
    binary = prior.get("binary")
    preimage = prior.get("preimage")
    if (
        set(prior) != {"state", "binary", "preimage"}
        or prior.get("state") != "present"
        or not isinstance(binary, dict)
        or set(binary) != {"sha256", "mode", "uid", "gid"}
        or not isinstance(preimage, dict)
        or set(preimage) != {"name", "sha256", "mode", "uid", "gid"}
        or not isinstance(binary.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", binary["sha256"])
        or preimage.get("name") != "preimage-v1.bin"
        or preimage.get("sha256") != binary["sha256"]
        or preimage.get("mode") != 0o600
        or preimage.get("uid") != root_uid
        or preimage.get("gid") != root_gid
        or isinstance(binary.get("mode"), bool)
        or not isinstance(binary.get("mode"), int)
        or not 0 <= binary["mode"] <= 0o7777
        or isinstance(binary.get("uid"), bool)
        or not isinstance(binary.get("uid"), int)
        or binary["uid"] < 0
        or isinstance(binary.get("gid"), bool)
        or not isinstance(binary.get("gid"), int)
        or binary["gid"] < 0
    ):
        raise ValueError("execd package prior receipt differs")
    return prior


def _execd_package_rollback_readback(
    manifest: dict[str, Any], root: Path, activation_receipt: dict[str, Any]
) -> str:
    prior_systemd = activation_receipt.get("systemd_before")
    if not isinstance(prior_systemd, dict) or not any(
        prior_systemd.get(unit, {}).get("ActiveState") == "active"
        for unit in ("buzz-ci-execd.socket", "buzz-ci-execd.service")
    ):
        return "not_required"
    active = _execd_package_json(root, EXECD_PACKAGE_RECEIPT_PATH)
    terminal = _execd_package_json(root, EXECD_PACKAGE_ROLLBACK_PATH)
    if terminal is None:
        if active is None:
            raise ValueError("active execd baseline lacks package rollback evidence")
        _bind_execd_install_receipt(manifest, root, active)
        return "required"
    if (
        set(terminal) != {"schema", "state", "install_receipt", "live_target"}
        or terminal.get("schema") != "buzz-ci-execd-package-rollback-receipt-v1"
        or terminal.get("state") != "rolled_back"
        or not isinstance(terminal.get("install_receipt"), dict)
        or not isinstance(terminal.get("live_target"), dict)
        or active is not None
        or _read_target(root, EXECD_PACKAGE_PREIMAGE_PATH) is not None
    ):
        raise ValueError("execd package rollback receipt differs")
    prior = _bind_execd_install_receipt(manifest, root, terminal["install_receipt"])
    live_target = terminal["live_target"]
    target = _read_target(root, EXECD_BINARY_PATH, MAX_BINARY_BYTES)
    if prior["state"] == "absent":
        if live_target != {"state": "absent"}:
            raise ValueError("execd package rollback live binding differs")
        if target is not None:
            raise ValueError("rolled-back absent execd baseline differs")
    else:
        binary = prior["binary"]
        if (
            set(live_target)
            != {"state", "device", "inode", "sha256", "mode", "uid", "gid"}
            or live_target.get("state") != "present"
            or isinstance(live_target.get("device"), bool)
            or not isinstance(live_target.get("device"), int)
            or live_target["device"] < 0
            or isinstance(live_target.get("inode"), bool)
            or not isinstance(live_target.get("inode"), int)
            or live_target["inode"] <= 0
            or live_target.get("sha256") != binary["sha256"]
            or live_target.get("mode") != binary["mode"]
            or live_target.get("uid") != binary["uid"]
            or live_target.get("gid") != binary["gid"]
        ):
            raise ValueError("execd package rollback live binding differs")
        if target is None:
            raise ValueError("rolled-back execd baseline is absent")
        payload, metadata = target
        expected_uid, expected_gid = _physical_ids(root, binary["uid"], binary["gid"])
        if (
            metadata.st_dev != live_target["device"]
            or metadata.st_ino != live_target["inode"]
            or activation_package.digest(payload) != live_target["sha256"]
            or stat.S_IMODE(metadata.st_mode) != live_target["mode"]
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
        ):
            raise ValueError("rolled-back execd baseline differs")
    return "rolled_back"


def _verify_target_digest(root: Path, target: str, expected: dict[str, object], limit: int) -> None:
    try:
        parent_fd, name = activation_package.open_parent_fd(root, target)
    except FileNotFoundError:
        raise ValueError(f"required target is absent: {target}") from None
    fd = -1
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        metadata = os.fstat(fd)
        expected_uid, expected_gid = _physical_ids(root, expected["uid"], expected["gid"])
        expected_mode = (
            activation_package.parse_mode(expected["mode"])
            if isinstance(expected["mode"], str) else expected["mode"]
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
        ):
            raise ValueError(f"target metadata drift: {target}")
        hasher = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, min(1024 * 1024, limit + 1 - total)):
            total += len(chunk)
            if total > limit:
                raise ValueError(f"target exceeds byte limit: {target}")
            hasher.update(chunk)
        if hasher.hexdigest() != expected["sha256"]:
            raise ValueError(f"target content drift: {target}")
    finally:
        os.close(fd)


def _stage_restart_boundary(_phase: str) -> None:
    """Test seam after restart-relevant durable filesystem boundaries."""


def _atomic_write(
    root: Path, target: str, payload: bytes, mode: int, uid: int, gid: int,
    *, restart_phase: str | None = None,
) -> None:
    parent_fd, name = activation_package.open_parent_fd(root, target, create=True)
    temporary_name = (
        f".{name}.activation-recovery-v1"
        if restart_phase is not None
        else f".{name}.activation-{os.getpid()}-{os.urandom(8).hex()}"
    )
    fd = -1
    cleanup_temporary = True
    try:
        created = False
        try:
            fd = os.open(
                temporary_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            created = True
        except FileExistsError:
            if restart_phase is None:
                raise
            cleanup_temporary = False
            fd = os.open(
                temporary_name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        if created:
            os.fchmod(fd, mode)
            if os.geteuid() == 0:
                os.fchown(fd, uid, gid)
            elif root == Path("/"):
                raise PermissionError("live writes require the requested UID and GID")
            view = memoryview(payload)
            while view:
                view = view[os.write(fd, view):]
        metadata = os.fstat(fd)
        expected_uid, expected_gid = _physical_ids(root, uid, gid)
        os.lseek(fd, 0, os.SEEK_SET)
        observed = bytearray()
        while len(observed) <= len(payload):
            chunk = os.read(fd, min(1024 * 1024, len(payload) + 1 - len(observed)))
            if not chunk:
                break
            observed.extend(chunk)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or bytes(observed) != payload
        ):
            raise ValueError(f"recovery write stage differs: {target}")
        cleanup_temporary = True
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if restart_phase is not None:
            _stage_restart_boundary(f"{restart_phase}:temp")
            named = os.stat(temporary_name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(named.st_mode)
                or named.st_dev != metadata.st_dev
                or named.st_ino != metadata.st_ino
            ):
                cleanup_temporary = False
                raise ValueError(f"recovery write stage identity differs: {target}")
        os.rename(temporary_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
        if restart_phase is not None:
            _stage_restart_boundary(f"{restart_phase}:published")
    finally:
        if fd >= 0:
            os.close(fd)
        if cleanup_temporary:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _unlink_target(root: Path, target: str) -> None:
    parent_fd, name = activation_package.open_parent_fd(root, target)
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"refusing to remove unsafe target: {target}")
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _write_receipt(root: Path, receipt: dict[str, object], controld_gid: int) -> None:
    _require_receipt_root(root, controld_gid, allow_private=True)
    _atomic_write(root, RECEIPT_PATH, activation_package.canonical_json(receipt), 0o600, 0 if os.geteuid() == 0 else os.geteuid(), 0 if os.geteuid() == 0 else os.getegid())


def _acquire_operator_lock(root: Path, controld_gid: int) -> int:
    _require_receipt_root(root, controld_gid, allow_private=True)
    parent_fd, name = activation_package.open_parent_fd(root, OPERATOR_LOCK_PATH, create=True)
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        metadata = os.fstat(fd)
        expected_uid, expected_gid = _physical_ids(root, 0, 0)
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != expected_uid or metadata.st_gid != expected_gid
        ):
            raise ValueError("activation operator lock metadata is unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("another activation operator operation is active") from error
        return fd
    except BaseException:
        os.close(fd)
        raise


def _run_operator_locked(
    manifest: dict[str, Any], root: Path, operation: Callable[[], dict[str, object]],
) -> dict[str, object]:
    lock_fd = _acquire_operator_lock(root, manifest["identities"]["controld"]["gid"])
    try:
        return operation()
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _read_receipt(root: Path) -> dict[str, Any] | None:
    opened = _read_target(root, RECEIPT_PATH, activation_package.MAX_JSON_BYTES)
    if opened is None:
        return None
    raw, metadata = opened
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    expected_gid = 0 if os.geteuid() == 0 else os.getegid()
    if _metadata_dict(metadata) != {"mode": 0o600, "uid": expected_uid, "gid": expected_gid}:
        raise ValueError("activation receipt metadata is unsafe")
    receipt = json.loads(raw, object_pairs_hook=activation_package.reject_duplicates)
    if not isinstance(receipt, dict) or receipt.get("schema") != activation_package.RECEIPT_SCHEMA:
        raise ValueError("activation receipt schema is invalid")
    return receipt


def _require_receipt_root(root: Path, _controld_gid: int, *, allow_private: bool = False) -> Path:
    directory = activation_package.rooted(root, "/var/lib/buzzci/activation-controller")
    parent_fd, name = activation_package.open_parent_fd(root, "/var/lib/buzzci/activation-controller", create=True)
    try:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        metadata = os.fstat(directory_fd)
    finally:
        os.close(directory_fd)
    expected_uid, expected_gid = _physical_ids(root, 0, 0)
    observed = (stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid)
    final = (0o711, expected_uid, expected_gid)
    private_uid, private_gid = _physical_ids(root, 0, 0)
    private = (0o700, private_uid, private_gid)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (observed != final and not (allow_private and observed == private))
    ):
        raise ValueError("activation receipt root metadata differs from the fixed plan")
    return directory


def _scenario_hex(value: object, lengths: set[int], where: str) -> str:
    if not isinstance(value, str) or len(value) not in lengths or not re.fullmatch(r"[0-9a-f]+", value) or set(value) == {"0"}:
        raise ValueError(f"acceptance scenario {where} is invalid")
    return value


def _scenario_u64(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"acceptance scenario {where} is invalid")
    return value


def _ordered_evidence(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"acceptance scenario {where} must be an object")
    activation_package.require_keys(value, {"name", "sha256", "bytes"}, f"acceptance scenario {where}")
    name = value["name"]
    if not isinstance(name, str) or not 1 <= len(name) <= 255 or "/" in name or "\\" in name or "\0" in name:
        raise ValueError(f"acceptance scenario {where} name is invalid")
    byte_count = _scenario_u64(value["bytes"], f"{where} bytes")
    return {"name": name, "sha256": _scenario_hex(value["sha256"], {64}, f"{where} sha256"), "bytes": byte_count}


def _acceptance_binding(manifest: dict[str, Any], scenario: object) -> dict[str, object]:
    if not isinstance(scenario, dict):
        raise ValueError("acceptance scenario must be an object")
    activation_package.require_keys(scenario, {"schema_version", "fixture", "driver"}, "acceptance scenario")
    if scenario["schema_version"] != "buzz-ci-capacity-one-scenario/v1":
        raise ValueError("acceptance scenario schema is unsupported")
    fixture = scenario["fixture"]
    fixture_fields = (
        "integrated_candidate_sha", "activation_id", "activation_package_digest", "run_id", "job_id",
        "request_digest", "manifest_digest", "source_oid", "approval_id", "grant_event_id", "grant_digest",
        "approved_by", "export_subject", "export_authorization_digest", "controller_generation",
        "runner_generation", "expected_log", "expected_artifacts",
    )
    if not isinstance(fixture, dict):
        raise ValueError("acceptance scenario fixture must be an object")
    activation_package.require_keys(fixture, set(fixture_fields), "acceptance scenario fixture")
    activation_id = fixture["activation_id"]
    if activation_id != manifest["activation_id"] or fixture["activation_package_digest"] != manifest["package_digest"]:
        raise ValueError("acceptance scenario belongs to a different activation package")
    if fixture["integrated_candidate_sha"] != manifest["source_commit"]:
        raise ValueError("acceptance scenario integrated candidate differs from the package source commit")
    job_id = fixture["job_id"]
    if not isinstance(job_id, str) or not 1 <= len(job_id) <= 64 or re.fullmatch(r"[A-Za-z0-9._-]+", job_id) is None:
        raise ValueError("acceptance scenario job id is invalid")
    artifacts = fixture["expected_artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise ValueError("acceptance scenario must bind exactly one expected artifact")
    ordered_fixture: dict[str, object] = {
        "integrated_candidate_sha": _scenario_hex(fixture["integrated_candidate_sha"], {40, 64}, "integrated candidate"),
        "activation_id": activation_id,
        "activation_package_digest": _scenario_hex(fixture["activation_package_digest"], {64}, "activation package digest"),
        "run_id": _scenario_hex(fixture["run_id"], {32}, "run id"),
        "job_id": job_id,
        "request_digest": _scenario_hex(fixture["request_digest"], {64}, "request digest"),
        "manifest_digest": _scenario_hex(fixture["manifest_digest"], {64}, "manifest digest"),
        "source_oid": _scenario_hex(fixture["source_oid"], {40, 64}, "source oid"),
        "approval_id": _scenario_hex(fixture["approval_id"], {32}, "approval id"),
        "grant_event_id": _scenario_hex(fixture["grant_event_id"], {64}, "grant event id"),
        "grant_digest": _scenario_hex(fixture["grant_digest"], {64}, "grant digest"),
        "approved_by": _scenario_hex(fixture["approved_by"], {64}, "approved by"),
        "export_subject": _scenario_hex(fixture["export_subject"], {64}, "export subject"),
        "export_authorization_digest": _scenario_hex(fixture["export_authorization_digest"], {64}, "export authorization digest"),
        "controller_generation": _scenario_u64(fixture["controller_generation"], "controller generation"),
        "runner_generation": _scenario_u64(fixture["runner_generation"], "runner generation"),
        "expected_log": _ordered_evidence(fixture["expected_log"], "expected log"),
        "expected_artifacts": [_ordered_evidence(artifacts[0], "expected artifact")],
    }
    driver = scenario["driver"]
    driver_fields = ("control", "observe", "export", "controller_process", "runner_process", "timeout_seconds")
    if not isinstance(driver, dict):
        raise ValueError("acceptance scenario driver must be an object")
    activation_package.require_keys(driver, set(driver_fields), "acceptance scenario driver")
    ordered_driver: dict[str, object] = {}
    for name in driver_fields[:-1]:
        endpoint = driver[name]
        if not isinstance(endpoint, dict) or set(endpoint) not in ({"program"}, {"program", "args"}):
            raise ValueError(f"acceptance scenario driver {name} is invalid")
        if endpoint["program"] != "/usr/libexec/buzz-ci-capacity-one-driver" or endpoint.get("args", []) != []:
            raise ValueError(f"acceptance scenario driver {name} differs from the fixed endpoint")
        ordered_driver[name] = {"program": endpoint["program"], "args": []}
    timeout_seconds = driver["timeout_seconds"]
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 300:
        raise ValueError("acceptance scenario driver timeout is invalid")
    ordered_driver["timeout_seconds"] = timeout_seconds
    ordered_scenario = {"schema_version": scenario["schema_version"], "fixture": ordered_fixture, "driver": ordered_driver}
    rust_bytes = json.dumps(ordered_scenario, ensure_ascii=False, separators=(",", ":")).encode()
    scenario_sha256 = activation_package.digest(rust_bytes)
    template = activation_package.validate_acceptance_template(manifest["acceptance_template"])
    grant_event_id = activation_package.digest(json.dumps(
        template["grant_event"], ensure_ascii=False, separators=(",", ":"),
    ).encode())
    if ordered_fixture["grant_event_id"] != grant_event_id:
        raise ValueError("acceptance grant event id differs from the frozen public template")
    acceptance = {
        "actor": {
            "public_key": template["actor"]["public_key"],
            "generation": template["actor"]["generation"],
        },
        "scenario_sha256": scenario_sha256,
        "run_event": template["run_event"],
        "grant_event": template["grant_event"],
        "rerun_event": template["rerun_event"],
        "tombstone_event": template["tombstone_event"],
    }
    controld = manifest["identities"]["controld"]
    return {
        "schema_version": activation_package.ACCEPTANCE_BINDING_SCHEMA,
        "activation_id": manifest["activation_id"],
        "activation_package_digest": manifest["package_digest"],
        "scenario_sha256": scenario_sha256,
        "peer_uid": controld["uid"],
        "peer_gid": controld["gid"],
        "timeout_millis": timeout_seconds * 1000,
        "fixture": ordered_fixture,
        "acceptance": acceptance,
    }


def _acceptance_binding_bytes(
    manifest: dict[str, Any], binding: dict[str, object],
) -> bytes:
    expected_top = [
        "schema_version", "activation_id", "activation_package_digest", "scenario_sha256",
        "peer_uid", "peer_gid", "timeout_millis", "fixture", "acceptance",
    ]
    expected_acceptance = [
        "actor", "scenario_sha256", "run_event", "grant_event", "rerun_event", "tombstone_event",
    ]
    acceptance = binding.get("acceptance")
    controld = manifest.get("identities", {}).get("controld", {})
    if (
        list(binding) != expected_top or binding["schema_version"] != activation_package.ACCEPTANCE_BINDING_SCHEMA
        or not isinstance(acceptance, dict) or list(acceptance) != expected_acceptance
        or binding["scenario_sha256"] != acceptance["scenario_sha256"]
        or (binding["peer_uid"], binding["peer_gid"])
        != (controld.get("uid"), controld.get("gid"))
    ):
        raise ValueError("acceptance binding scenario or controld peer differs")
    payload = json.dumps(binding, ensure_ascii=False, separators=(",", ":")).encode()
    if len(payload) > MAX_SCENARIO_BYTES:
        raise ValueError("acceptance binding exceeds its fixed byte bound")
    return payload


def load_acceptance_scenario(path: Path, manifest: dict[str, Any], *, live: bool) -> dict[str, object]:
    raw, metadata = activation_package.read_fd(Path(os.path.abspath(path)), MAX_SCENARIO_BYTES)
    expected_owner = 0 if live else os.geteuid()
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != expected_owner or not mode & stat.S_IRUSR or mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise ValueError("acceptance scenario metadata is unsafe")
    try:
        scenario = json.loads(raw, object_pairs_hook=activation_package.reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("acceptance scenario must be valid JSON") from error
    return _acceptance_binding(manifest, scenario)


def _generated_acceptance_files(
    manifest: dict[str, Any], payloads: dict[str, bytes], binding: dict[str, object],
) -> list[dict[str, object]]:
    fixture = binding["fixture"]
    qualification = manifest["identities"]["qualification"]
    controld = manifest["identities"]["controld"]
    common = {
        "activation_id": binding["activation_id"],
        "activation_package_digest": binding["activation_package_digest"],
        "integrated_candidate_sha": fixture["integrated_candidate_sha"],
        "scenario_sha256": binding["scenario_sha256"],
        "run_id": fixture["run_id"],
        "job_id": fixture["job_id"],
        "request_digest": fixture["request_digest"],
        "manifest_digest": fixture["manifest_digest"],
        "approval_id": fixture["approval_id"],
        "grant_event_id": fixture["grant_event_id"],
        "grant_digest": fixture["grant_digest"],
        "qualification_uid": qualification["uid"],
        "qualification_gid": qualification["gid"],
    }
    control = {
        "schema_version": "buzz-ci-acceptance-control-config/v1",
        **common,
        "controller_generation": fixture["controller_generation"],
        "runner_generation": fixture["runner_generation"],
    }
    driver = {
        "schema_version": "buzz-ci-capacity-one-driver-config/v1",
        **common,
        "controld_uid": controld["uid"],
        "controld_gid": controld["gid"],
        "control_socket": activation_package.SOCKET_POLICY["acceptance_control"]["path"],
        "controld_socket": activation_package.SOCKET_POLICY["controld_acceptance"]["path"],
        "timeout_millis": binding["timeout_millis"],
    }
    execd_entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
    execd_staged = _render_execd_config(manifest, payloads, execd_entry, binding, capacity=0)
    execd_active = _render_execd_config(manifest, payloads, execd_entry, binding, capacity=1)
    return [
        {
            "role": "controld_acceptance_binding", "target": ACCEPTANCE_BINDING_PATH,
            "payload": _acceptance_binding_bytes(manifest, binding), "mode": 0o444, "uid": 0, "gid": 0,
        },
        {
            "role": "acceptance_control_config", "target": "/etc/buzzci/acceptance-control-v1.json",
            "payload": activation_package.canonical_json(control), "mode": 0o400, "uid": 0, "gid": 0,
        },
        {
            "role": "acceptance_driver_config", "target": "/etc/buzzci/acceptance-driver-v1.json",
            "payload": activation_package.canonical_json(driver), "mode": 0o440, "uid": 0,
            "gid": qualification["gid"],
        },
        {
            "role": "execd_config", "target": activation_package.CONFIG_TARGETS["execd_config"],
            "payload": execd_staged, "active_payload": execd_active,
            "mode": 0o600, "uid": 0, "gid": 0,
        },
    ]


def _render_execd_config(
    manifest: dict[str, Any], payloads: dict[str, bytes], entry: dict[str, object],
    binding: dict[str, object], *, capacity: int,
) -> bytes:
    source_field = "source" if capacity == 0 else "active_source"
    source = entry.get(source_field)
    if not isinstance(source, str):
        raise ValueError("execd configuration template phase is absent")
    fixture = binding.get("fixture")
    if not isinstance(fixture, dict):
        raise ValueError("execd qualification fixture is absent")
    template = payloads.get(source)
    if template is None:
        raise ValueError("execd configuration template payload is unavailable")
    try:
        rendered = json.loads(template, object_pairs_hook=activation_package.reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("execd configuration template is invalid JSON") from error
    qualification = rendered.get("qualification")
    if not isinstance(qualification, dict) or rendered.get("capacity") != capacity:
        raise ValueError("execd configuration template phase differs")
    qualification.update({
        "activation_package_digest": manifest["package_digest"],
        "fixture_digest": binding["scenario_sha256"],
        "controller_generation": fixture["controller_generation"],
        "runner_generation": fixture["runner_generation"],
    })
    if fixture.get("manifest_digest") != rendered.get("lane_manifest_digest"):
        raise ValueError("acceptance fixture manifest digest differs from the execd lane manifest")
    execution = rendered.get("execution")
    activation_package.validate_execution_declaration(execution, allow_placeholder=True)
    execution["declaration_digest"] = activation_package.execution_declaration_digest(
        manifest["source_commit"], manifest["package_digest"], rendered["lane_manifest"], execution,
    )
    activation_package.validate_execution_declaration(execution, allow_placeholder=False)
    return activation_package.canonical_json(rendered)


def _capture_prior(root: Path, target: str) -> dict[str, object]:
    opened = _read_target(root, target, MAX_SCENARIO_BYTES)
    if opened is None:
        return {"exists": False}
    payload, metadata = opened
    return {
        "exists": True,
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "sha256": activation_package.digest(payload),
        **_metadata_dict(metadata),
    }


def _capture_acceptance_ledger(manifest: dict[str, Any], root: Path) -> dict[str, object]:
    prior = _capture_prior(root, CONTROLD_ACCEPTANCE_LEDGER_PATH)
    if prior["exists"]:
        expected_uid, expected_gid = _physical_ids(
            root, manifest["identities"]["controld"]["uid"], manifest["identities"]["controld"]["gid"],
        )
        if (prior["mode"], prior["uid"], prior["gid"]) != (0o600, expected_uid, expected_gid):
            raise ValueError("prior controld acceptance ledger metadata is unsafe")
    return prior


def _remove_captured_ledger(root: Path, prior: dict[str, object]) -> None:
    opened = _read_target(root, CONTROLD_ACCEPTANCE_LEDGER_PATH, MAX_SCENARIO_BYTES)
    if not prior["exists"]:
        if opened is not None:
            raise ValueError("controld acceptance ledger appeared during staging")
        return
    if opened is None:
        raise ValueError("prior controld acceptance ledger disappeared during staging")
    payload, metadata = opened
    if activation_package.digest(payload) != prior["sha256"] or _metadata_dict(metadata) != {
        "mode": prior["mode"], "uid": prior["uid"], "gid": prior["gid"],
    }:
        raise ValueError("prior controld acceptance ledger drifted during staging")
    _unlink_target(root, CONTROLD_ACCEPTANCE_LEDGER_PATH)


def _restore_acceptance_ledger(receipt: dict[str, Any], manifest: dict[str, Any], root: Path) -> None:
    prior = receipt["acceptance_ledger_prior"]
    opened = _read_target(root, CONTROLD_ACCEPTANCE_LEDGER_PATH, MAX_SCENARIO_BYTES)
    if opened is not None:
        _payload, metadata = opened
        expected_uid, expected_gid = _physical_ids(
            root, manifest["identities"]["controld"]["uid"], manifest["identities"]["controld"]["gid"],
        )
        if _metadata_dict(metadata) != {"mode": 0o600, "uid": expected_uid, "gid": expected_gid}:
            raise ValueError("current controld acceptance ledger metadata is unsafe")
    if prior["exists"]:
        payload = base64.b64decode(prior["payload_base64"], validate=True)
        _atomic_write(
            root, CONTROLD_ACCEPTANCE_LEDGER_PATH, payload,
            prior["mode"], prior["uid"], prior["gid"],
        )
    elif opened is not None:
        _unlink_target(root, CONTROLD_ACCEPTANCE_LEDGER_PATH)


def _acceptance_ledger_prior_readback(receipt: dict[str, Any], root: Path) -> str:
    prior = receipt["acceptance_ledger_prior"]
    opened = _read_target(root, CONTROLD_ACCEPTANCE_LEDGER_PATH, MAX_SCENARIO_BYTES)
    if not prior["exists"]:
        if opened is not None:
            raise ValueError("controld acceptance ledger prior absence readback failed")
        return "absent"
    if opened is None:
        raise ValueError("controld acceptance ledger prior readback failed")
    payload, metadata = opened
    if activation_package.digest(payload) != prior["sha256"] or _metadata_dict(metadata) != {
        "mode": prior["mode"], "uid": prior["uid"], "gid": prior["gid"],
    }:
        raise ValueError("controld acceptance ledger prior readback differs")
    return "restored"


def _generated_records(root: Path, generated: list[dict[str, object]]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for item in generated:
        record: dict[str, object] = {
            "role": item["role"], "target": item["target"], "sha256": activation_package.digest(item["payload"]),
            "mode": item["mode"], "uid": item["uid"], "gid": item["gid"],
            "payload_base64": base64.b64encode(item["payload"]).decode("ascii"),
            "prior": _capture_prior(root, item["target"]),
        }
        if "active_payload" in item:
            record.update({
                "active_sha256": activation_package.digest(item["active_payload"]),
                "active_payload_base64": base64.b64encode(item["active_payload"]).decode("ascii"),
            })
        records.append(record)
    return records


def _bind_generated_plan(records: object, generated: list[dict[str, object]]) -> None:
    if not isinstance(records, list) or len(records) != len(generated):
        raise ValueError("acceptance generated plan differs from the receipt")
    by_role = {record.get("role"): record for record in records if isinstance(record, dict)}
    if len(by_role) != len(generated):
        raise ValueError("acceptance generated plan differs from the receipt")
    for item in generated:
        record = by_role.get(item["role"])
        expected = {
            "target": item["target"], "sha256": activation_package.digest(item["payload"]),
            "mode": item["mode"], "uid": item["uid"], "gid": item["gid"],
            "payload_base64": base64.b64encode(item["payload"]).decode("ascii"),
        }
        if "active_payload" in item:
            expected.update({
                "active_sha256": activation_package.digest(item["active_payload"]),
                "active_payload_base64": base64.b64encode(item["active_payload"]).decode("ascii"),
            })
        if record is None or any(record.get(key) != value for key, value in expected.items()):
            raise ValueError("acceptance scenario differs from the staged receipt")


def _apply_generated(root: Path, records: list[dict[str, object]], *, phase: str = "staged") -> None:
    for record in records:
        active = phase == "active" and "active_payload_base64" in record
        payload_key = "active_payload_base64" if active else "payload_base64"
        digest_key = "active_sha256" if active else "sha256"
        payload = base64.b64decode(record[payload_key], validate=True)
        if activation_package.digest(payload) != record[digest_key]:
            raise ValueError(f"generated acceptance payload digest differs: {record['role']}")
        _atomic_write(root, record["target"], payload, record["mode"], record["uid"], record["gid"])


def _verify_generated(
    root: Path, records: list[dict[str, object]], *, phase: str = "staged",
) -> dict[str, str]:
    result: dict[str, str] = {}
    for record in records:
        active = phase == "active" and "active_sha256" in record
        expected = dict(record)
        if active:
            expected["sha256"] = record["active_sha256"]
        _verify_target_digest(root, record["target"], expected, MAX_SCENARIO_BYTES)
        result[record["role"]] = "active" if active else "exact"
    return result


def _package_asset(package: Path, source: str, mode: int, sha256: str, *, live: bool) -> bytes:
    path = package / source
    payload, metadata = activation_package.read_fd(path)
    expected_owner = 0 if live else os.geteuid()
    if stat.S_IMODE(metadata.st_mode) != mode or metadata.st_uid != expected_owner or metadata.st_gid != (0 if live else os.getegid()):
        raise ValueError(f"activation asset metadata differs: {source}")
    if activation_package.digest(payload) != sha256:
        raise ValueError(f"activation asset digest differs: {source}")
    return payload


def load_package(package: Path, *, live: bool) -> tuple[dict[str, Any], dict[str, bytes]]:
    package = Path(os.path.abspath(package))
    if Path(os.path.realpath(package)) != package:
        raise ValueError("activation package root must be real")
    package_metadata = package.lstat()
    assets_metadata = (package / "assets").lstat()
    expected_owner = 0 if live else os.geteuid()
    expected_group = 0 if live else os.getegid()
    for metadata, where in ((package_metadata, "package root"), (assets_metadata, "assets directory")):
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError(f"activation {where} must be mode 0700")
        if metadata.st_uid != expected_owner or metadata.st_gid != expected_group:
            raise ValueError(f"activation {where} ownership differs")
    manifest, _raw, metadata = activation_package.parse_json(package / "activation-manifest.json")
    if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != expected_owner or metadata.st_gid != expected_group:
        raise ValueError("activation manifest metadata differs")
    activation_package.validate_manifest(manifest)

    references: dict[str, tuple[int, str]] = {}
    for entry in manifest["entries"]:
        references[entry["source"]] = (activation_package.parse_mode(entry["source_mode"]), entry["sha256"])
        if "active_source" in entry:
            references[entry["active_source"]] = (activation_package.parse_mode(entry["active_source_mode"]), entry["active_sha256"])
    for component in manifest["components"]:
        references[component["provenance_source"]] = (0o400, component["provenance_sha256"])
        if component["name"] == "controld":
            references[component["package_manifest_source"]] = (0o400, component["package_manifest_sha256"])
    actual_assets = {f"assets/{item.name}" for item in (package / "assets").iterdir()}
    if actual_assets != set(references):
        raise ValueError("activation package has missing or extra assets")
    payloads = {
        source: _package_asset(package, source, mode, sha256, live=live)
        for source, (mode, sha256) in references.items()
    }
    for component in manifest["components"]:
        provenance = json.loads(payloads[component["provenance_source"]], object_pairs_hook=activation_package.reject_duplicates)
        if provenance != {
            "binary": Path(component["binary_path"]).name,
            "profile": "release",
            "schema": activation_package.PROVENANCE_SCHEMA,
            "sha256": component["binary_sha256"],
            "source_commit": component["source_commit"],
        }:
            raise ValueError(f"frozen provenance mismatch: {component['name']}")
    activation_package.validate_payloads(manifest, payloads)
    return manifest, payloads


def _package_references(manifest: dict[str, Any]) -> dict[str, int]:
    references: dict[str, int] = {}
    for entry in manifest["entries"]:
        references[entry["source"]] = activation_package.parse_mode(entry["source_mode"])
        if "active_source" in entry:
            references[entry["active_source"]] = activation_package.parse_mode(entry["active_source_mode"])
    for component in manifest["components"]:
        references[component["provenance_source"]] = 0o400
        if component["name"] == "controld":
            references[component["package_manifest_source"]] = 0o400
    return references


def _fixed_package_present(root: Path) -> bool:
    try:
        parent_fd, name = activation_package.open_parent_fd(root, FIXED_PACKAGE_PATH)
    except FileNotFoundError:
        return False
    try:
        try:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("fixed activation package path is not a directory")
        return True
    finally:
        os.close(parent_fd)


def _remove_package_tree(root: Path, target: str, *, expected_sources: set[str] | None) -> None:
    parent_fd, name = activation_package.open_parent_fd(root, target)
    directory_fd = -1
    assets_fd = -1
    try:
        directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        entries = set(os.listdir(directory_fd))
        if not entries <= {"activation-manifest.json", "assets"}:
            raise ValueError("fixed activation package contains unexpected entries")
        if "assets" in entries:
            assets_fd = os.open("assets", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
            assets = set(os.listdir(assets_fd))
            if expected_sources is not None and assets != {Path(item).name for item in expected_sources}:
                raise ValueError("fixed activation package assets differ before removal")
            for asset in sorted(assets):
                metadata = os.stat(asset, dir_fd=assets_fd, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError("fixed activation package contains an unsafe asset")
                os.unlink(asset, dir_fd=assets_fd)
            os.close(assets_fd)
            assets_fd = -1
            os.rmdir("assets", dir_fd=directory_fd)
        if "activation-manifest.json" in entries:
            metadata = os.stat("activation-manifest.json", dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("fixed activation manifest shape is unsafe")
            os.unlink("activation-manifest.json", dir_fd=directory_fd)
        os.close(directory_fd)
        directory_fd = -1
        os.rmdir(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if assets_fd >= 0:
            os.close(assets_fd)
        if directory_fd >= 0:
            os.close(directory_fd)
        os.close(parent_fd)


def _install_fixed_package(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
) -> dict[str, str]:
    live = root == Path("/")
    if _fixed_package_present(root):
        target = activation_package.rooted(root, FIXED_PACKAGE_PATH)
        installed_manifest, installed_payloads = load_package(target, live=live)
        if installed_manifest != manifest or installed_payloads != payloads:
            raise ValueError("fixed activation package belongs to a different package")
        return {"path": FIXED_PACKAGE_PATH, "status": "exact", "manifest_sha256": activation_package.digest(activation_package.canonical_json(manifest))}
    parent_fd, final_name = activation_package.open_parent_fd(root, FIXED_PACKAGE_PATH, create=True)
    temporary_name = f".package-install-{os.getpid()}-{os.urandom(8).hex()}"
    temporary_target = f"/var/lib/buzzci/activation-controller/{temporary_name}"
    created = False
    try:
        os.mkdir(temporary_name, 0o700, dir_fd=parent_fd)
        created = True
        temporary = activation_package.rooted(root, temporary_target)
        temporary.chmod(0o700)
        (temporary / "assets").mkdir(mode=0o700)
        references = _package_references(manifest)
        for source, mode in sorted(references.items()):
            _atomic_write(root, f"{temporary_target}/assets/{Path(source).name}", payloads[source], mode, 0, 0)
        _atomic_write(
            root, f"{temporary_target}/activation-manifest.json",
            activation_package.canonical_json(manifest), 0o600, 0, 0,
        )
        load_package(temporary, live=live)
        os.rename(temporary_name, final_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
        created = False
    finally:
        os.close(parent_fd)
        if created:
            try:
                _remove_package_tree(root, temporary_target, expected_sources=None)
            except BaseException:
                pass
    return {"path": FIXED_PACKAGE_PATH, "status": "installed", "manifest_sha256": activation_package.digest(activation_package.canonical_json(manifest))}


def _verify_fixed_package(manifest: dict[str, Any], root: Path) -> dict[str, str]:
    installed, _payloads = load_package(activation_package.rooted(root, FIXED_PACKAGE_PATH), live=root == Path("/"))
    if installed != manifest:
        raise ValueError("fixed activation package manifest differs")
    return {"path": FIXED_PACKAGE_PATH, "status": "exact", "manifest_sha256": activation_package.digest(activation_package.canonical_json(manifest))}


def _install_recovery_targets(
    receipt: dict[str, Any], manifest: dict[str, Any], root: Path,
) -> dict[str, str]:
    installed, payloads = load_package(
        activation_package.rooted(root, FIXED_PACKAGE_PATH), live=root == Path("/"),
    )
    if installed != manifest:
        raise ValueError("fixed activation package manifest differs before recovery install")
    records = _validate_receipt_targets(receipt, manifest)
    entries = {entry["role"]: entry for entry in manifest["entries"]}
    result: dict[str, str] = {}
    for role in ("activation_controller", "activation_package_module"):
        entry = entries[role]
        opened = _read_target(root, entry["target"])
        state = _entry_state(root, entry, opened)
        if state != "staged":
            prior = records[role]["prior"]
            if opened is None:
                if prior["exists"]:
                    raise ValueError(f"recovery target absence differs: {entry['target']}")
            else:
                current, metadata = opened
                if (
                    not prior["exists"]
                    or activation_package.digest(current) != prior["sha256"]
                    or _metadata_dict(metadata) != {
                        "mode": prior["mode"], "uid": prior["uid"], "gid": prior["gid"],
                    }
                ):
                    raise ValueError(f"recovery target drift blocks install: {entry['target']}")
            _atomic_write(
                root, entry["target"], payloads[entry["source"]],
                activation_package.parse_mode(entry["install_mode"]), entry["uid"], entry["gid"],
                restart_phase=f"recovery:{role}",
            )
        _verify_target_digest(root, entry["target"], {
            "sha256": entry["sha256"], "mode": entry["install_mode"],
            "uid": entry["uid"], "gid": entry["gid"],
        }, activation_package.MAX_ASSET_BYTES)
        _stage_restart_boundary(f"recovery:{role}:readback")
        result[role] = "exact"
    return result


def _remove_fixed_package(manifest: dict[str, Any], root: Path) -> None:
    if not _fixed_package_present(root):
        return
    _verify_fixed_package(manifest, root)
    _remove_package_tree(root, FIXED_PACKAGE_PATH, expected_sources=set(_package_references(manifest)))


def _rollback_cleanup_value(manifest: dict[str, Any]) -> dict[str, object]:
    return {
        "schema": ROLLBACK_CLEANUP_SCHEMA,
        "activation_id": manifest["activation_id"],
        "package_digest": manifest["package_digest"],
        "source_commit": manifest["source_commit"],
        "manifest_sha256": activation_package.digest(activation_package.canonical_json(manifest)),
        "package_assets": sorted(Path(source).name for source in _package_references(manifest)),
        "manifest": manifest,
    }


def _read_rollback_cleanup(root: Path) -> dict[str, Any] | None:
    opened = _read_target(root, ROLLBACK_CLEANUP_PATH, activation_package.MAX_JSON_BYTES)
    if opened is None:
        return None
    raw, metadata = opened
    expected_uid, expected_gid = _physical_ids(root, 0, 0)
    if _metadata_dict(metadata) != {"mode": 0o600, "uid": expected_uid, "gid": expected_gid}:
        raise ValueError("rollback cleanup marker metadata is unsafe")
    try:
        value = json.loads(raw, object_pairs_hook=activation_package.reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("rollback cleanup marker is invalid") from error
    if not isinstance(value, dict) or activation_package.canonical_json(value) != raw:
        raise ValueError("rollback cleanup marker is noncanonical")
    manifest = value.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("rollback cleanup marker lacks its manifest")
    activation_package.validate_manifest(manifest)
    if value != _rollback_cleanup_value(manifest):
        raise ValueError("rollback cleanup marker binding differs")
    return value


def _write_rollback_cleanup(manifest: dict[str, Any], root: Path) -> dict[str, Any]:
    value = _rollback_cleanup_value(manifest)
    existing = _read_rollback_cleanup(root)
    if existing is not None:
        if existing != value:
            raise ValueError("rollback cleanup marker belongs to a different activation")
        return existing
    _atomic_write(root, ROLLBACK_CLEANUP_PATH, activation_package.canonical_json(value), 0o600, 0, 0)
    readback = _read_rollback_cleanup(root)
    if readback != value:
        raise ValueError("rollback cleanup marker readback differs")
    return value


def _read_private_json(root: Path, target: str, *, label: str) -> dict[str, Any] | None:
    opened = _read_target(root, target, activation_package.MAX_JSON_BYTES)
    if opened is None:
        return None
    raw, metadata = opened
    expected_uid, expected_gid = _physical_ids(root, 0, 0)
    if _metadata_dict(metadata) != {"mode": 0o600, "uid": expected_uid, "gid": expected_gid}:
        raise ValueError(f"{label} metadata is unsafe")
    try:
        value = json.loads(raw, object_pairs_hook=activation_package.reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is invalid") from error
    if not isinstance(value, dict) or activation_package.canonical_json(value) != raw:
        raise ValueError(f"{label} is noncanonical")
    return value


def _rollback_marker_sha256(marker: dict[str, Any]) -> str:
    return activation_package.digest(activation_package.canonical_json(marker))


def _rollback_archive_path(marker: dict[str, Any], next_manifest: dict[str, Any]) -> str:
    marker_sha256 = _rollback_marker_sha256(marker)
    return (
        f"{ROLLBACK_ARCHIVE_ROOT}/{marker_sha256}-"
        f"{next_manifest['activation_id']}.json"
    )


def _rollback_retirement_value(
    marker: dict[str, Any], next_manifest: dict[str, Any],
) -> dict[str, object]:
    return {
        "schema": ROLLBACK_RETIREMENT_SCHEMA,
        "marker_sha256": _rollback_marker_sha256(marker),
        "archive_path": _rollback_archive_path(marker, next_manifest),
        "next_activation_id": next_manifest["activation_id"],
        "next_package_digest": next_manifest["package_digest"],
        "next_source_commit": next_manifest["source_commit"],
        "marker": marker,
    }


def _rollback_archive_value(retirement: dict[str, Any]) -> dict[str, object]:
    return {
        "schema": ROLLBACK_ARCHIVE_SCHEMA,
        "marker_sha256": retirement["marker_sha256"],
        "retired_by_activation_id": retirement["next_activation_id"],
        "retired_by_package_digest": retirement["next_package_digest"],
        "retired_by_source_commit": retirement["next_source_commit"],
        "marker": retirement["marker"],
    }


def _validate_rollback_retirement(value: dict[str, Any]) -> None:
    if set(value) != {
        "schema", "marker_sha256", "archive_path", "next_activation_id",
        "next_package_digest", "next_source_commit", "marker",
    } or value.get("schema") != ROLLBACK_RETIREMENT_SCHEMA:
        raise ValueError("rollback retirement marker shape differs")
    marker = value.get("marker")
    if not isinstance(marker, dict):
        raise ValueError("rollback retirement marker lacks cleanup marker")
    manifest = marker.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("rollback retirement cleanup marker lacks its manifest")
    activation_package.validate_manifest(manifest)
    if marker != _rollback_cleanup_value(manifest):
        raise ValueError("rollback retirement cleanup marker binding differs")
    if value.get("marker_sha256") != _rollback_marker_sha256(marker):
        raise ValueError("rollback retirement marker digest differs")
    next_binding = {
        "activation_id": value.get("next_activation_id"),
        "package_digest": value.get("next_package_digest"),
        "source_commit": value.get("next_source_commit"),
    }
    if not all(isinstance(item, str) for item in next_binding.values()):
        raise ValueError("rollback retirement next activation binding differs")
    expected_path = (
        f"{ROLLBACK_ARCHIVE_ROOT}/{value['marker_sha256']}-"
        f"{value['next_activation_id']}.json"
    )
    if value.get("archive_path") != expected_path:
        raise ValueError("rollback retirement archive path differs")


def _read_rollback_retirement(root: Path) -> dict[str, Any] | None:
    value = _read_private_json(root, ROLLBACK_RETIREMENT_PATH, label="rollback retirement marker")
    if value is not None:
        _validate_rollback_retirement(value)
    return value


def _read_rollback_archive(root: Path, retirement: dict[str, Any]) -> dict[str, Any] | None:
    value = _read_private_json(root, retirement["archive_path"], label="rollback archive")
    if value is not None and value != _rollback_archive_value(retirement):
        raise ValueError("rollback archive binding differs")
    return value


def _ensure_rollback_archive_root(root: Path) -> None:
    directory_fd, _name = activation_package.open_parent_fd(
        root, f"{ROLLBACK_ARCHIVE_ROOT}/archive", create=True,
    )
    try:
        metadata = os.fstat(directory_fd)
        expected_uid, expected_gid = _physical_ids(root, 0, 0)
        if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
            raise ValueError("rollback archive directory ownership is unsafe")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            os.fchmod(directory_fd, 0o700)
            os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _prepare_rollback_retirement(
    receipt: dict[str, Any], next_manifest: dict[str, Any], root: Path,
) -> dict[str, Any]:
    if receipt.get("state") != "rolled_back":
        raise ValueError("rollback marker retirement requires rolled-back receipt")
    marker = _read_rollback_cleanup(root)
    if marker is None:
        raise ValueError("rolled-back receipt lacks current rollback cleanup marker")
    _bind_receipt(receipt, marker["manifest"])
    expected = _rollback_retirement_value(marker, next_manifest)
    existing = _read_rollback_retirement(root)
    if existing is not None and existing != expected:
        raise ValueError("rollback retirement marker belongs to a different staged activation")
    if existing != expected:
        _atomic_write(
            root, ROLLBACK_RETIREMENT_PATH,
            activation_package.canonical_json(expected), 0o600, 0, 0,
        )
    readback = _read_rollback_retirement(root)
    if readback != expected:
        raise ValueError("rollback retirement marker readback differs")
    return expected


def _complete_rollback_retirement(next_manifest: dict[str, Any], root: Path) -> None:
    retirement = _read_rollback_retirement(root)
    if retirement is None:
        if _read_rollback_cleanup(root) is not None:
            raise ValueError("current rollback cleanup marker lacks retirement authorization")
        return
    if (
        retirement["next_activation_id"] != next_manifest["activation_id"]
        or retirement["next_package_digest"] != next_manifest["package_digest"]
        or retirement["next_source_commit"] != next_manifest["source_commit"]
    ):
        raise ValueError("rollback retirement marker belongs to a different staged activation")
    archive = _rollback_archive_value(retirement)
    existing_archive = _read_rollback_archive(root, retirement)
    if existing_archive is None:
        _ensure_rollback_archive_root(root)
        _atomic_write(
            root, retirement["archive_path"],
            activation_package.canonical_json(archive), 0o600, 0, 0,
        )
    if _read_rollback_archive(root, retirement) != archive:
        raise ValueError("rollback archive readback differs")
    current = _read_rollback_cleanup(root)
    if current is not None:
        if current != retirement["marker"]:
            raise ValueError("current rollback cleanup marker differs during retirement")
        _unlink_target(root, ROLLBACK_CLEANUP_PATH)
    if _read_rollback_cleanup(root) is not None:
        raise ValueError("current rollback cleanup marker retirement is incomplete")
    if _read_rollback_retirement(root) is not None:
        _unlink_target(root, ROLLBACK_RETIREMENT_PATH)
    if _read_rollback_retirement(root) is not None:
        raise ValueError("rollback retirement marker removal is incomplete")
    if _read_rollback_archive(root, retirement) != archive:
        raise ValueError("rollback archive changed after retirement")


def _remove_fixed_package_resumable(manifest: dict[str, Any], root: Path) -> None:
    expected_assets = {Path(source).name for source in _package_references(manifest)}
    try:
        parent_fd, name = activation_package.open_parent_fd(root, FIXED_PACKAGE_PATH)
    except FileNotFoundError:
        return
    directory_fd = -1
    assets_fd = -1
    try:
        try:
            directory_fd = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            return
        entries = set(os.listdir(directory_fd))
        if not entries <= {"activation-manifest.json", "assets"}:
            raise ValueError("fixed activation package contains unexpected entries during cleanup")
        if "assets" in entries:
            assets_fd = os.open(
                "assets", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            assets = set(os.listdir(assets_fd))
            if not assets <= expected_assets:
                raise ValueError("fixed activation package assets differ during cleanup")
            for asset in sorted(assets):
                metadata = os.stat(asset, dir_fd=assets_fd, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError("fixed activation package contains an unsafe cleanup asset")
                os.unlink(asset, dir_fd=assets_fd)
            os.close(assets_fd)
            assets_fd = -1
            os.rmdir("assets", dir_fd=directory_fd)
        if "activation-manifest.json" in entries:
            metadata = os.stat("activation-manifest.json", dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("fixed activation manifest cleanup shape is unsafe")
            os.unlink("activation-manifest.json", dir_fd=directory_fd)
        os.close(directory_fd)
        directory_fd = -1
        os.rmdir(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if assets_fd >= 0:
            os.close(assets_fd)
        if directory_fd >= 0:
            os.close(directory_fd)
        os.close(parent_fd)


def _validate_phase_configs(manifest: dict[str, Any], payloads: dict[str, bytes]) -> None:
    activation_package.validate_phase_configs(manifest, payloads)


class LiveSystemd:
    def __init__(self, root: Path) -> None:
        if root != Path("/"):
            raise ValueError("live systemd driver requires root /")

    @staticmethod
    def _run(program: str, arguments: list[str], *, mutation: bool = False) -> subprocess.CompletedProcess[bytes]:
        if mutation and os.geteuid() != 0:
            raise PermissionError("live activation mutations require root")
        return subprocess.run(
            [program, *arguments],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )

    def unit(self, name: str) -> dict[str, str]:
        if not activation_package.UNIT.fullmatch(name):
            raise ValueError("invalid systemd unit name")
        result = self._run(SYSTEMCTL, ["show", "--no-pager", "--property=LoadState,ActiveState,SubState,UnitFileState", name])
        values: dict[str, str] = {}
        for line in result.stdout.decode("utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        if set(values) != {"LoadState", "ActiveState", "SubState", "UnitFileState"}:
            raise ValueError(f"incomplete systemd readback: {name}")
        return values

    def effective_paths(self, name: str) -> dict[str, object]:
        if not activation_package.UNIT.fullmatch(name):
            raise ValueError("invalid systemd unit name")
        result = self._run(
            SYSTEMCTL,
            ["show", "--no-pager", "--property=FragmentPath,DropInPaths", name],
        )
        values: dict[str, str] = {}
        for line in result.stdout.decode("utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        if set(values) != {"FragmentPath", "DropInPaths"}:
            raise ValueError(f"incomplete systemd effective-path readback: {name}")
        drop_ins = values["DropInPaths"].split() if values["DropInPaths"] else []
        if len(drop_ins) != len(set(drop_ins)):
            raise ValueError(f"duplicated systemd drop-in readback: {name}")
        return {"fragment_path": values["FragmentPath"], "drop_in_paths": drop_ins}

    def fragment_path(self, name: str) -> str:
        return str(self.effective_paths(name)["fragment_path"])

    def process(self, name: str) -> dict[str, object]:
        if not activation_package.UNIT.fullmatch(name) or not name.endswith(".service"):
            raise ValueError("invalid systemd service name")
        result = self._run(
            SYSTEMCTL,
            ["show", "--no-pager", "--property=InvocationID,MainPID", name],
        )
        values: dict[str, str] = {}
        for line in result.stdout.decode("utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        if set(values) != {"InvocationID", "MainPID"} or not values["MainPID"].isdigit():
            raise ValueError(f"incomplete systemd process readback: {name}")
        return {"invocation_id": values["InvocationID"], "main_pid": int(values["MainPID"])}

    def provision(self, _identities: dict[str, object]) -> None:
        self._run(SYSUSERS, [activation_package.STATIC_TARGETS["sysusers"]], mutation=True)

    def tmpfiles(self) -> None:
        self._run(TMPFILES, ["--create", activation_package.STATIC_TARGETS["tmpfiles"]], mutation=True)
        self._run(TMPFILES, ["--create", activation_package.STATIC_TARGETS["acceptance_tmpfiles"]], mutation=True)

    def daemon_reload(self) -> None:
        self._run(SYSTEMCTL, ["daemon-reload"], mutation=True)

    def start(self, name: str) -> None:
        self._run(SYSTEMCTL, ["start", name], mutation=True)

    def stop(self, name: str) -> None:
        state = self.unit(name)
        if state["LoadState"] != "not-found":
            self._run(SYSTEMCTL, ["stop", name], mutation=True)

    def enable(self, name: str) -> None:
        self._run(SYSTEMCTL, ["enable", name], mutation=True)

    def disable(self, name: str) -> None:
        state = self.unit(name)
        if state["LoadState"] != "not-found":
            self._run(SYSTEMCTL, ["disable", name], mutation=True)

    def identity(self, name: str) -> dict[str, object] | None:
        try:
            account = pwd.getpwnam(name)
            group = grp.getgrnam(name)
        except KeyError:
            return None
        return {
            "user": account.pw_name,
            "group": group.gr_name,
            "uid": account.pw_uid,
            "gid": group.gr_gid,
            "primary_gid": account.pw_gid,
            "home": account.pw_dir,
            "shell": account.pw_shell,
            "supplementary_groups": sorted(
                candidate.gr_name for candidate in grp.getgrall() if account.pw_name in candidate.gr_mem
            ),
        }

    @staticmethod
    def group(name: str) -> dict[str, object] | None:
        try:
            group = grp.getgrnam(name)
        except KeyError:
            return None
        return {"group": group.gr_name, "gid": group.gr_gid, "members": sorted(group.gr_mem)}

    def numeric_identity(self, uid: int, gid: int) -> dict[str, str | None]:
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            user = None
        try:
            group = grp.getgrgid(gid).gr_name
        except KeyError:
            group = None
        return {"user": user, "group": group}

    @staticmethod
    def numeric_group(gid: int) -> str | None:
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return None

    def socket(self, policy: dict[str, object]) -> dict[str, object]:
        metadata = os.stat(policy["path"], follow_symlinks=False)
        if not stat.S_ISSOCK(metadata.st_mode):
            raise ValueError(f"live endpoint is not a socket: {policy['path']}")
        return {
            "path": policy["path"],
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
        }

    @staticmethod
    def socket_absent(policy: dict[str, object]) -> bool:
        try:
            os.stat(policy["path"], follow_symlinks=False)
        except FileNotFoundError:
            return True
        raise ValueError(f"live endpoint remains present: {policy['path']}")


class FakeSystemd:
    """Deterministic fake-root state driver. It never invokes systemd."""

    def __init__(
        self,
        root: Path,
        state_path: Path,
        identities: dict[str, object],
        access_group: dict[str, object],
        socket_policy: dict[str, object],
        effective_systemd: list[dict[str, object]],
    ) -> None:
        if root == Path("/"):
            raise ValueError("fake systemd requires a non-root filesystem")
        self.root = root
        self.state_path = Path(os.path.abspath(state_path))
        expected_parent = activation_package.rooted(root, "/var/lib/buzzci/activation-controller")
        if self.state_path.parent != expected_parent:
            raise ValueError("fake systemd state must stay in the fake activation root")
        if self.state_path.name != "fake-systemd-v1.json":
            raise ValueError("fake systemd state filename is fixed")
        _require_receipt_root(root, identities["controld"]["gid"], allow_private=True)
        self.planned_identities = identities
        self.access_group = access_group
        self.socket_policy = socket_policy
        self.effective_systemd = {item["unit"]: item for item in effective_systemd}

    def _read(self) -> dict[str, Any]:
        value, _raw, metadata = activation_package.parse_json(self.state_path)
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("fake systemd state must be mode 0600")
        if set(value) != {"schema", "units", "identities", "groups", "sockets"} or value["schema"] != "buzz-ci-fake-systemd-v1":
            raise ValueError("fake systemd state schema is invalid")
        return value

    def _write(self, value: dict[str, object]) -> None:
        _atomic_write(self.root, "/var/lib/buzzci/activation-controller/fake-systemd-v1.json", activation_package.canonical_json(value), 0o600, os.geteuid(), os.getegid())

    def unit(self, name: str) -> dict[str, str]:
        state = self._read()
        unit = state["units"].get(name)
        if not isinstance(unit, dict):
            return {"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled"}
        return {
            key: str(unit[key])
            for key in ("LoadState", "ActiveState", "SubState", "UnitFileState")
        }

    def effective_paths(self, name: str) -> dict[str, object]:
        unit = self._read()["units"].get(name)
        if not isinstance(unit, dict) or unit.get("LoadState") != "loaded":
            return {"fragment_path": "", "drop_in_paths": []}
        fragment_path = unit.get("FragmentPath")
        drop_in_paths = unit.get("DropInPaths")
        if not isinstance(fragment_path, str) or not isinstance(drop_in_paths, list):
            raise ValueError(f"incomplete fake systemd effective-path readback: {name}")
        if any(not isinstance(path, str) for path in drop_in_paths):
            raise ValueError(f"invalid fake systemd drop-in path: {name}")
        if len(drop_in_paths) != len(set(drop_in_paths)):
            raise ValueError(f"duplicated systemd drop-in readback: {name}")
        return {"fragment_path": fragment_path, "drop_in_paths": list(drop_in_paths)}

    def fragment_path(self, name: str) -> str:
        return str(self.effective_paths(name)["fragment_path"])

    def process(self, name: str) -> dict[str, object]:
        unit = self._read()["units"].get(name)
        if not isinstance(unit, dict):
            return {"invocation_id": "", "main_pid": 0}
        return {
            "invocation_id": unit.get("InvocationID", ""),
            "main_pid": unit.get("MainPID", 0),
        }

    def provision(self, identities: dict[str, object]) -> None:
        state = self._read()
        for role, identity in identities.items():
            existing = state["identities"].get(identity["user"])
            expected = {
                "user": identity["user"], "group": identity["group"], "uid": identity["uid"], "gid": identity["gid"],
                "primary_gid": identity["gid"], "home": identity["home"], "shell": identity["shell"],
                "supplementary_groups": identity["supplementary_groups"],
            }
            if existing is not None and existing != expected and not _legacy_qualification_identity(role, existing, expected):
                raise ValueError(f"fake principal drift: {role}")
            state["identities"][identity["user"]] = expected
        expected_group = {
            "group": self.access_group["group"],
            "gid": self.access_group["gid"],
            "members": self.access_group["members"],
        }
        existing_group = state["groups"].get(self.access_group["group"])
        if existing_group is not None and existing_group != expected_group:
            raise ValueError("fake execd access group drift")
        state["groups"][self.access_group["group"]] = expected_group
        self._write(state)

    def tmpfiles(self) -> None:
        directory = _require_receipt_root(
            self.root, self.planned_identities["controld"]["gid"], allow_private=True,
        )
        directory.chmod(0o711)
        acceptance = activation_package.rooted(self.root, "/var/lib/buzzci/acceptance-control")
        acceptance.mkdir(parents=True, mode=0o700, exist_ok=True)
        acceptance.chmod(0o700)
        for target, mode in (
            ("/var/lib/buzzci", 0o711),
            ("/var/lib/buzzci/seccomp", 0o711),
            ("/var/lib/buzzci/seccomp/v1", 0o711),
            ("/var/lib/buzzci/seccomp/v1/sha256", 0o711),
            ("/var/lib/buzzci/activation", 0o700),
            ("/var/lib/buzzci/activation/receipts", 0o700),
            ("/var/lib/buzzci/execd-v2", 0o711),
            (activation_package.EXECD_INTENT_ROOT, 0o700),
            (activation_package.EXECD_BINDING_ROOT, 0o700),
            (activation_package.EXECD_EVIDENCE_ROOT, 0o700),
            (activation_package.EXECD_TEARDOWN_ROOT, 0o700),
            (activation_package.EXECD_ATTEMPT_ROOT, 0o711),
            (activation_package.EXECD_QUALIFICATION_ROOT, 0o700),
        ):
            directory = activation_package.rooted(self.root, target)
            directory.mkdir(parents=True, mode=mode, exist_ok=True)
            directory.chmod(mode)
        _require_receipt_root(self.root, self.planned_identities["controld"]["gid"])

    def daemon_reload(self) -> None:
        state = self._read()
        for unit, effective in self.effective_systemd.items():
            fragment_path = str(effective["fragment"]["path"])
            unit_path = activation_package.rooted(self.root, fragment_path)
            if unit_path.exists():
                state["units"].setdefault(unit, {
                    "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled",
                })
                state["units"][unit]["LoadState"] = "loaded"
                state["units"][unit]["FragmentPath"] = fragment_path
                drop_in_directory = activation_package.rooted(
                    self.root, f"/etc/systemd/system/{unit}.d",
                )
                state["units"][unit]["DropInPaths"] = (
                    [f"/etc/systemd/system/{unit}.d/{path.name}" for path in sorted(drop_in_directory.glob("*.conf"), key=lambda item: item.name.encode())]
                    if drop_in_directory.is_dir() else []
                )
            else:
                state["units"][unit] = {
                    "LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled",
                    "FragmentPath": "", "DropInPaths": [],
                }
        self._write(state)

    def start(self, name: str) -> None:
        state = self._read()
        unit = state["units"].setdefault(name, {})
        was_active = unit.get("ActiveState") == "active"
        unit.update({"LoadState": "loaded", "ActiveState": "active", "SubState": "listening" if name.endswith(".socket") else "running"})
        unit.setdefault("UnitFileState", "disabled")
        if name.endswith(".service") and not was_active:
            start_count = unit.get("StartCount", 0) + 1
            unit.update({
                "StartCount": start_count,
                "InvocationID": hashlib.sha256(f"{name}:{start_count}".encode()).hexdigest()[:32],
                "MainPID": 1000 + start_count,
            })
        for policy in self.socket_policy.values():
            if policy["unit"] == name:
                identity = self.identity(policy["user"]) if policy["user"] != "root" else {"uid": 0}
                group = self.group(policy["group"]) if policy["group"] != "root" else {"gid": 0}
                state["sockets"][policy["path"]] = {
                    "path": policy["path"], "mode": policy["mode"], "uid": identity["uid"], "gid": group["gid"],
                }
        self._write(state)

    def stop(self, name: str) -> None:
        state = self._read()
        unit = state["units"].setdefault(name, {})
        unit.update({"LoadState": unit.get("LoadState", "loaded"), "ActiveState": "inactive", "SubState": "dead"})
        unit.setdefault("UnitFileState", "disabled")
        if name.endswith(".service"):
            unit.update({"InvocationID": "", "MainPID": 0})
        for policy in self.socket_policy.values():
            if policy["unit"] == name:
                state["sockets"].pop(policy["path"], None)
        self._write(state)

    def enable(self, name: str) -> None:
        state = self._read()
        unit = state["units"].setdefault(name, {})
        unit.update({"LoadState": "loaded", "UnitFileState": "enabled"})
        unit.setdefault("ActiveState", "inactive")
        unit.setdefault("SubState", "dead")
        self._write(state)

    def disable(self, name: str) -> None:
        state = self._read()
        unit = state["units"].setdefault(name, {})
        unit.update({"LoadState": unit.get("LoadState", "loaded"), "UnitFileState": "disabled"})
        unit.setdefault("ActiveState", "inactive")
        unit.setdefault("SubState", "dead")
        self._write(state)

    def identity(self, name: str) -> dict[str, object] | None:
        return self._read()["identities"].get(name)

    def group(self, name: str) -> dict[str, object] | None:
        state = self._read()
        group = state["groups"].get(name)
        if group is not None:
            return group
        identity = state["identities"].get(name)
        if identity is None:
            return None
        return {"group": identity["group"], "gid": identity["gid"], "members": []}

    def numeric_identity(self, uid: int, gid: int) -> dict[str, str | None]:
        state = self._read()
        user = next((name for name, value in state["identities"].items() if value.get("uid") == uid), None)
        group = next((value.get("group") for value in state["identities"].values() if value.get("gid") == gid), None)
        return {"user": user, "group": group}

    def numeric_group(self, gid: int) -> str | None:
        state = self._read()
        for name, value in state["groups"].items():
            if value.get("gid") == gid:
                return name
        return next((value.get("group") for value in state["identities"].values() if value.get("gid") == gid), None)

    def socket(self, policy: dict[str, object]) -> dict[str, object]:
        value = self._read()["sockets"].get(policy["path"])
        if value is None:
            raise ValueError(f"fake socket is absent: {policy['path']}")
        return value

    def socket_absent(self, policy: dict[str, object]) -> bool:
        if policy["path"] in self._read()["sockets"]:
            raise ValueError(f"fake endpoint remains present: {policy['path']}")
        return True


def _legacy_qualification_identity(
    role: str, observed: dict[str, object], expected: dict[str, object],
) -> bool:
    return (
        role == "qualification"
        and expected["uid"] == activation_package.QUALIFICATION_UID
        and expected["gid"] == activation_package.QUALIFICATION_GID
        and observed == {**expected, "supplementary_groups": []}
    )


def _identity_readback(driver: LiveSystemd | FakeSystemd, identities: dict[str, object], *, allow_absent: bool) -> dict[str, object]:
    result: dict[str, object] = {}
    for role, identity in identities.items():
        observed = driver.identity(identity["user"])
        if observed is None:
            if allow_absent:
                numeric = driver.numeric_identity(identity["uid"], identity["gid"])
                if numeric != {"user": None, "group": None}:
                    raise ValueError(f"planned numeric principal is already occupied: {identity['user']}")
                result[role] = {"status": "absent"}
                continue
            raise ValueError(f"required principal is absent: {identity['user']}")
        expected = {
            "user": identity["user"],
            "group": identity["group"],
            "uid": identity["uid"],
            "gid": identity["gid"],
            "primary_gid": identity["gid"],
            "home": identity["home"],
            "shell": identity["shell"],
            "supplementary_groups": identity["supplementary_groups"],
        }
        if observed != expected and allow_absent and _legacy_qualification_identity(role, observed, expected):
            result[role] = {"status": "convergent_legacy", **observed}
            continue
        if observed != expected:
            raise ValueError(f"principal drift: {identity['user']}")
        result[role] = {"status": "exact", **observed}
    return result


def _access_group_readback(
    driver: LiveSystemd | FakeSystemd,
    access_group: dict[str, object],
    *,
    allow_absent: bool,
) -> dict[str, object]:
    observed = driver.group(access_group["group"])
    if observed is None:
        if allow_absent:
            occupied = driver.numeric_group(access_group["gid"])
            if occupied is not None:
                raise ValueError("planned execd access group GID is already occupied")
            return {"status": "absent"}
        raise ValueError("required execd access group is absent")
    expected = {
        "group": access_group["group"],
        "gid": access_group["gid"],
        "members": access_group["members"],
    }
    if observed != expected:
        raise ValueError("execd access group drift")
    return {"status": "exact", **observed}


def _component_readback(
    manifest: dict[str, Any], root: Path, *, allow_installable_absent: bool = False,
) -> dict[str, object]:
    result: dict[str, object] = {}
    installable = set(activation_package.INSTALLABLE_COMPONENT_ROLES.values())
    for component in manifest["components"]:
        expected = {
            "sha256": component["binary_sha256"],
            "mode": component["mode"],
            "uid": component["uid"],
            "gid": component["gid"],
        }
        try:
            _verify_target_digest(root, component["binary_path"], expected, MAX_BINARY_BYTES)
        except (FileNotFoundError, ValueError) as error:
            if allow_installable_absent and component["name"] in installable and (
                isinstance(error, FileNotFoundError) or "required target is absent" in str(error)
            ):
                result[component["name"]] = {"binary_path": component["binary_path"], "status": "install_planned"}
                continue
            raise
        result[component["name"]] = {
            "binary_path": component["binary_path"],
            "binary_sha256": component["binary_sha256"],
            "source_commit": component["source_commit"],
            "provenance_sha256": component["provenance_sha256"],
        }
    return result


def _entry_state(root: Path, entry: dict[str, object], opened: tuple[bytes, os.stat_result] | None) -> str:
    if opened is None:
        return "absent"
    payload, metadata = opened
    expected_uid, expected_gid = _physical_ids(root, entry["uid"], entry["gid"])
    expected_metadata = {
        "mode": activation_package.parse_mode(entry["install_mode"]),
        "uid": expected_uid,
        "gid": expected_gid,
    }
    if _metadata_dict(metadata) != expected_metadata:
        return "drift"
    observed_digest = activation_package.digest(payload)
    if observed_digest == entry["sha256"]:
        return "staged"
    if observed_digest == entry.get("active_sha256"):
        return "active"
    if entry["role"] == "execd_config":
        return "prior"
    return "drift"


def _managed_readback(
    manifest: dict[str, Any], root: Path, allowed: set[str],
    *, allow_recovery_upgrade: bool = False,
) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in manifest["entries"]:
        state = _entry_state(root, entry, _read_target(root, entry["target"]))
        if state not in allowed and not (
            allow_recovery_upgrade
            and entry["role"] in ROLLBACK_RECOVERY_ROLES
            and state == "drift"
        ):
            raise ValueError(f"managed target drift: {entry['target']} ({state})")
        result[entry["role"]] = state
    return result


def _unit_readback(driver: LiveSystemd | FakeSystemd, names: list[str]) -> dict[str, dict[str, str]]:
    return {name: driver.unit(name) for name in names}


def _systemd_file_digest(root: Path, record: dict[str, object], where: str) -> str:
    opened = _read_target(root, str(record["path"]), activation_package.MAX_ASSET_BYTES)
    if opened is None:
        raise ValueError(f"effective systemd file is missing: {where}")
    payload, _metadata = opened
    observed = activation_package.digest(payload)
    if observed != record["sha256"]:
        raise ValueError(f"effective systemd file digest differs: {where}")
    return observed


def _effective_systemd_readback(
    manifest: dict[str, Any],
    root: Path,
    driver: LiveSystemd | FakeSystemd,
    *,
    phase: str,
    names: set[str] | None = None,
) -> dict[str, dict[str, object]]:
    if phase not in {"prior", "installed"}:
        raise ValueError("effective systemd phase is invalid")
    result: dict[str, dict[str, object]] = {}
    inventory = {item["unit"]: item for item in manifest["effective_systemd"]}
    selected = sorted(inventory if names is None else names)
    if not set(selected) <= set(inventory):
        raise ValueError("effective systemd readback names differ from the manifest")
    for name in selected:
        item = inventory[name]
        fragment = item["fragment"]
        state = driver.unit(name)
        paths = driver.effective_paths(name)
        expected_fragment = (
            fragment
            if phase == "installed" or fragment["owner"] != "activation" or state["LoadState"] == "loaded"
            else None
        )
        expected_drop_ins = [
            record for record in item["drop_ins"]
            if (
                phase == "installed"
                or record["owner"] != "activation"
                or _read_target(root, str(record["path"]), activation_package.MAX_ASSET_BYTES) is not None
            )
        ]
        if expected_fragment is None:
            if state["LoadState"] != "not-found" or paths != {"fragment_path": "", "drop_in_paths": []}:
                raise ValueError(f"absent activation systemd unit has an effective path: {name}")
            result[name] = {**state, "fragment_path": "", "fragment_sha256": None, "drop_in_paths": [], "drop_in_sha256": []}
            continue
        if state["LoadState"] != "loaded":
            raise ValueError(f"effective systemd unit is not loaded: {name}")
        expected_paths = [record["path"] for record in expected_drop_ins]
        if paths["fragment_path"] != expected_fragment["path"]:
            raise ValueError(f"effective systemd fragment is relocated: {name}")
        if paths["drop_in_paths"] != expected_paths:
            raise ValueError(f"effective systemd drop-in paths or order differ: {name}")
        fragment_sha256 = _systemd_file_digest(root, expected_fragment, f"{name} fragment")
        drop_in_sha256 = [
            _systemd_file_digest(root, record, f"{name} drop-in {index}")
            for index, record in enumerate(expected_drop_ins)
        ]
        result[name] = {
            **state,
            "fragment_path": paths["fragment_path"],
            "fragment_sha256": fragment_sha256,
            "drop_in_paths": list(paths["drop_in_paths"]),
            "drop_in_sha256": drop_in_sha256,
        }
    return result


def _preflight_units(driver: LiveSystemd | FakeSystemd) -> dict[str, dict[str, str]]:
    names = sorted(set(activation_package.START_ORDER + activation_package.STOP_ORDER))
    result = _unit_readback(driver, names)
    for name, state in result.items():
        package_owned = name in activation_package.PACKAGE_UNIT_ROLES
        if state["LoadState"] not in ({"loaded", "not-found"} if package_owned else {"loaded"}):
            raise ValueError(f"required systemd unit is not loaded: {name}")
        if state["LoadState"] == "not-found" and (
            state["ActiveState"] != "inactive" or state["UnitFileState"] not in {"disabled", "static"}
        ):
            raise ValueError(f"absent package-owned systemd unit is not dormant: {name}")
        baseline_execd = name == "buzz-ci-execd.socket"
        if state["ActiveState"] != "inactive" and not baseline_execd:
            raise ValueError(f"systemd unit is not dormant: {name}")
        if name.endswith(".socket") and state["UnitFileState"] not in {"disabled", "static"} and not baseline_execd:
            raise ValueError(f"systemd socket is enabled before activation: {name}")
    target = driver.unit(activation_package.PERSISTENT_UNIT)
    if target["LoadState"] not in {"not-found", "loaded"} or target["ActiveState"] != "inactive":
        raise ValueError("capacity-one target is not dormant")
    if target["LoadState"] == "loaded" and target["UnitFileState"] not in {"disabled", "static"}:
        raise ValueError("capacity-one target is enabled before activation")
    result[activation_package.PERSISTENT_UNIT] = target
    return result


def _installed_unit_readback(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, dict[str, object]]:
    entries = {entry["role"]: entry for entry in manifest["entries"]}
    result: dict[str, dict[str, object]] = {}
    for unit, role in activation_package.PACKAGE_UNIT_ROLES.items():
        entry = entries[role]
        _verify_target_digest(root, entry["target"], {
            "sha256": entry["sha256"], "mode": entry["install_mode"],
            "uid": entry["uid"], "gid": entry["gid"],
        }, activation_package.MAX_ASSET_BYTES)
        state = driver.unit(unit)
        if state["LoadState"] != "loaded":
            raise ValueError(f"installed package-owned systemd unit is not loaded: {unit}")
        result[unit] = {"sha256": entry["sha256"], **state}
    for unit in activation_package.DEPENDENCY_UNITS:
        state = driver.unit(unit)
        if state["LoadState"] != "loaded":
            raise ValueError(f"required dependency systemd unit is not loaded after installation: {unit}")
        result[unit] = state
    effective = _effective_systemd_readback(manifest, root, driver, phase="installed")
    for unit, readback in effective.items():
        result[unit] = {**result[unit], **readback}
    return result


def _keyholder_config_readback(
    manifest: dict[str, Any], root: Path, payloads: dict[str, bytes] | None = None,
) -> dict[str, object]:
    opened = _read_target(root, activation_package.KEYHOLDER_CONFIG_PATH, 64 * 1024)
    if opened is None:
        raise ValueError("external keyholder configuration is absent")
    raw, metadata = opened
    identity = manifest["identities"]["keyholder"]
    expected_uid, expected_gid = _physical_ids(root, identity["uid"], identity["gid"])
    if _metadata_dict(metadata) != {"mode": 0o600, "uid": expected_uid, "gid": expected_gid}:
        raise ValueError("external keyholder configuration metadata differs")
    try:
        value = json.loads(raw, object_pairs_hook=activation_package.reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("external keyholder configuration is invalid JSON") from error
    expected_selectors = None
    expected_nip98_origin = None
    if payloads is not None:
        entry = next(item for item in manifest["entries"] if item["role"] == "controld_config")
        active = json.loads(payloads[entry["active_source"]], object_pairs_hook=activation_package.reject_duplicates)
        expected_selectors = active["keyholder_selectors"]
        expected_nip98_origin = active["relay_http_origin"]
    activation_package.validate_external_keyholder_config(
        value, manifest, expected_selectors, expected_nip98_origin,
    )
    if raw != activation_package.canonical_json(value):
        raise ValueError("external keyholder configuration bytes are not canonical")
    return {"path": activation_package.KEYHOLDER_CONFIG_PATH, "sha256": activation_package.digest(raw), "status": "exact"}


def preflight(
    manifest: dict[str, Any],
    root: Path,
    driver: LiveSystemd | FakeSystemd,
    *,
    require_dormant: bool,
    payloads: dict[str, bytes] | None = None,
    allow_recovery_upgrade: bool = False,
) -> dict[str, object]:
    components = _component_readback(manifest, root, allow_installable_absent=True)
    principals = _identity_readback(driver, manifest["identities"], allow_absent=True)
    access_group = _access_group_readback(driver, manifest["access_group"], allow_absent=True)
    managed = _managed_readback(
        manifest, root, {"absent", "staged", "prior"},
        allow_recovery_upgrade=allow_recovery_upgrade,
    )
    for role in ("runner_config", "controld_config"):
        if managed[role] != "staged":
            raise ValueError(f"frozen component config is absent before activation: {role}")
    units: dict[str, dict[str, object]] = {}
    if require_dormant:
        _preflight_units(driver)
        units = _effective_systemd_readback(manifest, root, driver, phase="prior")
    keyholder_config = _keyholder_config_readback(manifest, root, payloads)
    return {
        "activation_id": manifest["activation_id"],
        "package_digest": manifest["package_digest"],
        "capacity": 0,
        "components": components,
        "keyholder_config": keyholder_config,
        "principals": principals,
        "access_group": access_group,
        "managed_targets": managed,
        "units": units,
        "socket_policy": manifest["socket_policy"],
    }


def _new_receipt(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
    generated: list[dict[str, object]],
) -> dict[str, object]:
    records: list[dict[str, object]] = []
    for entry in manifest["entries"]:
        opened = _read_target(root, entry["target"])
        if opened is None:
            prior: dict[str, object] = {"exists": False}
        else:
            payload, metadata = opened
            if (
                entry["role"] != "execd_config"
                and entry["role"] not in ROLLBACK_RECOVERY_ROLES
                and _entry_state(root, entry, opened) != "staged"
            ):
                raise ValueError(f"staging refuses existing target drift: {entry['target']}")
            prior = {
                "exists": True,
                "payload_base64": base64.b64encode(payload).decode("ascii"),
                "sha256": activation_package.digest(payload),
                **_metadata_dict(metadata),
            }
        records.append({
            "role": entry["role"],
            "target": entry["target"],
            "staged_sha256": entry["sha256"],
            "active_sha256": entry.get("active_sha256"),
            "prior": prior,
        })
    return {
        "schema": activation_package.RECEIPT_SCHEMA,
        "activation_id": manifest["activation_id"],
        "package_digest": manifest["package_digest"],
        "source_commit": manifest["source_commit"],
        "state": "preparing",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "principals_retained_on_rollback": True,
        "targets": records,
        "acceptance_generated": _generated_records(root, generated),
        "acceptance_ledger_prior": _capture_acceptance_ledger(manifest, root),
        "fixed_package": {
            "path": FIXED_PACKAGE_PATH,
            "manifest_sha256": activation_package.digest(activation_package.canonical_json(manifest)),
        },
        "systemd_before": _effective_systemd_readback(
            manifest, root, driver, phase="prior",
        ),
        "qualification": None,
        "capacity_one": None,
        "persistent_authorization": None,
        "persistent_activation": None,
        "qualification_zero": None,
        "last_error": None,
    }


def _bind_receipt(receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
    expected_keys = {
        "schema", "activation_id", "package_digest", "source_commit", "state", "created_at", "updated_at",
        "principals_retained_on_rollback", "targets", "acceptance_generated", "acceptance_ledger_prior",
        "fixed_package", "systemd_before", "qualification", "capacity_one", "persistent_authorization",
        "persistent_activation", "qualification_zero", "last_error",
    }
    if set(receipt) != expected_keys or receipt.get("schema") != activation_package.RECEIPT_SCHEMA:
        raise ValueError("activation receipt shape differs")
    if (
        receipt.get("activation_id") != manifest["activation_id"]
        or receipt.get("package_digest") != manifest["package_digest"]
        or receipt.get("source_commit") != manifest["source_commit"]
        or receipt.get("principals_retained_on_rollback") is not True
    ):
        raise ValueError("receipt belongs to a different activation package")
    records = receipt["acceptance_generated"]
    if not isinstance(records, list) or {record.get("role") for record in records if isinstance(record, dict)} != {
        "controld_acceptance_binding", "acceptance_control_config", "acceptance_driver_config", "execd_config",
    }:
        raise ValueError("receipt acceptance generated targets differ")
    if receipt["fixed_package"] != {
        "path": FIXED_PACKAGE_PATH,
        "manifest_sha256": activation_package.digest(activation_package.canonical_json(manifest)),
    }:
        raise ValueError("receipt fixed activation package binding differs")
    _validate_qualification_state(receipt["qualification"], receipt)
    _validate_capacity_one_state(receipt["capacity_one"], receipt)
    _validate_persistent_authorization(receipt["persistent_authorization"], receipt)
    _validate_capacity_one_state(receipt["persistent_activation"], receipt)
    _validate_qualification_zero_state(receipt["qualification_zero"], receipt)


def _validate_qualification_state(value: object, receipt: dict[str, Any]) -> None:
    if value is None:
        return
    required = {
        "schema", "status", "request_sha256", "request_base64",
        "response_sha256", "response_base64", "completed_at", "attempt_count",
        "last_error", "expired_at",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != QUALIFICATION_STATE_SCHEMA:
        raise ValueError("production qualification receipt state differs")
    if value["status"] not in {"pending", "passed", "expired_uncertain"}:
        raise ValueError("production qualification status differs")
    if (
        isinstance(value["attempt_count"], bool)
        or not isinstance(value["attempt_count"], int)
        or not 0 <= value["attempt_count"] <= QUALIFICATION_MAX_ATTEMPTS
    ):
        raise ValueError("production qualification attempt count differs")
    if value["last_error"] is not None and (
        not isinstance(value["last_error"], str) or not value["last_error"]
    ):
        raise ValueError("production qualification error evidence differs")
    try:
        request = base64.b64decode(value["request_base64"], validate=True)
        parsed = json.loads(request, object_pairs_hook=activation_package.reject_duplicates)
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("production qualification request receipt is invalid") from error
    if activation_package.digest(request) != value["request_sha256"] or request != _wire_qualification_json(parsed):
        raise ValueError("production qualification request receipt bytes differ")
    if (
        parsed.get("schema_version") != QUALIFICATION_REQUEST_SCHEMA
        or parsed.get("activation_package_digest") != receipt["package_digest"]
        or isinstance(parsed.get("issued_at"), bool)
        or not isinstance(parsed.get("issued_at"), int)
        or not isinstance(parsed.get("expires_at"), int)
        or parsed["expires_at"] - parsed["issued_at"] != 60
    ):
        raise ValueError("production qualification request belongs to a different package")
    if value["status"] == "pending":
        if any(value[field] is not None for field in ("response_sha256", "response_base64", "completed_at", "expired_at")):
            raise ValueError("pending production qualification contains response state")
        return
    if value["status"] == "expired_uncertain":
        if (
            any(value[field] is not None for field in ("response_sha256", "response_base64", "completed_at"))
            or not isinstance(value["expired_at"], str)
            or not value["expired_at"]
            or not isinstance(value["last_error"], str)
        ):
            raise ValueError("expired production qualification evidence is incomplete")
        return
    if not all(isinstance(value[field], str) and value[field] for field in ("response_sha256", "response_base64", "completed_at")):
        raise ValueError("passed production qualification response state is incomplete")
    if value["expired_at"] is not None or value["last_error"] is not None:
        raise ValueError("passed production qualification contains unresolved error state")
    response = base64.b64decode(value["response_base64"], validate=True)
    if activation_package.digest(response) != value["response_sha256"]:
        raise ValueError("passed production qualification response digest differs")
    _validate_qualification_response(request, response)


def _validate_capacity_one_state(value: object, receipt: dict[str, Any]) -> None:
    if value is None:
        return
    required = {
        "schema", "activation_id", "activation_package_digest", "scenario_sha256",
        "initial_controller_generation", "initial_runner_generation", "operation_id",
        "request_sha256", "phase", "attempt_count", "processes_before", "processes_after",
        "last_error",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != CAPACITY_ONE_SEQUENCE_SCHEMA:
        raise ValueError("capacity-one action receipt shape differs")
    if value["activation_id"] != receipt["activation_id"] or value["activation_package_digest"] != receipt["package_digest"]:
        raise ValueError("capacity-one action receipt belongs to a different activation")
    _scenario_hex(value["scenario_sha256"], {64}, "capacity-one scenario digest")
    _scenario_u64(value["initial_controller_generation"], "capacity-one controller generation")
    _scenario_u64(value["initial_runner_generation"], "capacity-one runner generation")
    _scenario_hex(value["operation_id"], {64}, "capacity-one operation id")
    _scenario_hex(value["request_sha256"], {64}, "capacity-one request digest")
    if value["phase"] not in {"activating", "compensated", "active_one", "failed"}:
        raise ValueError("capacity-one action phase differs")
    if (
        isinstance(value["attempt_count"], bool)
        or not isinstance(value["attempt_count"], int)
        or not 1 <= value["attempt_count"] <= MAX_CAPACITY_ONE_ATTEMPTS
    ):
        raise ValueError("capacity-one action attempt count differs")
    for field in ("processes_before", "processes_after"):
        processes = value[field]
        if processes is None:
            if field == "processes_before":
                raise ValueError("capacity-one processes_before is absent")
            continue
        if not isinstance(processes, dict) or set(processes) != set(CAPACITY_ONE_PROCESS_UNITS):
            raise ValueError(f"capacity-one {field} differs")
        for unit, process in processes.items():
            if not isinstance(process, dict) or set(process) != {"invocation_id", "main_pid"}:
                raise ValueError(f"capacity-one process readback differs: {unit}")
            if not isinstance(process["invocation_id"], str) or isinstance(process["main_pid"], bool) or not isinstance(process["main_pid"], int):
                raise ValueError(f"capacity-one process readback differs: {unit}")
    if value["phase"] == "active_one" and value["processes_after"] is None:
        raise ValueError("capacity-one active process readback is absent")
    if value["last_error"] is not None and (not isinstance(value["last_error"], str) or not value["last_error"]):
        raise ValueError("capacity-one action error differs")
    qualification = receipt.get("qualification")
    if not isinstance(qualification, dict) or qualification.get("status") != "passed":
        raise ValueError("capacity-one action lacks passed production qualification")
    request = json.loads(
        base64.b64decode(qualification["request_base64"], validate=True),
        object_pairs_hook=activation_package.reject_duplicates,
    )
    if (
        value["scenario_sha256"] != request.get("fixture_digest")
        or value["initial_controller_generation"] != request.get("controller_generation")
        or value["initial_runner_generation"] != request.get("runner_generation")
    ):
        raise ValueError("capacity-one action scope differs from production qualification")


def _validate_persistent_authorization(value: object, receipt: dict[str, Any]) -> None:
    if value is None:
        if receipt.get("persistent_activation") is not None:
            raise ValueError("persistent activation lacks acceptance authorization")
        return
    required = {
        "schema", "activation_id", "activation_package_digest", "integrated_candidate_sha",
        "scenario_sha256", "acceptance_scenario_sha256", "acceptance_receipt_sha256",
        "verifier_output_sha256", "zero_receipt_sha256", "operation_id",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != PERSISTENT_AUTHORIZATION_SCHEMA:
        raise ValueError("persistent activation authorization shape differs")
    if (
        value["activation_id"] != receipt["activation_id"]
        or value["activation_package_digest"] != receipt["package_digest"]
        or value["integrated_candidate_sha"] != receipt["source_commit"]
    ):
        raise ValueError("persistent activation authorization belongs to a different package")
    for field in (
        "scenario_sha256", "acceptance_scenario_sha256", "acceptance_receipt_sha256",
        "verifier_output_sha256", "zero_receipt_sha256", "operation_id",
    ):
        _scenario_hex(value[field], {64}, f"persistent activation {field}")
    activation = receipt.get("persistent_activation")
    if activation is not None and activation.get("operation_id") != value["operation_id"]:
        raise ValueError("persistent activation operation differs from its authorization")


def _validate_qualification_zero_state(value: object, receipt: dict[str, Any]) -> None:
    if value is None:
        return
    required = {
        "schema", "activation_id", "activation_package_digest", "scenario_sha256",
        "initial_controller_generation", "initial_runner_generation", "phase",
        "prepare", "finalize", "last_error",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != ZERO_SEQUENCE_SCHEMA:
        raise ValueError("qualification-zero receipt shape differs")
    if value["activation_id"] != receipt["activation_id"] or value["activation_package_digest"] != receipt["package_digest"]:
        raise ValueError("qualification-zero receipt belongs to a different activation")
    _scenario_hex(value["scenario_sha256"], {64}, "qualification-zero scenario digest")
    _scenario_u64(value["initial_controller_generation"], "qualification-zero controller generation")
    _scenario_u64(value["initial_runner_generation"], "qualification-zero runner generation")
    if value["phase"] not in {"preparing", "prepared", "prepare_failed", "finalizing", "finalize_failed", "finalized"}:
        raise ValueError("qualification-zero receipt phase differs")
    for action in ("prepare", "finalize"):
        record = value[action]
        if record is None:
            if action == "prepare":
                raise ValueError("qualification-zero prepare record is absent")
            continue
        if not isinstance(record, dict) or set(record) != {"operation_id", "request_sha256"}:
            raise ValueError(f"qualification-zero {action} record differs")
        _scenario_hex(record["operation_id"], {64}, f"qualification-zero {action} operation id")
        _scenario_hex(record["request_sha256"], {64}, f"qualification-zero {action} request digest")
    if value["phase"] in {"finalizing", "finalize_failed", "finalized"} and value["finalize"] is None:
        raise ValueError("qualification-zero finalize record is absent")
    if value["last_error"] is not None and (not isinstance(value["last_error"], str) or not value["last_error"]):
        raise ValueError("qualification-zero last error differs")


def _apply_phase(
    manifest: dict[str, Any],
    payloads: dict[str, bytes],
    root: Path,
    phase: str,
) -> None:
    for entry in manifest["entries"]:
        if entry["role"] == "execd_config":
            continue
        if phase == "active" and "active_source" not in entry:
            continue
        if phase == "active" and "active_source" in entry:
            source = entry["active_source"]
        else:
            source = entry["source"]
        _atomic_write(
            root,
            entry["target"],
            payloads[source],
            activation_package.parse_mode(entry["install_mode"]),
            entry["uid"],
            entry["gid"],
        )


def _verify_phase(manifest: dict[str, Any], root: Path, phase: str) -> dict[str, str]:
    expected_state = "active" if phase == "active" else "staged"
    result: dict[str, str] = {}
    for entry in manifest["entries"]:
        if entry["role"] == "execd_config":
            continue
        observed = _entry_state(root, entry, _read_target(root, entry["target"]))
        wanted = expected_state if "active_source" in entry else "staged"
        if observed != wanted:
            raise ValueError(f"{phase} readback failed: {entry['target']} ({observed})")
        result[entry["role"]] = observed
    return result


def _stop_zero_errors(driver: LiveSystemd | FakeSystemd) -> list[str]:
    errors: list[str] = []
    try:
        driver.disable(activation_package.PERSISTENT_UNIT)
    except BaseException as error:
        errors.append(f"disable {activation_package.PERSISTENT_UNIT}: {error}")
    for unit in activation_package.STOP_ORDER:
        try:
            driver.stop(unit)
        except BaseException as error:
            errors.append(f"stop {unit}: {error}")
    try:
        driver.stop(activation_package.PERSISTENT_UNIT)
    except BaseException as error:
        errors.append(f"stop {activation_package.PERSISTENT_UNIT}: {error}")
    return errors


def _stop_to_zero(driver: LiveSystemd | FakeSystemd) -> None:
    errors = _stop_zero_errors(driver)
    if errors:
        raise ValueError("capacity-zero stop failures: " + "; ".join(errors))


def _restore_systemd_prior_errors(
    receipt: dict[str, Any], driver: LiveSystemd | FakeSystemd,
) -> list[str]:
    prior = receipt.get("systemd_before")
    if not isinstance(prior, dict):
        return ["systemd prior state is invalid"]
    errors: list[str] = []
    for name, state in prior.items():
        if not isinstance(state, dict):
            errors.append(f"systemd prior state invalid: {name}")
            continue
        try:
            if state["UnitFileState"] == "enabled":
                driver.enable(name)
            elif state["UnitFileState"] == "disabled":
                driver.disable(name)
        except BaseException as error:
            errors.append(f"restore unit-file state {name}: {error}")
        try:
            if state["ActiveState"] == "active":
                driver.start(name)
            elif state["ActiveState"] == "inactive":
                driver.stop(name)
            else:
                errors.append(f"unsupported prior active state {name}: {state['ActiveState']}")
        except BaseException as error:
            errors.append(f"restore active state {name}: {error}")
    return errors


def _systemd_prior_readback(
    receipt: dict[str, Any], manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, dict[str, object]]:
    prior = receipt["systemd_before"]
    observed = _effective_systemd_readback(manifest, root, driver, phase="prior")
    for name, expected in prior.items():
        for field in (
            "LoadState", "ActiveState", "UnitFileState", "fragment_path",
            "fragment_sha256", "drop_in_paths", "drop_in_sha256",
        ):
            if observed[name][field] != expected[field]:
                raise ValueError(f"systemd prior readback differs for {name} {field}")
    return observed


def _zero_readback(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, dict[str, object]]:
    names = sorted(set(activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT]))
    result = _effective_systemd_readback(manifest, root, driver, phase="installed", names=set(names))
    for name, state in result.items():
        if state["ActiveState"] != "inactive":
            raise ValueError(f"capacity-zero readback found active unit: {name}")
    target = result[activation_package.PERSISTENT_UNIT]
    if target["LoadState"] != "not-found" and target["UnitFileState"] not in {"disabled", "static"}:
        raise ValueError("capacity-one target remains enabled")
    return result


def _staged_zero_readback(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    names = sorted(set(activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT]))
    units = _effective_systemd_readback(manifest, root, driver, phase="installed", names=set(names))
    staged = set(activation_package.STAGED_ZERO_UNITS)
    for name, state in units.items():
        wanted = "active" if name in staged else "inactive"
        if state["ActiveState"] != wanted:
            raise ValueError(f"staged-zero readback found unit {name} {state['ActiveState']}, expected {wanted}")
    target = units[activation_package.PERSISTENT_UNIT]
    if target["LoadState"] != "not-found" and target["UnitFileState"] not in {"disabled", "static"}:
        raise ValueError("capacity-one target remains enabled at staged zero")
    sockets = _socket_readback(
        manifest, driver, names={"acceptance_control", "controld_acceptance"},
    )
    return {"units": units, "sockets": sockets}


def _staged_zero_convergence_readback(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    names = sorted(set(activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT]))
    units = _effective_systemd_readback(manifest, root, driver, phase="installed", names=set(names))
    staged = set(activation_package.STAGED_ZERO_UNITS)
    for name, state in units.items():
        if name in staged:
            if state["ActiveState"] not in {"active", "inactive"}:
                raise ValueError(f"staged-zero convergence found unsupported unit state: {name}")
        elif state["ActiveState"] != "inactive":
            raise ValueError(f"staged-zero convergence found active capacity-one unit: {name}")
    target = units[activation_package.PERSISTENT_UNIT]
    if target["LoadState"] != "not-found" and target["UnitFileState"] not in {"disabled", "static"}:
        raise ValueError("capacity-one target remains enabled during staged-zero convergence")
    sockets: dict[str, object] = {}
    for name in ("acceptance_control", "controld_acceptance"):
        policy = manifest["socket_policy"][name]
        if units[policy["unit"]]["ActiveState"] == "active":
            sockets.update(_socket_readback(manifest, driver, names={name}))
        else:
            driver.socket_absent(policy)
    return {"units": units, "sockets": sockets}


ZERO_CLI_ACTIONS = {
    "prepare-qualification-zero": "prepare_qualification_zero",
    "finalize-qualification-zero": "finalize_qualification_zero",
    "prove-qualification-zero": "prove_qualification_zero",
}
CAPACITY_ONE_CLI_ACTION = "set-capacity-one"
CAPACITY_ONE_WIRE_ACTION = "set_capacity_one"
CAPACITY_ONE_REQUIRED_FIELDS = (
    "schema_version", "action", "activation_id", "activation_package_digest", "scenario_sha256",
    "initial_controller_generation", "initial_runner_generation", "operation_id",
)
ZERO_REQUIRED_FIELDS = (
    "schema_version", "action", "activation_id", "activation_package_digest", "scenario_sha256",
    "initial_controller_generation", "initial_runner_generation", "operation_id",
)
ZERO_OPTIONAL_FIELDS = (
    "failed_stage", "final_response_sha256", "expected_controller_generation", "expected_runner_generation",
)


def _wire_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def _binding_from_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    record = next(
        (item for item in receipt["acceptance_generated"] if item["role"] == "controld_acceptance_binding"),
        None,
    )
    if record is None:
        raise ValueError("controld acceptance binding is absent from the receipt")
    try:
        payload = base64.b64decode(record["payload_base64"], validate=True)
        binding = json.loads(payload, object_pairs_hook=activation_package.reject_duplicates)
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("controld acceptance binding receipt payload is invalid") from error
    if not isinstance(binding, dict) or activation_package.digest(payload) != record["sha256"]:
        raise ValueError("controld acceptance binding receipt payload differs")
    return binding


def _parse_capacity_one_request(raw: bytes, receipt: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if not raw or len(raw) > MAX_ZERO_REQUEST_BYTES:
        raise ValueError("capacity-one request size is invalid")
    try:
        request = json.loads(raw, object_pairs_hook=activation_package.reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("capacity-one request JSON is invalid") from error
    if not isinstance(request, dict) or raw != _wire_json(request):
        raise ValueError("capacity-one request is not canonical compact JSON")
    if tuple(request) != CAPACITY_ONE_REQUIRED_FIELDS:
        raise ValueError("capacity-one request field order or shape differs")
    if request["schema_version"] != CAPACITY_ONE_REQUEST_SCHEMA or request["action"] != CAPACITY_ONE_WIRE_ACTION:
        raise ValueError("capacity-one request action binding differs")
    if (
        request["activation_id"] != receipt["activation_id"]
        or request["activation_package_digest"] != receipt["package_digest"]
    ):
        raise ValueError("capacity-one request belongs to a different activation")
    _scenario_hex(request["scenario_sha256"], {64}, "capacity-one request scenario digest")
    _scenario_u64(request["initial_controller_generation"], "capacity-one initial controller generation")
    _scenario_u64(request["initial_runner_generation"], "capacity-one initial runner generation")
    _scenario_hex(request["operation_id"], {64}, "capacity-one operation id")
    binding = _binding_from_receipt(receipt)
    fixture = binding.get("fixture")
    if not isinstance(fixture, dict) or (
        binding.get("activation_id") != request["activation_id"]
        or binding.get("activation_package_digest") != request["activation_package_digest"]
        or binding.get("scenario_sha256") != request["scenario_sha256"]
        or fixture.get("controller_generation") != request["initial_controller_generation"]
        or fixture.get("runner_generation") != request["initial_runner_generation"]
    ):
        raise ValueError("capacity-one request differs from the acceptance binding")
    qualification = receipt.get("qualification")
    if not isinstance(qualification, dict) or qualification.get("status") != "passed":
        raise ValueError("capacity-one requires an exact qualified_closed result")
    _validate_qualification_state(qualification, receipt)
    qualification_request = json.loads(
        base64.b64decode(qualification["request_base64"], validate=True),
        object_pairs_hook=activation_package.reject_duplicates,
    )
    if (
        qualification_request.get("activation_package_digest") != request["activation_package_digest"]
        or qualification_request.get("fixture_digest") != request["scenario_sha256"]
        or qualification_request.get("controller_generation") != request["initial_controller_generation"]
        or qualification_request.get("runner_generation") != request["initial_runner_generation"]
    ):
        raise ValueError("capacity-one request differs from production qualification")
    return request, activation_package.digest(raw)


def _capacity_one_response(request: dict[str, Any], root: Path) -> dict[str, object]:
    return {
        "schema_version": CAPACITY_ONE_RESPONSE_SCHEMA,
        "action": request["action"],
        "activation_id": request["activation_id"],
        "activation_package_digest": request["activation_package_digest"],
        "scenario_sha256": request["scenario_sha256"],
        "operation_id": request["operation_id"],
        "state": "active_one",
        "receipt_sha256": _receipt_sha256(root),
    }


def _parse_zero_request(raw: bytes, cli_action: str, receipt: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if not raw or len(raw) > MAX_ZERO_REQUEST_BYTES:
        raise ValueError("qualification-zero request size is invalid")
    try:
        request = json.loads(raw, object_pairs_hook=activation_package.reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("qualification-zero request JSON is invalid") from error
    if not isinstance(request, dict) or raw != _wire_json(request):
        raise ValueError("qualification-zero request is not canonical compact JSON")
    present_optional = tuple(field for field in ZERO_OPTIONAL_FIELDS if field in request)
    if tuple(request) != ZERO_REQUIRED_FIELDS + present_optional:
        raise ValueError("qualification-zero request field order or shape differs")
    expected_action = ZERO_CLI_ACTIONS[cli_action]
    if request["schema_version"] != ZERO_REQUEST_SCHEMA or request["action"] != expected_action:
        raise ValueError("qualification-zero request action binding differs")
    if (
        request["activation_id"] != receipt["activation_id"]
        or request["activation_package_digest"] != receipt["package_digest"]
    ):
        raise ValueError("qualification-zero request belongs to a different activation")
    _scenario_hex(request["scenario_sha256"], {64}, "qualification-zero request scenario digest")
    _scenario_u64(request["initial_controller_generation"], "qualification-zero initial controller generation")
    _scenario_u64(request["initial_runner_generation"], "qualification-zero initial runner generation")
    _scenario_hex(request["operation_id"], {64}, "qualification-zero operation id")
    if "failed_stage" in request:
        value = request["failed_stage"]
        if not isinstance(value, str) or not 1 <= len(value) <= 64 or re.fullmatch(r"[A-Za-z0-9._-]+", value) is None:
            raise ValueError("qualification-zero failed stage is invalid")
    if "final_response_sha256" in request:
        _scenario_hex(request["final_response_sha256"], {64}, "qualification-zero final response digest")
    for field in ("expected_controller_generation", "expected_runner_generation"):
        if field in request:
            _scenario_u64(request[field], f"qualification-zero {field}")
    binding = _binding_from_receipt(receipt)
    fixture = binding.get("fixture")
    if (
        binding.get("activation_id") != request["activation_id"]
        or binding.get("activation_package_digest") != request["activation_package_digest"]
        or binding.get("scenario_sha256") != request["scenario_sha256"]
        or not isinstance(fixture, dict)
        or fixture.get("controller_generation") != request["initial_controller_generation"]
        or fixture.get("runner_generation") != request["initial_runner_generation"]
    ):
        raise ValueError("qualification-zero request differs from the acceptance binding")
    return request, activation_package.digest(raw)


def _qualification_zero_scope(request: dict[str, Any]) -> dict[str, object]:
    return {
        "schema": ZERO_SEQUENCE_SCHEMA,
        "activation_id": request["activation_id"],
        "activation_package_digest": request["activation_package_digest"],
        "scenario_sha256": request["scenario_sha256"],
        "initial_controller_generation": request["initial_controller_generation"],
        "initial_runner_generation": request["initial_runner_generation"],
    }


def _bind_zero_scope(state: dict[str, Any], request: dict[str, Any]) -> None:
    expected = _qualification_zero_scope(request)
    if any(state.get(field) != value for field, value in expected.items()):
        raise ValueError("qualification-zero request scope differs from the receipt")


def _receipt_sha256(root: Path) -> str:
    opened = _read_target(root, RECEIPT_PATH, activation_package.MAX_JSON_BYTES)
    if opened is None:
        raise ValueError("activation receipt is absent")
    raw, _metadata = opened
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("activation receipt is absent")
    return activation_package.digest(raw)


def _read_operator_evidence(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o022:
            raise ValueError(f"operator evidence file is unsafe: {path}")
        if os.geteuid() == 0 and metadata.st_uid != 0:
            raise ValueError(f"operator evidence file is not root-owned: {path}")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, min(1024 * 1024, activation_package.MAX_JSON_BYTES + 1 - total)):
            total += len(chunk)
            if total > activation_package.MAX_JSON_BYTES:
                raise ValueError(f"operator evidence file exceeds its byte limit: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _open_verified_program(
    root: Path, target: str, expected: dict[str, object], limit: int,
) -> int:
    parent_fd, name = activation_package.open_parent_fd(root, target)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        metadata = os.fstat(fd)
        expected_uid, expected_gid = _physical_ids(root, expected["uid"], expected["gid"])
        expected_mode = activation_package.parse_mode(expected["mode"])
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or metadata.st_uid != expected_uid or metadata.st_gid != expected_gid
        ):
            raise ValueError(f"program metadata drift: {target}")
        hasher = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, min(1024 * 1024, limit + 1 - total)):
            total += len(chunk)
            if total > limit:
                raise ValueError(f"program exceeds byte limit: {target}")
            hasher.update(chunk)
        if hasher.hexdigest() != expected["sha256"]:
            raise ValueError(f"program content drift: {target}")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _acceptance_authorization(
    manifest: dict[str, Any], root: Path, scenario_path: Path, acceptance_receipt_path: Path,
) -> dict[str, object]:
    scenario_raw = _read_operator_evidence(scenario_path)
    acceptance_raw = _read_operator_evidence(acceptance_receipt_path)
    try:
        scenario = json.loads(scenario_raw, object_pairs_hook=activation_package.reject_duplicates)
        acceptance = json.loads(acceptance_raw, object_pairs_hook=activation_package.reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("persistent activation evidence JSON is invalid") from error
    if not isinstance(scenario, dict) or not isinstance(acceptance, dict):
        raise ValueError("persistent activation evidence must contain JSON objects")
    binding = _acceptance_binding(manifest, scenario)
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("persistent activation requires an activation receipt")
    _bind_receipt(receipt, manifest)
    installed_binding = _binding_from_receipt(receipt)
    if binding != installed_binding:
        raise ValueError("persistent activation scenario differs from the installed acceptance binding")

    verifier_component = next(item for item in manifest["components"] if item["name"] == "receipt_verifier")
    verifier_fd = _open_verified_program(root, verifier_component["binary_path"], {
        "sha256": verifier_component["binary_sha256"], "mode": verifier_component["mode"],
        "uid": verifier_component["uid"], "gid": verifier_component["gid"],
    }, MAX_BINARY_BYTES)
    receipt_root = _require_receipt_root(root, manifest["identities"]["controld"]["gid"], allow_private=True)
    try:
        with tempfile.TemporaryDirectory(prefix="authorization-", dir=receipt_root) as temporary:
            temporary_root = Path(temporary)
            os.chmod(temporary_root, 0o700)
            frozen_scenario = temporary_root / "scenario.json"
            frozen_receipt = temporary_root / "acceptance-receipt.json"
            _atomic_write(temporary_root, "/scenario.json", scenario_raw, 0o600, 0, 0)
            _atomic_write(temporary_root, "/acceptance-receipt.json", acceptance_raw, 0o600, 0, 0)
            completed = subprocess.run(
                [f"/proc/self/fd/{verifier_fd}", str(frozen_scenario), str(frozen_receipt)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                cwd=str(receipt_root),
                timeout=60,
                check=False,
                pass_fds=(verifier_fd,),
                preexec_fn=_qualification_child_setup,
                start_new_session=True,
                umask=0o077,
            )
    finally:
        os.close(verifier_fd)
    expected_output = b'{"outcome":"pass","status":"verified"}\n'
    if completed.returncode != 0 or completed.stdout != expected_output or completed.stderr:
        raise ValueError("acceptance receipt verifier did not return its exact pass result")

    scenario_sha256 = installed_binding["scenario_sha256"]
    zero_transition = acceptance.get("zero_transition") if isinstance(acceptance, dict) else None
    phases = zero_transition.get("phases") if isinstance(zero_transition, dict) else None
    final_response = phases[-1].get("response") if isinstance(phases, list) and len(phases) == 2 and isinstance(phases[-1], dict) else None
    zero_receipt_sha256 = final_response.get("controller_receipt_sha256") if isinstance(final_response, dict) else None
    if (
        acceptance.get("outcome") != "pass"
        or acceptance.get("scenario_sha256") != scenario_sha256
        or acceptance.get("integrated_candidate_sha") != manifest["source_commit"]
        or not isinstance(zero_receipt_sha256, str)
    ):
        raise ValueError("acceptance receipt does not authorize this persistent activation")
    _scenario_hex(zero_receipt_sha256, {64}, "persistent activation final zero receipt digest")
    authorization_base = {
        "schema": PERSISTENT_AUTHORIZATION_SCHEMA,
        "activation_id": manifest["activation_id"],
        "activation_package_digest": manifest["package_digest"],
        "integrated_candidate_sha": manifest["source_commit"],
        "scenario_sha256": scenario_sha256,
        "acceptance_scenario_sha256": activation_package.digest(scenario_raw),
        "acceptance_receipt_sha256": activation_package.digest(acceptance_raw),
        "verifier_output_sha256": activation_package.digest(expected_output),
        "zero_receipt_sha256": zero_receipt_sha256,
    }
    operation_id = activation_package.digest(
        PERSISTENT_OPERATION_DOMAIN + activation_package.canonical_json(authorization_base),
    )
    authorization = {**authorization_base, "operation_id": operation_id}
    existing = receipt["persistent_authorization"]
    if existing is not None:
        if existing != authorization:
            raise ValueError("persistent activation authorization replay differs")
        return authorization
    if _receipt_sha256(root) != zero_receipt_sha256:
        raise ValueError("acceptance receipt is stale or does not bind the current finalized zero receipt")
    return authorization


def _persistent_capacity_one_request(authorization: dict[str, Any], receipt: dict[str, Any]) -> tuple[dict[str, Any], str]:
    binding = _binding_from_receipt(receipt)
    fixture = binding["fixture"]
    request = {
        "schema_version": CAPACITY_ONE_REQUEST_SCHEMA,
        "action": CAPACITY_ONE_WIRE_ACTION,
        "activation_id": authorization["activation_id"],
        "activation_package_digest": authorization["activation_package_digest"],
        "scenario_sha256": authorization["scenario_sha256"],
        "initial_controller_generation": fixture["controller_generation"],
        "initial_runner_generation": fixture["runner_generation"],
        "operation_id": authorization["operation_id"],
    }
    return _parse_capacity_one_request(_wire_json(request), receipt)


def _zero_response(request: dict[str, Any], root: Path) -> dict[str, object]:
    return {
        "schema_version": ZERO_RESPONSE_SCHEMA,
        "action": request["action"],
        "activation_id": request["activation_id"],
        "activation_package_digest": request["activation_package_digest"],
        "scenario_sha256": request["scenario_sha256"],
        "operation_id": request["operation_id"],
        "state": "staged_zero",
        "receipt_sha256": _receipt_sha256(root),
    }


def _process_snapshot(driver: LiveSystemd | FakeSystemd) -> dict[str, dict[str, object]]:
    return {unit: driver.process(unit) for unit in CAPACITY_ONE_PROCESS_UNITS}


def _validate_staged_processes(
    driver: LiveSystemd | FakeSystemd, processes: dict[str, dict[str, object]],
) -> None:
    for unit in CAPACITY_ONE_PROCESS_UNITS:
        active = driver.unit(unit)["ActiveState"] == "active"
        process = processes[unit]
        if unit == "buzz-ci-controld.service":
            if not active or not re.fullmatch(r"[0-9a-f]{32}", str(process["invocation_id"])) or process["main_pid"] <= 0:
                raise ValueError("staged controld process generation is absent")
        elif active or process != {"invocation_id": "", "main_pid": 0}:
            raise ValueError(f"stale staged process remains active: {unit}")


def _capacity_one_fragment_readback(driver: LiveSystemd | FakeSystemd) -> dict[str, str]:
    result: dict[str, str] = {}
    for unit, expected in CAPACITY_ONE_FRAGMENT_PATHS.items():
        observed = driver.fragment_path(unit)
        if observed != expected:
            raise ValueError(f"capacity-one systemd fragment differs: {unit}")
        result[unit] = observed
    return result


def _active_capacity_one_readback(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
    processes_before: dict[str, dict[str, object]],
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("capacity-one readback requires an activation receipt")
    _bind_receipt(receipt, manifest)
    managed = _verify_phase(manifest, root, "active")
    generated = _verify_generated(root, receipt["acceptance_generated"], phase="active")
    fixed_package = _verify_fixed_package(manifest, root)
    installed_units = _installed_unit_readback(manifest, root, driver)
    keyholder = _keyholder_config_readback(manifest, root)
    principals = _identity_readback(driver, manifest["identities"], allow_absent=False)
    access_group = _access_group_readback(driver, manifest["access_group"], allow_absent=False)
    required_units = tuple(dict.fromkeys((
        "buzz-ci-acceptance-control.socket", "buzz-ci-acceptance-control.service",
        *CAPACITY_ONE_START_ORDER,
    )))
    units = _unit_readback(driver, list(required_units))
    for unit, state in units.items():
        if state["LoadState"] != "loaded" or state["ActiveState"] != "active":
            raise ValueError(f"capacity-one unit is not active: {unit}")
    if units[activation_package.PERSISTENT_UNIT]["UnitFileState"] != "enabled":
        raise ValueError("capacity-one target enablement readback failed")
    fragments = _capacity_one_fragment_readback(driver)
    processes_after = _process_snapshot(driver)
    for unit, process in processes_after.items():
        if not re.fullmatch(r"[0-9a-f]{32}", str(process["invocation_id"])) or process["main_pid"] <= 0:
            raise ValueError(f"capacity-one process generation is absent: {unit}")
        before = processes_before[unit]
        if before["invocation_id"] and process["invocation_id"] == before["invocation_id"]:
            raise ValueError(f"capacity-one process generation is stale: {unit}")
    binding = _binding_from_receipt(receipt)
    qualification = receipt["qualification"]
    _validate_qualification_state(qualification, receipt)
    request = json.loads(
        base64.b64decode(qualification["request_base64"], validate=True),
        object_pairs_hook=activation_package.reject_duplicates,
    )
    fixture = binding["fixture"]
    expected_principal = _qualification_principal_digest(manifest)
    if (
        request["integrated_candidate_sha"] != manifest["source_commit"]
        or request["activation_package_digest"] != manifest["package_digest"]
        or request["fixture_digest"] != binding["scenario_sha256"]
        or request["principal_digest"] != expected_principal
        or request["controller_generation"] != fixture["controller_generation"]
        or request["runner_generation"] != fixture["runner_generation"]
    ):
        raise ValueError("capacity-one package, candidate, scenario, principal, or generation binding differs")
    return {
        "managed_targets": managed,
        "generated_targets": generated,
        "fixed_package": fixed_package,
        "installed_units": installed_units,
        "keyholder_config": keyholder,
        "principals": principals,
        "access_group": access_group,
        "units": units,
        "sockets": _socket_readback(manifest, driver),
        "fragments": fragments,
        "processes": processes_after,
        "binding": {
            "integrated_candidate_sha": request["integrated_candidate_sha"],
            "activation_package_digest": request["activation_package_digest"],
            "scenario_sha256": request["fixture_digest"],
            "principal_digest": request["principal_digest"],
            "controller_generation": request["controller_generation"],
            "runner_generation": request["runner_generation"],
            "capacity": 1,
            "admission": "open",
        },
    }


def _capacity_one_stop_errors(driver: LiveSystemd | FakeSystemd) -> list[str]:
    errors: list[str] = []
    try:
        driver.disable(activation_package.PERSISTENT_UNIT)
    except BaseException as error:
        errors.append(f"disable {activation_package.PERSISTENT_UNIT}: {error}")
    ordered = (
        "buzz-ci-controld-acceptance.socket", "buzz-ci-controld.service",
        activation_package.PERSISTENT_UNIT,
        "buzz-ci-runner.service", "buzz-ci-runner.socket",
        "buzz-ci-execd.service", "buzz-ci-execd.socket",
        "buzz-ci-executor.service", "buzz-ci-executor.socket",
        "buzz-ci-keyholder.service", "buzz-ci-keyholder.socket",
    )
    for unit in ordered:
        try:
            driver.stop(unit)
        except BaseException as error:
            errors.append(f"stop {unit}: {error}")
    return errors


def _apply_staged_configs(manifest: dict[str, Any], payloads: dict[str, bytes], root: Path) -> dict[str, str]:
    entries = {entry["role"]: entry for entry in manifest["entries"]}
    result: dict[str, str] = {}
    for role in ("runner_config", "controld_config"):
        entry = entries[role]
        _atomic_write(
            root, entry["target"], payloads[entry["source"]],
            activation_package.parse_mode(entry["install_mode"]), entry["uid"], entry["gid"],
        )
        observed = _entry_state(root, entry, _read_target(root, entry["target"]))
        if observed != "staged":
            raise ValueError(f"qualification-zero config readback failed: {role}")
        result[role] = observed
    return result


def _verify_zero_configs(manifest: dict[str, Any], root: Path) -> dict[str, str]:
    entries = {entry["role"]: entry for entry in manifest["entries"]}
    result: dict[str, str] = {}
    for role in ("runner_config", "controld_config"):
        observed = _entry_state(root, entries[role], _read_target(root, entries[role]["target"]))
        if observed != "staged":
            raise ValueError(f"qualification-zero config readback failed: {role}")
        result[role] = observed
    return result


def _prepare_zero_readback(manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd) -> None:
    _verify_phase(manifest, root, "staged")
    _verify_fixed_package(manifest, root)
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("activation receipt is absent")
    _bind_receipt(receipt, manifest)
    _verify_generated(root, receipt["acceptance_generated"])
    _effective_systemd_readback(manifest, root, driver, phase="installed")
    for unit in (
        "buzz-ci-controld-acceptance.socket", "buzz-ci-controld.service",
        "buzz-ci-acceptance-control.socket", "buzz-ci-acceptance-control.service",
    ):
        if driver.unit(unit)["ActiveState"] != "active":
            raise ValueError(f"qualification-zero prepare requires active unit: {unit}")
    _socket_readback(manifest, driver, names={"acceptance_control", "controld_acceptance"})


def _finalized_zero_readback(manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd) -> dict[str, object]:
    managed_targets = _verify_phase(manifest, root, "staged")
    _verify_fixed_package(manifest, root)
    units = _effective_systemd_readback(
        manifest, root, driver, phase="installed",
        names=set(activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT]),
    )
    keep = {"buzz-ci-acceptance-control.socket", "buzz-ci-acceptance-control.service"}
    for name, state in units.items():
        wanted = "active" if name in keep else "inactive"
        if state["ActiveState"] != wanted:
            raise ValueError(f"qualification-zero final readback found unit {name} {state['ActiveState']}, expected {wanted}")
    target = units[activation_package.PERSISTENT_UNIT]
    if target["LoadState"] != "not-found" and target["UnitFileState"] not in {"disabled", "static"}:
        raise ValueError("capacity-one target remains enabled after qualification zero")
    sockets = _socket_readback(manifest, driver, names={"acceptance_control"})
    driver.socket_absent(manifest["socket_policy"]["controld_acceptance"])
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("activation receipt is absent")
    _bind_receipt(receipt, manifest)
    generated: dict[str, str] = {}
    for record in receipt["acceptance_generated"]:
        if record["role"] == "controld_acceptance_binding":
            continue
        _verify_target_digest(root, record["target"], record, MAX_SCENARIO_BYTES)
        generated[record["role"]] = "exact"
    binding = _binding_prior_readback(receipt, root)
    return {
        "managed_targets": managed_targets, "units": units, "sockets": sockets,
        "acceptance_generated": generated, "controld_acceptance_path": "absent",
        "controld_acceptance_binding": binding,
    }


def _binding_record(receipt: dict[str, Any]) -> dict[str, Any]:
    return next(item for item in receipt["acceptance_generated"] if item["role"] == "controld_acceptance_binding")


def _restore_binding_prior(receipt: dict[str, Any], root: Path) -> None:
    record = _binding_record(receipt)
    prior = record["prior"]
    if prior["exists"]:
        payload = base64.b64decode(prior["payload_base64"], validate=True)
        _atomic_write(root, record["target"], payload, prior["mode"], prior["uid"], prior["gid"])
    elif _read_target(root, record["target"], MAX_SCENARIO_BYTES) is not None:
        _unlink_target(root, record["target"])


def _binding_prior_readback(receipt: dict[str, Any] | None, root: Path) -> str:
    if receipt is None:
        raise ValueError("activation receipt is absent")
    record = _binding_record(receipt)
    prior = record["prior"]
    opened = _read_target(root, record["target"], MAX_SCENARIO_BYTES)
    if not prior["exists"]:
        if opened is not None:
            raise ValueError("controld acceptance binding was not removed")
        return "absent"
    if opened is None:
        raise ValueError("prior controld acceptance binding is absent")
    payload, metadata = opened
    if activation_package.digest(payload) != prior["sha256"] or _metadata_dict(metadata) != {
        "mode": prior["mode"], "uid": prior["uid"], "gid": prior["gid"],
    }:
        raise ValueError("prior controld acceptance binding readback differs")
    return "restored"


def _prepare_qualification_zero_unlocked(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
    driver: LiveSystemd | FakeSystemd, request: dict[str, Any], request_sha256: str,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("qualification-zero prepare requires an activation receipt")
    _bind_receipt(receipt, manifest)
    _verify_fixed_package(manifest, root)
    operation = {"operation_id": request["operation_id"], "request_sha256": request_sha256}
    state = receipt["qualification_zero"]
    if state is None:
        if receipt["state"] != "active_one":
            raise ValueError("qualification-zero prepare requires active capacity one")
        state = {
            **_qualification_zero_scope(request), "phase": "preparing", "prepare": operation,
            "finalize": None, "last_error": None,
        }
        receipt.update({"state": "preparing_zero", "qualification_zero": state, "updated_at": utc_now(), "last_error": None})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    else:
        _bind_zero_scope(state, request)
        if state["prepare"] != operation:
            raise ValueError("qualification-zero prepare replay differs")
        if state["phase"] == "prepared":
            _prepare_zero_readback(manifest, root, driver)
            return _zero_response(request, root)
        if state["phase"] not in {"preparing", "prepare_failed"}:
            raise ValueError(f"qualification-zero prepare cannot resume from {state['phase']}")
    try:
        records = _validate_generated_records(receipt, root, apply=False)
        _apply_staged_configs(manifest, payloads, root)
        _apply_generated(root, records)
        _prepare_zero_readback(manifest, root, driver)
    except BaseException as error:
        state.update({"phase": "prepare_failed", "last_error": str(error)})
        receipt.update({"state": "rollback_failed", "updated_at": utc_now(), "last_error": str(error)})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        raise
    state.update({"phase": "prepared", "last_error": None})
    receipt.update({"state": "preparing_zero", "updated_at": utc_now(), "last_error": None})
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    return _zero_response(request, root)


def _prepare_qualification_zero(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
    driver: LiveSystemd | FakeSystemd, request: dict[str, Any], request_sha256: str,
) -> dict[str, object]:
    return _run_operator_locked(
        manifest, root,
        lambda: _prepare_qualification_zero_unlocked(
            manifest, payloads, root, driver, request, request_sha256,
        ),
    )


def _qualification_finalize_stop_errors(driver: LiveSystemd | FakeSystemd) -> list[str]:
    errors: list[str] = []
    keep = {"buzz-ci-acceptance-control.socket", "buzz-ci-acceptance-control.service"}
    ordered = ["buzz-ci-controld-acceptance.socket", "buzz-ci-controld.service"]
    ordered.extend(unit for unit in activation_package.STOP_ORDER if unit not in keep and unit not in ordered)
    for unit in ordered:
        try:
            driver.stop(unit)
        except BaseException as error:
            errors.append(f"stop {unit}: {error}")
    try:
        driver.disable(activation_package.PERSISTENT_UNIT)
    except BaseException as error:
        errors.append(f"disable {activation_package.PERSISTENT_UNIT}: {error}")
    try:
        driver.stop(activation_package.PERSISTENT_UNIT)
    except BaseException as error:
        errors.append(f"stop {activation_package.PERSISTENT_UNIT}: {error}")
    for unit in ("buzz-ci-acceptance-control.socket", "buzz-ci-acceptance-control.service"):
        try:
            driver.start(unit)
        except BaseException as error:
            errors.append(f"start {unit}: {error}")
    return errors


def _finalize_qualification_zero_unlocked(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path, driver: LiveSystemd | FakeSystemd,
    request: dict[str, Any], request_sha256: str,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("qualification-zero finalize requires an activation receipt")
    _bind_receipt(receipt, manifest)
    _verify_fixed_package(manifest, root)
    state = receipt["qualification_zero"]
    if not isinstance(state, dict):
        raise ValueError("qualification-zero finalize requires prepare")
    _bind_zero_scope(state, request)
    operation = {"operation_id": request["operation_id"], "request_sha256": request_sha256}
    if state["finalize"] is None:
        if state["phase"] not in {"prepared", "prepare_failed"}:
            raise ValueError(f"qualification-zero finalize cannot start from {state['phase']}")
        state.update({"phase": "finalizing", "finalize": operation, "last_error": None})
        receipt.update({"updated_at": utc_now(), "last_error": None})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    else:
        if state["finalize"] != operation:
            raise ValueError("qualification-zero finalize replay differs")
        if state["phase"] == "finalized":
            _finalized_zero_readback(manifest, root, driver)
            return _zero_response(request, root)
        if state["phase"] not in {"finalizing", "finalize_failed"}:
            raise ValueError(f"qualification-zero finalize cannot resume from {state['phase']}")
    errors = _qualification_finalize_stop_errors(driver)
    try:
        _apply_staged_configs(manifest, payloads, root)
        _apply_generated(root, receipt["acceptance_generated"], phase="staged")
    except BaseException as error:
        errors.append(f"restage capacity-zero configs: {error}")
    controld_stopped = True
    for unit in ("buzz-ci-controld-acceptance.socket", "buzz-ci-controld.service"):
        try:
            if driver.unit(unit)["ActiveState"] != "inactive":
                controld_stopped = False
                errors.append(f"refuse binding restoration while {unit} remains active")
        except BaseException as error:
            controld_stopped = False
            errors.append(f"read {unit} before binding restoration: {error}")
    if controld_stopped:
        try:
            _restore_binding_prior(receipt, root)
        except BaseException as error:
            errors.append(f"restore controld acceptance binding: {error}")
    try:
        _finalized_zero_readback(manifest, root, driver)
    except BaseException as error:
        errors.append(f"qualification-zero readback: {error}")
    if errors:
        combined = "qualification-zero finalize failures: " + "; ".join(errors)
        state.update({"phase": "finalize_failed", "last_error": combined})
        receipt.update({"state": "rollback_failed", "updated_at": utc_now(), "last_error": combined})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        raise ValueError(combined)
    state.update({"phase": "finalized", "last_error": None})
    receipt.update({"state": "staged_zero", "updated_at": utc_now(), "last_error": None})
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    _finalized_zero_readback(manifest, root, driver)
    return _zero_response(request, root)


def _finalize_qualification_zero(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
    driver: LiveSystemd | FakeSystemd, request: dict[str, Any], request_sha256: str,
) -> dict[str, object]:
    return _run_operator_locked(
        manifest, root,
        lambda: _finalize_qualification_zero_unlocked(
            manifest, payloads, root, driver, request, request_sha256,
        ),
    )


def _prove_qualification_zero(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd, request: dict[str, Any],
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("qualification-zero proof requires an activation receipt")
    _bind_receipt(receipt, manifest)
    state = receipt["qualification_zero"]
    if not isinstance(state, dict):
        raise ValueError("qualification-zero proof requires finalize")
    _bind_zero_scope(state, request)
    if receipt["state"] != "staged_zero" or state["phase"] != "finalized":
        raise ValueError("qualification-zero proof requires finalized staged zero")
    before = _receipt_sha256(root)
    _finalized_zero_readback(manifest, root, driver)
    after = _receipt_sha256(root)
    if after != before:
        raise ValueError("qualification-zero proof changed the activation receipt")
    return _zero_response(request, root)


def _compensate_failed_stage(
    receipt: dict[str, Any], manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> list[str]:
    errors: list[str] = []
    try:
        _install_recovery_targets(receipt, manifest, root)
    except BaseException as error:
        errors.append(f"install rollback recovery targets: {error}")
    errors.extend(_stop_zero_errors(driver))
    _restored, restore_errors = _restore_prior_best_effort(
        receipt, manifest, root, retain_roles=ROLLBACK_RECOVERY_ROLES,
    )
    errors.extend(restore_errors)
    _generated, generated_errors = _restore_generated_prior_best_effort(receipt, root)
    errors.extend(generated_errors)
    try:
        _restore_acceptance_ledger(receipt, manifest, root)
    except BaseException as error:
        errors.append(f"restore controld acceptance ledger: {error}")
    try:
        driver.daemon_reload()
    except BaseException as error:
        errors.append(f"daemon-reload: {error}")
    errors.extend(_restore_systemd_prior_errors(receipt, driver))
    for label, readback in (
        ("prior target readback", lambda: _prior_readback(
            receipt, manifest, root, retain_roles=ROLLBACK_RECOVERY_ROLES,
        )),
        ("acceptance prior readback", lambda: _generated_prior_readback(receipt, root)),
        ("acceptance ledger prior readback", lambda: _acceptance_ledger_prior_readback(receipt, root)),
        ("systemd prior readback", lambda: _systemd_prior_readback(receipt, manifest, root, driver)),
    ):
        try:
            readback()
        except BaseException as error:
            errors.append(f"{label}: {error}")
    return errors


def _retained_recovery_targets_readback(
    receipt: dict[str, Any], next_manifest: dict[str, Any], root: Path,
) -> dict[str, str]:
    marker = _read_rollback_cleanup(root)
    if marker is None:
        raise ValueError("rolled-back receipt lacks current rollback cleanup marker")
    prior_manifest = marker["manifest"]
    _bind_receipt(receipt, prior_manifest)
    prior_entries = {entry["role"]: entry for entry in prior_manifest["entries"]}
    next_entries = {entry["role"]: entry for entry in next_manifest["entries"]}
    result: dict[str, str] = {}
    for role in ROLLBACK_RECOVERY_ROLES:
        entry = prior_entries[role]
        try:
            _verify_target_digest(root, entry["target"], {
                "sha256": entry["sha256"],
                "mode": entry["install_mode"],
                "uid": entry["uid"],
                "gid": entry["gid"],
            }, activation_package.MAX_ASSET_BYTES)
            result[role] = "prior"
        except ValueError:
            entry = next_entries[role]
            _verify_target_digest(root, entry["target"], {
                "sha256": entry["sha256"],
                "mode": entry["install_mode"],
                "uid": entry["uid"],
                "gid": entry["gid"],
            }, activation_package.MAX_ASSET_BYTES)
            result[role] = "next"
    return result


def _stage_unlocked(
    manifest: dict[str, Any],
    payloads: dict[str, bytes],
    root: Path,
    driver: LiveSystemd | FakeSystemd,
    binding: dict[str, object],
) -> dict[str, object]:
    generated = _generated_acceptance_files(manifest, payloads, binding)
    existing = _read_receipt(root)
    rolled_back_receipt: dict[str, Any] | None = None
    if existing is not None:
        if existing.get("state") == "rolled_back":
            rolled_back_receipt = existing
            _retained_recovery_targets_readback(existing, manifest, root)
            prior_scope = _qualification_replay_scope(existing.get("qualification"), existing)
            if prior_scope is not None and prior_scope == _generated_qualification_replay_scope(manifest, generated):
                raise ValueError(
                    "unresolved qualification delivery forbids request rotation under the same package, fixture, and generations"
                )
        else:
            _bind_receipt(existing, manifest)
            if existing["state"] == "staged_zero":
                _bind_generated_plan(existing["acceptance_generated"], generated)
                if existing["qualification_zero"] is not None:
                    raise ValueError("finalized qualification zero requires rollback before staging")
                try:
                    managed_targets = _verify_phase(manifest, root, "staged")
                    principals = _identity_readback(driver, manifest["identities"], allow_absent=False)
                    access_group = _access_group_readback(driver, manifest["access_group"], allow_absent=False)
                    generated_readback = _verify_generated(root, existing["acceptance_generated"])
                    fixed_package = _verify_fixed_package(manifest, root)
                    installed_units = _installed_unit_readback(manifest, root, driver)
                    _staged_zero_convergence_readback(manifest, root, driver)
                    for unit in activation_package.STAGED_ZERO_UNITS:
                        driver.start(unit)
                    staged_zero = _staged_zero_readback(manifest, root, driver)
                    result = {
                        "status": "unchanged",
                        "state": "staged_zero",
                        "capacity": 0,
                        "managed_targets": managed_targets,
                        "principals": principals,
                        "access_group": access_group,
                        "acceptance_generated": generated_readback,
                        "fixed_package": fixed_package,
                        "installed_units": installed_units,
                        "staged_zero": staged_zero,
                    }
                except BaseException as error:
                    compensation_errors = _compensate_failed_stage(existing, manifest, root, driver)
                    last_error = str(error)
                    state = "stage_failed"
                    if compensation_errors:
                        last_error = f"stage={error}; compensation=" + "; ".join(compensation_errors)
                        state = "rollback_failed"
                    existing.update({"state": state, "updated_at": utc_now(), "last_error": last_error})
                    _write_receipt(root, existing, manifest["identities"]["controld"]["gid"])
                    if compensation_errors:
                        raise ValueError(last_error) from error
                    raise
                _complete_rollback_retirement(manifest, root)
                return result
            raise ValueError(f"activation receipt requires rollback from {existing['state']}")
    report = preflight(
        manifest, root, driver, require_dormant=True, payloads=payloads,
        allow_recovery_upgrade=rolled_back_receipt is not None,
    )
    fixed_package = _install_fixed_package(manifest, payloads, root)
    _verify_fixed_package(manifest, root)
    _stage_restart_boundary("fixed_package:readback")
    receipt = _new_receipt(manifest, root, driver, generated)
    _install_recovery_targets(receipt, manifest, root)
    if rolled_back_receipt is not None:
        _prepare_rollback_retirement(rolled_back_receipt, manifest, root)
        _stage_restart_boundary("rollback_retirement:readback")
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    _stage_restart_boundary("preparing_receipt:readback")
    try:
        _apply_phase(manifest, payloads, root, "staged")
        driver.provision(manifest["identities"])
        driver.tmpfiles()
        _apply_generated(root, receipt["acceptance_generated"])
        driver.daemon_reload()
        installed_units = _installed_unit_readback(manifest, root, driver)
        _stop_to_zero(driver)
        _zero_readback(manifest, root, driver)
        _remove_captured_ledger(root, receipt["acceptance_ledger_prior"])
        principals = _identity_readback(driver, manifest["identities"], allow_absent=False)
        access_group = _access_group_readback(driver, manifest["access_group"], allow_absent=False)
        targets = _verify_phase(manifest, root, "staged")
        generated_readback = _verify_generated(root, receipt["acceptance_generated"])
        receipt.update({"state": "staged_zero", "updated_at": utc_now(), "last_error": None})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        for unit in activation_package.STAGED_ZERO_UNITS:
            driver.start(unit)
        staged_zero = _staged_zero_readback(manifest, root, driver)
        result = {
            "status": "staged",
            "state": "staged_zero",
            "capacity": 0,
            "activation_id": manifest["activation_id"],
            "preflight": report,
            "principals": principals,
            "access_group": access_group,
            "managed_targets": targets,
            "acceptance_generated": generated_readback,
            "fixed_package": fixed_package,
            "installed_units": installed_units,
            "staged_zero": staged_zero,
        }
    except BaseException as error:
        compensation_errors = _compensate_failed_stage(receipt, manifest, root, driver)
        last_error = str(error)
        state = "stage_failed"
        if compensation_errors:
            last_error = f"stage={error}; compensation=" + "; ".join(compensation_errors)
            state = "rollback_failed"
        receipt.update({"state": state, "updated_at": utc_now(), "last_error": last_error})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        if compensation_errors:
            raise ValueError(last_error) from error
        raise
    _complete_rollback_retirement(manifest, root)
    return result


def stage(
    manifest: dict[str, Any],
    payloads: dict[str, bytes],
    root: Path,
    driver: LiveSystemd | FakeSystemd,
    binding: dict[str, object],
) -> dict[str, object]:
    return _run_operator_locked(
        manifest, root,
        lambda: _stage_unlocked(manifest, payloads, root, driver, binding),
    )


def _socket_readback(
    manifest: dict[str, Any], driver: LiveSystemd | FakeSystemd, *, names: set[str] | None = None,
) -> dict[str, object]:
    identities = manifest["identities"]
    result: dict[str, object] = {}
    for name, policy in manifest["socket_policy"].items():
        if names is not None and name not in names:
            continue
        observed = driver.socket(policy)
        expected_uid = 0
        if policy["user"] != "root":
            identity = next((item for item in identities.values() if item["user"] == policy["user"]), None)
            if identity is None:
                raise ValueError(f"socket user is not in the fixed plan: {policy['user']}")
            expected_uid = identity["uid"]
        if policy["group"] == "root":
            expected_gid = 0
        elif policy["group"] == activation_package.ACCESS_GROUP_NAME:
            expected_gid = manifest["access_group"]["gid"]
        else:
            identity = next((item for item in identities.values() if item["group"] == policy["group"]), None)
            if identity is None:
                raise ValueError(f"socket group is not in the fixed plan: {policy['group']}")
            expected_gid = identity["gid"]
        expected = {"path": policy["path"], "mode": policy["mode"], "uid": expected_uid, "gid": expected_gid}
        if observed != expected:
            raise ValueError(f"socket permission readback differs: {policy['path']}")
        result[name] = observed
    return result


def _active_health(manifest: dict[str, Any], driver: LiveSystemd | FakeSystemd, *, require_enabled: bool) -> dict[str, object]:
    names = activation_package.START_ORDER + [activation_package.PERSISTENT_UNIT]
    units = _unit_readback(driver, names)
    for name, state in units.items():
        if state["LoadState"] != "loaded" or state["ActiveState"] != "active":
            raise ValueError(f"activation health failed for unit: {name}")
    if require_enabled and units[activation_package.PERSISTENT_UNIT]["UnitFileState"] != "enabled":
        raise ValueError("capacity-one target enablement readback failed")
    return {"units": units, "sockets": _socket_readback(manifest, driver)}


def _limit_output() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_COMMAND_OUTPUT, MAX_COMMAND_OUTPUT))


def _qualification_child_setup() -> None:
    _limit_output()
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = getattr(libc, "prctl", None)
    if prctl is None:
        return
    if prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _terminate_process_group(process: subprocess.Popen[bytes], grace_seconds: int) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=grace_seconds)


def _qualification_credentials(manifest: dict[str, Any], root: Path) -> dict[str, object]:
    if root != Path("/"):
        return {}
    qualification = manifest["qualification"]
    principal = manifest["identities"][qualification["principal"]]
    return {
        "user": principal["uid"],
        "group": principal["gid"],
        "extra_groups": [manifest["access_group"]["gid"]],
    }


def _length_prefixed(value: str) -> bytes:
    encoded = value.encode("ascii")
    if not encoded or len(encoded) > 0xFFFF:
        raise ValueError("qualification digest string is outside its fixed bound")
    return len(encoded).to_bytes(2, "big") + encoded


def _qualification_principal_digest(manifest: dict[str, Any]) -> str:
    principal = manifest["identities"][manifest["qualification"]["principal"]]
    groups = principal["supplementary_groups"]
    hasher = hashlib.sha256(QUALIFICATION_PRINCIPAL_DOMAIN)
    hasher.update(_length_prefixed(principal["user"]))
    hasher.update(_length_prefixed(principal["group"]))
    hasher.update(principal["uid"].to_bytes(4, "big"))
    hasher.update(principal["gid"].to_bytes(4, "big"))
    hasher.update(_length_prefixed(principal["home"]))
    hasher.update(_length_prefixed(principal["shell"]))
    hasher.update(len(groups).to_bytes(2, "big"))
    for group in groups:
        hasher.update(_length_prefixed(group))
    return hasher.hexdigest()


def _executor_provenance_digest(executor: dict[str, Any]) -> str:
    source_commit = executor["source_commit"]
    encoded_source = bytes([20 if len(source_commit) == 40 else 32]) + bytes.fromhex(source_commit)
    hasher = hashlib.sha256(QUALIFICATION_EXECUTOR_DOMAIN)
    hasher.update(_length_prefixed(executor["path"]))
    hasher.update(bytes.fromhex(executor["sha256"]))
    hasher.update(encoded_source)
    hasher.update(executor["uid"].to_bytes(4, "big"))
    hasher.update(executor["gid"].to_bytes(4, "big"))
    hasher.update(executor["mode"].to_bytes(4, "big"))
    return hasher.hexdigest()


def _wire_qualification_json(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def _new_qualification_request(manifest: dict[str, Any], receipt: dict[str, Any]) -> bytes:
    record = next(item for item in receipt["acceptance_generated"] if item["role"] == "execd_config")
    config = json.loads(base64.b64decode(record["payload_base64"], validate=True), object_pairs_hook=activation_package.reject_duplicates)
    lane = config["lane_manifest"]
    executor = config["executor"]
    qualification = config["qualification"]
    issued_at = int(time.time())
    if issued_at <= 0:
        raise ValueError("qualification clock is invalid")
    request_id = os.urandom(16)
    nonce = os.urandom(32)
    if not any(request_id) or not any(nonce):
        raise ValueError("qualification randomness is zero")
    request: dict[str, object] = {
        "schema_version": QUALIFICATION_REQUEST_SCHEMA,
        "request_id": request_id.hex(),
        "integrated_candidate_sha": qualification["integrated_candidate_sha"],
        "activation_package_digest": qualification["activation_package_digest"],
        "fixture_digest": qualification["fixture_digest"],
        "principal_digest": _qualification_principal_digest(manifest),
        "lane_manifest_digest": config["lane_manifest_digest"],
        "broker_build_identity_digest": lane["broker_build_identity"],
        "host_profile_digest": lane["host_profile_digest"],
        "suite_digest": lane["suite_identity"],
        "isolation_profile_digest": lane["isolation_profile_digest"],
        "seccomp_profile_digest": activation_package.SECCOMP_PROFILE_DIGEST,
        "executor_program_digest": executor["sha256"],
        "executor_provenance_digest": _executor_provenance_digest(executor),
        "nonce": nonce.hex(),
        "controller_generation": qualification["controller_generation"],
        "runner_generation": qualification["runner_generation"],
        "lane_epoch": lane["lane_epoch"],
        "admission_key_generation": lane["admission_key_generation"],
        "issued_at": issued_at,
        "expires_at": issued_at + manifest["qualification"]["request_validity_seconds"],
    }
    return _wire_qualification_json(request)


def _qualification_request(manifest: dict[str, Any], receipt: dict[str, Any], root: Path) -> bytes:
    state = receipt["qualification"]
    if state is None:
        request = _new_qualification_request(manifest, receipt)
        receipt["qualification"] = {
            "schema": QUALIFICATION_STATE_SCHEMA,
            "status": "pending",
            "request_sha256": activation_package.digest(request),
            "request_base64": base64.b64encode(request).decode("ascii"),
            "response_sha256": None,
            "response_base64": None,
            "completed_at": None,
            "attempt_count": 0,
            "last_error": None,
            "expired_at": None,
        }
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        return request
    _validate_qualification_state(state, receipt)
    request = base64.b64decode(state["request_base64"], validate=True)
    if activation_package.digest(request) != state["request_sha256"]:
        raise ValueError("persisted qualification request digest differs")
    if state["status"] == "expired_uncertain":
        raise ValueError("qualification delivery outcome is unresolved after request expiry; rollback and restage with a new replay binding")
    if state["status"] == "pending":
        parsed = json.loads(request, object_pairs_hook=activation_package.reject_duplicates)
        if int(time.time()) >= parsed["expires_at"]:
            message = "qualification delivery outcome remained unresolved when the exact request expired"
            state.update({"status": "expired_uncertain", "expired_at": utc_now()})
            if state["last_error"] is None:
                state["last_error"] = message
            _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
            raise ValueError(message + "; rollback and restage with a new replay binding")
    return request


def _record_qualification_failure(
    manifest: dict[str, Any], root: Path, receipt: dict[str, Any], error: BaseException,
) -> None:
    state = receipt["qualification"]
    if not isinstance(state, dict) or state.get("status") != "pending":
        return
    request = json.loads(
        base64.b64decode(state["request_base64"], validate=True),
        object_pairs_hook=activation_package.reject_duplicates,
    )
    state["last_error"] = str(error)
    if int(time.time()) >= request["expires_at"]:
        state.update({"status": "expired_uncertain", "expired_at": utc_now()})
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])


def _qualification_requires_restage(value: object) -> bool:
    return isinstance(value, dict) and (
        value.get("status") == "expired_uncertain"
        or value.get("status") == "pending" and value.get("attempt_count") == QUALIFICATION_MAX_ATTEMPTS
    )


def _qualification_replay_scope(value: object, receipt: dict[str, Any]) -> tuple[object, ...] | None:
    if not isinstance(value, dict) or value.get("status") == "passed":
        return None
    _validate_qualification_state(value, receipt)
    request = json.loads(
        base64.b64decode(value["request_base64"], validate=True),
        object_pairs_hook=activation_package.reject_duplicates,
    )
    return tuple(request[field] for field in (
        "activation_package_digest", "fixture_digest", "controller_generation", "runner_generation",
    ))


def _generated_qualification_replay_scope(
    manifest: dict[str, Any], generated: list[dict[str, object]],
) -> tuple[object, ...]:
    record = next(item for item in generated if item["role"] == "execd_config")
    config = json.loads(record["payload"], object_pairs_hook=activation_package.reject_duplicates)
    qualification = config["qualification"]
    return (
        manifest["package_digest"], qualification["fixture_digest"],
        qualification["controller_generation"], qualification["runner_generation"],
    )


def _validate_qualification_response(request_raw: bytes, response: bytes) -> dict[str, Any]:
    try:
        request = json.loads(request_raw, object_pairs_hook=activation_package.reject_duplicates)
        value = json.loads(response, object_pairs_hook=activation_package.reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("qualification response is not valid closed JSON") from error
    expected_order = [
        "schema_version", "status", "disposition", "request_id", "request_frame_digest",
        "qualification_receipt_digest", "integrated_candidate_sha", "activation_package_digest",
        "fixture_digest", "principal_digest", "lane_manifest_digest", "broker_build_identity_digest",
        "host_profile_digest", "suite_digest", "isolation_profile_digest", "seccomp_profile_digest",
        "seccomp_install_receipt_digest", "executor_program_digest", "executor_provenance_digest",
        "controller_generation", "runner_generation", "lane_epoch", "admission_key_generation",
        "qualified_at", "request_expires_at",
    ]
    if not isinstance(value, dict) or list(value) != expected_order or response != _wire_qualification_json(value):
        raise ValueError("qualification response shape or canonical bytes differ")
    if value["schema_version"] != QUALIFICATION_RESPONSE_SCHEMA or value["status"] != "qualified_closed" or value["disposition"] not in {"created", "existing"}:
        raise ValueError("qualification response did not prove closed production-v2 qualification")
    echoed = [
        "request_id", "integrated_candidate_sha", "activation_package_digest", "fixture_digest",
        "principal_digest", "lane_manifest_digest", "broker_build_identity_digest", "host_profile_digest",
        "suite_digest", "isolation_profile_digest", "seccomp_profile_digest", "executor_program_digest",
        "executor_provenance_digest", "controller_generation", "runner_generation", "lane_epoch",
        "admission_key_generation",
    ]
    if any(value[field] != request[field] for field in echoed) or value["request_expires_at"] != request["expires_at"]:
        raise ValueError("qualification response binding differs from the exact request")
    for field in ("request_frame_digest", "qualification_receipt_digest", "seccomp_install_receipt_digest"):
        _scenario_hex(value[field], {64}, f"qualification {field}")
    qualified_at = value["qualified_at"]
    if isinstance(qualified_at, bool) or not isinstance(qualified_at, int) or not request["issued_at"] <= qualified_at <= request["expires_at"]:
        raise ValueError("qualification response timestamp differs")
    return value


def _run_qualification(manifest: dict[str, Any], root: Path, receipt: dict[str, Any]) -> dict[str, object]:
    qualification = manifest["qualification"]
    component = next(item for item in manifest["components"] if item["name"] == "qualification")
    parent_fd, name = activation_package.open_parent_fd(root, qualification["program"])
    program_fd = -1
    try:
        program_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    metadata = os.fstat(program_fd)
    expected_uid, expected_gid = _physical_ids(root, component["uid"], component["gid"])
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != activation_package.parse_mode(component["mode"])
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
    ):
        os.close(program_fd)
        raise ValueError("qualification executable metadata differs")
    binary_hasher = hashlib.sha256()
    binary_size = 0
    while chunk := os.read(program_fd, min(1024 * 1024, MAX_BINARY_BYTES + 1 - binary_size)):
        binary_size += len(chunk)
        if binary_size > MAX_BINARY_BYTES:
            os.close(program_fd)
            raise ValueError("qualification executable exceeds its byte limit")
        binary_hasher.update(chunk)
    if binary_hasher.hexdigest() != component["binary_sha256"]:
        os.close(program_fd)
        raise ValueError("qualification executable digest differs")
    os.lseek(program_fd, 0, os.SEEK_SET)
    request = _qualification_request(manifest, receipt, root)
    state = receipt["qualification"]
    if state["status"] == "passed":
        os.close(program_fd)
        response = base64.b64decode(state["response_base64"], validate=True)
        parsed = _validate_qualification_response(request, response)
        return {"controller_status": "passed", **parsed, "request_sha256": state["request_sha256"], "response_sha256": state["response_sha256"]}
    if state["attempt_count"] >= QUALIFICATION_MAX_ATTEMPTS:
        message = "qualification exact-request retry budget is exhausted with an unresolved delivery outcome"
        state["last_error"] = message
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        os.close(program_fd)
        raise ValueError(message + "; rollback and restage with a new replay binding")
    state["attempt_count"] += 1
    state["last_error"] = None
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    credential_options = _qualification_credentials(manifest, root)
    try:
        try:
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                process = subprocess.Popen(
                    [f"/proc/self/fd/{program_fd}"],
                    stdin=subprocess.PIPE,
                    stdout=stdout,
                    stderr=stderr,
                    cwd=str(root),
                    env={},
                    preexec_fn=_qualification_child_setup,
                    pass_fds=(program_fd,),
                    start_new_session=True,
                    umask=0o077,
                    **credential_options,
                )
                try:
                    process.communicate(input=request, timeout=qualification["timeout_seconds"])
                except subprocess.TimeoutExpired as error:
                    _terminate_process_group(process, qualification["terminate_grace_seconds"])
                    raise ValueError("qualification command timed out") from error
                stdout.seek(0)
                response = stdout.read(MAX_COMMAND_OUTPUT + 1)
                stderr.seek(0)
                error_output = stderr.read(MAX_COMMAND_OUTPUT + 1)
            if len(response) > MAX_COMMAND_OUTPUT or len(error_output) > MAX_COMMAND_OUTPUT:
                raise ValueError("qualification output exceeded its fixed bound")
            if process.returncode != 0:
                raise ValueError(f"qualification command failed with status {process.returncode}")
            if error_output:
                raise ValueError("qualification command wrote stderr on success")
            response_digest = activation_package.digest(response)
            parsed = _validate_qualification_response(request, response)
        except BaseException as error:
            _record_qualification_failure(manifest, root, receipt, error)
            raise
    finally:
        os.close(program_fd)
    state = receipt["qualification"]
    state.update({
        "status": "passed", "response_sha256": response_digest,
        "response_base64": base64.b64encode(response).decode("ascii"), "completed_at": utc_now(),
        "last_error": None, "expired_at": None,
    })
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    return {"status": "passed", **parsed, "request_sha256": state["request_sha256"], "response_sha256": response_digest}


def _return_to_staged_zero(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path, driver: LiveSystemd | FakeSystemd,
    generated: list[dict[str, object]], *, keep_acceptance_control: bool = False,
) -> dict[str, object]:
    errors = _capacity_one_stop_errors(driver) if keep_acceptance_control else _stop_zero_errors(driver)
    for entry in manifest["entries"]:
        if entry["role"] == "execd_config":
            continue
        try:
            _atomic_write(
                root,
                entry["target"],
                payloads[entry["source"]],
                activation_package.parse_mode(entry["install_mode"]),
                entry["uid"],
                entry["gid"],
            )
        except BaseException as error:
            errors.append(f"restage {entry['role']}: {error}")
    try:
        _apply_generated(root, generated, phase="staged")
    except BaseException as error:
        errors.append(f"restage generated configuration: {error}")
    try:
        driver.daemon_reload()
    except BaseException as error:
        errors.append(f"daemon-reload: {error}")
    for unit in activation_package.STAGED_ZERO_UNITS:
        try:
            driver.start(unit)
        except BaseException as error:
            errors.append(f"start {unit}: {error}")
    targets: dict[str, str] | None = None
    staged_zero: dict[str, object] | None = None
    try:
        targets = _verify_phase(manifest, root, "staged")
    except BaseException as error:
        errors.append(f"staged readback: {error}")
    try:
        _verify_generated(root, generated)
    except BaseException as error:
        errors.append(f"acceptance generated readback: {error}")
    try:
        staged_zero = _staged_zero_readback(manifest, root, driver)
    except BaseException as error:
        errors.append(f"capacity-zero readback: {error}")
    if errors:
        raise ValueError("return-to-zero failures: " + "; ".join(errors))
    return {"managed_targets": targets, "staged_zero": staged_zero}


def _set_capacity_one_unlocked(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
    driver: LiveSystemd | FakeSystemd, request: dict[str, Any], request_sha256: str,
    *, state_field: str = "capacity_one",
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("capacity-one action requires an activation receipt")
    _bind_receipt(receipt, manifest)
    _verify_fixed_package(manifest, root)
    if state_field not in {"capacity_one", "persistent_activation"}:
        raise ValueError("capacity-one state field is invalid")
    existing = receipt[state_field]
    expected_binding = {
        "activation_id": request["activation_id"],
        "activation_package_digest": request["activation_package_digest"],
        "scenario_sha256": request["scenario_sha256"],
        "initial_controller_generation": request["initial_controller_generation"],
        "initial_runner_generation": request["initial_runner_generation"],
        "operation_id": request["operation_id"],
        "request_sha256": request_sha256,
    }
    if existing is not None:
        if any(existing.get(field) != value for field, value in expected_binding.items()):
            raise ValueError("capacity-one exact replay differs")
        if receipt["state"] == "active_one" and existing["phase"] == "active_one":
            _active_capacity_one_readback(manifest, root, driver, existing["processes_before"])
            return _capacity_one_response(request, root)
        if receipt["state"] != "qualified_closed" or existing["phase"] != "compensated":
            raise ValueError(f"capacity-one action cannot resume from {receipt['state']}/{existing['phase']}")
        if existing["attempt_count"] >= MAX_CAPACITY_ONE_ATTEMPTS:
            raise ValueError("capacity-one exact replay budget is exhausted")
        state = existing
    else:
        if receipt["state"] != "qualified_closed":
            raise ValueError("capacity-one action requires qualified_closed capacity zero")
        state = {
            "schema": CAPACITY_ONE_SEQUENCE_SCHEMA,
            **expected_binding,
            "phase": "activating",
            "attempt_count": 0,
            "processes_before": None,
            "processes_after": None,
            "last_error": None,
        }
        receipt[state_field] = state
    _verify_phase(manifest, root, "staged")
    _verify_generated(root, receipt["acceptance_generated"], phase="staged")
    _keyholder_config_readback(manifest, root, payloads)
    _staged_zero_readback(manifest, root, driver)
    processes_before = _process_snapshot(driver)
    _validate_staged_processes(driver, processes_before)
    state.update({
        "phase": "activating",
        "attempt_count": state["attempt_count"] + 1,
        "processes_before": processes_before,
        "processes_after": None,
        "last_error": None,
    })
    receipt.update({"state": "activating", "updated_at": utc_now(), "last_error": None})
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    try:
        stop_errors = _capacity_one_stop_errors(driver)
        if stop_errors:
            raise ValueError("capacity-one quiesce failures: " + "; ".join(stop_errors))
        _apply_phase(manifest, payloads, root, "active")
        _apply_generated(root, receipt["acceptance_generated"], phase="active")
        _verify_phase(manifest, root, "active")
        _verify_generated(root, receipt["acceptance_generated"], phase="active")
        driver.daemon_reload()
        _installed_unit_readback(manifest, root, driver)
        _capacity_one_fragment_readback(driver)
        for unit in CAPACITY_ONE_START_ORDER:
            driver.start(unit)
        driver.enable(activation_package.PERSISTENT_UNIT)
        active = _active_capacity_one_readback(manifest, root, driver, state["processes_before"])
        state.update({"phase": "active_one", "processes_after": active["processes"], "last_error": None})
        receipt.update({"state": "active_one", "updated_at": utc_now(), "last_error": None})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        _active_capacity_one_readback(manifest, root, driver, state["processes_before"])
        return _capacity_one_response(request, root)
    except BaseException as error:
        compensation_error: str | None = None
        try:
            _return_to_staged_zero(
                manifest, payloads, root, driver, receipt["acceptance_generated"],
                keep_acceptance_control=True,
            )
        except BaseException as nested:
            compensation_error = str(nested)
        state.update({
            "phase": "compensated" if compensation_error is None else "failed",
            "processes_after": None,
            "last_error": str(error) if compensation_error is None else f"activation={error}; compensation={compensation_error}",
        })
        receipt.update({
            "state": "qualified_closed" if compensation_error is None else "rollback_failed",
            "updated_at": utc_now(),
            "last_error": state["last_error"],
        })
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        if compensation_error is not None:
            raise ValueError(state["last_error"]) from error
        raise


def _set_capacity_one(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
    driver: LiveSystemd | FakeSystemd, request: dict[str, Any], request_sha256: str,
    *, state_field: str = "capacity_one",
) -> dict[str, object]:
    return _run_operator_locked(
        manifest, root,
        lambda: _set_capacity_one_unlocked(
            manifest, payloads, root, driver, request, request_sha256,
            state_field=state_field,
        ),
    )


def _restore_finalized_zero_after_persistent_prepare(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
    driver: LiveSystemd | FakeSystemd, receipt: dict[str, Any],
) -> list[str]:
    errors = _qualification_finalize_stop_errors(driver)
    try:
        _apply_staged_configs(manifest, payloads, root)
        _apply_generated(root, receipt["acceptance_generated"], phase="staged")
    except BaseException as error:
        errors.append(f"restage persistent preparation: {error}")
    stopped = True
    for unit in ("buzz-ci-controld-acceptance.socket", "buzz-ci-controld.service"):
        try:
            if driver.unit(unit)["ActiveState"] != "inactive":
                stopped = False
                errors.append(f"refuse binding restoration while {unit} remains active")
        except BaseException as error:
            stopped = False
            errors.append(f"read {unit} before binding restoration: {error}")
    if stopped:
        try:
            _restore_binding_prior(receipt, root)
        except BaseException as error:
            errors.append(f"restore controld acceptance binding: {error}")
    try:
        _finalized_zero_readback(manifest, root, driver)
    except BaseException as error:
        errors.append(f"finalized-zero recovery readback: {error}")
    return errors


def _persist_capacity_one_locked(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
    driver: LiveSystemd | FakeSystemd, scenario_path: Path, acceptance_receipt_path: Path,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("persistent activation requires an activation receipt")
    _bind_receipt(receipt, manifest)
    _verify_fixed_package(manifest, root)
    authorization = _acceptance_authorization(manifest, root, scenario_path, acceptance_receipt_path)
    if receipt["persistent_authorization"] is None:
        zero = receipt["qualification_zero"]
        if receipt["state"] != "staged_zero" or not isinstance(zero, dict) or zero["phase"] != "finalized":
            raise ValueError("persistent activation requires a verified canary returned to finalized capacity zero")
        already_prepared = False
        try:
            _finalized_zero_readback(manifest, root, driver)
        except ValueError as finalized_error:
            try:
                _verify_phase(manifest, root, "staged")
                _verify_generated(root, receipt["acceptance_generated"], phase="staged")
                _staged_zero_readback(manifest, root, driver)
                already_prepared = True
            except ValueError:
                raise finalized_error
        if not already_prepared:
            try:
                _return_to_staged_zero(
                    manifest, payloads, root, driver, receipt["acceptance_generated"],
                    keep_acceptance_control=True,
                )
            except BaseException as error:
                recovery_errors = _restore_finalized_zero_after_persistent_prepare(
                    manifest, payloads, root, driver, receipt,
                )
                if recovery_errors:
                    combined = f"persistent preparation={error}; recovery=" + "; ".join(recovery_errors)
                    receipt.update({"state": "rollback_failed", "updated_at": utc_now(), "last_error": combined})
                    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
                    raise ValueError(combined) from error
                raise
        receipt = _read_receipt(root)
        if receipt is None:
            raise ValueError("activation receipt disappeared during persistent preparation")
        _bind_receipt(receipt, manifest)
        receipt.update({
            "state": "qualified_closed", "persistent_authorization": authorization,
            "updated_at": utc_now(), "last_error": None,
        })
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    elif receipt["persistent_authorization"] != authorization:
        raise ValueError("persistent activation authorization replay differs")

    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("activation receipt disappeared before persistent cutover")
    _bind_receipt(receipt, manifest)
    request, request_sha256 = _persistent_capacity_one_request(authorization, receipt)
    response = _set_capacity_one_unlocked(
        manifest, payloads, root, driver, request, request_sha256,
        state_field="persistent_activation",
    )
    final_receipt = _read_receipt(root)
    if final_receipt is None:
        raise ValueError("activation receipt disappeared after persistent cutover")
    _bind_receipt(final_receipt, manifest)
    state = final_receipt["persistent_activation"]
    if not isinstance(state, dict) or state["phase"] != "active_one":
        raise ValueError("persistent activation did not reach its terminal state")
    readback = _active_capacity_one_readback(manifest, root, driver, state["processes_before"])
    return {
        "status": "persistent_active", "state": "active_one", "capacity": 1,
        "activation_id": manifest["activation_id"], "activation_package_digest": manifest["package_digest"],
        "integrated_candidate_sha": manifest["source_commit"], "operation_id": authorization["operation_id"],
        "acceptance_receipt_sha256": authorization["acceptance_receipt_sha256"],
        "verifier_output_sha256": authorization["verifier_output_sha256"],
        "controller_response_sha256": activation_package.digest(_wire_json(response)),
        "readback_sha256": activation_package.digest(activation_package.canonical_json(readback)),
        "receipt_sha256": _receipt_sha256(root),
    }


def persist_capacity_one(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
    driver: LiveSystemd | FakeSystemd, scenario_path: Path, acceptance_receipt_path: Path,
) -> dict[str, object]:
    return _run_operator_locked(
        manifest, root,
        lambda: _persist_capacity_one_locked(
            manifest, payloads, root, driver, scenario_path, acceptance_receipt_path,
        ),
    )


def _activate_unlocked(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("activation must be staged before capacity one")
    _bind_receipt(receipt, manifest)
    if receipt["state"] == "active_one":
        action = receipt["persistent_activation"] or receipt["capacity_one"]
        if not isinstance(action, dict) or action["phase"] != "active_one":
            raise ValueError("active capacity one lacks the fixed controller action receipt")
        return {
            "status": "unchanged",
            "state": "active_one",
            "capacity": 1,
            "readback": _active_capacity_one_readback(manifest, root, driver, action["processes_before"]),
        }
    if receipt["state"] == "qualified_closed":
        return {
            "status": "unchanged",
            "state": "qualified_closed",
            "capacity": 0,
            "managed_targets": _verify_phase(manifest, root, "staged"),
            "generated_targets": _verify_generated(root, receipt["acceptance_generated"], phase="staged"),
            "staged_zero": _staged_zero_readback(manifest, root, driver),
            "qualification": receipt["qualification"],
        }
    if receipt["state"] != "staged_zero":
        raise ValueError(f"activation cannot start from receipt state {receipt['state']}")
    _verify_phase(manifest, root, "staged")
    _verify_generated(root, receipt["acceptance_generated"], phase="staged")
    _keyholder_config_readback(manifest, root, payloads)
    _staged_zero_readback(manifest, root, driver)
    receipt.update({"state": "activating", "updated_at": utc_now(), "last_error": None})
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    try:
        driver.start("buzz-ci-execd.socket")
        driver.start("buzz-ci-execd.service")
        qualification = _run_qualification(manifest, root, receipt)
        driver.stop("buzz-ci-execd.service")
        driver.stop("buzz-ci-execd.socket")
        staged_zero = _staged_zero_readback(manifest, root, driver)
        _verify_phase(manifest, root, "staged")
        _verify_generated(root, receipt["acceptance_generated"], phase="staged")
        receipt.update({"state": "qualified_closed", "updated_at": utc_now(), "last_error": None})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        return {
            "status": "qualified_closed",
            "state": "qualified_closed",
            "capacity": 0,
            "activation_id": manifest["activation_id"],
            "qualification": qualification,
            "staged_zero": staged_zero,
        }
    except BaseException as error:
        rollback_error: str | None = None
        try:
            _return_to_staged_zero(manifest, payloads, root, driver, receipt["acceptance_generated"])
        except BaseException as nested:
            rollback_error = str(nested)
        safe_state = "qualification_uncertain" if _qualification_requires_restage(receipt["qualification"]) else "staged_zero"
        receipt.update({
            "state": safe_state if rollback_error is None else "rollback_failed",
            "updated_at": utc_now(),
            "last_error": str(error),
        })
        if rollback_error is not None:
            receipt["last_error"] = f"activation={error}; rollback={rollback_error}"
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        raise


def activate(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
    driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    return _run_operator_locked(
        manifest, root,
        lambda: _activate_unlocked(manifest, payloads, root, driver),
    )


def _qualify_unlocked(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("qualification requires an activation receipt")
    _bind_receipt(receipt, manifest)
    if receipt["state"] != "active_one":
        raise ValueError("qualification requires active capacity one")
    _verify_phase(manifest, root, "active")
    _verify_generated(root, receipt["acceptance_generated"], phase="active")
    try:
        before = _active_health(manifest, driver, require_enabled=True)
        result = _run_qualification(manifest, root, receipt)
        after = _active_health(manifest, driver, require_enabled=True)
        receipt.update({"updated_at": utc_now()})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        return {"status": "qualified", "state": "active_one", "before": before, "qualification": result, "after": after}
    except BaseException as error:
        rollback_error: str | None = None
        try:
            _return_to_staged_zero(manifest, payloads, root, driver, receipt["acceptance_generated"])
        except BaseException as nested:
            rollback_error = str(nested)
        receipt.update({
            "state": "staged_zero" if rollback_error is None else "rollback_failed",
            "updated_at": utc_now(),
            "last_error": str(error) if rollback_error is None else f"qualification={error}; rollback={rollback_error}",
        })
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        raise


def qualify(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path,
    driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    return _run_operator_locked(
        manifest, root,
        lambda: _qualify_unlocked(manifest, payloads, root, driver),
    )


def _validate_receipt_targets(receipt: dict[str, Any], manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = receipt.get("targets")
    if not isinstance(records, list):
        raise ValueError("receipt targets are invalid")
    by_role: dict[str, dict[str, Any]] = {}
    entries = {entry["role"]: entry for entry in manifest["entries"]}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"role", "target", "staged_sha256", "active_sha256", "prior"}:
            raise ValueError("receipt target record is invalid")
        role = record["role"]
        if role in by_role or role not in entries:
            raise ValueError("receipt target roles differ")
        entry = entries[role]
        if (
            record["target"] != entry["target"]
            or record["staged_sha256"] != entry["sha256"]
            or record["active_sha256"] != entry.get("active_sha256")
        ):
            raise ValueError("receipt target binding differs")
        prior = record["prior"]
        if not isinstance(prior, dict) or prior.get("exists") not in {True, False}:
            raise ValueError("receipt prior target is invalid")
        if prior["exists"]:
            if set(prior) != {"exists", "payload_base64", "sha256", "mode", "uid", "gid"}:
                raise ValueError("receipt prior target metadata is invalid")
            try:
                payload = base64.b64decode(prior["payload_base64"], validate=True)
            except (ValueError, TypeError) as error:
                raise ValueError("receipt prior payload is invalid") from error
            if activation_package.digest(payload) != prior["sha256"]:
                raise ValueError("receipt prior payload digest differs")
            activation_package.require_u32(prior["uid"], "receipt prior uid", allow_zero=True)
            activation_package.require_u32(prior["gid"], "receipt prior gid", allow_zero=True)
            if isinstance(prior["mode"], bool) or not isinstance(prior["mode"], int) or not 0 <= prior["mode"] <= 0o7777:
                raise ValueError("receipt prior mode is invalid")
        elif set(prior) != {"exists"}:
            raise ValueError("absent prior target has unexpected fields")
        by_role[role] = record
    if set(by_role) != set(entries):
        raise ValueError("receipt targets are incomplete")
    return by_role


def _validate_generated_records(receipt: dict[str, Any], root: Path, *, apply: bool) -> list[dict[str, Any]]:
    records = receipt.get("acceptance_generated")
    expected_roles = {"controld_acceptance_binding", "acceptance_control_config", "acceptance_driver_config", "execd_config"}
    if not isinstance(records, list) or len(records) != len(expected_roles):
        raise ValueError("acceptance generated receipt records are invalid")
    seen: set[str] = set()
    for record in records:
        required = {"role", "target", "sha256", "mode", "uid", "gid", "payload_base64", "prior"}
        if isinstance(record, dict) and record.get("role") == "execd_config":
            required |= {"active_sha256", "active_payload_base64"}
        if not isinstance(record, dict) or set(record) != required or record["role"] in seen or record["role"] not in expected_roles:
            raise ValueError("acceptance generated receipt record differs")
        seen.add(record["role"])
        payload = base64.b64decode(record["payload_base64"], validate=True)
        if activation_package.digest(payload) != record["sha256"]:
            raise ValueError(f"acceptance generated receipt payload differs: {record['role']}")
        opened = _read_target(root, record["target"], MAX_SCENARIO_BYTES)
        if opened is None:
            if record["prior"]["exists"]:
                raise ValueError(f"acceptance generated target absence blocks rollback: {record['target']}")
            continue
        current, metadata = opened
        expected_uid, expected_gid = _physical_ids(root, record["uid"], record["gid"])
        observed = activation_package.digest(current)
        expected_metadata = {"mode": record["mode"], "uid": expected_uid, "gid": expected_gid}
        prior = record["prior"]
        generated_digests = {record["sha256"]}
        if "active_sha256" in record:
            active_payload = base64.b64decode(record["active_payload_base64"], validate=True)
            if activation_package.digest(active_payload) != record["active_sha256"]:
                raise ValueError(f"acceptance generated active payload differs: {record['role']}")
            generated_digests.add(record["active_sha256"])
        current_is_generated = observed in generated_digests and _metadata_dict(metadata) == expected_metadata
        current_is_prior = prior["exists"] and observed == prior["sha256"] and _metadata_dict(metadata) == {
            "mode": prior["mode"], "uid": prior["uid"], "gid": prior["gid"],
        }
        if not current_is_generated and not current_is_prior:
            raise ValueError(f"acceptance generated target drift blocks rollback: {record['target']}")
    return records


def _restore_generated_prior_best_effort(
    receipt: dict[str, Any], root: Path,
) -> tuple[list[str], list[str]]:
    restored: list[str] = []
    errors: list[str] = []
    for record in reversed(receipt["acceptance_generated"]):
        try:
            prior = record["prior"]
            if prior["exists"]:
                payload = base64.b64decode(prior["payload_base64"], validate=True)
                _atomic_write(root, record["target"], payload, prior["mode"], prior["uid"], prior["gid"])
            elif _read_target(root, record["target"], MAX_SCENARIO_BYTES) is not None:
                _unlink_target(root, record["target"])
            restored.append(record["target"])
        except BaseException as error:
            errors.append(f"restore {record['role']}: {error}")
    return restored, errors


def _generated_prior_readback(receipt: dict[str, Any], root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for record in receipt["acceptance_generated"]:
        prior = record["prior"]
        opened = _read_target(root, record["target"], MAX_SCENARIO_BYTES)
        if not prior["exists"]:
            if opened is not None:
                raise ValueError(f"acceptance prior absence readback failed: {record['target']}")
            result[record["role"]] = "absent"
            continue
        if opened is None:
            raise ValueError(f"acceptance prior readback failed: {record['target']}")
        payload, metadata = opened
        if activation_package.digest(payload) != prior["sha256"] or _metadata_dict(metadata) != {
            "mode": prior["mode"], "uid": prior["uid"], "gid": prior["gid"],
        }:
            raise ValueError(f"acceptance prior readback differs: {record['target']}")
        result[record["role"]] = "restored"
    return result


def _restore_prior(receipt: dict[str, Any], manifest: dict[str, Any], root: Path, *, apply: bool = True) -> list[str]:
    records = _validate_receipt_targets(receipt, manifest)
    entries = {entry["role"]: entry for entry in manifest["entries"]}
    plans: list[tuple[dict[str, Any], dict[str, Any], tuple[bytes, os.stat_result] | None]] = []
    for role, entry in entries.items():
        if role == "execd_config":
            continue
        record = records[role]
        opened = _read_target(root, entry["target"])
        if opened is None and record["prior"]["exists"]:
            raise ValueError(f"installed target absence blocks rollback: {entry['target']}")
        if opened is not None:
            payload, metadata = opened
            observed = activation_package.digest(payload)
            allowed = {entry["sha256"]}
            if entry.get("active_sha256") is not None:
                allowed.add(entry["active_sha256"])
            prior = record["prior"]
            if prior["exists"]:
                allowed.add(prior["sha256"])
            if observed not in allowed:
                raise ValueError(f"installed target drift blocks rollback: {entry['target']}")
            expected_uid, expected_gid = _physical_ids(root, entry["uid"], entry["gid"])
            if observed in {entry["sha256"], entry.get("active_sha256")} and _metadata_dict(metadata) != {
                "mode": activation_package.parse_mode(entry["install_mode"]), "uid": expected_uid, "gid": expected_gid,
            }:
                raise ValueError(f"installed target metadata drift blocks rollback: {entry['target']}")
        plans.append((entry, record, opened))

    if not apply:
        return []
    restored: list[str] = []
    for entry, record, opened in reversed(plans):
        prior = record["prior"]
        if prior["exists"]:
            payload = base64.b64decode(prior["payload_base64"], validate=True)
            _atomic_write(root, entry["target"], payload, prior["mode"], prior["uid"], prior["gid"])
        elif opened is not None:
            _unlink_target(root, entry["target"])
        restored.append(entry["target"])
    return restored


def _restore_prior_best_effort(
    receipt: dict[str, Any], manifest: dict[str, Any], root: Path,
    *, retain_roles: frozenset[str] = frozenset(),
) -> tuple[list[str], list[str]]:
    records = _validate_receipt_targets(receipt, manifest)
    restored: list[str] = []
    errors: list[str] = []
    for entry in reversed(manifest["entries"]):
        if entry["role"] == "execd_config" or entry["role"] in retain_roles:
            continue
        record = records[entry["role"]]
        prior = record["prior"]
        try:
            opened = _read_target(root, entry["target"])
            if prior["exists"]:
                payload = base64.b64decode(prior["payload_base64"], validate=True)
                _atomic_write(root, entry["target"], payload, prior["mode"], prior["uid"], prior["gid"])
            elif opened is not None:
                _unlink_target(root, entry["target"])
            restored.append(entry["target"])
        except BaseException as error:
            errors.append(f"restore {entry['role']}: {error}")
    return restored, errors


def _prior_readback(
    receipt: dict[str, Any], manifest: dict[str, Any], root: Path,
    *, retain_roles: frozenset[str] = frozenset(),
) -> dict[str, str]:
    records = _validate_receipt_targets(receipt, manifest)
    result: dict[str, str] = {}
    for entry in manifest["entries"]:
        if entry["role"] == "execd_config":
            continue
        if entry["role"] in retain_roles:
            opened = _read_target(root, entry["target"])
            if _entry_state(root, entry, opened) == "staged":
                result[entry["role"]] = "retained_recovery"
                continue
        prior = records[entry["role"]]["prior"]
        opened = _read_target(root, entry["target"])
        if not prior["exists"]:
            if opened is not None:
                raise ValueError(f"prior absence readback failed: {entry['target']}")
            result[entry["role"]] = "absent"
            continue
        if opened is None:
            raise ValueError(f"prior target readback failed: {entry['target']}")
        payload, metadata = opened
        if activation_package.digest(payload) != prior["sha256"] or _metadata_dict(metadata) != {
            "mode": prior["mode"], "uid": prior["uid"], "gid": prior["gid"],
        }:
            raise ValueError(f"prior target readback differs: {entry['target']}")
        result[entry["role"]] = "restored"
    return result


def _rollback_terminal_response(
    receipt: dict[str, Any], manifest: dict[str, Any], root: Path,
    driver: LiveSystemd | FakeSystemd, *, status: str,
) -> dict[str, object]:
    targets = _prior_readback(
        receipt, manifest, root, retain_roles=ROLLBACK_RECOVERY_ROLES,
    )
    generated_prior = _generated_prior_readback(receipt, root)
    ledger_prior = _acceptance_ledger_prior_readback(receipt, root)
    units = _systemd_prior_readback(receipt, manifest, root, driver)
    restored = [
        entry["target"] for entry in reversed(manifest["entries"])
        if entry["role"] != "execd_config" and entry["role"] not in ROLLBACK_RECOVERY_ROLES
    ]
    generated_restored = [record["target"] for record in reversed(receipt["acceptance_generated"])]
    return {
        "status": status,
        "state": "rolled_back",
        "capacity": 0,
        "activation_id": manifest["activation_id"],
        "restored_targets": restored,
        "restored_acceptance_targets": generated_restored,
        "managed_targets": targets,
        "acceptance_generated": generated_prior,
        "acceptance_ledger": ledger_prior,
        "fixed_package": "absent",
        "rollback_cleanup": ROLLBACK_CLEANUP_PATH,
        "retained_principals": sorted(identity["user"] for identity in manifest["identities"].values()),
        "units": units,
    }


def _finish_rollback_cleanup(
    receipt: dict[str, Any], manifest: dict[str, Any], root: Path,
    driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    marker = _read_rollback_cleanup(root)
    if marker != _rollback_cleanup_value(manifest):
        raise ValueError("rollback cleanup marker is absent or differs")
    if receipt["state"] not in {"rollback_cleanup", "rolled_back"}:
        raise ValueError("rollback cleanup receipt state differs")
    _rollback_terminal_response(receipt, manifest, root, driver, status="unchanged")
    if receipt["state"] == "rolled_back":
        if _fixed_package_present(root):
            raise ValueError("fixed activation package remains after rollback")
        return _rollback_terminal_response(receipt, manifest, root, driver, status="unchanged")
    _remove_fixed_package_resumable(manifest, root)
    if _fixed_package_present(root):
        raise ValueError("fixed activation package cleanup is incomplete")
    response = _rollback_terminal_response(receipt, manifest, root, driver, status="rolled_back")
    receipt.update({"state": "rolled_back", "updated_at": utc_now(), "last_error": None})
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    return response


def _rollback_unlocked(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("rollback requires an activation receipt")
    _bind_receipt(receipt, manifest)
    if receipt["state"] in {"rollback_cleanup", "rolled_back"}:
        return _finish_rollback_cleanup(receipt, manifest, root, driver)
    if receipt["state"] not in {
        "preparing", "stage_failed", "staged_zero", "qualified_closed", "activating", "active_one", "preparing_zero", "rollback_failed",
        "qualification_uncertain",
    }:
        raise ValueError(f"rollback cannot start from receipt state {receipt['state']}")
    try:
        _validate_receipt_targets(receipt, manifest)
        _restore_prior(receipt, manifest, root, apply=False)
        _validate_generated_records(receipt, root, apply=False)
        _install_recovery_targets(receipt, manifest, root)
        execd_package_rollback = _execd_package_rollback_readback(
            manifest, root, receipt
        )
    except BaseException as error:
        receipt.update({"state": "rollback_failed", "updated_at": utc_now(), "last_error": str(error)})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        raise
    errors = _stop_zero_errors(driver)
    restored, restore_errors = _restore_prior_best_effort(
        receipt, manifest, root, retain_roles=ROLLBACK_RECOVERY_ROLES,
    )
    errors.extend(restore_errors)
    generated_restored, generated_errors = _restore_generated_prior_best_effort(receipt, root)
    errors.extend(generated_errors)
    try:
        _restore_acceptance_ledger(receipt, manifest, root)
    except BaseException as error:
        errors.append(f"restore controld acceptance ledger: {error}")
    try:
        driver.daemon_reload()
    except BaseException as error:
        errors.append(f"daemon-reload: {error}")
    units: dict[str, dict[str, str]] | None = None
    targets: dict[str, str] | None = None
    try:
        targets = _prior_readback(
            receipt, manifest, root, retain_roles=ROLLBACK_RECOVERY_ROLES,
        )
    except BaseException as error:
        errors.append(f"prior target readback: {error}")
    if execd_package_rollback == "required":
        errors.append(
            "execd package rollback is required before systemd prior restore; "
            "run the bound execd package rollback and retry activation rollback"
        )
    else:
        try:
            errors.extend(_restore_systemd_prior_errors(receipt, driver))
            units = _systemd_prior_readback(receipt, manifest, root, driver)
        except BaseException as error:
            errors.append(f"systemd prior readback: {error}")
    generated_prior: dict[str, str] | None = None
    try:
        generated_prior = _generated_prior_readback(receipt, root)
    except BaseException as error:
        errors.append(f"acceptance prior readback: {error}")
    ledger_prior: str | None = None
    try:
        ledger_prior = _acceptance_ledger_prior_readback(receipt, root)
    except BaseException as error:
        errors.append(f"acceptance ledger prior readback: {error}")
    if errors:
        combined = "rollback failures: " + "; ".join(errors)
        receipt.update({"state": "rollback_failed", "updated_at": utc_now(), "last_error": combined})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        raise ValueError(combined)
    try:
        cleanup_marker = _read_rollback_cleanup(root)
        expected_marker = _rollback_cleanup_value(manifest)
        if cleanup_marker is not None and cleanup_marker != expected_marker:
            retirement = _read_rollback_retirement(root)
            if (
                retirement is None
                or retirement["marker"] != cleanup_marker
                or retirement["next_activation_id"] != manifest["activation_id"]
                or retirement["next_package_digest"] != manifest["package_digest"]
                or retirement["next_source_commit"] != manifest["source_commit"]
            ):
                raise ValueError("rollback cleanup marker belongs to a different activation")
            _verify_fixed_package(manifest, root)
            _complete_rollback_retirement(manifest, root)
            cleanup_marker = None
        if cleanup_marker is None:
            _verify_fixed_package(manifest, root)
            _write_rollback_cleanup(manifest, root)
        elif _fixed_package_present(root):
            _verify_fixed_package(manifest, root)
        receipt.update({"state": "rollback_cleanup", "updated_at": utc_now(), "last_error": None})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    except BaseException as error:
        receipt.update({"state": "rollback_failed", "updated_at": utc_now(), "last_error": str(error)})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        raise
    return _finish_rollback_cleanup(receipt, manifest, root, driver)


def rollback(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    return _run_operator_locked(
        manifest, root,
        lambda: _rollback_unlocked(manifest, root, driver),
    )


def check_current(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None or receipt.get("state") == "rolled_back":
        return {"status": "ready_to_stage", "state": "dormant", **preflight(manifest, root, driver, require_dormant=True)}
    _bind_receipt(receipt, manifest)
    if receipt["state"] == "staged_zero":
        qualification_zero = receipt["qualification_zero"]
        if isinstance(qualification_zero, dict) and qualification_zero["phase"] == "finalized":
            return {
                "status": "qualification_zero_finalized", "state": "staged_zero", "capacity": 0,
                "managed_targets": _managed_readback(manifest, root, {"staged", "active", "prior"}),
                "principals": _identity_readback(driver, manifest["identities"], allow_absent=False),
                "access_group": _access_group_readback(driver, manifest["access_group"], allow_absent=False),
                "fixed_package": _verify_fixed_package(manifest, root),
                "qualification_zero": _finalized_zero_readback(manifest, root, driver),
            }
        return {
            "status": "ready_to_activate", "state": "staged_zero", "capacity": 0,
            "managed_targets": _verify_phase(manifest, root, "staged"),
            "principals": _identity_readback(driver, manifest["identities"], allow_absent=False),
            "access_group": _access_group_readback(driver, manifest["access_group"], allow_absent=False),
            "acceptance_generated": _verify_generated(root, receipt["acceptance_generated"]),
            "staged_zero": _staged_zero_readback(manifest, root, driver),
        }
    if receipt["state"] == "qualified_closed":
        return {
            "status": "ready_for_fixed_capacity_one", "state": "qualified_closed", "capacity": 0,
            "managed_targets": _verify_phase(manifest, root, "staged"),
            "principals": _identity_readback(driver, manifest["identities"], allow_absent=False),
            "access_group": _access_group_readback(driver, manifest["access_group"], allow_absent=False),
            "acceptance_generated": _verify_generated(root, receipt["acceptance_generated"]),
            "fixed_package": _verify_fixed_package(manifest, root),
            "qualification": receipt["qualification"],
            "staged_zero": _staged_zero_readback(manifest, root, driver),
        }
    if receipt["state"] == "active_one":
        action = receipt["persistent_activation"] or receipt["capacity_one"]
        if not isinstance(action, dict) or action["phase"] != "active_one":
            raise ValueError("active capacity one lacks the fixed controller action receipt")
        return {
            "status": "healthy", "state": "active_one", "capacity": 1,
            "readback": _active_capacity_one_readback(manifest, root, driver, action["processes_before"]),
            "qualification": receipt.get("qualification"),
        }
    if receipt["state"] == "qualification_uncertain":
        return {
            "status": "rollback_and_restage_required", "state": "qualification_uncertain", "capacity": 0,
            "managed_targets": _verify_phase(manifest, root, "staged"),
            "acceptance_generated": _verify_generated(root, receipt["acceptance_generated"]),
            "staged_zero": _staged_zero_readback(manifest, root, driver),
            "qualification": receipt["qualification"],
        }
    raise ValueError(f"activation receipt requires recovery: {receipt['state']}")


def _driver(root: Path, fake_state: Path | None, manifest: dict[str, Any]) -> LiveSystemd | FakeSystemd:
    if fake_state is None:
        return LiveSystemd(root)
    return FakeSystemd(
        root, fake_state, manifest["identities"], manifest["access_group"],
        manifest["socket_policy"], manifest["effective_systemd"],
    )


def _load_rollback_package_for_cli(
    package: Path, root: Path, *, live: bool,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    receipt = _read_receipt(root)
    if receipt is not None and receipt.get("state") in {"rollback_cleanup", "rolled_back"}:
        expected = activation_package.rooted(root, FIXED_PACKAGE_PATH)
        if Path(os.path.abspath(package)) == expected:
            marker = _read_rollback_cleanup(root)
            if marker is None:
                raise ValueError("terminal rollback cleanup marker is absent")
            return marker["manifest"], {}
    return load_package(package, live=live)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    ordinary_actions = ("check", "stage", "activate", "qualify", "rollback")
    parser.add_argument(
        "action",
        choices=ordinary_actions + (CAPACITY_ONE_CLI_ACTION, PERSISTENT_CAPACITY_ONE_ACTION) + tuple(ZERO_CLI_ACTIONS),
    )
    parser.add_argument("--package", type=Path)
    parser.add_argument("--scenario", type=Path)
    parser.add_argument("--acceptance-receipt", type=Path)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--fake-systemd-state", type=Path)
    arguments = parser.parse_args()
    root = Path(os.path.abspath(arguments.root))
    live = arguments.fake_systemd_state is None
    try:
        if arguments.action == PERSISTENT_CAPACITY_ONE_ACTION:
            if (
                arguments.package is not None or root != Path("/") or arguments.fake_systemd_state is not None
                or arguments.scenario is None or arguments.acceptance_receipt is None
            ):
                raise ValueError(
                    "persistent capacity-one accepts only --scenario and --acceptance-receipt on the live root"
                )
            if os.geteuid() != 0:
                raise PermissionError("persistent capacity-one requires root")
            manifest, payloads = load_package(Path(FIXED_PACKAGE_PATH), live=True)
            result = persist_capacity_one(
                manifest, payloads, root, LiveSystemd(root),
                arguments.scenario, arguments.acceptance_receipt,
            )
            print(activation_package.canonical_json(result).decode(), end="")
            return 0
        if arguments.action == CAPACITY_ONE_CLI_ACTION:
            if (
                arguments.package is not None or arguments.scenario is not None or root != Path("/")
                or arguments.fake_systemd_state is not None or arguments.acceptance_receipt is not None
            ):
                raise ValueError("capacity-one action accepts no package, scenario, root, or fake-state arguments")
            if os.geteuid() != 0:
                raise PermissionError("capacity-one action requires root")
            manifest, payloads = load_package(Path(FIXED_PACKAGE_PATH), live=True)
            receipt = _read_receipt(root)
            if receipt is None:
                raise ValueError("capacity-one action requires an activation receipt")
            _bind_receipt(receipt, manifest)
            raw = sys.stdin.buffer.read(MAX_ZERO_REQUEST_BYTES + 1)
            request, request_sha256 = _parse_capacity_one_request(raw, receipt)
            result = _set_capacity_one(
                manifest, payloads, root, LiveSystemd(root), request, request_sha256,
            )
            sys.stdout.buffer.write(_wire_json(result))
            return 0
        if arguments.action in ZERO_CLI_ACTIONS:
            if (
                arguments.package is not None or arguments.scenario is not None or root != Path("/")
                or arguments.fake_systemd_state is not None or arguments.acceptance_receipt is not None
            ):
                raise ValueError("qualification-zero actions accept no package, scenario, root, or fake-state arguments")
            if os.geteuid() != 0:
                raise PermissionError("qualification-zero actions require root")
            manifest, payloads = load_package(Path(FIXED_PACKAGE_PATH), live=True)
            receipt = _read_receipt(root)
            if receipt is None:
                raise ValueError("qualification-zero action requires an activation receipt")
            _bind_receipt(receipt, manifest)
            raw = sys.stdin.buffer.read(MAX_ZERO_REQUEST_BYTES + 1)
            request, request_sha256 = _parse_zero_request(raw, arguments.action, receipt)
            driver = LiveSystemd(root)
            if arguments.action == "prepare-qualification-zero":
                result = _prepare_qualification_zero(manifest, payloads, root, driver, request, request_sha256)
            elif arguments.action == "finalize-qualification-zero":
                result = _finalize_qualification_zero(manifest, payloads, root, driver, request, request_sha256)
            else:
                result = _prove_qualification_zero(manifest, root, driver, request)
            sys.stdout.buffer.write(_wire_json(result))
            return 0
        if arguments.package is None:
            raise ValueError(f"{arguments.action} requires --package")
        if arguments.acceptance_receipt is not None:
            raise ValueError("--acceptance-receipt is accepted only by persist-capacity-one")
        if arguments.action == "rollback":
            manifest, payloads = _load_rollback_package_for_cli(arguments.package, root, live=live)
        else:
            manifest, payloads = load_package(arguments.package, live=live)
        driver = _driver(root, arguments.fake_systemd_state, manifest)
        if arguments.scenario is not None and arguments.action != "stage":
            raise ValueError("--scenario is accepted only by stage")
        if arguments.action == "check":
            result = check_current(manifest, root, driver)
        elif arguments.action == "stage":
            if arguments.scenario is None:
                raise ValueError("stage requires --scenario")
            binding = load_acceptance_scenario(arguments.scenario, manifest, live=live)
            result = stage(manifest, payloads, root, driver, binding)
        elif arguments.action == "activate":
            result = activate(manifest, payloads, root, driver)
        elif arguments.action == "qualify":
            result = qualify(manifest, payloads, root, driver)
        else:
            result = rollback(manifest, root, driver)
        print(activation_package.canonical_json(result).decode(), end="")
        return 0
    except (OSError, ValueError, PermissionError, subprocess.SubprocessError) as error:
        print(activation_package.canonical_json({"status": "error", "error": str(error)}).decode(), end="", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
