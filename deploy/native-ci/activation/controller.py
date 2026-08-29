#!/usr/bin/env python3
"""Preflight, stage, activate, qualify, or roll back Buzz CI capacity one."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import resource
import stat
import subprocess
import sys
import tempfile
from typing import Any

import package as activation_package

RECEIPT_PATH = "/var/lib/buzzci/activation-controller/receipt-v1.json"
SYSTEMCTL = "/usr/bin/systemctl"
SYSUSERS = "/usr/bin/systemd-sysusers"
TMPFILES = "/usr/bin/systemd-tmpfiles"
MAX_COMMAND_OUTPUT = 256 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024


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
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != activation_package.parse_mode(expected["mode"])
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


def _atomic_write(root: Path, target: str, payload: bytes, mode: int, uid: int, gid: int) -> None:
    parent_fd, name = activation_package.open_parent_fd(root, target, create=True)
    temporary_name = f".{name}.activation-{os.getpid()}-{os.urandom(8).hex()}"
    fd = -1
    try:
        fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(fd, mode)
        if os.geteuid() == 0:
            os.fchown(fd, uid, gid)
        elif root == Path("/"):
            raise PermissionError("live writes require the requested UID and GID")
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.rename(temporary_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if fd >= 0:
            os.close(fd)
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


def _write_receipt(root: Path, receipt: dict[str, object]) -> None:
    _require_receipt_root(root)
    _atomic_write(root, RECEIPT_PATH, activation_package.canonical_json(receipt), 0o600, 0 if os.geteuid() == 0 else os.geteuid(), 0 if os.geteuid() == 0 else os.getegid())


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


def _require_receipt_root(root: Path) -> Path:
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
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
    ):
        raise ValueError("activation receipt root must be a root-private real directory")
    return directory


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
    references[manifest["qualification"]["request_source"]] = (0o400, manifest["qualification"]["request_sha256"])
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

    def provision(self, _identities: dict[str, object]) -> None:
        self._run(SYSUSERS, [activation_package.STATIC_TARGETS["sysusers"]], mutation=True)

    def tmpfiles(self) -> None:
        self._run(TMPFILES, ["--create", activation_package.STATIC_TARGETS["tmpfiles"]], mutation=True)

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
        }

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


class FakeSystemd:
    """Deterministic fake-root state driver. It never invokes systemd."""

    def __init__(self, root: Path, state_path: Path, identities: dict[str, object], socket_policy: dict[str, object]) -> None:
        if root == Path("/"):
            raise ValueError("fake systemd requires a non-root filesystem")
        self.root = root
        self.state_path = Path(os.path.abspath(state_path))
        expected_parent = activation_package.rooted(root, "/var/lib/buzzci/activation-controller")
        if self.state_path.parent != expected_parent:
            raise ValueError("fake systemd state must stay in the fake activation root")
        if self.state_path.name != "fake-systemd-v1.json":
            raise ValueError("fake systemd state filename is fixed")
        _require_receipt_root(root)
        self.planned_identities = identities
        self.socket_policy = socket_policy

    def _read(self) -> dict[str, Any]:
        value, _raw, metadata = activation_package.parse_json(self.state_path)
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("fake systemd state must be mode 0600")
        if set(value) != {"schema", "units", "identities", "sockets"} or value["schema"] != "buzz-ci-fake-systemd-v1":
            raise ValueError("fake systemd state schema is invalid")
        return value

    def _write(self, value: dict[str, object]) -> None:
        _atomic_write(self.root, "/var/lib/buzzci/activation-controller/fake-systemd-v1.json", activation_package.canonical_json(value), 0o600, os.geteuid(), os.getegid())

    def unit(self, name: str) -> dict[str, str]:
        state = self._read()
        unit = state["units"].get(name)
        if not isinstance(unit, dict):
            return {"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled"}
        return dict(unit)

    def provision(self, identities: dict[str, object]) -> None:
        state = self._read()
        for role, identity in identities.items():
            existing = state["identities"].get(identity["user"])
            expected = {
                "user": identity["user"], "group": identity["group"], "uid": identity["uid"], "gid": identity["gid"],
                "primary_gid": identity["gid"], "home": identity["home"], "shell": identity["shell"],
            }
            if existing is not None and existing != expected:
                raise ValueError(f"fake principal drift: {role}")
            state["identities"][identity["user"]] = expected
        self._write(state)

    def tmpfiles(self) -> None:
        _require_receipt_root(self.root)

    def daemon_reload(self) -> None:
        state = self._read()
        target_path = activation_package.rooted(self.root, activation_package.STATIC_TARGETS["capacity_target"])
        if target_path.exists():
            state["units"].setdefault(activation_package.PERSISTENT_UNIT, {
                "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled",
            })
            state["units"][activation_package.PERSISTENT_UNIT]["LoadState"] = "loaded"
        else:
            state["units"][activation_package.PERSISTENT_UNIT] = {
                "LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled",
            }
        self._write(state)

    def start(self, name: str) -> None:
        state = self._read()
        unit = state["units"].setdefault(name, {})
        unit.update({"LoadState": "loaded", "ActiveState": "active", "SubState": "listening" if name.endswith(".socket") else "running"})
        unit.setdefault("UnitFileState", "disabled")
        for policy in self.socket_policy.values():
            if policy["unit"] == name:
                identity = self.identity(policy["user"]) if policy["user"] != "root" else {"uid": 0}
                group = self.identity(policy["group"])
                state["sockets"][policy["path"]] = {
                    "path": policy["path"], "mode": policy["mode"], "uid": identity["uid"], "gid": group["gid"],
                }
        self._write(state)

    def stop(self, name: str) -> None:
        state = self._read()
        unit = state["units"].setdefault(name, {})
        unit.update({"LoadState": unit.get("LoadState", "loaded"), "ActiveState": "inactive", "SubState": "dead"})
        unit.setdefault("UnitFileState", "disabled")
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

    def numeric_identity(self, uid: int, gid: int) -> dict[str, str | None]:
        state = self._read()
        user = next((name for name, value in state["identities"].items() if value.get("uid") == uid), None)
        group = next((value.get("group") for value in state["identities"].values() if value.get("gid") == gid), None)
        return {"user": user, "group": group}

    def socket(self, policy: dict[str, object]) -> dict[str, object]:
        value = self._read()["sockets"].get(policy["path"])
        if value is None:
            raise ValueError(f"fake socket is absent: {policy['path']}")
        return value


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
        }
        if observed != expected:
            raise ValueError(f"principal drift: {identity['user']}")
        result[role] = {"status": "exact", **observed}
    return result


def _component_readback(manifest: dict[str, Any], root: Path) -> dict[str, object]:
    result: dict[str, object] = {}
    for component in manifest["components"]:
        expected = {
            "sha256": component["binary_sha256"],
            "mode": component["mode"],
            "uid": component["uid"],
            "gid": component["gid"],
        }
        _verify_target_digest(root, component["binary_path"], expected, MAX_BINARY_BYTES)
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
    return "drift"


def _managed_readback(manifest: dict[str, Any], root: Path, allowed: set[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in manifest["entries"]:
        state = _entry_state(root, entry, _read_target(root, entry["target"]))
        if state not in allowed:
            raise ValueError(f"managed target drift: {entry['target']} ({state})")
        result[entry["role"]] = state
    return result


def _unit_readback(driver: LiveSystemd | FakeSystemd, names: list[str]) -> dict[str, dict[str, str]]:
    return {name: driver.unit(name) for name in names}


def _preflight_units(driver: LiveSystemd | FakeSystemd) -> dict[str, dict[str, str]]:
    names = sorted(set(activation_package.START_ORDER + activation_package.STOP_ORDER))
    result = _unit_readback(driver, names)
    for name, state in result.items():
        if state["LoadState"] != "loaded":
            raise ValueError(f"required systemd unit is not loaded: {name}")
        if state["ActiveState"] != "inactive":
            raise ValueError(f"systemd unit is not dormant: {name}")
        if name.endswith(".socket") and state["UnitFileState"] not in {"disabled", "static"}:
            raise ValueError(f"systemd socket is enabled before activation: {name}")
    target = driver.unit(activation_package.PERSISTENT_UNIT)
    if target["LoadState"] not in {"not-found", "loaded"} or target["ActiveState"] != "inactive":
        raise ValueError("capacity-one target is not dormant")
    if target["LoadState"] == "loaded" and target["UnitFileState"] not in {"disabled", "static"}:
        raise ValueError("capacity-one target is enabled before activation")
    result[activation_package.PERSISTENT_UNIT] = target
    return result


def preflight(
    manifest: dict[str, Any],
    root: Path,
    driver: LiveSystemd | FakeSystemd,
    *,
    require_dormant: bool,
) -> dict[str, object]:
    components = _component_readback(manifest, root)
    principals = _identity_readback(driver, manifest["identities"], allow_absent=True)
    managed = _managed_readback(manifest, root, {"absent", "staged"})
    for role in ("runner_config", "controld_config"):
        if managed[role] != "staged":
            raise ValueError(f"frozen component config is absent before activation: {role}")
    units = _preflight_units(driver) if require_dormant else {}
    return {
        "activation_id": manifest["activation_id"],
        "package_digest": manifest["package_digest"],
        "capacity": 0,
        "components": components,
        "principals": principals,
        "managed_targets": managed,
        "units": units,
        "socket_policy": manifest["socket_policy"],
    }


def _new_receipt(manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd) -> dict[str, object]:
    records: list[dict[str, object]] = []
    for entry in manifest["entries"]:
        opened = _read_target(root, entry["target"])
        if opened is None:
            prior: dict[str, object] = {"exists": False}
        else:
            payload, metadata = opened
            if _entry_state(root, entry, opened) != "staged":
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
        "systemd_before": _unit_readback(
            driver,
            sorted(set(activation_package.START_ORDER + activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT])),
        ),
        "qualification": None,
        "last_error": None,
    }


def _bind_receipt(receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
    expected_keys = {
        "schema", "activation_id", "package_digest", "source_commit", "state", "created_at", "updated_at",
        "principals_retained_on_rollback", "targets", "systemd_before", "qualification", "last_error",
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


def _apply_phase(
    manifest: dict[str, Any],
    payloads: dict[str, bytes],
    root: Path,
    phase: str,
) -> None:
    for entry in manifest["entries"]:
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
        observed = _entry_state(root, entry, _read_target(root, entry["target"]))
        wanted = expected_state if "active_source" in entry else "staged"
        if observed != wanted:
            raise ValueError(f"{phase} readback failed: {entry['target']} ({observed})")
        result[entry["role"]] = observed
    return result


def _stop_to_zero(driver: LiveSystemd | FakeSystemd) -> None:
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
    if errors:
        raise ValueError("capacity-zero stop failures: " + "; ".join(errors))


def _zero_readback(driver: LiveSystemd | FakeSystemd) -> dict[str, dict[str, str]]:
    names = sorted(set(activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT]))
    result = _unit_readback(driver, names)
    for name, state in result.items():
        if state["ActiveState"] != "inactive":
            raise ValueError(f"capacity-zero readback found active unit: {name}")
    target = result[activation_package.PERSISTENT_UNIT]
    if target["LoadState"] != "not-found" and target["UnitFileState"] not in {"disabled", "static"}:
        raise ValueError("capacity-one target remains enabled")
    return result


def stage(
    manifest: dict[str, Any],
    payloads: dict[str, bytes],
    root: Path,
    driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    existing = _read_receipt(root)
    if existing is not None:
        if existing.get("state") == "rolled_back":
            pass
        else:
            _bind_receipt(existing, manifest)
            if existing["state"] == "staged_zero":
                return {
                    "status": "unchanged",
                    "state": "staged_zero",
                    "capacity": 0,
                    "managed_targets": _verify_phase(manifest, root, "staged"),
                    "principals": _identity_readback(driver, manifest["identities"], allow_absent=False),
                    "units": _zero_readback(driver),
                }
            raise ValueError(f"activation receipt requires rollback from {existing['state']}")
    report = preflight(manifest, root, driver, require_dormant=True)
    receipt = _new_receipt(manifest, root, driver)
    _write_receipt(root, receipt)
    try:
        _apply_phase(manifest, payloads, root, "staged")
        driver.provision(manifest["identities"])
        driver.tmpfiles()
        driver.daemon_reload()
        _stop_to_zero(driver)
        principals = _identity_readback(driver, manifest["identities"], allow_absent=False)
        targets = _verify_phase(manifest, root, "staged")
        units = _zero_readback(driver)
        receipt.update({"state": "staged_zero", "updated_at": utc_now()})
        _write_receipt(root, receipt)
        return {
            "status": "staged",
            "state": "staged_zero",
            "capacity": 0,
            "activation_id": manifest["activation_id"],
            "preflight": report,
            "principals": principals,
            "managed_targets": targets,
            "units": units,
        }
    except BaseException as error:
        receipt.update({"state": "stage_failed", "updated_at": utc_now(), "last_error": str(error)})
        _write_receipt(root, receipt)
        raise


def _socket_readback(manifest: dict[str, Any], driver: LiveSystemd | FakeSystemd) -> dict[str, object]:
    identities = manifest["identities"]
    result: dict[str, object] = {}
    for name, policy in manifest["socket_policy"].items():
        observed = driver.socket(policy)
        expected_uid = 0 if policy["user"] == "root" else identities[name if name != "execd" else "runner"]["uid"]
        if policy["user"] == "buzzci-keyholder":
            expected_uid = identities["keyholder"]["uid"]
        elif policy["user"] == "buzzci-runner":
            expected_uid = identities["runner"]["uid"]
        expected_gid = identities["controld"]["gid"] if policy["group"] == "buzzci-controld" else identities["runner"]["gid"]
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


def _run_qualification(manifest: dict[str, Any], payloads: dict[str, bytes], root: Path) -> dict[str, object]:
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
    request = payloads[qualification["request_source"]]
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(
                [f"/proc/self/fd/{program_fd}"],
                input=request,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=qualification["timeout_seconds"],
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                preexec_fn=_limit_output,
                pass_fds=(program_fd,),
            )
            stdout.seek(0)
            response = stdout.read(MAX_COMMAND_OUTPUT + 1)
            stderr.seek(0)
            error_output = stderr.read(MAX_COMMAND_OUTPUT + 1)
    finally:
        os.close(program_fd)
    if len(response) > MAX_COMMAND_OUTPUT or len(error_output) > MAX_COMMAND_OUTPUT:
        raise ValueError("qualification output exceeded its fixed bound")
    if completed.returncode != 0:
        raise ValueError(f"qualification command failed with status {completed.returncode}")
    response_digest = activation_package.digest(response)
    if response_digest != qualification["expected_response_sha256"]:
        raise ValueError("qualification response digest differs")
    return {
        "status": "passed",
        "request_sha256": qualification["request_sha256"],
        "response_sha256": response_digest,
        "completed_at": utc_now(),
    }


def _return_to_staged_zero(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path, driver: LiveSystemd | FakeSystemd,
) -> None:
    _stop_to_zero(driver)
    _apply_phase(manifest, payloads, root, "staged")
    driver.daemon_reload()
    _verify_phase(manifest, root, "staged")
    _zero_readback(driver)


def activate(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("activation must be staged before capacity one")
    _bind_receipt(receipt, manifest)
    if receipt["state"] == "active_one":
        return {
            "status": "unchanged",
            "state": "active_one",
            "managed_targets": _verify_phase(manifest, root, "active"),
            "health": _active_health(manifest, driver, require_enabled=True),
        }
    if receipt["state"] != "staged_zero":
        raise ValueError(f"activation cannot start from receipt state {receipt['state']}")
    _verify_phase(manifest, root, "staged")
    _zero_readback(driver)
    receipt.update({"state": "activating", "updated_at": utc_now(), "last_error": None})
    _write_receipt(root, receipt)
    try:
        _apply_phase(manifest, payloads, root, "active")
        _verify_phase(manifest, root, "active")
        driver.daemon_reload()
        for unit in manifest["systemd"]["start_order"]:
            driver.start(unit)
        driver.start(manifest["systemd"]["persistent_unit"])
        prequalification = _active_health(manifest, driver, require_enabled=False)
        qualification = _run_qualification(manifest, payloads, root)
        postqualification = _active_health(manifest, driver, require_enabled=False)
        driver.enable(manifest["systemd"]["persistent_unit"])
        final_health = _active_health(manifest, driver, require_enabled=True)
        receipt.update({"state": "active_one", "updated_at": utc_now(), "qualification": qualification})
        _write_receipt(root, receipt)
        return {
            "status": "activated",
            "state": "active_one",
            "capacity": 1,
            "activation_id": manifest["activation_id"],
            "prequalification_health": prequalification,
            "qualification": qualification,
            "postqualification_health": postqualification,
            "final_health": final_health,
        }
    except BaseException as error:
        rollback_error: str | None = None
        try:
            _return_to_staged_zero(manifest, payloads, root, driver)
        except BaseException as nested:
            rollback_error = str(nested)
        receipt.update({
            "state": "staged_zero" if rollback_error is None else "rollback_failed",
            "updated_at": utc_now(),
            "last_error": str(error),
        })
        if rollback_error is not None:
            receipt["last_error"] = f"activation={error}; rollback={rollback_error}"
        _write_receipt(root, receipt)
        raise


def qualify(
    manifest: dict[str, Any], payloads: dict[str, bytes], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("qualification requires an activation receipt")
    _bind_receipt(receipt, manifest)
    if receipt["state"] != "active_one":
        raise ValueError("qualification requires active capacity one")
    _verify_phase(manifest, root, "active")
    try:
        before = _active_health(manifest, driver, require_enabled=True)
        result = _run_qualification(manifest, payloads, root)
        after = _active_health(manifest, driver, require_enabled=True)
        receipt.update({"qualification": result, "updated_at": utc_now()})
        _write_receipt(root, receipt)
        return {"status": "qualified", "state": "active_one", "before": before, "qualification": result, "after": after}
    except BaseException as error:
        rollback_error: str | None = None
        try:
            _return_to_staged_zero(manifest, payloads, root, driver)
        except BaseException as nested:
            rollback_error = str(nested)
        receipt.update({
            "state": "staged_zero" if rollback_error is None else "rollback_failed",
            "updated_at": utc_now(),
            "last_error": str(error) if rollback_error is None else f"qualification={error}; rollback={rollback_error}",
        })
        _write_receipt(root, receipt)
        raise


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


def _restore_prior(receipt: dict[str, Any], manifest: dict[str, Any], root: Path, *, apply: bool = True) -> list[str]:
    records = _validate_receipt_targets(receipt, manifest)
    entries = {entry["role"]: entry for entry in manifest["entries"]}
    plans: list[tuple[dict[str, Any], dict[str, Any], tuple[bytes, os.stat_result] | None]] = []
    for role, entry in entries.items():
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


def rollback(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("rollback requires an activation receipt")
    _bind_receipt(receipt, manifest)
    if receipt["state"] == "rolled_back":
        return {
            "status": "unchanged",
            "state": "rolled_back",
            "capacity": 0,
            "managed_targets": _managed_readback(manifest, root, {"absent", "staged"}),
            "units": _zero_readback(driver),
        }
    if receipt["state"] not in {"preparing", "stage_failed", "staged_zero", "activating", "active_one", "rollback_failed"}:
        raise ValueError(f"rollback cannot start from receipt state {receipt['state']}")
    _validate_receipt_targets(receipt, manifest)
    _restore_prior(receipt, manifest, root, apply=False)
    _stop_to_zero(driver)
    restored = _restore_prior(receipt, manifest, root)
    driver.daemon_reload()
    units = _zero_readback(driver)
    receipt.update({"state": "rolled_back", "updated_at": utc_now(), "last_error": None})
    _write_receipt(root, receipt)
    return {
        "status": "rolled_back",
        "state": "rolled_back",
        "capacity": 0,
        "activation_id": manifest["activation_id"],
        "restored_targets": restored,
        "retained_principals": sorted(identity["user"] for identity in manifest["identities"].values()),
        "units": units,
    }


def check_current(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None or receipt.get("state") == "rolled_back":
        return {"status": "ready_to_stage", "state": "dormant", **preflight(manifest, root, driver, require_dormant=True)}
    _bind_receipt(receipt, manifest)
    if receipt["state"] == "staged_zero":
        return {
            "status": "ready_to_activate", "state": "staged_zero", "capacity": 0,
            "managed_targets": _verify_phase(manifest, root, "staged"),
            "principals": _identity_readback(driver, manifest["identities"], allow_absent=False),
            "units": _zero_readback(driver),
        }
    if receipt["state"] == "active_one":
        return {
            "status": "healthy", "state": "active_one", "capacity": 1,
            "managed_targets": _verify_phase(manifest, root, "active"),
            "health": _active_health(manifest, driver, require_enabled=True),
            "qualification": receipt.get("qualification"),
        }
    raise ValueError(f"activation receipt requires recovery: {receipt['state']}")


def _driver(root: Path, fake_state: Path | None, manifest: dict[str, Any]) -> LiveSystemd | FakeSystemd:
    if fake_state is None:
        return LiveSystemd(root)
    return FakeSystemd(root, fake_state, manifest["identities"], manifest["socket_policy"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "stage", "activate", "qualify", "rollback"))
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--fake-systemd-state", type=Path)
    arguments = parser.parse_args()
    root = Path(os.path.abspath(arguments.root))
    live = arguments.fake_systemd_state is None
    try:
        manifest, payloads = load_package(arguments.package, live=live)
        driver = _driver(root, arguments.fake_systemd_state, manifest)
        if arguments.action == "check":
            result = check_current(manifest, root, driver)
        elif arguments.action == "stage":
            result = stage(manifest, payloads, root, driver)
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
