#!/usr/bin/python3
"""Preflight, stage, activate, qualify, or roll back Buzz CI capacity one."""

from __future__ import annotations

import argparse
import base64
import ctypes
from datetime import datetime, timezone
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
from typing import Any

try:
    import buzz_ci_activation_package as activation_package
except ModuleNotFoundError:
    if Path(__file__).name != "controller.py":
        raise
    import package as activation_package

RECEIPT_PATH = "/var/lib/buzzci/activation-controller/receipt-v1.json"
ACCEPTANCE_BINDING_PATH = activation_package.ACCEPTANCE_BINDING_PATH
CONTROLD_ACCEPTANCE_LEDGER_PATH = "/var/lib/buzzci/controld/acceptance-operation-ledger-v1.json"
FIXED_PACKAGE_PATH = activation_package.FIXED_PACKAGE_PATH
ZERO_REQUEST_SCHEMA = "buzz-ci-activation-qualification-zero-request/v1"
ZERO_RESPONSE_SCHEMA = "buzz-ci-activation-qualification-zero-response/v1"
ZERO_SEQUENCE_SCHEMA = "buzz-ci-activation-qualification-zero-state/v1"
MAX_ZERO_REQUEST_BYTES = 64 * 1024
MAX_SCENARIO_BYTES = 256 * 1024
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


def _write_receipt(root: Path, receipt: dict[str, object], controld_gid: int) -> None:
    _require_receipt_root(root, controld_gid, allow_private=True)
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
    qualification = manifest["identities"]["qualification"]
    return {
        "schema_version": activation_package.ACCEPTANCE_BINDING_SCHEMA,
        "activation_id": manifest["activation_id"],
        "activation_package_digest": manifest["package_digest"],
        "scenario_sha256": scenario_sha256,
        "peer_uid": qualification["uid"],
        "peer_gid": qualification["gid"],
        "timeout_millis": timeout_seconds * 1000,
        "fixture": ordered_fixture,
        "acceptance": acceptance,
    }


def _acceptance_binding_bytes(binding: dict[str, object]) -> bytes:
    expected_top = [
        "schema_version", "activation_id", "activation_package_digest", "scenario_sha256",
        "peer_uid", "peer_gid", "timeout_millis", "fixture", "acceptance",
    ]
    expected_acceptance = [
        "actor", "scenario_sha256", "run_event", "grant_event", "rerun_event", "tombstone_event",
    ]
    acceptance = binding.get("acceptance")
    if (
        list(binding) != expected_top or binding["schema_version"] != activation_package.ACCEPTANCE_BINDING_SCHEMA
        or not isinstance(acceptance, dict) or list(acceptance) != expected_acceptance
        or binding["scenario_sha256"] != acceptance["scenario_sha256"]
    ):
        raise ValueError("acceptance binding scenario digests differ")
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


def _generated_acceptance_files(manifest: dict[str, Any], binding: dict[str, object]) -> list[dict[str, object]]:
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
    return [
        {
            "role": "controld_acceptance_binding", "target": ACCEPTANCE_BINDING_PATH,
            "payload": _acceptance_binding_bytes(binding), "mode": 0o444, "uid": 0, "gid": 0,
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
    ]


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
    return [
        {
            "role": item["role"], "target": item["target"], "sha256": activation_package.digest(item["payload"]),
            "mode": item["mode"], "uid": item["uid"], "gid": item["gid"],
            "payload_base64": base64.b64encode(item["payload"]).decode("ascii"),
            "prior": _capture_prior(root, item["target"]),
        }
        for item in generated
    ]


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
        if record is None or any(record.get(key) != value for key, value in expected.items()):
            raise ValueError("acceptance scenario differs from the staged receipt")


def _apply_generated(root: Path, records: list[dict[str, object]]) -> None:
    for record in records:
        payload = base64.b64decode(record["payload_base64"], validate=True)
        if activation_package.digest(payload) != record["sha256"]:
            raise ValueError(f"generated acceptance payload digest differs: {record['role']}")
        _atomic_write(root, record["target"], payload, record["mode"], record["uid"], record["gid"])


def _verify_generated(root: Path, records: list[dict[str, object]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for record in records:
        _verify_target_digest(root, record["target"], record, MAX_SCENARIO_BYTES)
        result[record["role"]] = "exact"
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


def _package_references(manifest: dict[str, Any]) -> dict[str, int]:
    references: dict[str, int] = {}
    for entry in manifest["entries"]:
        references[entry["source"]] = activation_package.parse_mode(entry["source_mode"])
        if "active_source" in entry:
            references[entry["active_source"]] = activation_package.parse_mode(entry["active_source_mode"])
    for component in manifest["components"]:
        references[component["provenance_source"]] = 0o400
    references[manifest["qualification"]["request_source"]] = 0o400
    return references


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
    target = activation_package.rooted(root, FIXED_PACKAGE_PATH)
    live = root == Path("/")
    if target.exists():
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


def _remove_fixed_package(manifest: dict[str, Any], root: Path) -> None:
    target = activation_package.rooted(root, FIXED_PACKAGE_PATH)
    if not target.exists():
        return
    _verify_fixed_package(manifest, root)
    _remove_package_tree(root, FIXED_PACKAGE_PATH, expected_sources=set(_package_references(manifest)))


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
        return dict(unit)

    def provision(self, identities: dict[str, object]) -> None:
        state = self._read()
        for role, identity in identities.items():
            existing = state["identities"].get(identity["user"])
            expected = {
                "user": identity["user"], "group": identity["group"], "uid": identity["uid"], "gid": identity["gid"],
                "primary_gid": identity["gid"], "home": identity["home"], "shell": identity["shell"],
                "supplementary_groups": identity["supplementary_groups"],
            }
            if existing is not None and existing != expected:
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
            ("/var/lib/buzzci/seccomp", 0o700),
            ("/var/lib/buzzci/activation", 0o700),
            ("/var/lib/buzzci/activation/receipts", 0o700),
            ("/var/lib/buzzci/execd-v2", 0o700),
            (activation_package.EXECD_INTENT_ROOT, 0o700),
            (activation_package.EXECD_BINDING_ROOT, 0o700),
            (activation_package.EXECD_EVIDENCE_ROOT, 0o700),
            (activation_package.EXECD_TEARDOWN_ROOT, 0o700),
            (activation_package.EXECD_ATTEMPT_ROOT, 0o711),
        ):
            directory = activation_package.rooted(self.root, target)
            directory.mkdir(parents=True, mode=mode, exist_ok=True)
            directory.chmod(mode)
        _require_receipt_root(self.root, self.planned_identities["controld"]["gid"])

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
                group = self.group(policy["group"])
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
) -> dict[str, object]:
    components = _component_readback(manifest, root, allow_installable_absent=True)
    principals = _identity_readback(driver, manifest["identities"], allow_absent=True)
    access_group = _access_group_readback(driver, manifest["access_group"], allow_absent=True)
    managed = _managed_readback(manifest, root, {"absent", "staged"})
    for role in ("runner_config", "controld_config"):
        if managed[role] != "staged":
            raise ValueError(f"frozen component config is absent before activation: {role}")
    units = _preflight_units(driver) if require_dormant else {}
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
        "acceptance_generated": _generated_records(root, generated),
        "acceptance_ledger_prior": _capture_acceptance_ledger(manifest, root),
        "fixed_package": {
            "path": FIXED_PACKAGE_PATH,
            "manifest_sha256": activation_package.digest(activation_package.canonical_json(manifest)),
        },
        "systemd_before": _unit_readback(
            driver,
            sorted(set(activation_package.START_ORDER + activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT])),
        ),
        "qualification": None,
        "qualification_zero": None,
        "last_error": None,
    }


def _bind_receipt(receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
    expected_keys = {
        "schema", "activation_id", "package_digest", "source_commit", "state", "created_at", "updated_at",
        "principals_retained_on_rollback", "targets", "acceptance_generated", "acceptance_ledger_prior",
        "fixed_package", "systemd_before", "qualification", "qualification_zero", "last_error",
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
        "controld_acceptance_binding", "acceptance_control_config", "acceptance_driver_config",
    }:
        raise ValueError("receipt acceptance generated targets differ")
    if receipt["fixed_package"] != {
        "path": FIXED_PACKAGE_PATH,
        "manifest_sha256": activation_package.digest(activation_package.canonical_json(manifest)),
    }:
        raise ValueError("receipt fixed activation package binding differs")
    _validate_qualification_zero_state(receipt["qualification_zero"], receipt)


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
    receipt: dict[str, Any], driver: LiveSystemd | FakeSystemd,
) -> dict[str, dict[str, str]]:
    prior = receipt["systemd_before"]
    observed = _unit_readback(driver, sorted(prior))
    for name, expected in prior.items():
        for field in ("ActiveState", "UnitFileState"):
            if observed[name][field] != expected[field]:
                raise ValueError(f"systemd prior readback differs for {name} {field}")
    return observed


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


def _staged_zero_readback(
    manifest: dict[str, Any], driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    names = sorted(set(activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT]))
    units = _unit_readback(driver, names)
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


ZERO_CLI_ACTIONS = {
    "prepare-qualification-zero": "prepare_qualification_zero",
    "finalize-qualification-zero": "finalize_qualification_zero",
    "prove-qualification-zero": "prove_qualification_zero",
}
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
    units = _unit_readback(driver, sorted(set(activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT])))
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


def _prepare_qualification_zero(
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


def _finalize_qualification_zero(
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


def stage(
    manifest: dict[str, Any],
    payloads: dict[str, bytes],
    root: Path,
    driver: LiveSystemd | FakeSystemd,
    binding: dict[str, object],
) -> dict[str, object]:
    generated = _generated_acceptance_files(manifest, binding)
    existing = _read_receipt(root)
    if existing is not None:
        if existing.get("state") == "rolled_back":
            pass
        else:
            _bind_receipt(existing, manifest)
            if existing["state"] == "staged_zero":
                _bind_generated_plan(existing["acceptance_generated"], generated)
                return {
                    "status": "unchanged",
                    "state": "staged_zero",
                    "capacity": 0,
                    "managed_targets": _verify_phase(manifest, root, "staged"),
                    "principals": _identity_readback(driver, manifest["identities"], allow_absent=False),
                    "access_group": _access_group_readback(driver, manifest["access_group"], allow_absent=False),
                    "acceptance_generated": _verify_generated(root, existing["acceptance_generated"]),
                    "fixed_package": _verify_fixed_package(manifest, root),
                    "staged_zero": _staged_zero_readback(manifest, driver),
                }
            raise ValueError(f"activation receipt requires rollback from {existing['state']}")
    report = preflight(manifest, root, driver, require_dormant=True, payloads=payloads)
    receipt = _new_receipt(manifest, root, driver, generated)
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    try:
        _apply_phase(manifest, payloads, root, "staged")
        driver.provision(manifest["identities"])
        driver.tmpfiles()
        fixed_package = _install_fixed_package(manifest, payloads, root)
        _apply_generated(root, receipt["acceptance_generated"])
        driver.daemon_reload()
        _stop_to_zero(driver)
        _remove_captured_ledger(root, receipt["acceptance_ledger_prior"])
        for unit in activation_package.STAGED_ZERO_UNITS:
            driver.start(unit)
        principals = _identity_readback(driver, manifest["identities"], allow_absent=False)
        access_group = _access_group_readback(driver, manifest["access_group"], allow_absent=False)
        targets = _verify_phase(manifest, root, "staged")
        generated_readback = _verify_generated(root, receipt["acceptance_generated"])
        staged_zero = _staged_zero_readback(manifest, driver)
        receipt.update({"state": "staged_zero", "updated_at": utc_now()})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        return {
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
            "staged_zero": staged_zero,
        }
    except BaseException as error:
        receipt.update({"state": "stage_failed", "updated_at": utc_now(), "last_error": str(error)})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        raise


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
        if policy["group"] == activation_package.ACCESS_GROUP_NAME:
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
    credential_options = _qualification_credentials(manifest, root)
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
    finally:
        os.close(program_fd)
    if len(response) > MAX_COMMAND_OUTPUT or len(error_output) > MAX_COMMAND_OUTPUT:
        raise ValueError("qualification output exceeded its fixed bound")
    if process.returncode != 0:
        raise ValueError(f"qualification command failed with status {process.returncode}")
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
    generated: list[dict[str, object]],
) -> dict[str, object]:
    errors = _stop_zero_errors(driver)
    for entry in manifest["entries"]:
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
        staged_zero = _staged_zero_readback(manifest, driver)
    except BaseException as error:
        errors.append(f"capacity-zero readback: {error}")
    if errors:
        raise ValueError("return-to-zero failures: " + "; ".join(errors))
    return {"managed_targets": targets, "staged_zero": staged_zero}


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
    _verify_generated(root, receipt["acceptance_generated"])
    _keyholder_config_readback(manifest, root, payloads)
    _staged_zero_readback(manifest, driver)
    receipt.update({"state": "activating", "updated_at": utc_now(), "last_error": None})
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    try:
        driver.stop("buzz-ci-controld.service")
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
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
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
            _return_to_staged_zero(manifest, payloads, root, driver, receipt["acceptance_generated"])
        except BaseException as nested:
            rollback_error = str(nested)
        receipt.update({
            "state": "staged_zero" if rollback_error is None else "rollback_failed",
            "updated_at": utc_now(),
            "last_error": str(error),
        })
        if rollback_error is not None:
            receipt["last_error"] = f"activation={error}; rollback={rollback_error}"
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
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
    expected_roles = {"controld_acceptance_binding", "acceptance_control_config", "acceptance_driver_config"}
    if not isinstance(records, list) or len(records) != len(expected_roles):
        raise ValueError("acceptance generated receipt records are invalid")
    seen: set[str] = set()
    for record in records:
        required = {"role", "target", "sha256", "mode", "uid", "gid", "payload_base64", "prior"}
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
        current_is_generated = observed == record["sha256"] and _metadata_dict(metadata) == expected_metadata
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


def _restore_prior_best_effort(receipt: dict[str, Any], manifest: dict[str, Any], root: Path) -> tuple[list[str], list[str]]:
    records = _validate_receipt_targets(receipt, manifest)
    restored: list[str] = []
    errors: list[str] = []
    for entry in reversed(manifest["entries"]):
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


def _prior_readback(receipt: dict[str, Any], manifest: dict[str, Any], root: Path) -> dict[str, str]:
    records = _validate_receipt_targets(receipt, manifest)
    result: dict[str, str] = {}
    for entry in manifest["entries"]:
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


def rollback(
    manifest: dict[str, Any], root: Path, driver: LiveSystemd | FakeSystemd,
) -> dict[str, object]:
    receipt = _read_receipt(root)
    if receipt is None:
        raise ValueError("rollback requires an activation receipt")
    _bind_receipt(receipt, manifest)
    if receipt["state"] == "rolled_back":
        if activation_package.rooted(root, FIXED_PACKAGE_PATH).exists():
            raise ValueError("fixed activation package remains after rollback")
        return {
            "status": "unchanged",
            "state": "rolled_back",
            "capacity": 0,
            "managed_targets": _managed_readback(manifest, root, {"absent", "staged"}),
            "acceptance_generated": _generated_prior_readback(receipt, root),
            "acceptance_ledger": _acceptance_ledger_prior_readback(receipt, root),
            "fixed_package": "absent",
            "units": _systemd_prior_readback(receipt, driver),
        }
    if receipt["state"] not in {
        "preparing", "stage_failed", "staged_zero", "activating", "active_one", "preparing_zero", "rollback_failed",
    }:
        raise ValueError(f"rollback cannot start from receipt state {receipt['state']}")
    try:
        _validate_receipt_targets(receipt, manifest)
        _restore_prior(receipt, manifest, root, apply=False)
        _validate_generated_records(receipt, root, apply=False)
    except BaseException as error:
        receipt.update({"state": "rollback_failed", "updated_at": utc_now(), "last_error": str(error)})
        _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
        raise
    errors = _stop_zero_errors(driver)
    restored, restore_errors = _restore_prior_best_effort(receipt, manifest, root)
    errors.extend(restore_errors)
    generated_restored, generated_errors = _restore_generated_prior_best_effort(receipt, root)
    errors.extend(generated_errors)
    try:
        _remove_fixed_package(manifest, root)
    except BaseException as error:
        errors.append(f"remove fixed activation package: {error}")
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
        targets = _prior_readback(receipt, manifest, root)
    except BaseException as error:
        errors.append(f"prior target readback: {error}")
    try:
        errors.extend(_restore_systemd_prior_errors(receipt, driver))
        units = _systemd_prior_readback(receipt, driver)
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
    receipt.update({"state": "rolled_back", "updated_at": utc_now(), "last_error": None})
    _write_receipt(root, receipt, manifest["identities"]["controld"]["gid"])
    return {
        "status": "rolled_back",
        "state": "rolled_back",
        "capacity": 0,
        "activation_id": manifest["activation_id"],
        "restored_targets": restored,
        "restored_acceptance_targets": generated_restored,
        "managed_targets": targets,
        "acceptance_generated": generated_prior,
        "acceptance_ledger": ledger_prior,
        "fixed_package": "absent",
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
        qualification_zero = receipt["qualification_zero"]
        if isinstance(qualification_zero, dict) and qualification_zero["phase"] == "finalized":
            return {
                "status": "qualification_zero_finalized", "state": "staged_zero", "capacity": 0,
                "managed_targets": _managed_readback(manifest, root, {"staged", "active"}),
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
            "staged_zero": _staged_zero_readback(manifest, driver),
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
    return FakeSystemd(root, fake_state, manifest["identities"], manifest["access_group"], manifest["socket_policy"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    ordinary_actions = ("check", "stage", "activate", "qualify", "rollback")
    parser.add_argument("action", choices=ordinary_actions + tuple(ZERO_CLI_ACTIONS))
    parser.add_argument("--package", type=Path)
    parser.add_argument("--scenario", type=Path)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--fake-systemd-state", type=Path)
    arguments = parser.parse_args()
    root = Path(os.path.abspath(arguments.root))
    live = arguments.fake_systemd_state is None
    try:
        if arguments.action in ZERO_CLI_ACTIONS:
            if (
                arguments.package is not None or arguments.scenario is not None or root != Path("/")
                or arguments.fake_systemd_state is not None
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
