#!/usr/bin/env python3
"""Fail-closed verifier for a capacity-one acceptance pass receipt."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_STAGES_BYTES = 4096
DRIVER_VERSION = "buzz-ci-capacity-one-driver/v2"
RECEIPT_VERSION = "buzz-ci-capacity-one-acceptance-receipt/v2"
ZERO_TRANSITION_VERSION = "buzz-ci-capacity-one-zero-transition/v1"
ZERO_PROOF_VERSION = "buzz-ci-capacity-one-zero-proof/v1"
EXPECTED_STAGES_PATH = Path("/usr/libexec/buzz-ci-acceptance-expected-stages.json")
EXPECTED_STAGES_MODE = 0o644
EXPECTED_STAGES_SHA256 = "5129005b9fcbf56c1f67aeed7bd02bd2356626b6819120032b28ae4824371178"
EXPECTED_STAGES_CANONICAL_SHA256 = "9a02a936620acb6fea03d9d71141d6b7f9b2d625ad0e194534a84149c705eae6"
EXPECTED_STAGES = (
    "capacity_zero_closed",
    "capacity_one_open",
    "manifest_identity",
    "approval_grant",
    "grant_resume",
    "first_attempt_terminal",
    "authenticated_export",
    "failed_manifest_identity",
    "failed_attempt_running",
    "failed_attempt_terminal",
    "rerun_separation",
    "cancellation_terminal",
    "tombstone_folding",
    "controller_restart_recovery",
    "runner_restart_recovery",
    "prepare_capacity_zero",
)
OPERATIONS = [
    "observe_initial",
    "set_capacity_one",
    "submit_manifest",
    "approve_grant",
    "resume_grant",
    "await_first_terminal",
    "export_first_evidence",
    "submit_failure_manifest",
    "resume_failure",
    "await_failure_terminal",
    "rerun",
    "cancel_rerun",
    "tombstone_rerun",
    "restart_controller",
    "restart_runner",
    "set_capacity_zero",
]


class ReceiptError(ValueError):
    """Stable verifier rejection without embedding receipt data."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError("duplicate JSON field")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > MAX_JSON_BYTES:
            raise ReceiptError("input metadata rejected")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            raw = stream.read(MAX_JSON_BYTES + 1)
    except OSError as error:
        raise ReceiptError("input unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise ReceiptError("input size rejected")
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError("invalid JSON") from error


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def _exact(value: Any, required: list[str], optional: list[str] | None = None) -> dict[str, Any]:
    _require(isinstance(value, dict), "object shape rejected")
    allowed = set(required) | set(optional or [])
    _require(set(value) == set(required) | (set(value) & set(optional or [])), "object fields rejected")
    _require(set(value) <= allowed, "object fields rejected")
    return value


def _integer(value: Any, minimum: int = 0, maximum: int | None = None) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), "integer rejected")
    _require(value >= minimum and (maximum is None or value <= maximum), "integer range rejected")
    return value


def _hex(value: Any, lengths: tuple[int, ...]) -> str:
    _require(isinstance(value, str) and len(value) in lengths, "hex field rejected")
    _require(any(character != "0" for character in value), "zero hex field rejected")
    _require(all(character in "0123456789abcdef" for character in value), "hex field rejected")
    return value


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError) as error:
        raise ReceiptError("canonical JSON rejected") from error


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _open_absolute_nofollow(path: Path) -> int:
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise ReceiptError("stage fixture path rejected")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = child
        return os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
    except OSError as error:
        raise ReceiptError("stage fixture unavailable") from error
    finally:
        os.close(directory)


def load_expected_stages(path: Path, expected_uid: int, expected_gid: int) -> list[str]:
    descriptor = -1
    try:
        descriptor = _open_absolute_nofollow(path)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != EXPECTED_STAGES_MODE
            or not 0 < metadata.st_size <= MAX_STAGES_BYTES
        ):
            raise ReceiptError("stage fixture metadata rejected")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, MAX_STAGES_BYTES + 1 - size):
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_STAGES_BYTES:
                raise ReceiptError("stage fixture size rejected")
        raw = b"".join(chunks)
    except OSError as error:
        raise ReceiptError("stage fixture unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) != metadata.st_size or hashlib.sha256(raw).hexdigest() != EXPECTED_STAGES_SHA256:
        raise ReceiptError("stage fixture integrity rejected")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError("stage fixture JSON rejected") from error
    _require(value == list(EXPECTED_STAGES), "stage fixture schema rejected")
    _require(
        hashlib.sha256(_canonical(value)).hexdigest() == EXPECTED_STAGES_CANONICAL_SHA256,
        "stage fixture canonical vector rejected",
    )
    return value


def _ordered_evidence(value: Any) -> dict[str, Any]:
    value = _exact(value, ["name", "sha256", "bytes"])
    _require(
        isinstance(value["name"], str)
        and 0 < len(value["name"]) <= 255
        and "/" not in value["name"]
        and "\\" not in value["name"],
        "evidence name rejected",
    )
    return {
        "name": value["name"],
        "sha256": _hex(value["sha256"], (64,)),
        "bytes": _integer(value["bytes"], 1),
    }


def _ordered_approval(value: Any) -> dict[str, Any]:
    value = _exact(value, ["approval_id", "grant_event_id", "grant_digest", "approved_by", "resumed"])
    _require(isinstance(value["resumed"], bool), "approval resume rejected")
    return {
        "approval_id": _hex(value["approval_id"], (32,)),
        "grant_event_id": _hex(value["grant_event_id"], (64,)),
        "grant_digest": _hex(value["grant_digest"], (64,)),
        "approved_by": _hex(value["approved_by"], (64,)),
        "resumed": value["resumed"],
    }


def _ordered_attempt(value: Any) -> dict[str, Any]:
    required = [
        "attempt_id", "attempt", "state", "conclusion", "integrated_candidate_sha",
        "request_digest", "manifest_digest", "source_oid", "artifacts",
    ]
    optional = ["parent_attempt_id", "evidence_set_digest", "log"]
    value = _exact(value, required, optional)
    _require(value["state"] in {"queued", "running", "terminal", "tombstoned"}, "attempt state rejected")
    _require(value["conclusion"] in {"none", "success", "failure", "cancelled", "timed_out", "infrastructure_failure"}, "attempt conclusion rejected")
    _require(isinstance(value["artifacts"], list) and len(value["artifacts"]) <= 64, "artifact list rejected")
    result: dict[str, Any] = {
        "attempt_id": _hex(value["attempt_id"], (32,)),
        "attempt": _integer(value["attempt"], 1, 2),
    }
    if "parent_attempt_id" in value:
        result["parent_attempt_id"] = _hex(value["parent_attempt_id"], (32,))
    result.update({
        "state": value["state"],
        "conclusion": value["conclusion"],
        "integrated_candidate_sha": _hex(value["integrated_candidate_sha"], (40, 64)),
        "request_digest": _hex(value["request_digest"], (64,)),
        "manifest_digest": _hex(value["manifest_digest"], (64,)),
        "source_oid": _hex(value["source_oid"], (40, 64)),
    })
    if "evidence_set_digest" in value:
        result["evidence_set_digest"] = _hex(value["evidence_set_digest"], (64,))
    if "log" in value:
        result["log"] = _ordered_evidence(value["log"])
    result["artifacts"] = [_ordered_evidence(item) for item in value["artifacts"]]
    return result


def _ordered_run(value: Any) -> dict[str, Any]:
    required = [
        "run_id", "integrated_candidate_sha", "request_digest", "manifest_digest",
        "source_oid", "state", "aggregate_conclusion", "attempts",
    ]
    value = _exact(value, required, ["approval", "selected_attempt_id"])
    _require(value["state"] in {"awaiting_approval", "granted_awaiting_resume", "running", "terminal"}, "run state rejected")
    _require(value["aggregate_conclusion"] in {"none", "success", "failure", "cancelled", "timed_out", "infrastructure_failure"}, "run conclusion rejected")
    _require(isinstance(value["attempts"], list) and len(value["attempts"]) <= 2, "attempt list rejected")
    result: dict[str, Any] = {
        "run_id": _hex(value["run_id"], (32,)),
        "integrated_candidate_sha": _hex(value["integrated_candidate_sha"], (40, 64)),
        "request_digest": _hex(value["request_digest"], (64,)),
        "manifest_digest": _hex(value["manifest_digest"], (64,)),
        "source_oid": _hex(value["source_oid"], (40, 64)),
        "state": value["state"],
        "aggregate_conclusion": value["aggregate_conclusion"],
    }
    if "approval" in value:
        result["approval"] = _ordered_approval(value["approval"])
    if "selected_attempt_id" in value:
        result["selected_attempt_id"] = _hex(value["selected_attempt_id"], (32,))
    result["attempts"] = [_ordered_attempt(item) for item in value["attempts"]]
    return result


def _ordered_snapshot(value: Any) -> dict[str, Any]:
    required = [
        "capacity", "admission", "active_run_count", "active_attempt_count",
        "controller_generation", "runner_generation",
    ]
    value = _exact(value, required, ["run"])
    _require(value["admission"] in {"closed", "open"}, "admission rejected")
    result: dict[str, Any] = {
        "capacity": _integer(value["capacity"], 0, 1),
        "admission": value["admission"],
        "active_run_count": _integer(value["active_run_count"], 0, 1),
        "active_attempt_count": _integer(value["active_attempt_count"], 0, 1),
        "controller_generation": _integer(value["controller_generation"], 1),
        "runner_generation": _integer(value["runner_generation"], 1),
    }
    if "run" in value:
        result["run"] = _ordered_run(value["run"])
    return result


def _ordered_export(value: Any) -> dict[str, Any]:
    required = [
        "authenticated", "subject", "generation", "authorization_digest", "attempt_id",
        "request_digest", "manifest_digest", "evidence_set_digest", "objects",
    ]
    value = _exact(value, required)
    _require(value["authenticated"] is True, "export authentication rejected")
    _require(isinstance(value["objects"], list) and 0 < len(value["objects"]) <= 65, "export objects rejected")
    return {
        "authenticated": True,
        "subject": _hex(value["subject"], (64,)),
        "generation": _integer(value["generation"], 1, 9_007_199_254_740_991),
        "authorization_digest": _hex(value["authorization_digest"], (64,)),
        "attempt_id": _hex(value["attempt_id"], (32,)),
        "request_digest": _hex(value["request_digest"], (64,)),
        "manifest_digest": _hex(value["manifest_digest"], (64,)),
        "evidence_set_digest": _hex(value["evidence_set_digest"], (64,)),
        "objects": [_ordered_evidence(item) for item in value["objects"]],
    }


def _ordered_scenario(value: Any) -> dict[str, Any]:
    value = _exact(value, ["schema_version", "fixture", "driver"])
    _require(value["schema_version"] == "buzz-ci-capacity-one-scenario/v2", "scenario version rejected")
    fixture_fields = [
        "integrated_candidate_sha", "activation_id", "activation_package_digest", "run_id",
        "failure_run_id", "failure_selector", "job_id", "request_digest", "failure_request_digest", "manifest_digest", "source_oid", "approval_id",
        "grant_event_id", "grant_digest", "approved_by", "export_subject",
        "export_generation", "export_authorization_digest", "controller_generation", "runner_generation",
        "expected_log", "expected_failure_log", "expected_artifacts",
    ]
    fixture = _exact(value["fixture"], fixture_fields)
    _hex(fixture["integrated_candidate_sha"], (40, 64))
    _require(isinstance(fixture["activation_id"], str) and 0 < len(fixture["activation_id"]) <= 128, "activation ID rejected")
    for name in ["activation_package_digest", "request_digest", "failure_request_digest", "manifest_digest", "grant_event_id", "grant_digest", "approved_by", "export_subject", "export_authorization_digest"]:
        _hex(fixture[name], (64,))
    _integer(fixture["export_generation"], 1, 9_007_199_254_740_991)
    _hex(fixture["run_id"], (32,)); _hex(fixture["failure_run_id"], (32,)); _hex(fixture["approval_id"], (32,)); _hex(fixture["source_oid"], (40, 64))
    _require(fixture["run_id"] != fixture["failure_run_id"], "run identities must be distinct")
    _require(fixture["request_digest"] != fixture["failure_request_digest"], "request identities must be distinct")
    _require(
        isinstance(fixture["job_id"], str)
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", fixture["job_id"]) is not None,
        "job ID rejected",
    )
    selector = _exact(
        fixture["failure_selector"],
        ["schema_version", "selector", "job_id", "run_id", "attempt", "sha256"],
    )
    _require(
        selector["schema_version"] == "buzz-ci-capacity-one-fixture-selector/v1"
        and selector["selector"] == "deterministic-failure"
        and selector["job_id"] == fixture["job_id"]
        and selector["attempt"] == 1,
        "failure selector rejected",
    )
    try:
        selector_run_id = str(uuid.UUID(selector["run_id"]))
    except (AttributeError, TypeError, ValueError) as error:
        raise ReceiptError("failure selector run ID rejected") from error
    _require(selector_run_id == selector["run_id"], "failure selector run ID rejected")
    selector_lines = (
        "buzz-ci:capacity-one:fixture-selector:v1",
        selector["schema_version"], selector["selector"], selector["job_id"],
        uuid.UUID(selector_run_id).hex, str(selector["attempt"]),
    )
    selector_sha256 = hashlib.sha256(("\n".join(selector_lines) + "\n").encode("ascii")).hexdigest()
    _require(
        selector["sha256"] == selector_sha256
        and uuid.UUID(selector_run_id).hex == fixture["failure_run_id"],
        "failure selector binding rejected",
    )
    _integer(fixture["controller_generation"], 1); _integer(fixture["runner_generation"], 1)
    _ordered_evidence(fixture["expected_log"])
    _ordered_evidence(fixture["expected_failure_log"])
    _require(isinstance(fixture["expected_artifacts"], list) and len(fixture["expected_artifacts"]) == 1, "expected artifacts rejected")
    for item in fixture["expected_artifacts"]:
        _ordered_evidence(item)
    driver_fields = ["control", "observe", "export", "controller_process", "runner_process", "timeout_seconds"]
    driver = _exact(value["driver"], driver_fields)
    for name in driver_fields[:-1]:
        endpoint = _exact(driver[name], ["program"], ["args"])
        _require(endpoint["program"] == "/usr/libexec/buzz-ci-capacity-one-driver", "driver endpoint rejected")
        _require(endpoint.get("args", []) == [], "driver arguments rejected")
    _integer(driver["timeout_seconds"], 1, 300)
    ordered_fixture = {name: fixture[name] for name in fixture_fields}
    ordered_fixture["failure_selector"] = {
        name: selector[name]
        for name in ("schema_version", "selector", "job_id", "run_id", "attempt", "sha256")
    }
    ordered_fixture["expected_log"] = _ordered_evidence(fixture["expected_log"])
    ordered_fixture["expected_failure_log"] = _ordered_evidence(fixture["expected_failure_log"])
    ordered_fixture["expected_artifacts"] = [_ordered_evidence(item) for item in fixture["expected_artifacts"]]
    ordered_driver: dict[str, Any] = {}
    for name in driver_fields[:-1]:
        ordered_driver[name] = {"program": driver[name]["program"], "args": driver[name].get("args", [])}
    ordered_driver["timeout_seconds"] = driver["timeout_seconds"]
    return {"schema_version": value["schema_version"], "fixture": ordered_fixture, "driver": ordered_driver}


def _validate_run_binding(run: dict[str, Any], fixture: dict[str, Any], failure: bool = False) -> None:
    run_id = fixture["failure_run_id"] if failure else fixture["run_id"]
    request_digest = fixture["failure_request_digest"] if failure else fixture["request_digest"]
    _require(run["run_id"] == run_id and run["request_digest"] == request_digest, "run binding rejected")
    for name in ["integrated_candidate_sha", "manifest_digest", "source_oid"]:
        _require(run[name] == fixture[name], "run binding rejected")
    ids: set[str] = set()
    for attempt in run["attempts"]:
        _require(attempt["request_digest"] == request_digest, "attempt binding rejected")
        for name in ["integrated_candidate_sha", "manifest_digest", "source_oid"]:
            _require(attempt[name] == fixture[name], "attempt binding rejected")
        _require(attempt["attempt_id"] not in ids, "duplicate attempt rejected")
        ids.add(attempt["attempt_id"])


def _validate_approval(run: dict[str, Any], fixture: dict[str, Any], resumed: bool) -> None:
    _require("approval" in run, "approval missing")
    approval = run["approval"]
    for name in ["approval_id", "grant_event_id", "grant_digest", "approved_by"]:
        _require(approval[name] == fixture[name], "approval binding rejected")
    _require(approval["resumed"] is resumed, "approval resume rejected")


def _validate_first(attempt: dict[str, Any], fixture: dict[str, Any], terminal: bool) -> None:
    _require(attempt["attempt"] == 1 and "parent_attempt_id" not in attempt, "first attempt lineage rejected")
    if not terminal:
        _require(attempt["state"] == "running" and attempt["conclusion"] == "none", "first attempt state rejected")
        _require("evidence_set_digest" not in attempt and "log" not in attempt and attempt["artifacts"] == [], "premature evidence rejected")
        return
    _require(attempt["state"] == "terminal" and attempt["conclusion"] == "success", "first terminal rejected")
    _require(attempt.get("log") == fixture["expected_log"], "terminal log rejected")
    _require(attempt["artifacts"] == fixture["expected_artifacts"], "terminal artifacts rejected")
    _hex(attempt.get("evidence_set_digest"), (64,))


def _validate_failed_first(attempt: dict[str, Any], fixture: dict[str, Any], terminal: bool) -> None:
    _require(attempt["attempt"] == 1 and "parent_attempt_id" not in attempt, "failed-parent lineage rejected")
    if not terminal:
        _require(attempt["state"] == "running" and attempt["conclusion"] == "none", "failed-parent running state rejected")
        _require("evidence_set_digest" not in attempt and "log" not in attempt and attempt["artifacts"] == [], "premature failed-parent evidence rejected")
        return
    _require(attempt["state"] == "terminal" and attempt["conclusion"] == "failure", "failed-parent terminal rejected")
    _require(attempt.get("log") == fixture["expected_failure_log"], "failed-parent log rejected")
    _require(attempt["artifacts"] == [], "failed-parent artifacts rejected")
    _hex(attempt.get("evidence_set_digest"), (64,))


def _validate_snapshots(checks: list[dict[str, Any]], fixture: dict[str, Any]) -> None:
    snapshots = [check["snapshot"] for check in checks]
    for index, snapshot in enumerate(snapshots, start=1):
        expected_capacity = 0 if index in {1, 16} else 1
        expected_admission = "closed" if expected_capacity == 0 else "open"
        _require(snapshot["capacity"] == expected_capacity and snapshot["admission"] == expected_admission, "capacity snapshot rejected")
        active = 1 if index in {5, 9, 11} else 0
        _require(snapshot["active_run_count"] == active and snapshot["active_attempt_count"] == active, "active count rejected")
        if index <= 2:
            _require("run" not in snapshot, "run exists before submission")
        else:
            _require("run" in snapshot, "run snapshot missing")
            _validate_run_binding(snapshot["run"], fixture, failure=index >= 8)
    _require(snapshots[0]["controller_generation"] == fixture["controller_generation"] and snapshots[0]["runner_generation"] == fixture["runner_generation"], "initial generation rejected")
    for index in range(1, 13):
        _require(snapshots[index]["controller_generation"] == snapshots[index - 1]["controller_generation"] and snapshots[index]["runner_generation"] == snapshots[index - 1]["runner_generation"], "unexpected generation change")
    _require(snapshots[13]["controller_generation"] > snapshots[12]["controller_generation"] and snapshots[13]["runner_generation"] >= snapshots[12]["runner_generation"], "controller restart generation rejected")
    _require(snapshots[14]["runner_generation"] > snapshots[13]["runner_generation"] and snapshots[14]["controller_generation"] >= snapshots[13]["controller_generation"], "runner restart generation rejected")
    _require((snapshots[15]["controller_generation"], snapshots[15]["runner_generation"]) == (snapshots[14]["controller_generation"], snapshots[14]["runner_generation"]), "prepare-zero generation rejected")

    run3, run4, run5, run6, run7, run8, run9, run10, run11, run12, run13, run14, run15, run16 = [snapshot["run"] for snapshot in snapshots[2:]]
    _require(run3["state"] == "awaiting_approval" and run3["aggregate_conclusion"] == "none" and "approval" not in run3 and "selected_attempt_id" not in run3 and run3["attempts"] == [], "submission snapshot rejected")
    _validate_approval(run4, fixture, False)
    _require(run4["state"] == "granted_awaiting_resume" and run4["aggregate_conclusion"] == "none" and "selected_attempt_id" not in run4 and run4["attempts"] == [], "grant snapshot rejected")
    _validate_approval(run5, fixture, True)
    _require(run5["state"] == "running" and run5["aggregate_conclusion"] == "none" and "selected_attempt_id" not in run5 and len(run5["attempts"]) == 1, "resume snapshot rejected")
    first_id = run5["attempts"][0]["attempt_id"]
    _validate_first(run5["attempts"][0], fixture, False)
    for run in [run6, run7]:
        _validate_approval(run, fixture, True)
        _require(run["state"] == "terminal" and run["aggregate_conclusion"] == "success" and run.get("selected_attempt_id") == first_id and len(run["attempts"]) == 1, "first terminal snapshot rejected")
        _validate_first(run["attempts"][0], fixture, True)
        _require(run["attempts"][0]["attempt_id"] == first_id, "first attempt identity changed")
    _require(run7 == run6, "export changed durable snapshot")
    _validate_approval(run8, fixture, False)
    _require(run8["state"] == "granted_awaiting_resume" and run8["aggregate_conclusion"] == "none" and "selected_attempt_id" not in run8 and run8["attempts"] == [], "failed-parent submission rejected")
    _validate_approval(run9, fixture, True)
    _require(run9["state"] == "running" and run9["aggregate_conclusion"] == "none" and len(run9["attempts"]) == 1, "failed-parent running rejected")
    failed_id = run9["attempts"][0]["attempt_id"]
    _validate_failed_first(run9["attempts"][0], fixture, False)
    _validate_approval(run10, fixture, True)
    _require(run10["state"] == "terminal" and run10["aggregate_conclusion"] == "failure" and run10.get("selected_attempt_id") == failed_id and len(run10["attempts"]) == 1, "failed-parent terminal snapshot rejected")
    _validate_failed_first(run10["attempts"][0], fixture, True)
    _require(run10["attempts"][0]["attempt_id"] == failed_id, "failed-parent attempt identity changed")
    for run in [run11, run12, run13, run14, run15, run16]:
        _validate_approval(run, fixture, True)
        _require(len(run["attempts"]) == 2, "rerun evidence missing")
        _validate_failed_first(run["attempts"][0], fixture, True)
        _require(run["attempts"][0] == run10["attempts"][0], "failed-parent evidence changed")
    second_id = run11["attempts"][1]["attempt_id"]
    _require(second_id != failed_id and run11["attempts"][1].get("parent_attempt_id") == failed_id and run11["attempts"][1]["attempt"] == 2, "rerun lineage rejected")
    _require(run11["state"] == "running" and run11["aggregate_conclusion"] == "none" and "selected_attempt_id" not in run11 and run11["attempts"][1]["state"] == "running" and run11["attempts"][1]["conclusion"] == "none", "rerun snapshot rejected")
    for run in [run11, run12, run13, run14, run15, run16]:
        second = run["attempts"][1]
        _require(second["attempt_id"] == second_id and second["attempt"] == 2 and second.get("parent_attempt_id") == failed_id, "second attempt lineage changed")
        _require("evidence_set_digest" not in second and "log" not in second and second["artifacts"] == [], "cancelled attempt evidence rejected")
    _require(run12["state"] == "terminal" and run12["aggregate_conclusion"] == "cancelled" and run12.get("selected_attempt_id") == second_id and run12["attempts"][1]["state"] == "terminal" and run12["attempts"][1]["conclusion"] == "cancelled", "cancellation snapshot rejected")
    _require(run13["state"] == "terminal" and run13["aggregate_conclusion"] == "failure" and run13.get("selected_attempt_id") == failed_id and run13["attempts"][1]["state"] == "tombstoned" and run13["attempts"][1]["conclusion"] == "cancelled", "tombstone fold rejected")
    _require(run14 == run13 and run15 == run13 and run16 == run13, "restart or zero prepare changed durable run")

    export = checks[6]["export"]
    terminal = run6["attempts"][0]
    _require(
        export["subject"] == fixture["export_subject"]
        and export["generation"] == fixture["export_generation"]
        and export["authorization_digest"] == fixture["export_authorization_digest"],
        "export authority rejected",
    )
    _require(export["attempt_id"] == first_id and export["request_digest"] == fixture["request_digest"] and export["manifest_digest"] == fixture["manifest_digest"], "export binding rejected")
    _require(export["evidence_set_digest"] == terminal["evidence_set_digest"], "export evidence set rejected")
    _require(export["objects"] == [fixture["expected_log"], *fixture["expected_artifacts"]], "export objects rejected")


def _ordered_zero_proof(value: Any) -> dict[str, Any]:
    fields = [
        "schema_version", "scenario_sha256", "activation_id", "activation_package_digest",
        "integrated_candidate_sha", "capacity", "admission", "controller_generation",
        "runner_generation", "controld_service_active", "controld_acceptance_socket_active",
        "controld_acceptance_socket_present",
    ]
    value = _exact(value, fields)
    _require(value["schema_version"] == ZERO_PROOF_VERSION, "zero proof version rejected")
    _hex(value["scenario_sha256"], (64,)); _hex(value["activation_package_digest"], (64,)); _hex(value["integrated_candidate_sha"], (40, 64))
    _require(isinstance(value["activation_id"], str) and 0 < len(value["activation_id"]) <= 128, "zero activation rejected")
    _require(value["capacity"] == 0 and value["admission"] == "closed", "zero state rejected")
    _integer(value["controller_generation"], 1); _integer(value["runner_generation"], 1)
    for name in fields[-3:]:
        _require(value[name] is False, "zero transport proof rejected")
    return {name: value[name] for name in fields}


def _ordered_zero_request(value: Any) -> dict[str, Any]:
    required = ["sequence", "operation", "operation_id", "scenario_sha256", "activation_id", "activation_package_digest", "integrated_candidate_sha", "failed_stage"]
    optional = ["final_response_sha256", "expected_controller_generation", "expected_runner_generation"]
    value = _exact(value, required, optional)
    result: dict[str, Any] = {
        "sequence": _integer(value["sequence"], 17, 18),
        "operation": value["operation"],
        "operation_id": _hex(value["operation_id"], (64,)),
        "scenario_sha256": _hex(value["scenario_sha256"], (64,)),
        "activation_id": value["activation_id"],
        "activation_package_digest": _hex(value["activation_package_digest"], (64,)),
        "integrated_candidate_sha": _hex(value["integrated_candidate_sha"], (40, 64)),
        "failed_stage": value["failed_stage"],
    }
    if "final_response_sha256" in value:
        result["final_response_sha256"] = _hex(value["final_response_sha256"], (64,))
    for name in ["expected_controller_generation", "expected_runner_generation"]:
        if name in value:
            result[name] = _integer(value[name], 1)
    return result


def _ordered_zero_response(value: Any) -> dict[str, Any]:
    value = _exact(value, ["operation_id", "controller_receipt_sha256", "proof"])
    return {
        "operation_id": _hex(value["operation_id"], (64,)),
        "controller_receipt_sha256": _hex(value["controller_receipt_sha256"], (64,)),
        "proof": _ordered_zero_proof(value["proof"]),
    }


def _zero_operation_id(request: dict[str, Any], run_id: str) -> str:
    digest = hashlib.sha256()
    digest.update(b"buzz-ci-capacity-one-zero-operation-v1\0")
    digest.update(request["scenario_sha256"].encode())
    digest.update(request["sequence"].to_bytes(4, "big"))
    digest.update(_canonical(request["operation"]))
    digest.update(request["activation_id"].encode())
    digest.update(request["activation_package_digest"].encode())
    digest.update(request["integrated_candidate_sha"].encode())
    digest.update(run_id.encode())
    digest.update(_canonical(request["failed_stage"]))
    digest.update(request["final_response_sha256"].encode())
    digest.update(request["expected_controller_generation"].to_bytes(8, "big"))
    digest.update(request["expected_runner_generation"].to_bytes(8, "big"))
    return digest.hexdigest()


def verify(receipt: Any, scenario: Any, expected_stages: Any) -> None:
    scenario = _ordered_scenario(scenario)
    fixture = scenario["fixture"]
    _require(expected_stages == list(EXPECTED_STAGES), "stage fixture rejected")
    receipt = _exact(receipt, ["schema_version", "outcome", "scenario_sha256", "integrated_candidate_sha", "run_id", "checks", "zero_transition"], ["failure"])
    _require(receipt["schema_version"] == RECEIPT_VERSION and receipt["outcome"] == "pass" and "failure" not in receipt, "pass receipt shape rejected")
    scenario_sha256 = _digest(scenario)
    _require(receipt["scenario_sha256"] == scenario_sha256, "scenario digest rejected")
    _require(receipt["integrated_candidate_sha"] == fixture["integrated_candidate_sha"] and receipt["run_id"] == fixture["run_id"], "receipt identity rejected")
    _require(isinstance(receipt["checks"], list) and len(receipt["checks"]) == 16, "full stage coverage required")
    checks: list[dict[str, Any]] = []
    for index, raw_check in enumerate(receipt["checks"], start=1):
        check = _exact(raw_check, ["sequence", "stage", "outcome", "evidence_sha256", "snapshot"], ["export"])
        _require(check["sequence"] == index and check["stage"] == expected_stages[index - 1] and check["outcome"] == "pass", "ordered stage rejected")
        ordered: dict[str, Any] = {
            "sequence": index,
            "stage": check["stage"],
            "outcome": "pass",
            "evidence_sha256": _hex(check["evidence_sha256"], (64,)),
            "snapshot": _ordered_snapshot(check["snapshot"]),
        }
        if "export" in check:
            ordered["export"] = _ordered_export(check["export"])
        _require((index == 7) == ("export" in ordered), "export placement rejected")
        response: dict[str, Any] = {
            "schema_version": DRIVER_VERSION,
            "sequence": index,
            "operation": OPERATIONS[index - 1],
            "snapshot": ordered["snapshot"],
        }
        if "export" in ordered:
            response["export"] = ordered["export"]
        _require(_digest(response) == ordered["evidence_sha256"], "stage evidence digest rejected")
        checks.append(ordered)
    _validate_snapshots(checks, fixture)

    transition = _exact(receipt["zero_transition"], ["schema_version", "outcome", "attempts", "phases", "zero_proof"])
    _require(transition["schema_version"] == ZERO_TRANSITION_VERSION and transition["outcome"] == "pass", "zero transition rejected")
    _integer(transition["attempts"], 1, 2)
    _require(isinstance(transition["phases"], list) and len(transition["phases"]) == 2, "zero phases rejected")
    final_snapshot = checks[-1]["snapshot"]
    phase_proofs: list[dict[str, Any]] = []
    operation_ids: set[str] = set()
    for offset, raw_phase in enumerate(transition["phases"]):
        sequence = 17 + offset
        operation = "finalize_capacity_zero" if sequence == 17 else "prove_capacity_zero"
        phase = _exact(raw_phase, ["sequence", "operation", "outcome", "attempts", "request_sha256", "response_sha256", "request", "response"])
        _require(phase["sequence"] == sequence and phase["operation"] == operation and phase["outcome"] == "pass", "zero phase ordering rejected")
        _integer(phase["attempts"], 1, 2)
        request = _ordered_zero_request(phase["request"])
        response = _ordered_zero_response(phase["response"])
        _require(request["sequence"] == sequence and request["operation"] == operation, "zero request operation rejected")
        _require(request["scenario_sha256"] == scenario_sha256 and request["activation_id"] == fixture["activation_id"] and request["activation_package_digest"] == fixture["activation_package_digest"] and request["integrated_candidate_sha"] == fixture["integrated_candidate_sha"], "zero request binding rejected")
        _require(request["failed_stage"] == "prepare_capacity_zero" and request.get("final_response_sha256") == checks[-1]["evidence_sha256"], "zero request final response rejected")
        _require(request.get("expected_controller_generation") == final_snapshot["controller_generation"] and request.get("expected_runner_generation") == final_snapshot["runner_generation"], "zero request generation rejected")
        expected_operation_id = _zero_operation_id(request, fixture["run_id"])
        _require(request["operation_id"] == expected_operation_id and response["operation_id"] == expected_operation_id and expected_operation_id not in operation_ids, "zero operation ID rejected")
        operation_ids.add(expected_operation_id)
        _require(_digest(request) == phase["request_sha256"] and _digest(response) == phase["response_sha256"], "zero phase digest rejected")
        proof = response["proof"]
        _require(proof["scenario_sha256"] == scenario_sha256 and proof["activation_id"] == fixture["activation_id"] and proof["activation_package_digest"] == fixture["activation_package_digest"] and proof["integrated_candidate_sha"] == fixture["integrated_candidate_sha"], "zero proof binding rejected")
        _require(proof["controller_generation"] == final_snapshot["controller_generation"] and proof["runner_generation"] == final_snapshot["runner_generation"], "zero proof generation rejected")
        phase_proofs.append(proof)
    final_proof = _ordered_zero_proof(transition["zero_proof"])
    _require(final_proof == phase_proofs[1], "independent final zero proof rejected")


def _run(
    argv: list[str],
    expected_stages_path: Path,
    expected_stages_uid: int,
    expected_stages_gid: int,
) -> int:
    if len(argv) != 2:
        print("usage: buzz-ci-verify-acceptance-receipt SCENARIO RECEIPT", file=sys.stderr)
        return 2
    try:
        stages = load_expected_stages(
            expected_stages_path,
            expected_stages_uid,
            expected_stages_gid,
        )
        verify(load_json(Path(argv[1])), load_json(Path(argv[0])), stages)
    except ReceiptError as error:
        print(f"receipt rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"outcome": "pass", "status": "verified"}, separators=(",", ":")))
    return 0


def main(argv: list[str]) -> int:
    return _run(argv, EXPECTED_STAGES_PATH, 0, 0)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
