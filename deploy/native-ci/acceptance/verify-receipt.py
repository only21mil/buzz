#!/usr/bin/env python3
"""Fail-closed verifier for a capacity-one acceptance pass receipt."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_STAGES_BYTES = 4096
DRIVER_VERSION = "buzz-ci-capacity-one-driver/v1"
RECEIPT_VERSION = "buzz-ci-capacity-one-acceptance-receipt/v1"
EXPECTED_STAGES_PATH = Path("/usr/libexec/buzz-ci-acceptance-expected-stages.json")
EXPECTED_STAGES_MODE = 0o644
EXPECTED_STAGES_SHA256 = "a41c84589521d3ca02cf944be8c6c80d29bbb4b1fdf18982b44d0f550cf58785"
EXPECTED_STAGES_CANONICAL_SHA256 = "253f704e0e3ab1c3773db5f872e237c20458f929062ac2611b75d54423b818f4"
EXPECTED_STAGES = (
    "capacity_zero_closed",
    "capacity_one_open",
    "manifest_identity",
    "approval_grant",
    "grant_resume",
    "first_attempt_terminal",
    "authenticated_export",
    "rerun_separation",
    "cancellation_terminal",
    "tombstone_folding",
    "controller_restart_recovery",
    "runner_restart_recovery",
    "return_capacity_zero",
)
OPERATIONS = [
    "observe_initial",
    "set_capacity_one",
    "submit_manifest",
    "approve_grant",
    "resume_grant",
    "await_first_terminal",
    "export_first_evidence",
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
    value = _exact(value, ["approval_id", "grant_digest", "approved_by", "resumed"])
    _require(isinstance(value["resumed"], bool), "approval resume rejected")
    return {
        "approval_id": _hex(value["approval_id"], (32,)),
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
        "authenticated", "subject", "authorization_digest", "attempt_id",
        "request_digest", "manifest_digest", "evidence_set_digest", "objects",
    ]
    value = _exact(value, required)
    _require(value["authenticated"] is True, "export authentication rejected")
    _require(isinstance(value["objects"], list) and 0 < len(value["objects"]) <= 65, "export objects rejected")
    return {
        "authenticated": True,
        "subject": _hex(value["subject"], (64,)),
        "authorization_digest": _hex(value["authorization_digest"], (64,)),
        "attempt_id": _hex(value["attempt_id"], (32,)),
        "request_digest": _hex(value["request_digest"], (64,)),
        "manifest_digest": _hex(value["manifest_digest"], (64,)),
        "evidence_set_digest": _hex(value["evidence_set_digest"], (64,)),
        "objects": [_ordered_evidence(item) for item in value["objects"]],
    }


def _ordered_scenario(value: Any) -> dict[str, Any]:
    value = _exact(value, ["schema_version", "fixture", "driver"])
    _require(value["schema_version"] == "buzz-ci-capacity-one-scenario/v1", "scenario version rejected")
    fixture_fields = [
        "integrated_candidate_sha", "activation_id", "activation_package_digest", "run_id",
        "request_digest", "manifest_digest", "source_oid", "approval_id", "grant_digest",
        "approved_by", "export_subject", "export_authorization_digest", "expected_log",
        "expected_artifacts",
    ]
    fixture = _exact(value["fixture"], fixture_fields)
    _hex(fixture["integrated_candidate_sha"], (40, 64))
    _require(isinstance(fixture["activation_id"], str) and 0 < len(fixture["activation_id"]) <= 128, "activation ID rejected")
    activation_digest = _hex(fixture["activation_package_digest"], (64,))
    _require(
        fixture["activation_id"]
        == f"buzz-ci-capacity-one-{fixture['integrated_candidate_sha'][:12]}-{activation_digest[:12]}",
        "activation ID rejected",
    )
    for name in ["activation_package_digest", "request_digest", "manifest_digest", "grant_digest", "approved_by", "export_subject", "export_authorization_digest"]:
        _hex(fixture[name], (64,))
    _hex(fixture["run_id"], (32,)); _hex(fixture["approval_id"], (32,)); _hex(fixture["source_oid"], (40, 64))
    _ordered_evidence(fixture["expected_log"])
    _require(isinstance(fixture["expected_artifacts"], list) and 0 < len(fixture["expected_artifacts"]) <= 64, "expected artifacts rejected")
    for item in fixture["expected_artifacts"]:
        _ordered_evidence(item)
    driver_fields = ["control", "observe", "export", "controller_process", "runner_process", "timeout_seconds"]
    driver = _exact(value["driver"], driver_fields)
    for name in driver_fields[:-1]:
        endpoint = _exact(driver[name], ["program"], ["args"])
        _require(
            isinstance(endpoint["program"], str)
            and endpoint["program"].startswith("/")
            and len(endpoint["program"]) > 1,
            "driver endpoint rejected",
        )
        args = endpoint.get("args", [])
        _require(
            isinstance(args, list)
            and len(args) <= 32
            and all(isinstance(argument, str) and len(argument) <= 4096 for argument in args),
            "driver arguments rejected",
        )
    _integer(driver["timeout_seconds"], 1, 300)
    ordered_fixture = {name: fixture[name] for name in fixture_fields}
    ordered_fixture["expected_log"] = _ordered_evidence(fixture["expected_log"])
    ordered_fixture["expected_artifacts"] = [_ordered_evidence(item) for item in fixture["expected_artifacts"]]
    ordered_driver: dict[str, Any] = {}
    for name in driver_fields[:-1]:
        ordered_driver[name] = {"program": driver[name]["program"], "args": driver[name].get("args", [])}
    ordered_driver["timeout_seconds"] = driver["timeout_seconds"]
    return {"schema_version": value["schema_version"], "fixture": ordered_fixture, "driver": ordered_driver}


def _validate_run_binding(run: dict[str, Any], fixture: dict[str, Any]) -> None:
    for name in ["run_id", "integrated_candidate_sha", "request_digest", "manifest_digest", "source_oid"]:
        _require(run[name] == fixture[name], "run binding rejected")
    ids: set[str] = set()
    for attempt in run["attempts"]:
        for name in ["integrated_candidate_sha", "request_digest", "manifest_digest", "source_oid"]:
            _require(attempt[name] == fixture[name], "attempt binding rejected")
        _require(attempt["attempt_id"] not in ids, "duplicate attempt rejected")
        ids.add(attempt["attempt_id"])


def _validate_approval(run: dict[str, Any], fixture: dict[str, Any], resumed: bool) -> None:
    _require("approval" in run, "approval missing")
    approval = run["approval"]
    for name in ["approval_id", "grant_digest", "approved_by"]:
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


def _validate_snapshots(checks: list[dict[str, Any]], fixture: dict[str, Any]) -> None:
    snapshots = [check["snapshot"] for check in checks]
    for index, snapshot in enumerate(snapshots, start=1):
        expected_capacity = 0 if index in {1, 13} else 1
        expected_admission = "closed" if expected_capacity == 0 else "open"
        _require(snapshot["capacity"] == expected_capacity and snapshot["admission"] == expected_admission, "capacity snapshot rejected")
        active = 1 if index in {5, 8} else 0
        _require(snapshot["active_run_count"] == active and snapshot["active_attempt_count"] == active, "active count rejected")
        if index <= 2:
            _require("run" not in snapshot, "run exists before submission")
        else:
            _require("run" in snapshot, "run snapshot missing")
            _validate_run_binding(snapshot["run"], fixture)
    for index in range(1, 10):
        _require(
            snapshots[index]["controller_generation"] >= snapshots[index - 1]["controller_generation"]
            and snapshots[index]["runner_generation"] >= snapshots[index - 1]["runner_generation"],
            "generation regression rejected",
        )
    _require(snapshots[10]["controller_generation"] > snapshots[9]["controller_generation"] and snapshots[10]["runner_generation"] >= snapshots[9]["runner_generation"], "controller restart generation rejected")
    _require(snapshots[11]["runner_generation"] > snapshots[10]["runner_generation"] and snapshots[11]["controller_generation"] >= snapshots[10]["controller_generation"], "runner restart generation rejected")
    _require(
        snapshots[12]["controller_generation"] >= snapshots[11]["controller_generation"]
        and snapshots[12]["runner_generation"] >= snapshots[11]["runner_generation"],
        "return-zero generation rejected",
    )

    run3, run4, run5, run6, run7, run8, run9, run10, run11, run12, run13 = [snapshot["run"] for snapshot in snapshots[2:]]
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
    for run in [run8, run9, run10, run11, run12, run13]:
        _validate_approval(run, fixture, True)
        _require(len(run["attempts"]) == 2, "rerun evidence missing")
        _validate_first(run["attempts"][0], fixture, True)
        _require(run["attempts"][0]["attempt_id"] == first_id, "first attempt changed")
        _require(run["attempts"][0] == run6["attempts"][0], "first attempt evidence changed")
    second_id = run8["attempts"][1]["attempt_id"]
    _require(second_id != first_id and run8["attempts"][1].get("parent_attempt_id") == first_id and run8["attempts"][1]["attempt"] == 2, "rerun lineage rejected")
    _require(run8["state"] == "running" and run8["aggregate_conclusion"] == "none" and "selected_attempt_id" not in run8 and run8["attempts"][1]["state"] == "running" and run8["attempts"][1]["conclusion"] == "none", "rerun snapshot rejected")
    for run in [run8, run9, run10, run11, run12, run13]:
        second = run["attempts"][1]
        _require(second["attempt_id"] == second_id and second["attempt"] == 2 and second.get("parent_attempt_id") == first_id, "second attempt lineage changed")
        _require("evidence_set_digest" not in second and "log" not in second and second["artifacts"] == [], "cancelled attempt evidence rejected")
    _require(run9["state"] == "terminal" and run9["aggregate_conclusion"] == "cancelled" and run9.get("selected_attempt_id") == second_id and run9["attempts"][1]["state"] == "terminal" and run9["attempts"][1]["conclusion"] == "cancelled", "cancellation snapshot rejected")
    _require(run10["state"] == "terminal" and run10["aggregate_conclusion"] == "success" and run10.get("selected_attempt_id") == first_id and run10["attempts"][1]["state"] == "tombstoned" and run10["attempts"][1]["conclusion"] == "cancelled", "tombstone fold rejected")
    _require(run11 == run10 and run12 == run10 and run13 == run10, "restart or return-zero changed durable run")

    export = checks[6]["export"]
    terminal = run6["attempts"][0]
    _require(export["subject"] == fixture["export_subject"] and export["authorization_digest"] == fixture["export_authorization_digest"], "export authority rejected")
    _require(export["attempt_id"] == first_id and export["request_digest"] == fixture["request_digest"] and export["manifest_digest"] == fixture["manifest_digest"], "export binding rejected")
    _require(export["evidence_set_digest"] == terminal["evidence_set_digest"], "export evidence set rejected")
    _require(export["objects"] == [fixture["expected_log"], *fixture["expected_artifacts"]], "export objects rejected")


def verify(receipt: Any, scenario: Any, expected_stages: Any) -> None:
    scenario = _ordered_scenario(scenario)
    fixture = scenario["fixture"]
    _require(expected_stages == list(EXPECTED_STAGES), "stage fixture rejected")
    receipt = _exact(
        receipt,
        [
            "schema_version",
            "outcome",
            "scenario_sha256",
            "integrated_candidate_sha",
            "run_id",
            "checks",
        ],
        ["failure"],
    )
    _require(
        receipt["schema_version"] == RECEIPT_VERSION
        and receipt["outcome"] == "pass"
        and "failure" not in receipt,
        "pass receipt shape rejected",
    )
    scenario_sha256 = _digest(scenario)
    _require(receipt["scenario_sha256"] == scenario_sha256, "scenario digest rejected")
    _require(
        receipt["integrated_candidate_sha"] == fixture["integrated_candidate_sha"]
        and receipt["run_id"] == fixture["run_id"],
        "receipt identity rejected",
    )
    _require(
        isinstance(receipt["checks"], list) and len(receipt["checks"]) == 13,
        "full stage coverage required",
    )
    checks: list[dict[str, Any]] = []
    for index, raw_check in enumerate(receipt["checks"], start=1):
        check = _exact(
            raw_check,
            ["sequence", "stage", "outcome", "evidence_sha256", "snapshot"],
            ["export"],
        )
        _require(
            check["sequence"] == index
            and check["stage"] == expected_stages[index - 1]
            and check["outcome"] == "pass",
            "ordered stage rejected",
        )
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
        _require(
            _digest(response) == ordered["evidence_sha256"],
            "stage evidence digest rejected",
        )
        checks.append(ordered)
    _validate_snapshots(checks, fixture)


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
