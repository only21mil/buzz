#!/usr/bin/python3
"""Deterministic capacity-one controller/systemd fixture for Rust integration tests."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

REQUEST_KEYS = [
    "schema_version",
    "action",
    "activation_id",
    "activation_package_digest",
    "scenario_sha256",
    "initial_controller_generation",
    "initial_runner_generation",
    "operation_id",
]
ACTIVE_UNITS = [
    "buzz-ci-capacity-one.target",
    "buzz-ci-controld.service",
    "buzz-ci-controld-acceptance.socket",
    "buzz-ci-acceptance-control.socket",
    "buzz-ci-acceptance-control.service",
    "buzz-ci-runner.service",
    "buzz-ci-runner.socket",
    "buzz-ci-execd.service",
    "buzz-ci-execd.socket",
    "buzz-ci-keyholder.service",
    "buzz-ci-keyholder.socket",
]


def compact(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()


def fail(message: str) -> None:
    sys.stderr.write(message + "\n")
    raise SystemExit(4)


def main() -> None:
    if sys.argv[1:] != ["set-capacity-one"]:
        fail("fixed action required")
    state_path = Path(os.environ["BUZZ_FAKE_SYSTEMD_STATE"])
    receipt_path = Path(os.environ["BUZZ_FAKE_ACTIVATION_RECEIPT"])
    mode = os.environ.get("BUZZ_FAKE_CAPACITY_ONE_MODE", "success")
    raw = sys.stdin.buffer.read(65_537)
    if len(raw) > 65_536 or not raw.endswith(b"\n"):
        fail("bounded canonical request required")
    body = raw[:-1]
    try:
        request = json.loads(body, object_pairs_hook=dict)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("request JSON rejected")
    if list(request) != REQUEST_KEYS or compact(request) != body:
        fail("request shape rejected")
    if (
        request["schema_version"] != "buzz-ci-activation-capacity-one-request/v1"
        or request["action"] != "set_capacity_one"
    ):
        fail("request contract rejected")
    if mode == "timeout":
        time.sleep(30)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    request_sha256 = hashlib.sha256(body).hexdigest()
    prior_sha256 = state.get("transition_request_sha256")
    if prior_sha256 is not None:
        if prior_sha256 != request_sha256:
            fail("transition replay differs")
        sys.stdout.buffer.write(compact(state["transition_response"]) + b"\n")
        return

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if (
        receipt["state"] != "qualified_closed"
        or receipt["activation_id"] != request["activation_id"]
        or receipt["package_digest"] != request["activation_package_digest"]
        or receipt["scenario_sha256"] != request["scenario_sha256"]
        or receipt["controller_generation"]
        != request["initial_controller_generation"]
        or receipt["runner_generation"] != request["initial_runner_generation"]
    ):
        fail("receipt binding rejected")

    # Model the live transition (systemd 259, H6 clean host): every started
    # service reports SubState=running, the target reports active, and an
    # Accept=no socket reports `running` once its service is up rather than the
    # `listening` it shows while only the socket is bound.
    for unit in ACTIVE_UNITS:
        state["units"][unit]["state"] = "active"
        state["units"][unit]["sub_state"] = (
            "active" if unit.endswith(".target") else "running"
        )
    state["units"]["buzz-ci-controld.service"]["invocation_id"] = "2" * 32
    state["units"]["buzz-ci-runner.service"]["invocation_id"] = "3" * 32
    state["units"]["buzz-ci-execd.service"]["invocation_id"] = "4" * 32
    state["units"]["buzz-ci-keyholder.service"]["invocation_id"] = "5" * 32
    if mode == "stale_controller":
        state["units"]["buzz-ci-controld.service"]["invocation_id"] = "1" * 32
    if mode == "wrong_fragment":
        state["units"]["buzz-ci-runner.socket"]["fragment_path"] = (
            "/usr/lib/systemd/system/buzz-ci-runner.socket"
        )

    receipt["state"] = "active_one"
    receipt_bytes = compact(receipt) + b"\n"
    receipt_path.write_bytes(receipt_bytes)
    response = {
        "schema_version": "buzz-ci-activation-capacity-one-response/v1",
        "action": "set_capacity_one",
        "activation_id": request["activation_id"],
        "activation_package_digest": request["activation_package_digest"],
        "scenario_sha256": request["scenario_sha256"],
        "operation_id": request["operation_id"],
        "state": "active_one",
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
    }
    state["transition_request_sha256"] = request_sha256
    state["transition_response"] = response
    state_path.write_bytes(compact(state) + b"\n")
    if mode == "drift_response":
        response["scenario_sha256"] = "0" * 64
    if mode == "malformed":
        sys.stdout.buffer.write(b'{"schema_version":"wrong"}\n')
        return
    sys.stdout.buffer.write(compact(response) + b"\n")


if __name__ == "__main__":
    main()
