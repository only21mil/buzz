from __future__ import annotations

import copy
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
ACCEPTANCE = ROOT / "deploy/native-ci/acceptance"
SPEC = importlib.util.spec_from_file_location("receipt_verifier", ACCEPTANCE / "verify-receipt.py")
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def _install_verifier(root: Path):
    libexec = root / "usr/libexec"
    libexec.mkdir(parents=True)
    verifier_path = libexec / "buzz-ci-verify-acceptance-receipt"
    stages_path = libexec / "buzz-ci-acceptance-expected-stages.json"
    shutil.copyfile(ACCEPTANCE / "verify-receipt.py", verifier_path)
    shutil.copyfile(ACCEPTANCE / "expected-stages.json", stages_path)
    os.chmod(verifier_path, 0o755)
    os.chmod(stages_path, 0o644)
    loader = importlib.machinery.SourceFileLoader(
        "installed_receipt_verifier", str(verifier_path)
    )
    spec = importlib.util.spec_from_loader("installed_receipt_verifier", loader)
    assert spec is not None and spec.loader is not None
    installed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installed)
    return installed, verifier_path, stages_path


def _invoke(installed, stages_path: Path, scenario_path: Path, receipt_path: Path, uid=None, gid=None):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        return_code = installed._run(
            [str(scenario_path), str(receipt_path)],
            stages_path,
            os.getuid() if uid is None else uid,
            os.getgid() if gid is None else gid,
        )
    return return_code, stdout.getvalue(), stderr.getvalue()


def _h(character: str, length: int) -> str:
    return character * length


def _attempt(fixture, attempt_id, number, state, conclusion, parent=None, evidence=False):
    value = {
        "attempt_id": attempt_id,
        "attempt": number,
        "state": state,
        "conclusion": conclusion,
        "integrated_candidate_sha": fixture["integrated_candidate_sha"],
        "request_digest": fixture["request_digest"],
        "manifest_digest": fixture["manifest_digest"],
        "source_oid": fixture["source_oid"],
        "artifacts": [],
    }
    if parent is not None:
        value["parent_attempt_id"] = parent
    if evidence:
        value["evidence_set_digest"] = _h("9", 64)
        value["log"] = copy.deepcopy(fixture["expected_log"])
        value["artifacts"] = copy.deepcopy(fixture["expected_artifacts"])
    return value


def _approval(fixture, resumed):
    return {
        "approval_id": fixture["approval_id"],
        "grant_event_id": fixture["grant_event_id"],
        "grant_digest": fixture["grant_digest"],
        "approved_by": fixture["approved_by"],
        "resumed": resumed,
    }


def _run(fixture, state, conclusion, attempts, approval=None, selected=None):
    value = {
        "run_id": fixture["run_id"],
        "integrated_candidate_sha": fixture["integrated_candidate_sha"],
        "request_digest": fixture["request_digest"],
        "manifest_digest": fixture["manifest_digest"],
        "source_oid": fixture["source_oid"],
        "state": state,
        "aggregate_conclusion": conclusion,
        "attempts": copy.deepcopy(attempts),
    }
    if approval is not None:
        value["approval"] = copy.deepcopy(approval)
    if selected is not None:
        value["selected_attempt_id"] = selected
    return value


def _snapshot(capacity, controller, runner, run=None, active=0):
    value = {
        "capacity": capacity,
        "admission": "open" if capacity else "closed",
        "active_run_count": active,
        "active_attempt_count": active,
        "controller_generation": controller,
        "runner_generation": runner,
    }
    if run is not None:
        value["run"] = copy.deepcopy(run)
    return value


def valid_receipt():
    scenario = json.loads((ACCEPTANCE / "scenario.template.json").read_text())
    scenario = VERIFIER._ordered_scenario(scenario)
    fixture = scenario["fixture"]
    stages = json.loads((ACCEPTANCE / "expected-stages.json").read_text())
    first_id = _h("a", 32)
    second_id = _h("b", 32)
    first_running = _attempt(fixture, first_id, 1, "running", "none")
    first_terminal = _attempt(fixture, first_id, 1, "terminal", "success", evidence=True)
    second_running = _attempt(fixture, second_id, 2, "running", "none", first_id)
    second_cancelled = _attempt(fixture, second_id, 2, "terminal", "cancelled", first_id)
    second_tombstoned = _attempt(fixture, second_id, 2, "tombstoned", "cancelled", first_id)
    granted = _approval(fixture, False)
    resumed = _approval(fixture, True)
    run3 = _run(fixture, "awaiting_approval", "none", [])
    run4 = _run(fixture, "granted_awaiting_resume", "none", [], granted)
    run5 = _run(fixture, "running", "none", [first_running], resumed)
    run6 = _run(fixture, "terminal", "success", [first_terminal], resumed, first_id)
    run8 = _run(fixture, "running", "none", [first_terminal, second_running], resumed)
    run9 = _run(fixture, "terminal", "cancelled", [first_terminal, second_cancelled], resumed, second_id)
    folded = _run(fixture, "terminal", "success", [first_terminal, second_tombstoned], resumed, first_id)
    snapshots = [
        _snapshot(0, 1, 1), _snapshot(1, 1, 1), _snapshot(1, 1, 1, run3),
        _snapshot(1, 1, 1, run4), _snapshot(1, 1, 1, run5, 1),
        _snapshot(1, 1, 1, run6), _snapshot(1, 1, 1, run6),
        _snapshot(1, 1, 1, run8, 1), _snapshot(1, 1, 1, run9),
        _snapshot(1, 1, 1, folded), _snapshot(1, 2, 1, folded),
        _snapshot(1, 2, 2, folded), _snapshot(0, 2, 2, folded),
    ]
    export = {
        "authenticated": True,
        "subject": fixture["export_subject"],
        "authorization_digest": fixture["export_authorization_digest"],
        "attempt_id": first_id,
        "request_digest": fixture["request_digest"],
        "manifest_digest": fixture["manifest_digest"],
        "evidence_set_digest": _h("9", 64),
        "objects": [copy.deepcopy(fixture["expected_log"]), *copy.deepcopy(fixture["expected_artifacts"])],
    }
    checks = []
    for sequence, (stage, operation, snapshot) in enumerate(zip(stages, VERIFIER.OPERATIONS, snapshots), start=1):
        response = {
            "schema_version": VERIFIER.DRIVER_VERSION,
            "sequence": sequence,
            "operation": operation,
            "snapshot": VERIFIER._ordered_snapshot(snapshot),
        }
        if sequence == 7:
            response["export"] = VERIFIER._ordered_export(export)
        check = {
            "sequence": sequence,
            "stage": stage,
            "outcome": "pass",
            "evidence_sha256": VERIFIER._digest(response),
            "snapshot": copy.deepcopy(snapshot),
        }
        if sequence == 7:
            check["export"] = copy.deepcopy(export)
        checks.append(check)
    scenario_sha256 = VERIFIER._digest(scenario)
    proof = {
        "schema_version": VERIFIER.ZERO_PROOF_VERSION,
        "scenario_sha256": scenario_sha256,
        "activation_id": fixture["activation_id"],
        "activation_package_digest": fixture["activation_package_digest"],
        "integrated_candidate_sha": fixture["integrated_candidate_sha"],
        "capacity": 0,
        "admission": "closed",
        "controller_generation": 2,
        "runner_generation": 2,
        "controld_service_active": False,
        "controld_acceptance_socket_active": False,
        "controld_acceptance_socket_present": False,
    }
    phases = []
    for sequence, operation in [(14, "finalize_capacity_zero"), (15, "prove_capacity_zero")]:
        request = {
            "sequence": sequence,
            "operation": operation,
            "operation_id": "pending",
            "scenario_sha256": scenario_sha256,
            "activation_id": fixture["activation_id"],
            "activation_package_digest": fixture["activation_package_digest"],
            "integrated_candidate_sha": fixture["integrated_candidate_sha"],
            "failed_stage": "prepare_capacity_zero",
            "final_response_sha256": checks[-1]["evidence_sha256"],
            "expected_controller_generation": 2,
            "expected_runner_generation": 2,
        }
        request["operation_id"] = VERIFIER._zero_operation_id(request, fixture["run_id"])
        response = {
            "operation_id": request["operation_id"],
            "controller_receipt_sha256": _h("c" if sequence == 14 else "d", 64),
            "proof": copy.deepcopy(proof),
        }
        phases.append({
            "sequence": sequence,
            "operation": operation,
            "outcome": "pass",
            "attempts": 1,
            "request_sha256": VERIFIER._digest(request),
            "response_sha256": VERIFIER._digest(response),
            "request": request,
            "response": response,
        })
    receipt = {
        "schema_version": VERIFIER.RECEIPT_VERSION,
        "outcome": "pass",
        "scenario_sha256": scenario_sha256,
        "integrated_candidate_sha": fixture["integrated_candidate_sha"],
        "run_id": fixture["run_id"],
        "checks": checks,
        "zero_transition": {
            "schema_version": VERIFIER.ZERO_TRANSITION_VERSION,
            "outcome": "pass",
            "attempts": 1,
            "phases": phases,
            "zero_proof": copy.deepcopy(proof),
        },
    }
    return scenario, stages, receipt


class ReceiptVerifierTests(unittest.TestCase):
    def test_full_closed_pass_is_verified(self):
        scenario, stages, receipt = valid_receipt()
        VERIFIER.verify(receipt, scenario, stages)

    def test_partial_hash_only_wrong_binding_and_zero_faults_fail_closed(self):
        scenario, stages, receipt = valid_receipt()
        mutations = []
        value = copy.deepcopy(receipt); del value["checks"][0]["snapshot"]; mutations.append(value)
        value = copy.deepcopy(receipt); value["checks"][0], value["checks"][1] = value["checks"][1], value["checks"][0]; mutations.append(value)
        value = copy.deepcopy(receipt); value["integrated_candidate_sha"] = _h("e", 40); mutations.append(value)
        value = copy.deepcopy(receipt); value["run_id"] = _h("e", 32); mutations.append(value)
        value = copy.deepcopy(receipt); value["checks"][5]["snapshot"]["run"]["attempts"][0]["manifest_digest"] = _h("e", 64); mutations.append(value)
        value = copy.deepcopy(receipt); value["checks"][4]["evidence_sha256"] = _h("e", 64); mutations.append(value)
        value = copy.deepcopy(receipt); value["checks"][6]["export"]["authenticated"] = False; mutations.append(value)
        value = copy.deepcopy(receipt); value["zero_transition"]["phases"][0]["request"]["activation_package_digest"] = _h("e", 64); mutations.append(value)
        value = copy.deepcopy(receipt); value["zero_transition"]["phases"].reverse(); mutations.append(value)
        value = copy.deepcopy(receipt); value["zero_transition"]["phases"][0]["request_sha256"] = _h("e", 64); mutations.append(value)
        value = copy.deepcopy(receipt); value["zero_transition"]["phases"][1]["response"]["proof"]["runner_generation"] = 3; mutations.append(value)
        value = copy.deepcopy(receipt); value["zero_transition"]["phases"][1]["response"]["proof"]["controld_service_active"] = True; mutations.append(value)
        value = copy.deepcopy(receipt); value["zero_transition"]["zero_proof"]["controller_generation"] = 3; mutations.append(value)
        for candidate in mutations:
            with self.subTest(candidate=mutations.index(candidate)), self.assertRaises(
                VERIFIER.ReceiptError
            ):
                VERIFIER.verify(candidate, scenario, stages)

    def test_installed_layout_accepts_exact_pass_and_rejects_bad_receipts(self):
        scenario, _stages, receipt = valid_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prior = os.umask(0o077)
            try:
                installed, verifier_path, stages_path = _install_verifier(root)
            finally:
                os.umask(prior)
            self.assertEqual(stat.S_IMODE(verifier_path.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(stages_path.stat().st_mode), 0o644)
            self.assertEqual(
                installed.EXPECTED_STAGES_PATH,
                Path("/usr/libexec/buzz-ci-acceptance-expected-stages.json"),
            )
            scenario_path = root / "scenario.json"
            receipt_path = root / "receipt.json"
            scenario_path.write_text(json.dumps(scenario, separators=(",", ":")))
            receipt_path.write_text(json.dumps(receipt, separators=(",", ":")))
            return_code, stdout, stderr = _invoke(
                installed, stages_path, scenario_path, receipt_path
            )
            self.assertEqual(return_code, 0, stderr)
            self.assertEqual(json.loads(stdout), {"outcome": "pass", "status": "verified"})
            receipt_path.write_text('{"schema_version":"x","schema_version":"y"}')
            return_code, stdout, stderr = _invoke(
                installed, stages_path, scenario_path, receipt_path
            )
            self.assertEqual(return_code, 1)
            self.assertEqual(stdout, "")
            self.assertNotIn("scenario", stderr)

            oversized = root / "oversized.json"
            oversized.write_bytes(b"{" + b" " * VERIFIER.MAX_JSON_BYTES + b"}")
            return_code, _stdout, stderr = _invoke(
                installed, stages_path, scenario_path, oversized
            )
            self.assertEqual(return_code, 1)
            self.assertLess(len(stderr), 128)

            linked = root / "linked.json"
            linked.symlink_to(receipt_path)
            return_code, stdout, _stderr = _invoke(
                installed, stages_path, scenario_path, linked
            )
            self.assertEqual(return_code, 1)
            self.assertEqual(stdout, "")

    def test_installed_stage_data_rejects_absence_tamper_and_path_attacks(self):
        scenario, _stages, receipt = valid_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installed, _verifier_path, stages_path = _install_verifier(root)
            scenario_path = root / "scenario.json"
            receipt_path = root / "receipt.json"
            scenario_path.write_text(json.dumps(scenario, separators=(",", ":")))
            receipt_path.write_text(json.dumps(receipt, separators=(",", ":")))
            expected = (ACCEPTANCE / "expected-stages.json").read_bytes()

            def rejected(uid=None, gid=None):
                return_code, stdout, stderr = _invoke(
                    installed,
                    stages_path,
                    scenario_path,
                    receipt_path,
                    uid=uid,
                    gid=gid,
                )
                self.assertEqual(return_code, 1)
                self.assertEqual(stdout, "")
                self.assertLess(len(stderr), 128)

            stages_path.unlink()
            rejected()

            stages_path.write_bytes(expected + b" ")
            os.chmod(stages_path, 0o644)
            rejected()

            stages_path.write_text(json.dumps(list(VERIFIER.EXPECTED_STAGES), separators=(",", ":")))
            os.chmod(stages_path, 0o644)
            rejected()

            stages_path.write_bytes(expected)
            os.chmod(stages_path, 0o600)
            rejected()

            os.chmod(stages_path, 0o644)
            rejected(uid=os.getuid() + 1)

            outside = root / "outside-stages.json"
            outside.write_bytes(expected)
            os.chmod(outside, 0o644)
            stages_path.unlink()
            stages_path.symlink_to(outside)
            rejected()

            stages_path.unlink()
            os.link(outside, stages_path)
            rejected()

            stages_path.unlink()
            shutil.copyfile(ACCEPTANCE / "expected-stages.json", stages_path)
            os.chmod(stages_path, 0o644)
            real_usr = root / "real-usr"
            (root / "usr").rename(real_usr)
            (root / "usr").symlink_to(real_usr, target_is_directory=True)
            rejected()

    def test_schema_and_upstream_stage_fixture_are_exactly_aligned(self):
        schema = json.loads((ACCEPTANCE / "receipt.schema.json").read_text())
        stages_raw = (ACCEPTANCE / "expected-stages.json").read_bytes()
        stages = json.loads(stages_raw)
        self.assertEqual(schema["$defs"]["stage"]["enum"], stages)
        self.assertEqual(tuple(stages), VERIFIER.EXPECTED_STAGES)
        self.assertEqual(
            hashlib.sha256(stages_raw).hexdigest(), VERIFIER.EXPECTED_STAGES_SHA256
        )
        self.assertEqual(
            hashlib.sha256(VERIFIER._canonical(stages)).hexdigest(),
            VERIFIER.EXPECTED_STAGES_CANONICAL_SHA256,
        )
        self.assertEqual(schema["properties"]["schema_version"]["const"], VERIFIER.RECEIPT_VERSION)
        self.assertEqual(schema["properties"]["checks"]["maxItems"], 13)
        self.assertEqual(len(schema["properties"]["checks"]["prefixItems"]), 13)
        references = []

        def collect(value):
            if isinstance(value, dict):
                if "$ref" in value:
                    references.append(value["$ref"])
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        collect(schema)
        for reference in references:
            self.assertTrue(reference.startswith("#/$defs/"), reference)
            self.assertIn(reference.removeprefix("#/$defs/"), schema["$defs"])


if __name__ == "__main__":
    unittest.main()
