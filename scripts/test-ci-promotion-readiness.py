#!/usr/bin/env python3
"""Hermetic tests for ci-promotion-readiness.py."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("ci-promotion-readiness.py")
REPO_ROOT = SCRIPT.parent.parent
NOW = 1_787_832_000
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
IMAGE_A = f"sha256:{'1' * 64}"
IMAGE_B = f"sha256:{'2' * 64}"
PRIOR_IMAGE = f"sha256:{'3' * 64}"


def run(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def write_jsonl(path: Path, values: list[dict]) -> None:
    path.write_text("".join(json.dumps(value, sort_keys=True) + "\n" for value in values),
                    encoding="utf-8")
    path.chmod(0o600)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PromotionReadinessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "repo"
        self.evidence_dir = self.root / "evidence"
        self.repo.mkdir()
        self.evidence_dir.mkdir(mode=0o700)
        run(["git", "init", "-q"], self.repo)
        run(["git", "config", "user.name", "Test User"], self.repo)
        run(["git", "config", "user.email", "test@example.invalid"], self.repo)
        (self.repo / "source.txt").write_text("base\n", encoding="utf-8")
        run(["git", "add", "source.txt"], self.repo)
        run(["git", "commit", "-q", "-m", "base"], self.repo)
        self.base = run(["git", "rev-parse", "HEAD"], self.repo)
        (self.repo / "source.txt").write_text("candidate\n", encoding="utf-8")
        run(["git", "add", "source.txt"], self.repo)
        run(["git", "commit", "-q", "-m", "candidate"], self.repo)
        self.candidate = run(["git", "rev-parse", "HEAD"], self.repo)
        self.tree = run(["git", "rev-parse", "HEAD^{tree}"], self.repo)
        self.red_sha = "f" * 40 if self.candidate != "f" * 40 else "e" * 40
        timestamp = dt.datetime.fromtimestamp(NOW - 60, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")

        self.pre_freeze_path = self.evidence_dir / "pre-freeze.json"
        write_json(self.pre_freeze_path, {
            "schema_version": 1,
            "source": "pre-freeze",
            "repository": "only21mil/buzz",
            "head_sha": self.candidate,
            "base_sha": self.base,
            "timestamp": timestamp,
            "overall": "PASS",
            "checks": [{"name": "source", "status": "PASS"}],
        })
        self.protected_ci_path = self.evidence_dir / "protected-ci.json"
        write_json(self.protected_ci_path, {
            "schema_version": 1,
            "source": "protected-ci",
            "repository": "only21mil/buzz",
            "head_sha": self.candidate,
            "timestamp": timestamp,
            "overall": "PASS",
            "protected": True,
            "full_exact_head": True,
            "checks": [{"name": "required", "status": "PASS"}],
        })
        self.acceptance_path = self.evidence_dir / "acceptance-verdict.json"
        write_json(self.acceptance_path, {
            "candidate_sha": self.candidate,
            "security": {"passed": 17, "total": 17},
            "probes": {"passed_runs": 12, "total_runs": 12},
            "green": True,
            "missing": [],
            "failed": [],
            "sha_conflicts": [],
        })
        self.acceptance_records_path = self.evidence_dir / "acceptance-records.jsonl"
        records = []
        for number in range(1, 18):
            records.append(self.acceptance_record("security", f"TM-{number:02d}"))
        for probe in ("P-i", "P-ii", "P-iii", "P-iv", "P-v", "P-vi"):
            for run_number in (1, 2):
                records.append(self.acceptance_record("probe", probe, run=run_number))
        write_jsonl(self.acceptance_records_path, records)
        self.bundle = self.valid_bundle()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def acceptance_record(self, suite: str, test_id: str, *, run: int | None = None) -> dict:
        record = {
            "suite": suite,
            "test_id": test_id,
            "title": f"Canonical {test_id}",
            "candidate_sha": self.candidate,
            "pass": True,
            "evidence_ref": f"sha256:{DIGEST_A}",
            "executor": "hermetic-test",
            "host": "test.invalid",
            "started_at": NOW - 20,
            "finished_at": NOW - 10,
        }
        if run is not None:
            record["run"] = run
        return record

    def valid_bundle(self) -> dict:
        log = {
            "authorized_status": 200,
            "unauthorized_status": 403,
            "redirects": 0,
            "sha256": DIGEST_A,
            "computed_sha256": DIGEST_A,
            "byte_count": 128,
            "byte_cap": 1024,
        }
        return {
            "schema_version": 1,
            "repository": "only21mil/buzz",
            "candidate_sha": self.candidate,
            "base_sha": self.base,
            "tree_sha": self.tree,
            "source": {"checkout_sha": self.candidate, "clean": True},
            "evidence_files": {
                "pre_freeze": {"path": str(self.pre_freeze_path), "sha256": digest(self.pre_freeze_path)},
                "protected_ci": {"path": str(self.protected_ci_path), "sha256": digest(self.protected_ci_path)},
                "acceptance_verdict": {"path": str(self.acceptance_path), "sha256": digest(self.acceptance_path)},
                "acceptance_records": {"path": str(self.acceptance_records_path),
                                       "sha256": digest(self.acceptance_records_path)},
            },
            "protected_ci": {
                "head_sha": self.candidate,
                "protected": True,
                "conclusion": "success",
                "contexts": [
                    {"name": "build", "head_sha": self.candidate, "conclusion": "success",
                     "run_url": "https://ci.example.invalid/run/1"},
                    {"name": "test", "head_sha": self.candidate, "conclusion": "success",
                     "run_url": "https://ci.example.invalid/run/2"},
                ],
            },
            "tier2": {
                "eligible_commit": self.candidate,
                "checked_commit": self.candidate,
                "check_exit_code": 0,
                "verdict": "PASS",
                "reviewer": "claude:test-reviewer",
                "model": "claude-opus-5",
                "effort": "high",
                "lineage": "lineage-1",
                "state_sha256": DIGEST_A,
                "fingerprint": DIGEST_B,
                "prepared_at": NOW - 100,
                "reviewed_at": NOW - 50,
                "expires_at": NOW + 5_000,
            },
            "artifacts": {
                "image_ref": f"localhost/buzz-relay:{self.candidate}",
                "image_ids": [IMAGE_B, IMAGE_A],
                "running_image_id": IMAGE_A,
                "binary_sha256": DIGEST_C,
                "oci_revision": self.candidate,
                "required_migration": 35,
                "database_migration": 35,
            },
            "staging": {
                "candidate_sha": self.candidate,
                "absent_policy_status": 503,
                "configured_policy_status": 200,
                "root_executor_handoff": True,
                "advertised_bounds_sha256": DIGEST_A,
                "enforced_bounds_sha256": DIGEST_A,
                "scenarios": {
                    "success": "PASS",
                    "policy_refusal": "PASS",
                    "teardown_failure": "PASS",
                    "restart_recovery": "PASS",
                    "unaccepted_refusal": "PASS",
                },
                "immutable_request_sha": self.candidate,
                "records": [46101, 46102, 46103, 46104, 46105, 46106],
                "signer": DIGEST_B,
                "job_set_sha256": DIGEST_A,
                "evidence_sha256": DIGEST_B,
                "teardown_sha256": DIGEST_C,
                "conclusion": "success",
                "log": copy.deepcopy(log),
            },
            "production_canary": {
                "candidate_sha": self.candidate,
                "initial_concurrency": 0,
                "enabled_concurrency": 1,
                "accepted_executed": True,
                "unaccepted_refused": True,
                "signed": True,
                "allowed_kinds_only": True,
                "records": [46101, 46102, 46103, 46104, 46105, 46106],
                "run_id": "run-1",
                "signer": DIGEST_B,
                "conclusion": "success",
                "log_sha256": DIGEST_A,
                "evidence_sha256": DIGEST_B,
                "teardown_sha256": DIGEST_C,
                "retry": {
                    "request_id": "request-1",
                    "first_run_id": "run-1",
                    "duplicate_run_id": "run-1",
                    "attempts": [1, 2],
                    "workspaces": ["workspace-1", "workspace-2"],
                    "terminal_events": 1,
                },
            },
            "deliberate_red": {
                "system_sha": self.candidate,
                "red_sha": self.red_sha,
                "accepted_commit": True,
                "required_check": "buzz-native-ci",
                "conclusion": "failure",
                "merge_allowed": False,
                "protected_rule": True,
                "terminal_events": 1,
                "first_run_id": "red-run-1",
                "duplicate_run_id": "red-run-1",
            },
            "deployment": {
                "commit_sha": self.candidate,
                "image_ref": f"localhost/buzz-relay:{self.candidate}",
                "running_image_id": IMAGE_A,
                "binary_sha256": DIGEST_C,
                "oci_revision": self.candidate,
                "database_migration": 35,
                "dump_before_swap": True,
                "dump_sha256": DIGEST_B,
                "readiness": True,
                "nip11": True,
                "started_at": NOW - 40,
                "swapped_at": NOW - 30,
                "finished_at": NOW - 20,
                "log": copy.deepcopy(log),
            },
            "rollback": {
                "compatible": {
                    "mode": "restored",
                    "current_migration": 35,
                    "prior_required_migration": 35,
                    "prior_image_id": PRIOR_IMAGE,
                    "prior_binary_sha256": DIGEST_A,
                    "prior_dump_sha256": DIGEST_B,
                    "restore_attempted": True,
                    "restored_image_id": PRIOR_IMAGE,
                    "restored_binary_sha256": DIGEST_A,
                    "restored_dump_sha256": DIGEST_B,
                    "readiness": True,
                    "nip11": True,
                },
                "advanced": {
                    "mode": "refused",
                    "current_migration": 36,
                    "prior_required_migration": 35,
                    "restore_attempted": False,
                    "reason": "migration_advanced",
                },
            },
            "landing": {
                "relay_sha": self.candidate,
                "mirror_sha": self.candidate,
                "merge_sha": self.candidate,
            },
        }

    def invoke(self, bundle: dict, *, now: int = NOW) -> subprocess.CompletedProcess[str]:
        bundle_path = self.evidence_dir / "bundle.json"
        receipt_path = self.evidence_dir / "receipt.json"
        write_json(bundle_path, bundle)
        return subprocess.run(
            [sys.executable, str(SCRIPT),
             "--candidate-dir", str(self.repo),
             "--evidence", str(bundle_path),
             "--receipt", str(receipt_path),
             "--now", str(now)],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_refused(self, bundle: dict, message: str, *, now: int = NOW) -> None:
        result = self.invoke(bundle, now=now)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)

    def test_valid_bundle_is_deterministic_and_complete(self) -> None:
        first = self.invoke(self.bundle)
        self.assertEqual(first.returncode, 0, first.stderr)
        first_bytes = (self.evidence_dir / "receipt.json").read_bytes()
        second = self.invoke(self.bundle)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_bytes, (self.evidence_dir / "receipt.json").read_bytes())
        receipt = json.loads(first_bytes)
        self.assertEqual(receipt["overall"], "PASS")
        self.assertEqual(receipt["gates"]["threat_model"], {"passed": 17, "total": 17})
        self.assertEqual(receipt["gates"]["probes"], {"passed_runs": 12, "total_runs": 12})
        self.assertEqual(receipt["identities"]["relay_sha"], self.candidate)
        self.assertEqual(receipt["identities"]["mirror_sha"], self.candidate)

    def test_json_schemas_are_parseable(self) -> None:
        for name in ("promotion-evidence.schema.json", "promotion-readiness-receipt.schema.json"):
            schema = json.loads((REPO_ROOT / "docs" / "ci" / name).read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_wrong_sha_is_refused(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["landing"]["mirror_sha"] = self.red_sha
        self.assert_refused(bundle, "landing mirror_sha")

    def test_wrong_image_is_refused(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["artifacts"]["running_image_id"] = PRIOR_IMAGE
        self.assert_refused(bundle, "not one of the built image IDs")

    def test_stale_tier2_review_is_refused(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["tier2"]["expires_at"] = NOW - 1
        self.assert_refused(bundle, "tier2 review is stale")

    def test_rollback_migration_limit_is_enforced(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["rollback"]["compatible"]["current_migration"] = 36
        self.assert_refused(bundle, "compatible rollback exceeds")

    def test_deliberate_red_must_block_merge(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["deliberate_red"]["merge_allowed"] = True
        self.assert_refused(bundle, "did not block merge")

    def test_log_authentication_is_required(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["staging"]["log"]["unauthorized_status"] = 200
        self.assert_refused(bundle, "unauthorized request")

    def test_duplicate_request_must_be_idempotent(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["production_canary"]["retry"]["duplicate_run_id"] = "run-2"
        self.assert_refused(bundle, "created a second run")

    def test_accepted_and_unaccepted_paths_are_required(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["production_canary"]["unaccepted_refused"] = False
        self.assert_refused(bundle, "unaccepted code path")

    def test_dirty_checkout_is_refused_before_receipt(self) -> None:
        (self.repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        self.assert_refused(self.bundle, "candidate checkout is dirty")

    def test_mismatched_protected_ci_receipt_is_refused(self) -> None:
        receipt = json.loads(self.protected_ci_path.read_text(encoding="utf-8"))
        receipt["head_sha"] = self.red_sha
        write_json(self.protected_ci_path, receipt)
        bundle = copy.deepcopy(self.bundle)
        bundle["evidence_files"]["protected_ci"]["sha256"] = digest(self.protected_ci_path)
        self.assert_refused(bundle, "head_sha does not match")

    def test_world_readable_evidence_is_refused(self) -> None:
        self.pre_freeze_path.chmod(0o644)
        self.assert_refused(self.bundle, "mode 0600")

    def test_incomplete_tm_probe_verdict_is_refused(self) -> None:
        verdict = json.loads(self.acceptance_path.read_text(encoding="utf-8"))
        verdict["security"]["passed"] = 16
        write_json(self.acceptance_path, verdict)
        bundle = copy.deepcopy(self.bundle)
        bundle["evidence_files"]["acceptance_verdict"]["sha256"] = digest(self.acceptance_path)
        self.assert_refused(bundle, "all 17 TM checks")

    def test_named_probe_record_is_required(self) -> None:
        records = self.acceptance_records_path.read_text(encoding="utf-8").splitlines()
        write_jsonl(self.acceptance_records_path, [json.loads(line) for line in records[:-1]])
        bundle = copy.deepcopy(self.bundle)
        bundle["evidence_files"]["acceptance_records"]["sha256"] = digest(self.acceptance_records_path)
        self.assert_refused(bundle, "six probes twice")

    def test_secret_value_is_not_logged(self) -> None:
        secret = "test-secret-must-never-appear"
        bundle = copy.deepcopy(self.bundle)
        bundle["artifacts"]["image_ref"] = secret
        result = self.invoke(bundle)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(secret, result.stdout + result.stderr)
        receipt = self.evidence_dir / "receipt.json"
        if receipt.exists():
            self.assertNotIn(secret, receipt.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
