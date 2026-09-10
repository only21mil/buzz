import dataclasses
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import worker
from container_runtime import ContainerResult
from workflow_source import Refused, compile_job


class WorkerTests(unittest.TestCase):
    def setUp(self):
        worker._cancelled = False
        self.admission = {"candidate_sha": "a" * 40, "base_sha": "b" * 40,
                          "admission_message_digest": "1" * 64, "signed_request_digest": "2" * 64,
                          "run_id": "3" * 32, "attempt": 1, "wall_timeout_seconds": 60,
                          "expires_at": int(time.time()) + 60, "workflow_file_sha256": "4" * 64,
                          "workflow_id": "CI", "job_id": "dead-token-guard", "isolation_profile_digest": "9" * 64,
                          "artifacts": [{"artifact_id": "result", "name": "result.json", "media_type": "application/json",
                                         "relative_name": "result.json", "max_bytes": 32768}]}
        self.profile = {"workflow_id": "CI", "job_id": "dead-token-guard", "workflow_path": ".github/workflows/ci.yml",
                        "image": "docker.io/library/ubuntu@sha256:" + "5" * 64,
                        "maximum_wall_seconds": 60, "memory_mib": 2048, "cpus": 2, "pids_limit": 256,
                        "semantic_profile_sha256": "9" * 64}

    def test_logical_attempt_replay_refused_even_with_new_admission_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker.claim_job(root, self.admission, self.profile["job_id"])
            self.admission["admission_message_digest"] = "6" * 64
            with self.assertRaises(FileExistsError):
                worker.claim_job(root, self.admission, self.profile["job_id"])
            self.admission["attempt"] = 2
            self.assertTrue(worker.claim_job(root, self.admission, self.profile["job_id"]).is_dir())

    def test_actual_guard_success_and_deliberate_failure(self):
        workflow = (ROOT.parents[2] / ".github/workflows/ci.yml").read_bytes()
        compiled = compile_job(workflow, hashlib.sha256(workflow).hexdigest(), "dead-token-guard")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ("desktop/src", "desktop/tests", "mobile/test", "mobile/lib"):
                (directory / name).mkdir(parents=True, exist_ok=True)
            (directory / ".env.example").write_text("")
            script = compiled.script.replace(b"/workspace", str(directory).encode())
            success = subprocess.run(["/bin/bash", "--noprofile", "--norc"], input=script, capture_output=True)
            self.assertEqual(success.returncode, 0, success.stderr)
            (directory / "desktop/src/negative.ts").write_text("TokenScope\n")
            failure = subprocess.run(["/bin/bash", "--noprofile", "--norc"], input=script, capture_output=True)
            self.assertEqual(failure.returncode, 1)
            self.assertIn(b"Dead API token references", failure.stdout)

    def fake_materialize(self, job_dir, *args):
        (job_dir / "source").mkdir()
        (job_dir / "objects").mkdir()
        data = (ROOT.parents[2] / ".github/workflows/ci.yml").read_bytes()
        (job_dir / "trusted-workflow.yml").write_bytes(data)
        return {"candidate_sha": self.admission["candidate_sha"], "tree_sha": "7" * 40}

    def execute(self, outcome):
        data = (ROOT.parents[2] / ".github/workflows/ci.yml").read_bytes()
        self.admission["workflow_file_sha256"] = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(worker, "materialize", self.fake_materialize), patch.object(worker, "run_container", return_value=outcome):
                receipt = worker.execute_verified(self.profile, "8" * 64, self.admission, root)
            self.assertFalse((root / "source").exists())
            self.assertFalse((root / "objects").exists())
            return receipt

    def test_terminal_success_contains_native_step_and_source_binding(self):
        receipt = self.execute(ContainerResult(0, "success", True, "container", b"ok", b"", 2))
        self.assertEqual(receipt["conclusion"], "success")
        self.assertEqual(receipt["admission"], self.admission)
        self.assertEqual(receipt["workflow_execution"]["executed_step_indices"], [1])
        self.assertEqual(receipt["workflow_execution"]["native_step_indices"], [0, 2, 3])
        self.assertEqual(receipt["container"]["stdout_sha256"], hashlib.sha256(b"ok").hexdigest())
        self.assertTrue(receipt["source_cleanup_proven"])

    def test_failure_cancel_timeout_and_unclean_never_succeed(self):
        for outcome, expected in ((ContainerResult(1, "job_failed", True, "x"), "failure"),
                                  (ContainerResult(None, "cancelled", True, "x"), "cancelled"),
                                  (ContainerResult(None, "deadline", True, "x"), "timed_out"),
                                  (ContainerResult(0, "success", False, "x"), "infrastructure_failure")):
            self.assertEqual(self.execute(outcome)["conclusion"], expected)

    def test_receipt_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            worker._publish(path, {"conclusion": "failure"})
            with self.assertRaises(FileExistsError):
                worker._publish(path, {"conclusion": "success"})
            self.assertEqual(json.loads(path.read_bytes())["conclusion"], "failure")

    def test_expired_admission_never_materializes(self):
        self.admission["expires_at"] = 1
        with tempfile.TemporaryDirectory() as temporary, patch.object(worker, "materialize") as materialize:
            with self.assertRaises(Refused):
                worker.execute_verified(self.profile, "8" * 64, self.admission, Path(temporary))
            materialize.assert_not_called()


if __name__ == "__main__":
    unittest.main()
