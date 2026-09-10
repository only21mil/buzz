import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import submit
import worker
from workflow_source import Refused


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        submit._cancelled = False
        self.profile = {"job_id": "dead-token-guard", "maximum_wall_seconds": 300, "runtime_uid": 1234}
        self.admission = {"admission_message_digest": "1" * 64, "candidate_sha": "a" * 40,
                          "base_sha": "b" * 40, "workflow_file_sha256": "c" * 64,
                          "wall_timeout_seconds": 300, "expires_at": int(time.time()) + 300}
        self.profile_digest = "d" * 64
        self.invocation = hashlib.sha256(worker._canonical({"admission_message_digest": "1" * 64,
                                                          "profile_sha256": self.profile_digest})).hexdigest()
        self.state = {"InvocationID": "e" * 32, "SubState": "exited", "ActiveState": "active",
                      "ExecMainCode": "1", "ExecMainStatus": "0"}
        self.result = {"schema_version": "buzz-ci-native-linux-receipt/v1", "admission": self.admission,
                       "profile_sha256": self.profile_digest, "invocation_digest": self.invocation,
                       "job_id": "dead-token-guard", "cleanup_proven": True, "source_cleanup_proven": True,
                       "conclusion": "success",
                       "container": {"container_name": "buzzci-" + self.invocation, "cleanup_proven": True,
                                     "reason": "success", "exit_code": 0},
                       "materialization": {"candidate_sha": "a" * 40, "base_sha": "b" * 40,
                                           "workflow_file_sha256": "c" * 64, "tree_sha": "f" * 40,
                                           "checkout_sha256": "a" * 64},
                       "workflow_execution": {"schema_version": "buzz-ci-native-shell-projection/v1",
                                              "job_id": "dead-token-guard", "trusted_base_sha": "b" * 40,
                                              "workflow_file_sha256": "c" * 64, "script_sha256": "b" * 64,
                                              "executed_step_indices": [1], "native_step_indices": [0, 2, 3]}}

    def validate(self, result=None, state=None):
        submit.validate_result(self.result if result is None else result, self.admission, self.profile,
                               self.profile_digest, self.invocation, self.state if state is None else state)

    def test_matching_source_and_actual_exit_are_required(self):
        self.validate()
        for change in ("admission", "profile_sha256", "invocation_digest", "job_id", "cleanup_proven"):
            changed = copy.deepcopy(self.result)
            changed[change] = None
            with self.assertRaises(Refused):
                self.validate(changed)
        changed = dict(self.state, ExecMainStatus="1")
        with self.assertRaises(Refused):
            self.validate(state=changed)

    def test_missing_workload_and_forged_source_refused(self):
        for field in ("materialization", "workflow_execution", "container"):
            changed = copy.deepcopy(self.result)
            changed[field] = {}
            with self.assertRaises(Refused):
                self.validate(changed)
        changed = copy.deepcopy(self.result)
        changed["materialization"]["candidate_sha"] = "0" * 40
        with self.assertRaises(Refused):
            self.validate(changed)

    def test_root_proof_requires_independent_container_and_cgroup_readback(self):
        for container_absent, cgroup_empty, succeeds in ((True, True, True), (False, True, False), (True, False, False)):
            with tempfile.TemporaryDirectory() as temporary:
                descriptor = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
                states = [{"LoadState": "not-found"}, self.state, self.state, {"ActiveState": "inactive"}]
                with patch.object(submit, "_state", side_effect=states), patch.object(submit, "_launch"), \
                     patch.object(submit, "_cgroup", return_value=(descriptor, Path(temporary), (1, 2))), \
                     patch.object(submit, "_empty_cgroup", return_value=cgroup_empty), \
                     patch.object(submit, "_container_absent", return_value=container_absent), \
                     patch.object(worker, "_read_root_file", return_value=json.dumps(self.result).encode()), \
                     patch.object(submit, "_command", return_value=subprocess.CompletedProcess([], 0, b"")) as command:
                    if succeeds:
                        proof = submit.supervise(Path(temporary), self.profile, self.profile_digest, self.admission)
                        self.assertTrue(proof["unit_inactive"])
                        self.assertTrue(proof["recursive_cgroup_empty"])
                    else:
                        with self.assertRaises(Refused):
                            submit.supervise(Path(temporary), self.profile, self.profile_digest, self.admission)
                    self.assertEqual(command.call_args.args[0][1], "stop")

    def test_existing_unit_is_not_started_or_stopped(self):
        with patch.object(submit, "_state", return_value={"LoadState": "loaded"}), \
             patch.object(submit, "_launch") as launch, patch.object(submit, "_command") as command:
            with self.assertRaises(Refused):
                submit.supervise(Path("/unused"), self.profile, self.profile_digest, self.admission)
            launch.assert_not_called()
            command.assert_not_called()

    def test_partial_start_failure_still_stops_exact_unit(self):
        with patch.object(submit, "_state", side_effect=[{"LoadState": "not-found"}, {"ActiveState": "inactive"}]), \
             patch.object(submit, "_launch", side_effect=Refused("start")), \
             patch.object(submit, "_command", return_value=subprocess.CompletedProcess([], 0, b"")) as command:
            with self.assertRaises(Refused):
                submit.supervise(Path("/unused"), self.profile, self.profile_digest, self.admission)
            self.assertEqual(command.call_args.args[0][1], "stop")


if __name__ == "__main__":
    unittest.main()
