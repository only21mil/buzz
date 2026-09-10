import copy
from contextlib import ExitStack
import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
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
        self.admission = {"run_id": "a" * 32, "attempt": 1, "admission_message_digest": "1" * 64, "candidate_sha": "a" * 40,
                          "base_sha": "b" * 40, "workflow_file_sha256": "c" * 64,
                          "wall_timeout_seconds": 300, "expires_at": int(time.time()) + 300}
        self.profile_digest = "d" * 64
        self.invocation = hashlib.sha256(worker._canonical({"admission_message_digest": "1" * 64,
                                                          "profile_sha256": self.profile_digest})).hexdigest()
        self.slice_name = "buzzcilinux" + self.invocation + ".slice"
        self.slice_state = {"InvocationID": "f" * 32, "ActiveState": "active", "ControlGroup": "/" + self.slice_name}
        self.state = {"Slice": self.slice_name, "ControlGroup": "/" + self.slice_name + "/buzz-ci-linux-" + self.invocation + ".service", "InvocationID": "e" * 32, "SubState": "exited", "ActiveState": "active",
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

    def lifecycle_states(self):
        return [{"LoadState": "not-found"}, {"ActiveState": "inactive"}, self.state, self.slice_state,
                self.state, {"ActiveState": "inactive"}, self.slice_state, {"ActiveState": "inactive"}]

    def validate(self, result=None, state=None):
        submit.validate_result(self.result if result is None else result, self.admission, self.profile,
                               self.profile_digest, self.invocation, self.state if state is None else state)

    def test_missing_events_and_removed_directory_never_prove_empty(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent) / "slice"
            directory.mkdir()
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(FileNotFoundError):
                    submit._empty_cgroup(descriptor)
                events = directory / "cgroup.events"
                events.write_text("populated 1\nfrozen 0\n")
                self.assertFalse(submit._empty_cgroup(descriptor))
                events.write_text("populated 0\nfrozen 0\n")
                self.assertTrue(submit._empty_cgroup(descriptor))
                events.unlink()
                directory.rmdir()
                with self.assertRaises(FileNotFoundError):
                    submit._empty_cgroup(descriptor)
            finally:
                os.close(descriptor)

    def test_existing_slice_is_not_started_or_stopped(self):
        with patch.object(submit, "_state", side_effect=[{"LoadState": "not-found"}, self.slice_state]), \
             patch.object(submit, "_launch") as launch, patch.object(submit, "_command") as command:
            with self.assertRaises(Refused):
                submit.supervise(Path("/unused"), self.profile, self.profile_digest, self.admission)
            launch.assert_not_called()
            command.assert_not_called()

    def test_control_commands_do_not_inherit_operator_working_directory(self):
        previous = Path.cwd()
        try:
            with tempfile.TemporaryDirectory() as private:
                os.chdir(private)
                result = submit._command(["/usr/bin/pwd"])
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"/\n")
        finally:
            os.chdir(previous)

    def test_launch_exposes_only_dedicated_runtime_under_private_home_mounts(self):
        account = SimpleNamespace(pw_uid=1234, pw_gid=1234, pw_name="buzzci-linux",
                                  pw_dir="/var/lib/buzzci/linux-runner/home")
        with patch.object(submit.pwd, "getpwuid", return_value=account), \
             patch.object(submit, "_command", return_value=subprocess.CompletedProcess([], 0)) as command:
            submit._launch("buzz-ci-linux-test.service", Path("/private/claim"), self.profile)
        argv = command.call_args.args[0]
        self.assertIn("--property=ProtectHome=tmpfs", argv)
        self.assertIn("--property=BindPaths=/run/user/1234", argv)
        self.assertNotIn("--property=ProtectHome=yes", argv)
        self.assertIn("--property=ProtectSystem=strict", argv)
        self.assertIn("--property=RestrictSUIDSGID=no", argv)
        self.assertIn("--property=Slice=buzzcilinuxtest.slice", argv)

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
                states = self.lifecycle_states()
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
                        self.assertTrue(proof["slice_inactive"])
                        self.assertEqual(proof["slice"], self.slice_name)
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
        with patch.object(submit, "_state", side_effect=[{"LoadState": "not-found"}, {"ActiveState": "inactive"}, self.slice_state, {"ActiveState": "inactive"}, self.slice_state, {"ActiveState": "inactive"}]), \
             patch.object(submit, "_launch", side_effect=Refused("start")), \
             patch.object(submit, "_container_absent", return_value=False) as absent, \
             patch.object(submit, "_command", return_value=subprocess.CompletedProcess([], 0, b"")) as command:
            with self.assertRaises(Refused):
                submit.supervise(Path("/unused"), self.profile, self.profile_digest, self.admission)
            self.assertEqual(command.call_args.args[0][1], "stop")
            absent.assert_called_once()

    def test_invalid_worker_output_still_measures_cleanup_and_stops(self):
        with tempfile.TemporaryDirectory() as temporary:
            descriptor = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            with patch.object(submit, "_state", side_effect=self.lifecycle_states()), \
                 patch.object(submit, "_launch"), \
                 patch.object(submit, "_cgroup", return_value=(descriptor, Path(temporary), (1, 2))), \
                 patch.object(submit, "_empty_cgroup", return_value=False) as empty, \
                 patch.object(submit, "_container_absent", return_value=False) as absent, \
                 patch.object(worker, "_read_root_file", return_value=b"invalid"), \
                 patch.object(submit, "_command", return_value=subprocess.CompletedProcess([], 0, b"")) as command:
                with self.assertRaises(ValueError):
                    submit.supervise(Path(temporary), self.profile, self.profile_digest, self.admission)
                empty.assert_called_once_with(descriptor)
                absent.assert_called_once_with(self.profile, self.invocation)
                self.assertEqual(command.call_args.args[0][1], "stop")
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def proof(self):
        result = copy.deepcopy(self.result)
        result["admission"] = self.admission.copy()
        return {"schema_version": "buzz-ci-native-linux-supervisor/v2", "native_result": result,
                "unit": "buzz-ci-linux-" + self.invocation + ".service", "invocation_id": "e" * 32,
                "slice": self.slice_name, "slice_invocation_id": "f" * 32, "slice_inactive": True,
                "cgroup_path": "/sys/fs/cgroup/" + self.slice_name, "cgroup_observation": "retained-slice-populated-zero",
                "container_absent": True, "recursive_cgroup_empty": True, "unit_inactive": True,
                "exec_main_code": 1, "exec_main_status": 0, "finished_at": int(time.time())}

    def main_environment(self, root):
        stack = ExitStack()
        self.addCleanup(stack.close)
        original_lstat = Path.lstat

        def root_lstat(path):
            metadata = original_lstat(path)
            if path == root or root in path.parents:
                fields = list(metadata)
                fields[4] = 0
                return os.stat_result(fields)
            return metadata

        stack.enter_context(patch.object(Path, "lstat", root_lstat))
        stack.enter_context(patch.object(submit, "SUPERVISOR_ROOT", root))
        stack.enter_context(patch.object(os, "geteuid", return_value=0))
        stack.enter_context(patch.object(worker, "_load_profile", return_value=(self.profile, self.profile_digest)))
        stack.enter_context(patch.object(worker, "verify_admission", side_effect=lambda frame: self.admission.copy()))
        # Test files belong to the test user; production validates root ownership.
        stack.enter_context(patch.object(worker, "_read_root_file", side_effect=lambda path, limit: path.read_bytes()))
        stack.enter_context(patch.object(submit.signal, "signal"))
        stack.enter_context(patch.object(sys, "argv", ["submit.py", "run"]))
        stack.enter_context(patch.object(sys, "stdout", SimpleNamespace(buffer=io.BytesIO())))
        return stack

    def run_main(self):
        with patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"x" * 992))):
            return submit.main()

    def test_refusal_quarantines_successor_run_and_attempt_after_lock_release(self):
        for successor in ({"run_id": "b" * 32}, {"attempt": 2}):
            with self.subTest(successor=successor), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with self.main_environment(root), patch.object(submit, "supervise", side_effect=Refused("unclean")) as run:
                    with self.assertRaisesRegex(Refused, "unclean"):
                        self.run_main()
                    self.admission.update(successor)
                    with self.assertRaisesRegex(Refused, "root recovery"):
                        self.run_main()
                    self.assertEqual(run.call_count, 1)
                    self.assertEqual(len(list(root.glob("*/registration.bin"))), 1)

    @unittest.skipUnless(hasattr(os, "fork"), "Linux crash regression")
    def test_hard_exit_leaves_slot_quarantined(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.main_environment(root), patch.object(submit, "supervise", side_effect=lambda *args: os._exit(23)):
                child = os.fork()
                if child == 0:
                    try:
                        self.run_main()
                    finally:
                        os._exit(24)
                _, status = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 23)
            with self.main_environment(root), patch.object(submit, "supervise") as run:
                self.admission["run_id"] = "b" * 32
                with self.assertRaisesRegex(Refused, "root recovery"):
                    self.run_main()
                run.assert_not_called()

    def test_invalid_or_unclean_prior_proof_quarantines_successor(self):
        variants = [b"{", b"{}", b"null"]
        for key in ("container_absent", "recursive_cgroup_empty", "unit_inactive", "slice_inactive"):
            proof = self.proof()
            proof[key] = False
            variants.append(worker._canonical(proof))
        proof = self.proof()
        proof["registration_sha256"] = "0" * 64
        variants.append(worker._canonical(proof))
        proof = self.proof()
        proof["registration_sha256"] = hashlib.sha256(b"x" * 992).hexdigest()
        proof["unit"] = "buzz-ci-linux-" + "0" * 64 + ".service"
        variants.append(worker._canonical(proof))
        for data in variants:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with self.main_environment(root), patch.object(submit, "supervise") as run:
                    directory = worker.claim_job(root, self.admission, self.profile["job_id"])
                    worker._publish_bytes(directory / "registration.bin", b"x" * 992)
                    worker._publish_bytes(directory / "supervisor.json", data)
                    self.admission["attempt"] += 1
                    with self.assertRaisesRegex(Refused, "root recovery"):
                        self.run_main()
                    run.assert_not_called()

    def test_complete_root_proof_allows_new_attempt_but_refuses_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.main_environment(root), patch.object(submit, "supervise", side_effect=lambda *args: self.proof()) as run:
                self.assertEqual(self.run_main(), 0)
                with self.assertRaises(FileExistsError):
                    self.run_main()
                self.admission = dict(self.admission, attempt=2)
                self.assertEqual(self.run_main(), 0)
                self.assertEqual(run.call_count, 2)
                self.assertEqual(len(list(root.glob("*/supervisor.json"))), 2)


if __name__ == "__main__":
    unittest.main()
