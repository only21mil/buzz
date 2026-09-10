"""No runtime commands are executed by these tests."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "linux-runner/container_runtime.py"
SPEC = importlib.util.spec_from_file_location("linux_container_runtime", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNTIME = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNTIME
SPEC.loader.exec_module(RUNTIME)


class FakeProcess:
    def __init__(self, stdout=b"output", stderr=b"diagnostic", running=False):
        self.stdout = self.pipe(stdout)
        self.stderr = self.pipe(stderr)
        self.returncode = None if running else 0
        self.terminated = False

    @staticmethod
    def pipe(data):
        reader, writer = os.pipe()
        os.write(writer, data)
        os.close(writer)
        return os.fdopen(reader, "rb")

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    def wait(self, timeout):
        return self.returncode


class ContainerRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.job_dir = self.root / "job"
        self.job_dir.mkdir(mode=0o700)
        self.source = self.job_dir / "source"
        self.source.mkdir(mode=0o755)
        self.script = self.job_dir / "workflow.sh"
        self.script.write_text("printf hello\n")
        self.script.chmod(0o644)
        self.spec = RUNTIME.ContainerSpec("a" * 64, "registry.example/ci@sha256:" + "b" * 64)

    def run_fake(self, process, *, control=(1, 0, 1), cancelled=lambda: False, clock=None):
        with (
            patch.object(RUNTIME.os, "geteuid", return_value=os.getuid() or 1000),
            patch.object(RUNTIME, "_environment", return_value={"PATH": "/usr/bin:/bin"}),
            patch.object(RUNTIME.subprocess, "Popen", return_value=process) as launch,
            patch.object(RUNTIME, "_control", side_effect=control) as control_mock,
        ):
            if clock is None:
                result = RUNTIME.run_container(self.spec, self.source, self.script, self.job_dir, cancelled)
            else:
                with patch.object(RUNTIME.time, "monotonic", side_effect=clock):
                    result = RUNTIME.run_container(self.spec, self.source, self.script, self.job_dir, cancelled)
            return result, launch, control_mock

    def test_fixed_argv_has_no_host_shell_engine_socket_or_writable_source(self):
        args = RUNTIME._command(self.spec, self.source, self.script, self.job_dir)
        self.assertEqual(args[:3], ["/usr/bin/podman", "--remote=false", "run"])
        for fixed in ("--userns=auto:size=65536", "--user=1000:1000", "--network=none", "--pull=never", "--cap-drop=ALL", "--read-only", "--unsetenv-all", "--http-proxy=false"):
            self.assertIn(fixed, args)
        self.assertIn(f"type=bind,src={self.source},dst=/source,ro=true,relabel=private", args)
        self.assertIn(f"type=bind,src={self.script},dst=/workflow.sh,ro=true,relabel=private", args)
        self.assertIn("type=tmpfs,dst=/workspace,rw,exec,nosuid,nodev,notmpcopyup,tmpfs-size=2048m,tmpfs-mode=0700,U=true", args)
        self.assertFalse(any("docker.sock" in arg or "podman.sock" in arg for arg in args))
        self.assertEqual(args[-1], "cp -R /source/. /workspace/; exec /bin/bash --noprofile --norc -e -o pipefail /workflow.sh")

    def test_success_waits_for_cleanup_and_captures_counts(self):
        result, launch, control = self.run_fake(FakeProcess())
        self.assertEqual((result.exit_code, result.reason, result.cleanup_proven), (0, "success", True))
        self.assertEqual(result.stdout, b"output")
        self.assertEqual(result.stderr_bytes, 10)
        self.assertFalse(result.stdout_truncated)
        self.assertTrue(launch.call_args.kwargs["close_fds"])
        self.assertEqual(control.call_args_list[-1].args[0], ["container", "exists", result.container_name])

    def test_zero_exit_with_unproven_cleanup_is_not_success(self):
        for code in (0, 125, None):
            with self.subTest(code=code):
                result, _, _ = self.run_fake(FakeProcess(), control=(1, 0, code))
                self.assertFalse(result.cleanup_proven)
                self.assertEqual(result.reason, "cleanup_unproven")

    def test_capture_drains_large_output_without_retaining_it(self):
        capture = RUNTIME._Capture()
        for _ in range(1024):
            capture.append(b"x" * 65536)
        self.assertEqual(capture.count, 64 * 1024 * 1024)
        self.assertEqual(len(capture.kept), 32768)

    def test_result_reports_truncation_and_total_observed_output(self):
        with patch.object(RUNTIME, "OUTPUT_LIMIT", 4):
            result, _, _ = self.run_fake(FakeProcess())
        self.assertEqual(result.stdout, b"outp")
        self.assertEqual(result.stderr, b"diag")
        self.assertEqual((result.stdout_bytes, result.stderr_bytes), (6, 10))
        self.assertTrue(result.stdout_truncated and result.stderr_truncated)

    def test_nonzero_job_exit_is_preserved_after_cleanup(self):
        process = FakeProcess()
        process.returncode = 7
        result, _, _ = self.run_fake(process)
        self.assertEqual((result.exit_code, result.reason), (7, "job_failed"))
        self.assertTrue(result.cleanup_proven)

    def test_cancel_and_deadline_stop_client_before_removing_container(self):
        process = FakeProcess(running=True)
        calls = iter([False, True])
        result, _, control = self.run_fake(process, cancelled=lambda: next(calls))
        self.assertEqual(result.reason, "cancelled")
        self.assertTrue(process.terminated)
        self.assertTrue(result.cleanup_proven)
        self.assertEqual(control.call_args_list[1].args[0][:3], ["rm", "--force", "--time=5"])
        process = FakeProcess(running=True)
        result, _, _ = self.run_fake(process, clock=[0, 901])
        self.assertEqual(result.reason, "deadline")
        self.assertTrue(process.terminated)

    def test_existing_container_is_never_removed_or_started(self):
        process = FakeProcess()
        try:
            with self.assertRaises(RuntimeError):
                self.run_fake(process, control=(0,))
        finally:
            process.stdout.close()
            process.stderr.close()

    def test_inherited_output_pipe_cannot_outlive_deadline(self):
        process = FakeProcess()
        process.stdout.close()
        reader, inherited_writer = os.pipe()
        process.stdout = os.fdopen(reader, "rb")
        try:
            result, _, _ = self.run_fake(process, clock=[0, 0, 901])
        finally:
            os.close(inherited_writer)
        self.assertEqual(result.reason, "deadline")
        self.assertTrue(result.cleanup_proven)

    def test_root_unsafe_policy_and_symlink_are_refused_before_launch(self):
        with patch.object(RUNTIME.subprocess, "Popen") as launch:
            with patch.object(RUNTIME.os, "geteuid", return_value=0):
                with self.assertRaises(PermissionError):
                    RUNTIME.run_container(self.spec, self.source, self.script, self.job_dir, lambda: False)
            for field, value in (("image", "alpine:latest"), ("network", "host"), ("network", "slirp4netns:allow_host_loopback=false"), ("timeout_seconds", True), ("memory_mib", 1), ("cpus", 9)):
                values = dict(vars(self.spec), **{field: value})
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    RUNTIME.ContainerSpec(**values).validate()
            self.script.unlink()
            self.script.symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                RUNTIME._safe_path(self.script, directory=False, owner=os.getuid())
            launch.assert_not_called()

    def test_private_relabel_refuses_shared_source_and_linked_script_before_launch(self):
        shared = self.root / "shared"
        shared.mkdir(mode=0o755)
        with patch.object(RUNTIME.subprocess, "Popen") as launch, patch.object(RUNTIME, "_control") as control:
            with self.assertRaisesRegex(ValueError, "fresh job-owned"):
                RUNTIME.run_container(self.spec, shared, self.script, self.job_dir, lambda: False)
            external = self.root / "shared-script"
            external.hardlink_to(self.script)
            with self.assertRaisesRegex(ValueError, "fresh job-owned"):
                RUNTIME.run_container(self.spec, self.source, self.script, self.job_dir, lambda: False)
            launch.assert_not_called()
            control.assert_not_called()

    def test_control_errors_never_prove_absence(self):
        with patch.object(RUNTIME.subprocess, "run", side_effect=subprocess.TimeoutExpired("podman", 20)):
            self.assertFalse(RUNTIME._remove_and_verify("buzzci-" + "a" * 64, {}))


if __name__ == "__main__":
    unittest.main()
