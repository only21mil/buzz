#!/usr/bin/env python3
"""Hermetic shim tests for scripts/ci-apt-retry.sh: no apt, sudo or sleep runs."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name("ci-apt-retry.sh")


class AptRetryTests(unittest.TestCase):
    def run_helper(self, *args, failures=0, env=None):
        """Shim sudo (fails `failures` times, then succeeds) and sleep (records delays)."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sudo").write_text(
                "#!/bin/bash\n"
                f"calls={root / 'sudo.calls'}\n"
                'printf "%s\\n" "$*" >> "$calls"\n'
                f'[[ $(wc -l < "$calls") -gt {failures} ]]\n')
            (root / "sleep").write_text(f"#!/bin/bash\nprintf '%s\\n' \"$1\" >> {root / 'sleep.calls'}\n")
            for name in ("sudo", "sleep"):
                (root / name).chmod(0o700)
            environment = {"PATH": f"{root}:/usr/bin:/bin", **(env or {})}
            result = subprocess.run(["/bin/bash", str(SCRIPT), *args], env=environment,
                                    capture_output=True, text=True, timeout=30)
            calls = (root / "sudo.calls").read_text().splitlines() if (root / "sudo.calls").exists() else []
            sleeps = (root / "sleep.calls").read_text().splitlines() if (root / "sleep.calls").exists() else []
            return result, calls, sleeps

    def test_transient_failures_retry_with_backoff_then_succeed(self):
        result, calls, sleeps = self.run_helper("true", failures=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(call.startswith("apt-get update") for call in calls))
        self.assertEqual(sleeps, ["20", "40"])

    def test_install_command_failure_retries_and_then_fails_the_step(self):
        result, calls, sleeps = self.run_helper("false")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleeps, ["20", "40"])
        self.assertIn("::error::apt install failed after 3 attempts: false", result.stderr)

    def test_attempt_count_override_is_honoured(self):
        result, calls, sleeps = self.run_helper("true", failures=1, env={"APT_RETRY_ATTEMPTS": "2"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((len(calls), sleeps), (2, ["20"]))
        result, calls, sleeps = self.run_helper("true", failures=1, env={"APT_RETRY_ATTEMPTS": "1"})
        self.assertEqual((result.returncode, len(calls), sleeps), (1, 1, []))

    def test_invalid_attempt_count_fails_closed_without_installing(self):
        for value in ("0", "-1", "abc", "3x", "07", " 3"):
            with self.subTest(value=value):
                result, calls, sleeps = self.run_helper("true", env={"APT_RETRY_ATTEMPTS": value})
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual((calls, sleeps), ([], []))
                self.assertIn("APT_RETRY_ATTEMPTS must be a positive integer", result.stderr)

    def test_empty_attempt_count_uses_the_default(self):
        result, calls, sleeps = self.run_helper("true", failures=2, env={"APT_RETRY_ATTEMPTS": ""})
        self.assertEqual((result.returncode, len(calls), sleeps), (0, 3, ["20", "40"]))

    def test_missing_command_is_a_usage_error(self):
        result, calls, sleeps = self.run_helper()
        self.assertEqual((result.returncode, calls, sleeps), (2, [], []))
        self.assertIn("usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
