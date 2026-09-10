import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import workflow_source as source


def digest(data):
    return hashlib.sha256(data).hexdigest()


def workflow(body):
    return ("name: native\non: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: " + source.CHECKOUT + "\n" + body).encode()


class WorkflowTests(unittest.TestCase):
    def test_actual_required_guard_compiles_from_exact_workflow(self):
        data = (ROOT.parents[2] / ".github/workflows/ci.yml").read_bytes()
        result = source.compile_job(data, digest(data), "dead-token-guard")
        self.assertEqual(result.workload_steps, (1,))
        self.assertEqual(result.native_steps, (0, 2, 3))
        self.assertIn(b"grep -rn", result.script)
        self.assertNotIn(b"protected-ci-landing.py", result.script)

    def test_mutated_qualification_command_is_not_omitted(self):
        data = (ROOT.parents[2] / ".github/workflows/ci.yml").read_bytes()
        data = data.replace(source.CAPTURE.encode(), source.CAPTURE.encode() + b"; exit 1")
        with self.assertRaises(source.Refused):
            source.compile_job(data, digest(data), "dead-token-guard")

    def test_digest_drift_and_missing_job_refused(self):
        data = workflow("      - run: exit 0\n")
        for expected, job in (("0" * 64, "check"), (digest(data), "missing")):
            with self.assertRaises(source.Refused):
                source.compile_job(data, expected, job)

    def test_workload_exit_failure_is_preserved(self):
        data = workflow("      - run: exit 23\n")
        result = source.compile_job(data, digest(data), "check")
        self.assertIn(b"exit 23", result.script)

    def test_actions_and_dynamic_semantics_refused(self):
        for body in ("      - uses: evil/action@main\n", "      - run: echo ${{ secrets.KEY }}\n",
                     "      - run: echo ok\n        if: false\n", "      - run: echo ok\n        continue-on-error: true\n"):
            data = workflow(body)
            with self.assertRaises(source.Refused):
                source.compile_job(data, digest(data), "check")
        for feature in ("    needs: prior\n", "    strategy: {matrix: {x: [1, 2]}}\n", "    services: {}\n"):
            data = workflow("      - run: exit 0\n").replace(b"    steps:\n", feature.encode() + b"    steps:\n")
            with self.assertRaises(source.Refused):
                source.compile_job(data, digest(data), "check")

    def test_duplicate_yaml_keys_refused(self):
        data = workflow("      - run: exit 1\n        run: exit 0\n")
        with self.assertRaises(source.Refused):
            source.compile_job(data, digest(data), "check")

    def test_step_subshell_env_and_workdir_are_literal(self):
        data = workflow("      - run: echo ok\n        working-directory: desktop\n        env:\n          VALUE: '$(touch /no)'\n")
        result = source.compile_job(data, digest(data), "check")
        self.assertIn(b"export VALUE='$(touch /no)'", result.script)
        self.assertIn(b"cd -- /workspace/desktop", result.script)


class MaterializationTests(unittest.TestCase):
    def fake_git(self, files, workflow_bytes):
        blobs = {}
        records = []
        for mode, path, content in files:
            oid = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
            blobs[oid] = content
            records.append((mode + " blob " + oid + "\t" + path).encode())
        def call(repo, args, deadline, **kwargs):
            if args[0] == "init" or "fetch" in args:
                return b""
            if args[:2] == ["cat-file", "-t"]:
                return b"commit\n"
            if args[0] == "rev-parse":
                return b"c" * 40 + b"\n"
            if args[0] == "ls-tree":
                return b"\0".join(records) + b"\0"
            if args[:2] == ["cat-file", "blob"] and ":" in args[2]:
                return workflow_bytes
            if args[:2] == ["cat-file", "-s"]:
                return str(len(blobs[args[2]])).encode()
            return blobs[args[2]]
        return call

    def materialize(self, root, files):
        data = workflow("      - run: exit 0\n")
        with patch.object(source, "_git", self.fake_git(files, data)):
            return source.materialize(root, "a" * 40, "b" * 40, ".github/workflows/ci.yml", digest(data), time.monotonic() + 10)

    def test_raw_source_and_internal_symlink_materialize(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.materialize(root, [("100755", "bin/run", b"echo real"), ("120000", "run", b"bin/run")])
            self.assertEqual((root / "source/run").read_bytes(), b"echo real")
            self.assertEqual((root / "source/bin/run").stat().st_mode & 0o777, 0o755)
            self.assertEqual(result["tree_sha"], "c" * 40)

    def test_escape_symlink_gitlink_and_ancestor_refused(self):
        cases = [[("120000", "escape", b"../../outside")], [("160000", "submodule", b"x")],
                 [("120000", "dir", b"safe"), ("100644", "dir/file", b"x")],
                 [("100644", ".git/config", b"x")], [("100644", "../outside", b"x")]]
        for files in cases:
            with tempfile.TemporaryDirectory() as temporary, self.assertRaises(source.Refused):
                self.materialize(Path(temporary), files)

    def test_source_size_bound_applies_before_blob_write(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(source, "MAX_BLOB", 2):
            with self.assertRaises(source.Refused):
                self.materialize(Path(temporary), [("100644", "large", b"123")])


if __name__ == "__main__":
    unittest.main()
