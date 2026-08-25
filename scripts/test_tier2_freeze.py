import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("tier2-freeze.py")


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        check=check,
        capture_output=True,
        text=True,
    )


class Tier2FreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        temp_parent = Path(os.environ.get("BUZZ_TEST_TMPDIR", Path.home() / "work"))
        temp_parent.mkdir(parents=True, exist_ok=True)
        self.tempdir = tempfile.TemporaryDirectory(dir=temp_parent)
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "config", "user.email", "test@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "config", "user.name", "Tier2 Test"],
            check=True,
        )
        (self.repo / "tracked.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "base"], check=True)
        self.base = (
            subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"])
            .decode()
            .strip()
        )
        (self.repo / "committed.txt").write_text("committed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "committed.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "direct"], check=True)
        (self.repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")
        (self.repo / "untracked.txt").write_text("new\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_freeze_emits_parser_compatible_manifest_and_git_summary(self) -> None:
        manifest = self.root / "candidate.jsonl"
        result = run(str(self.repo), self.base, "--manifest", str(manifest))
        bundle = json.loads(result.stdout)
        lines = manifest.read_text(encoding="utf-8").splitlines()
        header = json.loads(lines[0])
        entries = [json.loads(line) for line in lines[1:]]

        self.assertEqual(stat_mode(manifest), 0o600)
        self.assertEqual(header["manifest"], "git-source-manifest-v1")
        self.assertEqual(header["entry_count"], len(entries))
        self.assertEqual(
            [entry["path"] for entry in entries],
            sorted((entry["path"] for entry in entries), key=lambda value: value.encode()),
        )
        self.assertEqual(bundle["artifact_target"]["manifest_sha256"], bundle["artifact_fingerprint"])
        self.assertEqual(bundle["git_summary"]["base"], self.base)
        self.assertEqual(bundle["git_summary"]["first_parent_total"], 1)
        self.assertEqual(bundle["git_summary"]["first_parent_merge"], 0)
        self.assertEqual(bundle["git_summary"]["first_parent_direct"], 1)
        self.assertEqual(bundle["git_summary"]["name_status_count"], 1)
        self.assertTrue(bundle["created_utc"].endswith("Z"))

    def test_verify_rejects_stale_sha_and_accepts_listed_merged_tip(self) -> None:
        manifest = self.root / "candidate.jsonl"
        result = run(str(self.repo), self.base, "--manifest", str(manifest))
        bundle = json.loads(result.stdout)
        stale = "1" * 40
        bundle["note"] = stale
        bundle_path = self.root / "bundle.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

        rejected = run(
            str(self.repo), self.base, "--verify", str(bundle_path), check=False
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(stale, rejected.stderr)

        bundle["git_summary"]["merged_tips"] = [stale]
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        accepted = run(
            str(self.repo), self.base, "--verify", str(bundle_path), check=False
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
