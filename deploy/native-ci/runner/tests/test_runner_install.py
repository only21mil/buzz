from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import subprocess
import tempfile
import unittest

RUNNER_DIR = Path(__file__).resolve().parents[1]
SOURCE_ROOT = RUNNER_DIR.parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RENDERER = load_module("render_runner_config", RUNNER_DIR / "render_runner_config.py")
FREEZER = load_module("freeze_package", RUNNER_DIR / "freeze_package.py")
INSTALLER = load_module("runner_install", RUNNER_DIR / "install.py")


class RunnerInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.source_root = self.base / "source"
        copied = self.source_root / "deploy/native-ci/runner"
        copied.parent.mkdir(mode=0o700, parents=True)
        shutil.copytree(
            RUNNER_DIR,
            copied,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        subprocess.run(["git", "init", "-q", str(self.source_root)], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.name", "Runner test"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.email", "runner@test.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "add", "deploy/native-ci/runner"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "commit", "-qm", "fixture"], check=True)
        self.source_commit = FREEZER.git_output(self.source_root, "rev-parse", "HEAD")
        self.binary = self.base / "buzz-ci-runner"
        self.binary.write_bytes(b"test buzz-ci-runner binary\n")
        self.binary.chmod(0o755)
        self.provenance = self.base / "binary-provenance.json"
        self.provenance.write_text(
            json.dumps(
                {
                    "schema": "buzz-ci-binary-provenance-v1",
                    "binary": "buzz-ci-runner",
                    "source_commit": self.source_commit,
                    "profile": "release",
                    "sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        self.provenance.chmod(0o600)
        self.package = self.base / "package"
        self.runner_uid = os.geteuid()
        self.runner_gid = os.getegid()

    def freeze(self) -> dict[str, object]:
        return FREEZER.freeze_package(
            self.source_root,
            self.source_commit,
            self.binary,
            self.provenance,
            self.package,
            self.runner_uid,
            self.runner_gid,
            self.runner_uid,
            self.runner_gid,
        )

    def make_root(self) -> Path:
        root = self.base / "root"
        root.mkdir(mode=0o700)
        for relative in (
            "etc/systemd/system",
            "usr/libexec",
            "usr/lib/tmpfiles.d",
            "usr/share/doc",
            "var/lib",
        ):
            current = root
            for component in Path(relative).parts:
                current /= component
                current.mkdir(mode=0o755, exist_ok=True)
        (root / "etc/passwd").write_text(
            f"buzzci-runner:x:{self.runner_uid}:{self.runner_gid}:runner:/nonexistent:/usr/sbin/nologin\n"
            f"buzzci-controld:x:{self.runner_uid}:{self.runner_gid}:controld:/nonexistent:/usr/sbin/nologin\n"
        )
        (root / "etc/group").write_text(
            f"buzzci-runner:x:{self.runner_gid}:\n"
            f"buzzci-controld:x:{self.runner_gid}:\n"
        )
        (root / "etc/passwd").chmod(0o644)
        (root / "etc/group").chmod(0o644)
        return root

    def test_config_renderer_is_canonical_closed_and_nofollow(self) -> None:
        output = self.base / "runner-v1.json"
        RENDERER.render(output, self.runner_uid)
        self.assertEqual(
            output.read_bytes(),
            f'{{"controld_uid":{self.runner_uid},"schema_version":1}}\n'.encode(),
        )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        RENDERER.check(output, self.runner_uid, self.runner_uid)
        value = json.loads(output.read_bytes())
        self.assertNotIn("host", value)
        self.assertNotIn("capacity", value)

        linked = self.base / "linked.json"
        linked.symlink_to(output)
        with self.assertRaises(OSError):
            RENDERER.check(linked, self.runner_uid)

    def test_freeze_binds_source_binary_package_and_dormant_state(self) -> None:
        manifest = self.freeze()
        parsed, entries = INSTALLER.parse_manifest(self.package, self.base)
        self.assertEqual(parsed["source_commit"], self.source_commit)
        self.assertEqual(parsed["default_state"], INSTALLER.DEFAULT_STATE)
        self.assertEqual(parsed["package_digest"], manifest["package_digest"])
        self.assertEqual({entry.role for entry in entries}, set(INSTALLER.EXPECTED_TARGETS))
        binary = next(entry for entry in entries if entry.role == "binary")
        self.assertEqual(binary.sha256, hashlib.sha256(self.binary.read_bytes()).hexdigest())

    def test_check_rejects_linked_asset_and_binary_provenance_drift(self) -> None:
        self.freeze()
        binary_asset = self.package / "assets/buzz-ci-runner"
        original = self.package / "assets/original"
        binary_asset.rename(original)
        binary_asset.symlink_to(original)
        with self.assertRaises(OSError):
            INSTALLER.parse_manifest(self.package, self.base)

        binary_asset.unlink()
        original.rename(binary_asset)
        provenance = json.loads((self.package / "binary-provenance.json").read_text())
        provenance["source_commit"] = "0" * 40
        (self.package / "binary-provenance.json").write_text(json.dumps(provenance))
        (self.package / "binary-provenance.json").chmod(0o600)
        with self.assertRaisesRegex(ValueError, "provenance digest"):
            INSTALLER.parse_manifest(self.package, self.base)

    def test_dry_run_install_idempotency_and_exact_rollback(self) -> None:
        self.freeze()
        root = self.make_root()
        dry_run = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, dry_run=True)
        self.assertEqual(dry_run["status"], "dry_run")
        self.assertEqual(len(dry_run["changed_targets"]), 6)
        self.assertFalse((root / "usr/libexec/buzz-ci-runner").exists())

        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(installed["status"], "installed")
        self.assertFalse(installed["enabled"])
        self.assertFalse(installed["provisioned"])
        self.assertEqual(installed["capacity"], 0)
        unchanged = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(unchanged["status"], "unchanged")
        self.assertEqual(unchanged["changed_targets"], [])

        preview = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
            dry_run=True,
        )
        self.assertEqual(preview["status"], "rollback_dry_run")
        rolled_back = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )
        self.assertEqual(rolled_back["status"], "rolled_back")
        for target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertFalse(INSTALLER.rooted(root, target).exists())
        self.assertFalse((root / "etc/buzzci").exists())
        self.assertFalse((root / "usr/share/doc/buzz-ci-runner").exists())

    def test_install_refuses_target_symlink_and_rollback_refuses_drift(self) -> None:
        self.freeze()
        root = self.make_root()
        outside = self.base / "outside"
        outside.write_text("do not touch")
        target = root / "usr/libexec/buzz-ci-runner"
        target.symlink_to(outside)
        with self.assertRaises(OSError):
            INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, dry_run=True)
        self.assertEqual(outside.read_text(), "do not touch")

        target.unlink()
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        target.write_text("drift")
        target.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "drift blocks rollback"):
            INSTALLER.rollback(
                self.package,
                root,
                INSTALLER.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
            )

    def test_templates_keep_runner_and_control_resources_separate(self) -> None:
        service = (RUNNER_DIR / "templates/buzz-ci-runner.service").read_text()
        socket = (RUNNER_DIR / "templates/buzz-ci-runner.socket").read_text()
        tmpfiles = (RUNNER_DIR / "templates/buzzci-runner.tmpfiles").read_text()
        self.assertIn("/run/buzzci/runner-control.sock", socket)
        self.assertNotIn("/run/buzzci/execd.sock", socket)
        self.assertIn("ReadWritePaths=/var/lib/buzzci/runner", service)
        self.assertNotIn("/var/lib/buzzci/runner-output", service + tmpfiles)
        self.assertNotIn("systemctl", (RUNNER_DIR / "install.py").read_text())

    def test_schemas_are_strict_json(self) -> None:
        for name in (
            "runner-config.schema.json",
            "package-manifest.schema.json",
            "binary-provenance.schema.json",
        ):
            schema = json.loads((RUNNER_DIR / name).read_text())
            self.assertFalse(schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
