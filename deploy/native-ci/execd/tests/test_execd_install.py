from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

EXECD_DIR = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


FREEZER = load_module("execd_freeze_package", EXECD_DIR / "freeze_package.py")
INSTALLER = load_module("execd_install", EXECD_DIR / "install.py")


class ExecdInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.source_root = self.base / "source"
        copied = self.source_root / "deploy/native-ci/execd"
        copied.parent.mkdir(mode=0o700, parents=True)
        shutil.copytree(EXECD_DIR, copied, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        subprocess.run(["git", "init", "-q", str(self.source_root)], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.name", "Execd test"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.email", "execd@test.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "add", "deploy/native-ci/execd"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "commit", "-qm", "fixture"], check=True)
        self.source_commit = FREEZER.git_output(self.source_root, "rev-parse", "HEAD")
        self.binary = self.base / "buzz-ci-execd"
        self.binary.write_bytes(b"test buzz-ci-execd binary\n")
        self.binary.chmod(0o755)
        self.provenance = self.base / "binary-provenance.json"
        self.provenance.write_text(json.dumps({
            "schema": "buzz-ci-binary-provenance-v1",
            "binary": "buzz-ci-execd",
            "source_commit": self.source_commit,
            "profile": "release",
            "sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
        }, sort_keys=True, separators=(",", ":")) + "\n")
        self.provenance.chmod(0o600)
        self.package = self.base / "package"
        if os.geteuid() == 0:
            self.skipTest("fake-root tests require a non-root invoking identity")

    def freeze(self) -> dict[str, object]:
        return FREEZER.freeze_package(
            self.source_root, self.source_commit, self.binary, self.provenance, self.package,
        )

    def make_root(self, name: str = "root") -> Path:
        root = self.base / name
        root.mkdir(mode=0o700)
        for relative in ("etc/systemd/system", "usr/libexec", "usr/lib/tmpfiles.d", "usr/share/doc", "var/lib"):
            current = root
            for component in Path(relative).parts:
                current /= component
                current.mkdir(mode=0o755, exist_ok=True)
        (root / "etc/passwd").write_text(
            "buzzci-ctl:x:961:961:broker:/var/lib/buzzci/principals/ctl:/usr/sbin/nologin\n"
            "buzzci-runner:x:968:968:runner:/nonexistent:/usr/sbin/nologin\n"
        )
        (root / "etc/passwd").chmod(0o644)
        return root

    def test_freeze_binds_source_binary_manifest_and_dormant_contract(self) -> None:
        manifest = self.freeze()
        parsed, entries = INSTALLER.parse_manifest(self.package, self.base)
        self.assertEqual(parsed["source_commit"], self.source_commit)
        self.assertEqual(parsed["default_state"], INSTALLER.DEFAULT_STATE)
        self.assertEqual(parsed["daemon_contract"], INSTALLER.DAEMON_CONTRACT)
        self.assertEqual(parsed["package_digest"], manifest["package_digest"])
        self.assertEqual({entry.role for entry in entries}, set(INSTALLER.EXPECTED_TARGETS))
        binary = next(entry for entry in entries if entry.role == "binary")
        self.assertEqual(binary.sha256, hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertNotIn("config", {entry.role for entry in entries})

    def test_package_refuses_symlink_and_provenance_drift(self) -> None:
        self.freeze()
        binary_asset = self.package / "assets/buzz-ci-execd"
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

    def test_check_is_read_only_and_reports_machine_state(self) -> None:
        self.freeze()
        root = self.make_root()

        def snapshot() -> dict[str, tuple[int, bytes | None]]:
            return {
                str(path.relative_to(root)): (
                    path.lstat().st_mode,
                    path.read_bytes() if stat.S_ISREG(path.lstat().st_mode) else None,
                )
                for path in sorted(root.rglob("*"))
            }

        before = snapshot()
        checked = INSTALLER.check(self.package, root)
        self.assertEqual(snapshot(), before)
        self.assertEqual(checked["status"], "checked")
        self.assertEqual(checked["daemon_contract"], INSTALLER.DAEMON_CONTRACT)
        for key, value in INSTALLER.DEFAULT_STATE.items():
            self.assertEqual(checked[key], value)
        self.assertEqual(set(checked["changed_targets"]), set(INSTALLER.EXPECTED_TARGETS.values()))

    def test_host_identity_must_match_exactly(self) -> None:
        self.freeze()
        root = self.make_root()
        (root / "etc/passwd").write_text(
            "buzzci-ctl:x:42:42:broker:/var/lib/buzzci/principals/ctl:/usr/sbin/nologin\n"
            "buzzci-runner:x:968:968:runner:/nonexistent:/usr/sbin/nologin\n"
        )
        with self.assertRaisesRegex(ValueError, "does not match the package"):
            INSTALLER.check(self.package, root)
        (root / "etc/passwd").write_text(
            "buzzci-ctl:x:961:961:broker:/var/lib/buzzci/principals/ctl:/usr/sbin/nologin\n"
        )
        with self.assertRaisesRegex(ValueError, "missing or duplicated"):
            INSTALLER.check(self.package, root)
        (root / "etc/passwd").write_text(
            "buzzci-ctl:x:961:961:broker:/var/lib/buzzci/principals/ctl:/bin/sh\n"
            "buzzci-runner:x:968:968:runner:/nonexistent:/usr/sbin/nologin\n"
        )
        with self.assertRaisesRegex(ValueError, "login posture"):
            INSTALLER.check(self.package, root)

    def test_dry_run_install_idempotence_and_rollback(self) -> None:
        self.freeze()
        root = self.make_root()
        dry_run = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, dry_run=True)
        self.assertEqual(dry_run["status"], "dry_run")
        self.assertFalse((root / "usr/share/doc/buzz-ci-execd").exists())
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(installed["status"], "installed")
        for target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertTrue(INSTALLER.rooted(root, target).is_file())
        binary = root / "usr/libexec/buzz-ci-execd"
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
        service = root / "etc/systemd/system/buzz-ci-execd.service"
        self.assertEqual(stat.S_IMODE(service.stat().st_mode), 0o644)
        unchanged = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(unchanged["status"], "unchanged")
        rolled_back = INSTALLER.rollback(
            self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, str(installed["backup_id"]),
        )
        self.assertEqual(rolled_back["status"], "rolled_back")
        for target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertFalse(INSTALLER.rooted(root, target).exists())

    def test_rollback_refuses_installed_target_drift(self) -> None:
        self.freeze()
        root = self.make_root()
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        service = root / "etc/systemd/system/buzz-ci-execd.service"
        service.write_text("drift\n")
        service.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "drift blocks rollback"):
            INSTALLER.rollback(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, str(installed["backup_id"]))

    def test_rollback_preflights_prior_backup_digest(self) -> None:
        self.freeze()
        root = self.make_root()
        prior = root / "usr/lib/tmpfiles.d/buzzci-execd.conf"
        prior.write_text("prior\n")
        prior.chmod(0o644)
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        transaction = INSTALLER.backup_root_path(root, INSTALLER.DEFAULT_BACKUP_ROOT) / str(installed["backup_id"])
        receipt = json.loads((transaction / "receipt.json").read_text())
        record = next(item for item in receipt["inventory"] if item["target"] == "/usr/lib/tmpfiles.d/buzzci-execd.conf")
        backup = transaction / str(record["backup"])
        backup.write_text("corrupt\n")
        backup.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "backup file digest drift"):
            INSTALLER.rollback(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, str(installed["backup_id"]))
        self.assertEqual(
            (root / "usr/lib/tmpfiles.d/buzzci-execd.conf").read_bytes(),
            b"d /run/buzzci 0711 root root -\n",
        )

    def test_templates_are_dormant_socket_activated_and_keyless(self) -> None:
        service = (EXECD_DIR / "templates/buzz-ci-execd.service").read_text()
        socket = (EXECD_DIR / "templates/buzz-ci-execd.socket").read_text()
        tmpfiles = (EXECD_DIR / "templates/buzzci-execd.tmpfiles").read_text()
        self.assertNotIn("[Install]", service)
        self.assertIn("ExecStart=/usr/libexec/buzz-ci-execd --socket-activation", service)
        self.assertIn("Restart=no", service)
        self.assertNotIn("User=", service)
        self.assertIn("ListenStream=/run/buzzci/execd.sock", socket)
        self.assertIn("FileDescriptorName=buzz-ci-execd", socket)
        self.assertIn("[Install]", socket)
        for token in ("keyholder", "relay", "runner-control", "controld"):
            self.assertNotIn(token, (service + socket + tmpfiles).lower())
        self.assertEqual(
            [line for line in tmpfiles.splitlines() if line and not line.startswith("#")],
            ["d /run/buzzci 0711 root root -"],
        )

    def test_json_schemas_are_strict_and_parseable(self) -> None:
        for name in ("binary-provenance.schema.json", "package-manifest.schema.json"):
            schema = json.loads((EXECD_DIR / name).read_text())
            self.assertFalse(schema["additionalProperties"])
        manifest_schema = json.loads((EXECD_DIR / "package-manifest.schema.json").read_text())
        self.assertEqual(
            manifest_schema["properties"]["daemon_contract"]["const"],
            INSTALLER.DAEMON_CONTRACT,
        )


if __name__ == "__main__":
    unittest.main()
