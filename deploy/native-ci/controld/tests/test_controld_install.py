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

CONTROLD_DIR = Path(__file__).resolve().parents[1]
NATIVE_CI_DIR = CONTROLD_DIR.parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RENDERER = load_module("render_controld_config", CONTROLD_DIR / "render_controld_config.py")
FREEZER = load_module("freeze_package", CONTROLD_DIR / "freeze_package.py")
INSTALLER = load_module("controld_install", CONTROLD_DIR / "install.py")


class ControldInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.source_root = self.base / "source"
        copied = self.source_root / "deploy/native-ci/controld"
        copied.parent.mkdir(mode=0o700, parents=True)
        shutil.copytree(CONTROLD_DIR, copied, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy2(NATIVE_CI_DIR / "package_source.py", copied.parent / "package_source.py")
        subprocess.run(["git", "init", "-q", str(self.source_root)], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.name", "Controld test"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.email", "controld@test.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "add", "deploy/native-ci"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "commit", "-qm", "fixture"], check=True)
        self.source_commit = FREEZER.git_output(self.source_root, "rev-parse", "HEAD")
        self.binary = self.base / "buzz-ci-controld"
        self.binary.write_bytes(b"test buzz-ci-controld binary\n")
        self.binary.chmod(0o755)
        self.provenance = self.base / "binary-provenance.json"
        self.provenance.write_text(json.dumps({
            "schema": "buzz-ci-binary-provenance-v1",
            "binary": "buzz-ci-controld",
            "source_commit": self.source_commit,
            "profile": "release",
            "sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
        }, sort_keys=True, separators=(",", ":")) + "\n")
        self.provenance.chmod(0o600)
        self.package = self.base / "package"
        self.controld_uid = os.geteuid()
        self.controld_gid = os.getegid()
        if self.controld_uid == 0 or self.controld_gid == 0:
            self.skipTest("fake-root tests require a non-root invoking identity")

    def freeze(self) -> dict[str, object]:
        return FREEZER.freeze_package(
            self.source_root, self.source_commit, self.binary, self.provenance,
            self.package, self.controld_uid, self.controld_gid,
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
            f"buzzci-controld:x:{self.controld_uid}:{self.controld_gid}:controller:/nonexistent:/usr/sbin/nologin\n"
        )
        (root / "etc/group").write_text(f"buzzci-controld:x:{self.controld_gid}:\n")
        (root / "etc/passwd").chmod(0o644)
        (root / "etc/group").chmod(0o644)
        return root

    def test_renderer_is_canonical_capacity_zero_absolute_and_nofollow(self) -> None:
        output = self.base / "controld-v1.json"
        RENDERER.render(output)
        self.assertEqual(
            output.read_bytes(),
            b'{"acceptance_binding":"/var/lib/buzzci/activation-controller/controld-acceptance-v1.json","capacity":0,"schema_version":1,"store_root":"/var/lib/buzzci/controld"}\n',
        )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        RENDERER.check(output, expected_uid=self.controld_uid)
        with self.assertRaisesRegex(ValueError, "capacity exactly zero"):
            RENDERER.config_bytes(capacity=1)
        with self.assertRaisesRegex(ValueError, "absolute normalized"):
            RENDERER.config_bytes("relative/store")
        with self.assertRaisesRegex(ValueError, "fixed receipt path"):
            RENDERER.config_bytes(acceptance_binding="/var/lib/buzzci/other.json")
        linked = self.base / "linked.json"
        linked.symlink_to(output)
        with self.assertRaises(OSError):
            RENDERER.check(linked)

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
        socket = next(entry for entry in entries if entry.role == "acceptance_socket")
        self.assertEqual(
            socket.target,
            "/etc/systemd/system/buzz-ci-controld-acceptance.socket",
        )

    def test_package_refuses_symlink_and_provenance_drift(self) -> None:
        self.freeze()
        binary_asset = self.package / "assets/buzz-ci-controld"
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
        (root / "etc/passwd").write_text("buzzci-controld:x:42:42:wrong:/nonexistent:/usr/sbin/nologin\n")
        with self.assertRaisesRegex(ValueError, "does not match"):
            INSTALLER.check(self.package, root)

    def test_dry_run_install_idempotence_and_rollback(self) -> None:
        self.freeze()
        root = self.make_root()
        dry_run = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, dry_run=True)
        self.assertEqual(dry_run["status"], "dry_run")
        self.assertFalse((root / "etc/buzzci").exists())
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(installed["status"], "installed")
        for target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertTrue(INSTALLER.rooted(root, target).is_file())
        config = root / "etc/buzzci/controld-v1.json"
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
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
        service = root / "etc/systemd/system/buzz-ci-controld.service"
        service.write_text("drift\n")
        service.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "drift blocks rollback"):
            INSTALLER.rollback(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, str(installed["backup_id"]))

    def test_rollback_preflights_prior_backup_digest(self) -> None:
        self.freeze()
        root = self.make_root()
        prior = root / "usr/lib/tmpfiles.d/buzzci-controld.conf"
        prior.write_text("prior\n")
        prior.chmod(0o644)
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        transaction = INSTALLER.backup_root_path(root, INSTALLER.DEFAULT_BACKUP_ROOT) / str(installed["backup_id"])
        receipt = json.loads((transaction / "receipt.json").read_text())
        record = next(item for item in receipt["inventory"] if item["target"] == "/usr/lib/tmpfiles.d/buzzci-controld.conf")
        backup = transaction / str(record["backup"])
        backup.write_text("corrupt\n")
        backup.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "backup file digest drift"):
            INSTALLER.rollback(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, str(installed["backup_id"]))
        self.assertEqual((root / "etc/buzzci/controld-v1.json").read_bytes(), RENDERER.config_bytes())

    def test_templates_are_static_networkless_and_keyless(self) -> None:
        service = (CONTROLD_DIR / "templates/buzz-ci-controld.service").read_text()
        acceptance_socket = (
            CONTROLD_DIR / "templates/buzz-ci-controld-acceptance.socket"
        ).read_text()
        tmpfiles = (CONTROLD_DIR / "templates/buzzci-controld.tmpfiles").read_text()
        self.assertNotIn("[Install]", service)
        self.assertIn("PrivateNetwork=yes", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", service)
        self.assertIn("Restart=no", service)
        self.assertNotIn("ListenStream", service)
        self.assertIn("ListenStream=/run/buzzci/controld-acceptance.sock", acceptance_socket)
        self.assertIn("DirectoryMode=0711", acceptance_socket)
        self.assertIn("Service=buzz-ci-controld.service", acceptance_socket)
        self.assertNotIn("[Install]", acceptance_socket)
        for token in ("keyholder", "relay", "runner", "execd", "systemctl"):
            self.assertNotIn(token, (service + tmpfiles).lower())
        self.assertEqual(
            [line for line in tmpfiles.splitlines() if line and not line.startswith("#")],
            ["d /var/lib/buzzci/controld 0700 buzzci-controld buzzci-controld -"],
        )

    def test_json_schemas_are_strict_and_parseable(self) -> None:
        for name in ("binary-provenance.schema.json", "controld-config.schema.json", "package-manifest.schema.json"):
            schema = json.loads((CONTROLD_DIR / name).read_text())
            self.assertFalse(schema["additionalProperties"])
        config_schema = json.loads((CONTROLD_DIR / "controld-config.schema.json").read_text())
        self.assertEqual(config_schema["properties"]["capacity"]["const"], 0)
        self.assertEqual(config_schema["properties"]["store_root"]["const"], "/var/lib/buzzci/controld")
        self.assertEqual(
            config_schema["properties"]["acceptance_binding"]["const"],
            RENDERER.ACCEPTANCE_BINDING,
        )


if __name__ == "__main__":
    unittest.main()
