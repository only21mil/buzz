from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


PACKAGER = load("evidence_packager", PACKAGE_DIR / "package.py")
INSTALLER = load("evidence_installer", PACKAGE_DIR / "install.py")


class EvidenceMaintenancePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.binary = self.root / "buzz-ci-evidence-maintenance"
        self.binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def freeze(self) -> tuple[Path, dict[str, object]]:
        output = self.private / "package"
        manifest = PACKAGER.freeze_package(
            PACKAGE_DIR.parents[2],
            "a" * 40,
            self.binary,
            output,
            1234,
            1234,
        )
        return output, manifest

    def test_freeze_and_fake_root_install_are_dormant_and_exact(self) -> None:
        package, manifest = self.freeze()
        self.assertEqual(manifest["default_state"], {"enabled": False, "active": False, "credentials_installed": False})
        self.assertEqual(len(manifest["entries"]), 7)
        install_root = self.root / "install-root"
        install_root.mkdir()
        installed = INSTALLER.install_package(package, install_root)
        self.assertEqual(installed["package_digest"], manifest["package_digest"])
        service = (install_root / "usr/lib/systemd/system/buzz-ci-evidence-maintenance.service").read_text()
        timer = (install_root / "usr/lib/systemd/system/buzz-ci-evidence-maintenance.timer").read_text()
        self.assertIn("ConditionPathExists=/etc/buzzci/evidence-maintenance.env", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ReadWritePaths=/var/lib/buzzci/evidence-maintenance", service)
        self.assertNotIn("[Install]", service)
        self.assertIn("Persistent=true", timer)
        self.assertFalse((install_root / "etc/buzzci/evidence-maintenance.env").exists())
        self.assertFalse(any((install_root / "etc/systemd/system").glob("**/*.wants/*")))
        binary = install_root / "usr/libexec/buzz-ci-evidence-maintenance"
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o500)
        analyzer = shutil.which("systemd-analyze")
        if analyzer is not None:
            unit_dir = install_root / "usr/lib/systemd/system"
            for target in ["sysinit.target", "basic.target", "network-online.target", "systemd-tmpfiles-setup.service", "timers.target"]:
                (unit_dir / target).write_text("[Unit]\nDescription=Fake-root verification stub\n")
            result = subprocess.run(
                [analyzer, f"--root={install_root}", "verify", "buzz-ci-evidence-maintenance.service", "buzz-ci-evidence-maintenance.timer"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_installer_rejects_asset_tampering_and_symlink_targets(self) -> None:
        package, _ = self.freeze()
        asset = package / "assets/evidence-maintenance-v1.json"
        asset.write_bytes(asset.read_bytes() + b" ")
        install_root = self.root / "tamper-root"
        install_root.mkdir()
        with self.assertRaisesRegex(ValueError, "integrity"):
            INSTALLER.install_package(package, install_root)

        shutil.rmtree(package)
        package, _ = self.freeze()
        target = install_root / "usr/libexec/buzz-ci-evidence-maintenance"
        target.parent.mkdir(parents=True)
        target.symlink_to(self.binary)
        with self.assertRaisesRegex(ValueError, "symlink"):
            INSTALLER.install_package(package, install_root)

    def test_config_and_manifest_schemas_are_closed_and_units_verify(self) -> None:
        for name in ["evidence-maintenance-config.schema.json", "package-manifest.schema.json"]:
            schema = json.loads((PACKAGE_DIR / name).read_text())
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        config = json.loads((PACKAGE_DIR / "templates/evidence-maintenance-v1.json").read_text())
        self.assertEqual(set(config), set(json.loads((PACKAGE_DIR / "evidence-maintenance-config.schema.json").read_text())["required"]))



if __name__ == "__main__":
    unittest.main()
