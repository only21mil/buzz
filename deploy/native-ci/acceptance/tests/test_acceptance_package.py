from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[4]
ACCEPTANCE = ROOT / "deploy/native-ci/acceptance"
DRIVER = "/usr/libexec/buzz-ci-capacity-one-driver"


class AcceptancePackageTests(unittest.TestCase):
    def test_json_assets_parse_and_template_uses_only_installed_driver(self) -> None:
        for name in (
            "scenario.schema.json",
            "receipt.schema.json",
            "driver-config.schema.json",
            "control-config.schema.json",
            "scenario.template.json",
            "fixtures/fixture-manifest.json",
        ):
            value = json.loads((ACCEPTANCE / name).read_text(encoding="utf-8"))
            if name.endswith("config.schema.json"):
                self.assertEqual(set(value["required"]), set(value["properties"]))
        scenario = json.loads(
            (ACCEPTANCE / "scenario.template.json").read_text(encoding="utf-8")
        )
        schema = json.loads(
            (ACCEPTANCE / "scenario.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(schema["$defs"]["fixture"]["required"]),
            set(scenario["fixture"]),
        )
        self.assertEqual(
            set(schema["$defs"]["driver"]["required"]),
            set(scenario["driver"]),
        )
        self.assertEqual(
            {value["program"] for value in scenario["driver"].values() if isinstance(value, dict)},
            {DRIVER},
        )
        self.assertTrue(
            all(
                value.get("args", []) == []
                for value in scenario["driver"].values()
                if isinstance(value, dict)
            )
        )

    def test_systemd_assets_freeze_socket_principals_and_paths(self) -> None:
        templates = ACCEPTANCE / "templates"
        control_socket = (templates / "buzz-ci-acceptance-control.socket").read_text()
        controld_socket = (templates / "buzz-ci-controld-acceptance.socket").read_text()
        service = (templates / "buzz-ci-acceptance-control.service").read_text()
        self.assertIn("ListenStream=/run/buzzci/acceptance-control.sock", control_socket)
        self.assertIn("FileDescriptorName=buzz-ci-acceptance-control", control_socket)
        self.assertIn("ListenStream=/run/buzzci/controld-acceptance.sock", controld_socket)
        self.assertIn("FileDescriptorName=buzz-ci-controld-acceptance", controld_socket)
        for value in (control_socket, controld_socket):
            self.assertIn("SocketUser=root", value)
            self.assertIn("SocketGroup=buzzci-ctl", value)
            self.assertIn("SocketMode=0620", value)
        self.assertIn("ExecStart=/usr/libexec/buzz-ci-acceptance-control", service)
        self.assertNotIn("Environment=", service)
        self.assertNotIn("sudo", service)

    def test_fresh_umask_copy_keeps_declared_package_modes(self) -> None:
        prior = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                destinations = {
                    "buzz-ci-acceptance-control.socket": (ACCEPTANCE / "templates" / "buzz-ci-acceptance-control.socket", 0o644),
                    "buzz-ci-acceptance-control.service": (ACCEPTANCE / "templates" / "buzz-ci-acceptance-control.service", 0o644),
                    "buzz-ci-controld-acceptance.socket": (ACCEPTANCE / "templates" / "buzz-ci-controld-acceptance.socket", 0o644),
                    "buzzci-acceptance.tmpfiles": (ACCEPTANCE / "templates" / "buzzci-acceptance.tmpfiles", 0o644),
                    "verify-receipt.py": (ACCEPTANCE / "verify-receipt.py", 0o755),
                }
                for name, (source, mode) in destinations.items():
                    if name == "verify-receipt.py":
                        self.assertEqual(stat.S_IMODE(source.stat().st_mode), mode)
                    target = root / name
                    shutil.copyfile(source, target)
                    os.chmod(target, mode)
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)
        finally:
            os.umask(prior)

    def test_no_placeholder_or_ambient_credential_channel(self) -> None:
        checked = [
            ACCEPTANCE / "scenario.template.json",
            ACCEPTANCE / "verify-receipt.py",
            *sorted((ACCEPTANCE / "templates").iterdir()),
        ]
        for path in checked:
            value = path.read_text(encoding="utf-8")
            self.assertNotIn("/opt/", value, path)
            self.assertNotIn("TOKEN", value, path)
            self.assertNotIn("PASSWORD", value, path)


if __name__ == "__main__":
    unittest.main()
