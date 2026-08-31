from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest


ACTIVATION_ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PACKAGE = load_module("package", ACTIVATION_ROOT / "package.py")
CONTROLLER = load_module("activation_controller_identity_test", ACTIVATION_ROOT / "controller.py")


class InstalledIdentityPolicyTests(unittest.TestCase):
    def expected(self) -> dict[str, object]:
        return {
            "user": "buzzci-ctl",
            "group": "buzzci-ctl",
            "uid": 961,
            "gid": 961,
            "primary_gid": 961,
            "home": "/var/lib/buzzci/principals/ctl",
            "shell": "/usr/sbin/nologin",
            "supplementary_groups": ["buzzci-execd"],
        }

    def test_package_schema_and_sysusers_preserve_installed_identity(self) -> None:
        self.assertEqual((PACKAGE.QUALIFICATION_UID, PACKAGE.QUALIFICATION_GID), (961, 961))
        self.assertEqual(PACKAGE.IDENTITY_HOMES["qualification"], "/var/lib/buzzci/principals/ctl")
        schema = json.loads((ACTIVATION_ROOT / "activation-manifest.schema.json").read_bytes())
        properties = schema["$defs"]["qualificationIdentity"]["allOf"][1]["properties"]
        self.assertEqual(properties["uid"]["const"], 961)
        self.assertEqual(properties["gid"]["const"], 961)
        self.assertEqual(properties["home"]["const"], "/var/lib/buzzci/principals/ctl")
        sysusers = (ACTIVATION_ROOT / "templates/buzzci-activation.sysusers.in").read_text()
        self.assertIn("/var/lib/buzzci/principals/ctl /usr/sbin/nologin", sysusers)
        self.assertNotIn("/var/lib/buzzci/ctl", sysusers)

    def test_only_the_exact_pre_group_identity_is_convergent(self) -> None:
        expected = self.expected()
        legacy = {**expected, "supplementary_groups": []}
        self.assertTrue(CONTROLLER._legacy_qualification_identity("qualification", legacy, expected))
        for field, value in (
            ("uid", 1203),
            ("gid", 1203),
            ("home", "/var/lib/buzzci/ctl"),
            ("shell", "/bin/sh"),
        ):
            with self.subTest(field=field):
                drift = {**legacy, field: value}
                self.assertFalse(
                    CONTROLLER._legacy_qualification_identity("qualification", drift, expected)
                )
        self.assertFalse(CONTROLLER._legacy_qualification_identity("runner", legacy, expected))


if __name__ == "__main__":
    unittest.main()
