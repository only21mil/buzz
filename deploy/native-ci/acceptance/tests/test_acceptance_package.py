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

ROOT = Path(__file__).resolve().parents[4]
ACCEPTANCE = ROOT / "deploy/native-ci/acceptance"
CONTROLD = ROOT / "deploy/native-ci/controld"
DRIVER = "/usr/libexec/buzz-ci-capacity-one-driver"
VERIFIER_INSTALL = "/usr/libexec/buzz-ci-verify-acceptance-receipt"

SOURCE_SPEC = importlib.util.spec_from_file_location(
    "acceptance_verifier_source", ACCEPTANCE / "verifier_source.py"
)
assert SOURCE_SPEC is not None and SOURCE_SPEC.loader is not None
VERIFIER_SOURCE = importlib.util.module_from_spec(SOURCE_SPEC)
SOURCE_SPEC.loader.exec_module(VERIFIER_SOURCE)


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
            {
                value["program"]
                for value in scenario["driver"].values()
                if isinstance(value, dict)
            },
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
        service = (templates / "buzz-ci-acceptance-control.service").read_text()
        self.assertIn(
            "ListenStream=/run/buzzci/acceptance-control.sock", control_socket
        )
        self.assertIn("FileDescriptorName=buzz-ci-acceptance-control", control_socket)
        self.assertIn("SocketUser=root", control_socket)
        self.assertIn("SocketGroup=buzzci-ctl", control_socket)
        self.assertIn("SocketMode=0620", control_socket)
        self.assertIn("ExecStart=/usr/libexec/buzz-ci-acceptance-control", service)
        self.assertNotIn("Environment=", service)
        self.assertNotIn("sudo", service)

    def test_controld_is_the_only_source_owner_of_its_acceptance_socket(self) -> None:
        duplicate = ACCEPTANCE / "templates/buzz-ci-controld-acceptance.socket"
        canonical = CONTROLD / "templates/buzz-ci-controld-acceptance.socket"
        self.assertFalse(duplicate.exists())
        self.assertTrue(canonical.is_file())
        self.assertFalse(canonical.is_symlink())
        socket = canonical.read_text(encoding="utf-8")
        self.assertIn("ListenStream=/run/buzzci/controld-acceptance.sock", socket)
        self.assertIn("FileDescriptorName=buzz-ci-controld-acceptance", socket)

    def test_fresh_umask_copy_keeps_declared_template_modes(self) -> None:
        prior = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                destinations = {
                    "buzz-ci-acceptance-control.socket": (
                        ACCEPTANCE / "templates" / "buzz-ci-acceptance-control.socket",
                        0o644,
                    ),
                    "buzz-ci-acceptance-control.service": (
                        ACCEPTANCE / "templates" / "buzz-ci-acceptance-control.service",
                        0o644,
                    ),
                    "buzzci-acceptance.tmpfiles": (
                        ACCEPTANCE / "templates" / "buzzci-acceptance.tmpfiles",
                        0o644,
                    ),
                }
                for name, (source, mode) in destinations.items():
                    target = root / name
                    shutil.copyfile(source, target)
                    os.chmod(target, mode)
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)
        finally:
            os.umask(prior)

    def test_verifier_source_contract_accepts_restrictive_git_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seed = root / "seed"
            checkout = root / "checkout"
            source = seed / VERIFIER_SOURCE.SOURCE_RELATIVE
            stages_source = seed / VERIFIER_SOURCE.STAGES_SOURCE_RELATIVE
            source.parent.mkdir(parents=True)
            shutil.copyfile(ACCEPTANCE / "verify-receipt.py", source)
            shutil.copyfile(ACCEPTANCE / "expected-stages.json", stages_source)
            os.chmod(source, 0o755)
            os.chmod(stages_source, 0o644)
            subprocess.run(["git", "init", "-q", str(seed)], check=True)
            subprocess.run(
                ["git", "-C", str(seed), "config", "user.name", "Acceptance Tests"],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(seed),
                    "config",
                    "user.email",
                    "acceptance@example.invalid",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(seed), "config", "core.sharedRepository", "true"],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(seed),
                    "add",
                    str(VERIFIER_SOURCE.SOURCE_RELATIVE),
                    str(VERIFIER_SOURCE.STAGES_SOURCE_RELATIVE),
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(seed), "commit", "-qm", "fixture"], check=True
            )

            prior = os.umask(0o077)
            try:
                subprocess.run(
                    ["git", "clone", "-q", "--no-hardlinks", str(seed), str(checkout)],
                    check=True,
                )
            finally:
                os.umask(prior)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(checkout),
                    "config",
                    "core.sharedRepository",
                    "true",
                ],
                check=True,
            )

            materialized = checkout / VERIFIER_SOURCE.SOURCE_RELATIVE
            self.assertEqual(stat.S_IMODE(materialized.stat().st_mode), 0o700)
            contract = VERIFIER_SOURCE.source_contract(checkout)
            self.assertEqual(contract["source_git_mode"], "100755")
            self.assertEqual(contract["materialized_source_mode"], "0700")
            self.assertEqual(contract["install_path"], VERIFIER_INSTALL)
            self.assertEqual(contract["install_mode"], "0755")
            stages_contract = VERIFIER_SOURCE.expected_stages_contract(checkout)
            self.assertEqual(stages_contract["source_git_mode"], "100644")
            self.assertEqual(stages_contract["materialized_source_mode"], "0600")
            self.assertEqual(
                stages_contract["install_path"],
                "/usr/libexec/buzz-ci-acceptance-expected-stages.json",
            )
            self.assertEqual(stages_contract["install_mode"], "0644")
            self.assertEqual(stages_contract["package_mode"], "0400")
            self.assertEqual(stages_contract["install_owner"], "root")
            self.assertEqual(stages_contract["install_group"], "root")
            self.assertEqual(stages_contract["type"], "static_entry")

    def test_verifier_source_contract_rejects_unsafe_modes_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / VERIFIER_SOURCE.SOURCE_RELATIVE
            source.parent.mkdir(parents=True)
            shutil.copyfile(ACCEPTANCE / "verify-receipt.py", source)
            os.chmod(source, 0o755)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "add", str(VERIFIER_SOURCE.SOURCE_RELATIVE)],
                check=True,
            )

            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "update-index",
                    "--chmod=-x",
                    str(VERIFIER_SOURCE.SOURCE_RELATIVE),
                ],
                check=True,
            )
            with self.assertRaisesRegex(ValueError, "Git mode differs"):
                VERIFIER_SOURCE.tracked_verifier(root)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "update-index",
                    "--chmod=+x",
                    str(VERIFIER_SOURCE.SOURCE_RELATIVE),
                ],
                check=True,
            )

            os.chmod(source, 0o100)
            with self.assertRaisesRegex(
                ValueError, "cannot be opened safely|owner access differs"
            ):
                VERIFIER_SOURCE.tracked_verifier(root)

            for mode in (0o720, 0o740, 0o600):
                with self.subTest(mode=oct(mode)):
                    os.chmod(source, mode)
                    with self.assertRaisesRegex(
                        ValueError, "permissions|executable class"
                    ):
                        VERIFIER_SOURCE.tracked_verifier(root)

            os.chmod(source, 0o700)
            target = root / "verifier-target"
            shutil.copyfile(source, target)
            source.unlink()
            source.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                VERIFIER_SOURCE.tracked_verifier(root)

            source.unlink()
            os.link(target, source)
            with self.assertRaisesRegex(ValueError, "single regular file"):
                VERIFIER_SOURCE.tracked_verifier(root)

    def test_no_placeholder_or_ambient_credential_channel(self) -> None:
        checked = [
            ACCEPTANCE / "scenario.template.json",
            ACCEPTANCE / "verify-receipt.py",
            ACCEPTANCE / "verifier_source.py",
            *sorted((ACCEPTANCE / "templates").iterdir()),
        ]
        for path in checked:
            value = path.read_text(encoding="utf-8")
            self.assertNotIn("/opt/", value, path)
            self.assertNotIn("TOKEN", value, path)
            self.assertNotIn("PASSWORD", value, path)


if __name__ == "__main__":
    unittest.main()
