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

KEYHOLDER_DIR = Path(__file__).resolve().parents[1]
SOURCE_ROOT = KEYHOLDER_DIR.parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RENDERER = load_module("render_keyholder_config", KEYHOLDER_DIR / "render_keyholder_config.py")
FREEZER = load_module("freeze_keyholder_package", KEYHOLDER_DIR / "freeze_package.py")
INSTALLER = load_module("install_keyholder_package", KEYHOLDER_DIR / "install.py")


def identity(public_key: str, generation: int) -> dict[str, object]:
    return {"public_key": public_key, "generation": generation}


def public_spec(uid: int = 1201, gid: int = 1201) -> dict[str, object]:
    return {
        "schema_version": 1,
        "peer": {"uid": uid, "gid": gid},
        "selectors": {
            "ci_event": identity("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 7),
            "nip98": identity("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", 8),
            "manifest": identity("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", 9),
        },
        "nip98_origin": "https://relay.example.test",
        "acceptance": {
            "binding_receipt_path": RENDERER.BINDING_RECEIPT_PATH,
            "credential_selector": RENDERER.ACCEPTANCE_CREDENTIAL_SELECTOR,
        },
    }


class KeyholderPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=SOURCE_ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.spec = self.base / "public-spec.json"
        self.spec.write_bytes(RENDERER.canonical_json(public_spec()))
        self.spec.chmod(0o600)
        self.package = self.base / "package"
        self.commit = subprocess.run(
            ["git", "-C", str(SOURCE_ROOT), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()

    def freeze(self, source_root: Path = SOURCE_ROOT) -> dict[str, object]:
        return FREEZER.freeze_package(
            source_root,
            self.commit,
            self.spec,
            self.package,
            keyholder_uid=os.getuid(),
            keyholder_gid=os.getgid(),
            controld_uid=1201,
            controld_gid=1201,
        )

    def make_root(self) -> Path:
        root = self.base / "root"
        root.mkdir(mode=0o700)
        etc = root / "etc"
        etc.mkdir(mode=0o755)
        (root / "usr").mkdir(mode=0o755)
        passwd = etc / "passwd"
        passwd.write_text(
            f"buzzci-keyholder:x:{os.getuid()}:{os.getgid()}:keyholder:/nonexistent:/usr/sbin/nologin\n"
            "buzzci-controld:x:1201:1201:controld:/nonexistent:/usr/sbin/nologin\n"
        )
        passwd.chmod(0o644)
        group = etc / "group"
        group.write_text(
            f"buzzci-keyholder:x:{os.getgid()}:\n"
            "buzzci-controld:x:1201:\n"
        )
        group.chmod(0o644)
        return root

    def add_credential(self, root: Path, mode: int = 0o400) -> Path:
        directory = root / "etc/credstore.encrypted/buzzci-keyholder"
        directory.mkdir(mode=0o700, parents=True)
        directory.chmod(0o700)
        credential = directory / "acceptance-actor.key"
        credential.write_bytes(b"opaque-systemd-encrypted-credential")
        credential.chmod(mode)
        return credential

    def test_renderer_emits_exact_static_contract_without_activation_values(self) -> None:
        rendered = RENDERER.validate_spec(public_spec())
        self.assertEqual(rendered["peer"]["allowed_operations"], RENDERER.OPERATIONS)
        self.assertEqual(set(rendered["selectors"]), {"ci_event", "nip98", "manifest"})
        self.assertNotIn("acceptance", rendered["selectors"])
        self.assertEqual(rendered["acceptance"], {
            "binding_receipt_path": RENDERER.BINDING_RECEIPT_PATH,
            "credential_selector": RENDERER.ACCEPTANCE_CREDENTIAL_SELECTOR,
        })
        encoded = RENDERER.canonical_json(rendered).decode()
        for forbidden in ("scenario_sha256", "activation_package_digest", "run_event", "grant_event"):
            self.assertNotIn(forbidden, encoded)

    def test_renderer_rejects_unknown_fields_binding_drift_and_operation_injection(self) -> None:
        unknown = public_spec()
        unknown["key_descriptor"] = "/forbidden"
        with self.assertRaisesRegex(ValueError, "fields"):
            RENDERER.validate_spec(unknown)
        drifted = public_spec()
        drifted["acceptance"]["binding_receipt_path"] = "/tmp/receipt"
        with self.assertRaisesRegex(ValueError, "contract differs"):
            RENDERER.validate_spec(drifted)
        dynamic = public_spec()
        dynamic["acceptance"]["scenario_sha256"] = "09" * 32
        with self.assertRaisesRegex(ValueError, "fields"):
            RENDERER.validate_spec(dynamic)
        active = RENDERER.validate_spec(public_spec())
        active["peer"]["allowed_operations"] = RENDERER.OPERATIONS + ["unknown"]
        with self.assertRaisesRegex(ValueError, "operation set"):
            RENDERER.validate_config(active)

    def test_schemas_are_closed_parseable_and_match_required_contracts(self) -> None:
        config_schema = json.loads((KEYHOLDER_DIR / "keyholder-config.schema.json").read_text())
        package_schema = json.loads((KEYHOLDER_DIR / "package-manifest.schema.json").read_text())
        self.assertFalse(config_schema["additionalProperties"])
        self.assertFalse(config_schema["properties"]["acceptance"]["additionalProperties"])
        self.assertEqual(config_schema["properties"]["peer"]["properties"]["allowed_operations"]["const"], RENDERER.OPERATIONS)
        self.assertFalse(package_schema["additionalProperties"])
        self.assertEqual(package_schema["properties"]["credential_contract"]["const"], FREEZER.CREDENTIAL_CONTRACT)
        self.assertEqual(package_schema["properties"]["runtime_contract"]["const"], FREEZER.RUNTIME_CONTRACT)

    def test_systemd_domains_fd_and_dormant_base_are_exact(self) -> None:
        service = (KEYHOLDER_DIR / "templates/buzz-ci-keyholder.service").read_text()
        socket = (KEYHOLDER_DIR / "templates/buzz-ci-keyholder.socket").read_text()
        dropin = (KEYHOLDER_DIR / "templates/20-acceptance-actor.conf").read_text()
        self.assertNotIn("acceptance-actor.key", service)
        self.assertEqual(service.count("LoadCredentialEncrypted="), 3)
        self.assertEqual(dropin.count("LoadCredentialEncrypted="), 1)
        self.assertIn("LoadCredentialEncrypted=acceptance-actor.key:/etc/credstore.encrypted/buzzci-keyholder/acceptance-actor.key", dropin)
        self.assertNotIn("ci-event.key", dropin)
        self.assertIn("ListenStream=/run/buzzci/keyholder.sock", socket)
        self.assertIn("FileDescriptorName=buzz-ci-keyholder-control", socket)
        self.assertIn("LimitCORE=0", service)
        self.assertIn(RENDERER.BINDING_RECEIPT_PATH, service)
        self.assertIn("ProtectSystem=strict", service)

    def test_systemd_units_verify_with_active_dropin(self) -> None:
        root = self.base / "systemd-root"
        unit_directory = root / "etc/systemd/system"
        dropin_directory = unit_directory / "buzz-ci-keyholder.service.d"
        binary_directory = root / "usr/libexec"
        dropin_directory.mkdir(mode=0o755, parents=True)
        binary_directory.mkdir(mode=0o755, parents=True)
        shutil.copyfile("/bin/true", binary_directory / "buzz-ci-keyholder")
        (binary_directory / "buzz-ci-keyholder").chmod(0o755)
        shutil.copyfile(KEYHOLDER_DIR / "templates/buzz-ci-keyholder.service", unit_directory / "buzz-ci-keyholder.service")
        shutil.copyfile(KEYHOLDER_DIR / "templates/buzz-ci-keyholder.socket", unit_directory / "buzz-ci-keyholder.socket")
        shutil.copyfile(KEYHOLDER_DIR / "templates/20-acceptance-actor.conf", dropin_directory / "20-acceptance-actor.conf")
        for target in ("sysinit.target", "basic.target", "local-fs.target", "sockets.target", "shutdown.target"):
            (unit_directory / target).write_text("[Unit]\nDefaultDependencies=no\n")
        verified = subprocess.run(
            [
                "systemd-analyze",
                "verify",
                f"--root={root}",
                "buzz-ci-keyholder.socket",
                "buzz-ci-keyholder.service",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_package_contains_no_credential_and_binds_public_config(self) -> None:
        manifest = self.freeze()
        self.assertFalse(manifest["credential_contract"]["packaged"])
        self.assertFalse(any("credstore" in entry["source"] for entry in manifest["entries"]))
        self.assertEqual({entry["role"] for entry in manifest["entries"]}, set(INSTALLER.EXPECTED_TARGETS))
        parsed, _ = INSTALLER.parse_package(self.package, self.package)
        self.assertEqual(parsed["package_digest"], manifest["package_digest"])
        config_entry = next(entry for entry in manifest["entries"] if entry["role"] == "config")
        config = json.loads((self.package / config_entry["source"]).read_bytes())
        self.assertEqual(config["acceptance"], {
            "binding_receipt_path": RENDERER.BINDING_RECEIPT_PATH,
            "credential_selector": RENDERER.ACCEPTANCE_CREDENTIAL_SELECTOR,
        })
        serialized = json.dumps(config, sort_keys=True)
        for forbidden in ("scenario_sha256", "activation_package_digest", "run_event", "grant_event"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(stat.S_IMODE(self.package.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in (self.package / "assets").iterdir()))

    def test_fake_root_fails_closed_without_credential_or_with_loose_mode(self) -> None:
        self.freeze()
        root = self.make_root()
        with self.assertRaisesRegex(ValueError, "credential is unavailable"):
            INSTALLER.check(self.package, root)
        credential = self.add_credential(root, 0o444)
        with self.assertRaisesRegex(ValueError, "credential metadata is invalid"):
            INSTALLER.check(self.package, root)
        credential.chmod(0o400)
        checked = INSTALLER.check(self.package, root)
        self.assertFalse(checked["credential_bytes_read"])

    def test_fake_root_install_preserves_opaque_credential_and_exact_modes(self) -> None:
        self.freeze()
        root = self.make_root()
        credential = self.add_credential(root)
        before = credential.read_bytes()
        installed = INSTALLER.install(self.package, root)
        self.assertEqual(installed["status"], "installed")
        self.assertFalse(installed["enabled"])
        self.assertFalse(installed["active"])
        self.assertEqual(credential.read_bytes(), before)
        for role, target in INSTALLER.EXPECTED_TARGETS.items():
            path = INSTALLER.rooted(root, target)
            self.assertTrue(path.is_file())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600 if role == "config" else 0o644)
        self.assertEqual(INSTALLER.install(self.package, root)["status"], "unchanged")

    def test_fresh_restrictive_umask_checkout_freezes_identically(self) -> None:
        clone = self.base / "clone"
        old_umask = os.umask(0o077)
        try:
            subprocess.run(["git", "clone", "--quiet", "--no-local", str(SOURCE_ROOT), str(clone)], check=True)
        finally:
            os.umask(old_umask)
        restrictive_modes = {
            stat.S_IMODE(path.stat().st_mode)
            for path in (clone / "deploy/native-ci/keyholder").rglob("*")
            if path.is_file()
        }
        self.assertTrue(restrictive_modes.issubset({0o600, 0o700}))
        self.freeze(clone)
        self.assertTrue(self.package.is_dir())


if __name__ == "__main__":
    unittest.main()
