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
from unittest import mock

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
        self.binary = self.base / "buzz-ci-keyholder"
        self.binary.write_bytes(b"fixed keyholder release binary\n")
        self.binary.chmod(0o755)
        self.provenance = self.base / "binary-provenance.json"
        self.provenance.write_bytes(FREEZER.canonical_json({
            "schema": FREEZER.PROVENANCE_SCHEMA,
            "binary": "buzz-ci-keyholder",
            "source_commit": self.commit,
            "profile": "release",
            "sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
        }))
        self.provenance.chmod(0o600)

    def freeze(self, source_root: Path = SOURCE_ROOT) -> dict[str, object]:
        return FREEZER.freeze_package(
            source_root,
            self.commit,
            self.binary,
            self.provenance,
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
        provenance_schema = json.loads((KEYHOLDER_DIR / "binary-provenance.schema.json").read_text())
        self.assertFalse(config_schema["additionalProperties"])
        self.assertFalse(config_schema["properties"]["acceptance"]["additionalProperties"])
        self.assertEqual(config_schema["properties"]["peer"]["properties"]["allowed_operations"]["const"], RENDERER.OPERATIONS)
        self.assertFalse(package_schema["additionalProperties"])
        self.assertFalse(provenance_schema["additionalProperties"])
        self.assertEqual(provenance_schema["properties"]["binary"]["const"], "buzz-ci-keyholder")
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
        binary_entry = next(entry for entry in manifest["entries"] if entry["role"] == "binary")
        self.assertEqual(binary_entry["target"], "/usr/libexec/buzz-ci-keyholder")
        self.assertEqual(binary_entry["sha256"], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(binary_entry["size"], len(self.binary.read_bytes()))
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
        asset_modes = {path.name: stat.S_IMODE(path.stat().st_mode) for path in (self.package / "assets").iterdir()}
        self.assertEqual(asset_modes.pop("buzz-ci-keyholder"), 0o500)
        self.assertEqual(set(asset_modes.values()), {0o400})

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
            expected_mode = 0o755 if role == "binary" else (0o600 if role == "config" else 0o644)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected_mode)
        self.assertEqual(INSTALLER.install(self.package, root)["status"], "unchanged")

    def test_post_validation_package_swap_cannot_change_published_bytes(self) -> None:
        self.freeze()
        root = self.make_root()
        self.add_credential(root)
        expected = self.binary.read_bytes()
        original_parse = INSTALLER.parse_package

        def swap_after_validation(package: Path, install_root: Path):
            parsed = original_parse(package, install_root)
            asset = package / "assets/buzz-ci-keyholder"
            asset.unlink()
            asset.write_bytes(b"caller-controlled substitute\n")
            asset.chmod(0o500)
            return parsed

        with mock.patch.object(INSTALLER, "parse_package", side_effect=swap_after_validation):
            INSTALLER.install(self.package, root)
        self.assertEqual((root / "usr/libexec/buzz-ci-keyholder").read_bytes(), expected)

    def test_publication_failure_restores_targets_and_removes_new_receipt(self) -> None:
        self.freeze()
        root = self.make_root()
        self.add_credential(root)
        target = root / "usr/libexec/buzz-ci-keyholder"
        target.parent.mkdir(mode=0o755)
        target.parent.chmod(0o755)
        prior = b"prior keyholder binary\n"
        target.write_bytes(prior)
        target.chmod(0o700)
        original_publish = INSTALLER._atomic_publish
        failed = False

        def fail_after_first_publish(*args, **kwargs) -> None:
            nonlocal failed
            original_publish(*args, **kwargs)
            if not failed:
                failed = True
                raise OSError("forced target readback failure")

        with mock.patch.object(INSTALLER, "_atomic_publish", side_effect=fail_after_first_publish):
            with self.assertRaisesRegex(OSError, "forced target readback failure"):
                INSTALLER.install(self.package, root)
        self.assertEqual(target.read_bytes(), prior)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        receipt_directory = root / INSTALLER.RECEIPT_DIRECTORY.removeprefix("/")
        self.assertFalse((receipt_directory / "receipt-v1.json").exists())
        self.assertEqual(list(receipt_directory.glob("prior-*")) if receipt_directory.exists() else [], [])

    def test_receipt_readback_failure_restores_all_targets_and_receipt_artifacts(self) -> None:
        self.freeze()
        root = self.make_root()
        self.add_credential(root)
        target = root / "usr/libexec/buzz-ci-keyholder"
        target.parent.mkdir(mode=0o755)
        target.parent.chmod(0o755)
        prior = b"prior keyholder binary\n"
        target.write_bytes(prior)
        target.chmod(0o700)
        original_read = INSTALLER._read_receipt
        present_reads = 0

        def fail_final_readback(directory_fd: int, name: str, *, absent_ok: bool):
            nonlocal present_reads
            result = original_read(directory_fd, name, absent_ok=absent_ok)
            if name == "receipt-v1.json" and not absent_ok:
                present_reads += 1
                if present_reads == 2:
                    raise OSError("forced receipt readback failure")
            return result

        with mock.patch.object(INSTALLER, "_read_receipt", side_effect=fail_final_readback):
            with self.assertRaisesRegex(OSError, "forced receipt readback failure"):
                INSTALLER.install(self.package, root)
        self.assertEqual(target.read_bytes(), prior)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        receipt_directory = root / INSTALLER.RECEIPT_DIRECTORY.removeprefix("/")
        self.assertFalse(receipt_directory.exists())

    def test_existing_receipt_retry_completes_and_then_is_unchanged(self) -> None:
        self.freeze()
        root = self.make_root()
        self.add_credential(root)
        INSTALLER.install(self.package, root)
        target = root / "usr/libexec/buzz-ci-keyholder"
        target.unlink()
        retried = INSTALLER.install(self.package, root)
        self.assertEqual(retried["status"], "installed")
        self.assertEqual(retried["changed_targets"], ["/usr/libexec/buzz-ci-keyholder"])
        self.assertEqual(target.read_bytes(), self.binary.read_bytes())
        self.assertEqual(INSTALLER.install(self.package, root)["status"], "unchanged")

    def test_fresh_host_not_found_installs_exec_start_and_rollback_restores_absence(self) -> None:
        self.freeze()
        root = self.make_root()
        self.add_credential(root)
        binary = root / "usr/libexec/buzz-ci-keyholder"
        self.assertFalse(binary.exists())
        installed = INSTALLER.install(self.package, root)
        self.assertEqual(installed["status"], "installed")
        self.assertEqual(binary.read_bytes(), self.binary.read_bytes())
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
        preview = INSTALLER.rollback(self.package, root, dry_run=True)
        self.assertEqual(preview["status"], "rollback_dry_run")
        rolled_back = INSTALLER.rollback(self.package, root)
        self.assertEqual(rolled_back["status"], "rolled_back")
        for target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertFalse(INSTALLER.rooted(root, target).exists())
        self.assertFalse((root / "usr/libexec").exists())
        self.assertFalse((root / "etc/buzzci").exists())
        with self.assertRaisesRegex(ValueError, "already rolled back"):
            INSTALLER.install(self.package, root)

    def test_rollback_restores_preexisting_binary_bytes_and_metadata(self) -> None:
        self.freeze()
        root = self.make_root()
        self.add_credential(root)
        binary = root / "usr/libexec/buzz-ci-keyholder"
        binary.parent.mkdir(mode=0o755)
        binary.parent.chmod(0o755)
        binary.write_bytes(b"prior keyholder binary\n")
        binary.chmod(0o700)
        before = (binary.read_bytes(), stat.S_IMODE(binary.stat().st_mode), binary.stat().st_uid, binary.stat().st_gid)
        INSTALLER.install(self.package, root)
        self.assertEqual(binary.read_bytes(), self.binary.read_bytes())
        INSTALLER.rollback(self.package, root)
        after = (binary.read_bytes(), stat.S_IMODE(binary.stat().st_mode), binary.stat().st_uid, binary.stat().st_gid)
        self.assertEqual(after, before)

    def test_umask_0000_and_0077_produce_exact_package_and_install_modes(self) -> None:
        package_digests = []
        for index, mask in enumerate((0o000, 0o077)):
            with self.subTest(mask=oct(mask)):
                self.package = self.base / f"package-{index}"
                previous = os.umask(mask)
                try:
                    manifest = self.freeze()
                finally:
                    os.umask(previous)
                package_digests.append(manifest["package_digest"])
                self.assertEqual(stat.S_IMODE(self.package.stat().st_mode), 0o700)
                root = self.make_root() if index == 0 else self.base / f"root-{index}"
                if index:
                    original_base = self.base
                    self.base = self.base / f"fixture-{index}"
                    self.base.mkdir(mode=0o700)
                    try:
                        root = self.make_root()
                    finally:
                        self.base = original_base
                self.add_credential(root)
                previous = os.umask(mask)
                try:
                    INSTALLER.install(self.package, root)
                finally:
                    os.umask(previous)
                for role, target in INSTALLER.EXPECTED_TARGETS.items():
                    expected = 0o755 if role == "binary" else (0o600 if role == "config" else 0o644)
                    self.assertEqual(stat.S_IMODE(INSTALLER.rooted(root, target).stat().st_mode), expected)
        self.assertEqual(package_digests[0], package_digests[1])

    def test_hostile_link_replay_drift_and_candidate_receipt_mismatch_are_rejected(self) -> None:
        self.freeze()
        root = self.make_root()
        self.add_credential(root)
        (root / "usr/libexec").mkdir(mode=0o755)
        (root / "usr/libexec").chmod(0o755)
        outside = self.base / "outside"
        outside.write_text("untouched\n")
        target = root / "usr/libexec/buzz-ci-keyholder"
        target.symlink_to(outside)
        with self.assertRaises(OSError):
            INSTALLER.install(self.package, root)
        self.assertEqual(outside.read_text(), "untouched\n")
        target.unlink()
        INSTALLER.install(self.package, root)
        target.write_text("drift\n")
        target.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "drift blocks replay"):
            INSTALLER.install(self.package, root)
        receipt = root / INSTALLER.RECEIPT_DIRECTORY.removeprefix("/") / "receipt-v1.json"
        value = json.loads(receipt.read_text())
        value["source_commit"] = "f" * 40
        receipt.write_bytes(INSTALLER.canonical_json(value))
        receipt.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "package binding differs"):
            INSTALLER.install(self.package, root)

    def test_credential_rejects_intermediate_symlink_and_path_replacement_race(self) -> None:
        self.freeze()
        root = self.make_root()
        credential = self.add_credential(root)
        original_directory = credential.parents[1]
        outside = self.base / "outside-credentials"
        shutil.copytree(original_directory, outside)
        shutil.rmtree(original_directory)
        original_directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "path is unsafe"):
            INSTALLER.validate_encrypted_credential(root)

        original_directory.unlink()
        shutil.copytree(outside, original_directory)
        real_open = os.open
        opens = 0

        def replace_during_revalidation(path, flags, *args, **kwargs):
            nonlocal opens
            if path == "credstore.encrypted":
                opens += 1
                if opens == 2:
                    original_directory.rename(root / "etc/credstore.encrypted-held")
                    shutil.copytree(outside, original_directory)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(INSTALLER.os, "open", side_effect=replace_during_revalidation):
            with self.assertRaisesRegex(ValueError, "path changed during validation"):
                INSTALLER.validate_encrypted_credential(root)

    def test_parent_rename_during_publish_fails_exact_readback(self) -> None:
        self.freeze()
        root = self.make_root()
        self.add_credential(root)
        real_rename = os.rename
        moved = False

        def hostile_rename(source, destination, *args, **kwargs):
            nonlocal moved
            if destination == "buzz-ci-keyholder" and not moved:
                moved = True
                real_rename(root / "usr/libexec", root / "usr/libexec-moved")
                (root / "usr/libexec").mkdir(mode=0o755)
                (root / "usr/libexec").chmod(0o755)
            return real_rename(source, destination, *args, **kwargs)

        with mock.patch.object(INSTALLER.os, "rename", side_effect=hostile_rename):
            with self.assertRaisesRegex(ValueError, "directory changed"):
                INSTALLER.install(self.package, root)
        self.assertFalse((root / "usr/libexec-moved/buzz-ci-keyholder").exists())
        self.assertFalse((root / "usr/libexec/buzz-ci-keyholder").exists())
        self.assertFalse((root / INSTALLER.RECEIPT_DIRECTORY.removeprefix("/") / "receipt-v1.json").exists())

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
