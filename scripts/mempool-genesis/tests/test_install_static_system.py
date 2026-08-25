from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "install-static-system.py"
SPEC = importlib.util.spec_from_file_location("install_static_system", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
FREEZE_SCRIPT = SCRIPT.parent / "freeze-install-package.py"
FREEZE_SPEC = importlib.util.spec_from_file_location("freeze_install_package", FREEZE_SCRIPT)
assert FREEZE_SPEC is not None and FREEZE_SPEC.loader is not None
FREEZER = importlib.util.module_from_spec(FREEZE_SPEC)
FREEZE_SPEC.loader.exec_module(FREEZER)


class StaticManifestTests(unittest.TestCase):
    def make_package(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        package = Path(temporary.name)
        package.chmod(0o700)
        entries = []
        contracts = {
            target: (source_name, "static", "static", mode, mode)
            for target, (source_name, mode) in MODULE.TARGETS.items()
        }
        contracts.update(
            {
                target: (source_name, "desktop", role, source_mode, install_mode)
                for target, (source_name, role, source_mode, install_mode) in MODULE.DESKTOP_TARGETS.items()
            }
        )
        for target, (source_name, owner, role, source_mode, install_mode) in contracts.items():
            source = package / source_name
            source.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source.write_bytes(target.encode())
            source.chmod(source_mode)
            entries.append(
                {
                    "owner": owner,
                    "role": role,
                    "source": source_name,
                    "target": target,
                    "source_mode": f"{source_mode:04o}",
                    "install_mode": f"{install_mode:04o}",
                    "status": "A",
                    "sha256": hashlib.sha256(target.encode()).hexdigest(),
                }
            )
        entries.sort(key=lambda entry: entry["target"].encode())
        launcher_hash = next(
            entry["sha256"] for entry in entries if entry["role"] == "desktop_launcher"
        )
        manifest = package / MODULE.MANIFEST_NAME
        manifest.write_text(
            json.dumps(
                {
                    "schema": MODULE.SCHEMA,
                    "package_id": "mempool-genesis-static-test",
                    "entries": entries,
                    "desktop_launcher_sha256": launcher_hash,
                    "desktop_previous_launcher_sha256": "a" * 64,
                    "package_fingerprint": MODULE.package_fingerprint(entries),
                }
            )
        )
        manifest.chmod(0o600)
        return temporary, package

    def make_closure(
        self,
        package: Path,
        *,
        changed_paths: list[dict[str, str]] | None = None,
        fingerprints: dict[str, str] | None = None,
    ) -> Path:
        if changed_paths is None:
            manifest = json.loads((package / MODULE.MANIFEST_NAME).read_text())
            changed_paths = sorted(
                [
                    {
                        "status": "A",
                        "path": str(package / entry["source"]),
                        "sha256": entry["sha256"],
                    }
                    for entry in manifest["entries"]
                ],
                key=lambda entry: entry["path"].encode(),
            )
        artifact_fingerprint = hashlib.sha256(
            "".join(
                f'{entry["status"]}\t{entry.get("sha256", "-")}\t{entry["path"]}\n'
                for entry in changed_paths
            ).encode()
        ).hexdigest()
        manifest = json.loads((package / MODULE.MANIFEST_NAME).read_text())
        package_fingerprints = {
            "package_fingerprint": manifest["package_fingerprint"],
            "desktop_launcher_sha256": manifest["desktop_launcher_sha256"],
            "desktop_previous_launcher_sha256": manifest[
                "desktop_previous_launcher_sha256"
            ],
        }
        if fingerprints is not None:
            package_fingerprints.update(fingerprints)
        bundle = {
            "schema": "tier2-evidence-v2",
            "revision": 1,
            "candidate": {"mode": "files"},
            "changed_paths": changed_paths,
            "fingerprints": package_fingerprints,
            "artifact_fingerprint": artifact_fingerprint,
        }
        bundle_path = package / "evidence.json"
        bundle_path.write_text(json.dumps(bundle))
        bundle_path.chmod(0o600)
        state = {
            "schema": "tier2-closure-state-v2",
            "current_revision": 1,
            "lineage": {"terminal": True, "accepted": True},
            "revisions": {
                "1": {
                    "bundle_path": str(bundle_path),
                    "bundle_digest": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                    "artifact_fingerprint": artifact_fingerprint,
                }
            },
        }
        state_path = package / "state.json"
        state_path.write_text(json.dumps(state))
        state_path.chmod(0o600)
        return state_path

    def make_attestation(self, state: Path) -> dict[str, str]:
        closure = json.loads(state.read_text())
        revision = closure["revisions"][str(closure["current_revision"])]
        return {
            "state_digest": hashlib.sha256(state.read_bytes()).hexdigest(),
            "bundle_digest": revision["bundle_digest"],
            "artifact_fingerprint": revision["artifact_fingerprint"],
            "bundle_path": revision["bundle_path"],
        }

    def test_accepts_exact_manifest(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        manifest, entries = MODULE.exact_manifest(package)
        self.assertEqual(manifest["package_id"], "mempool-genesis-static-test")
        self.assertEqual(len(entries), len(MODULE.TARGETS) + len(MODULE.DESKTOP_TARGETS))

    def test_freeze_manifest_is_deterministic(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        repo = root / "repo"
        binary_dir = repo / "target/release"
        binary_dir.mkdir(mode=0o700, parents=True)
        system_dir = repo / "scripts/mempool-genesis"
        system_dir.mkdir(mode=0o700, parents=True)
        for _target, (source_name, mode) in MODULE.TARGETS.items():
            source = (
                binary_dir / Path(source_name).name
                if source_name.startswith("bin/")
                else system_dir / Path(source_name).name
            )
            source.write_bytes(source_name.encode())
            source.chmod(FREEZER.repository_source_modes(source_name, mode)[-1])
        launcher = system_dir / "launch-buzz-desktop"
        launcher.write_bytes(b"new launcher")
        launcher.chmod(0o755)
        app = root / "Buzz.AppImage"
        app.write_bytes(b"desktop app")
        app.chmod(0o755)
        previous = root / "previous-launcher"
        previous.write_bytes(b"previous launcher")
        previous.chmod(0o700)

        for name in ("one", "two"):
            FREEZER.freeze_package(
                root / name,
                "mempool-genesis-static-test",
                repo,
                binary_dir,
                app,
                previous,
            )
        self.assertEqual(
            (root / "one" / MODULE.MANIFEST_NAME).read_bytes(),
            (root / "two" / MODULE.MANIFEST_NAME).read_bytes(),
        )
        self.assertEqual(
            (root / "one/system/buzz-agent-key-handoff.sudoers").stat().st_mode
            & 0o777,
            0o440,
        )

    def test_rejects_duplicate_json_keys(self) -> None:
        with self.assertRaises(ValueError):
            json.loads('{"schema":"one","schema":"two"}', object_pairs_hook=MODULE.reject_duplicates)

    def test_rejects_manifest_target_drift(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        manifest = json.loads((package / MODULE.MANIFEST_NAME).read_text())
        manifest["entries"][0]["target"] = "/etc/passwd"
        (package / MODULE.MANIFEST_NAME).write_text(json.dumps(manifest))
        (package / MODULE.MANIFEST_NAME).chmod(0o600)
        with self.assertRaises(ValueError):
            MODULE.exact_manifest(package)

    def test_rejects_manifest_entry_missing_sha256(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        manifest = json.loads((package / MODULE.MANIFEST_NAME).read_text())
        del manifest["entries"][0]["sha256"]
        (package / MODULE.MANIFEST_NAME).write_text(json.dumps(manifest))
        (package / MODULE.MANIFEST_NAME).chmod(0o600)
        with self.assertRaisesRegex(ValueError, "invalid manifest entry"):
            MODULE.exact_manifest(package)

    def test_desktop_launcher_hash_mismatch_is_rejected(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        manifest = json.loads((package / MODULE.MANIFEST_NAME).read_text())
        manifest["desktop_launcher_sha256"] = "0" * 64
        (package / MODULE.MANIFEST_NAME).write_text(json.dumps(manifest))
        (package / MODULE.MANIFEST_NAME).chmod(0o600)
        with self.assertRaisesRegex(ValueError, "desktop launcher hash mismatch"):
            MODULE.exact_manifest(package)

    def test_closure_binding_requires_exact_package_source_set_and_hashes(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        manifest = json.loads((package / MODULE.MANIFEST_NAME).read_text())
        parsed_manifest, entries = MODULE.exact_manifest(package)
        state = self.make_closure(package)
        MODULE.bind_accepted_manifest(
            package, parsed_manifest, entries, self.make_attestation(state), state
        )

        bundle = json.loads((package / "evidence.json").read_text())
        incomplete = bundle["changed_paths"][:-1]
        missing_state = self.make_closure(package, changed_paths=incomplete)
        with self.assertRaisesRegex(ValueError, "exactly"):
            MODULE.bind_accepted_manifest(
                package,
                parsed_manifest,
                entries,
                self.make_attestation(missing_state),
                missing_state,
            )

        mismatched = [dict(entry) for entry in bundle["changed_paths"]]
        mismatched[0]["sha256"] = "0" * 64
        mismatch_state = self.make_closure(package, changed_paths=mismatched)
        with self.assertRaisesRegex(ValueError, "hash"):
            MODULE.bind_accepted_manifest(
                package,
                parsed_manifest,
                entries,
                self.make_attestation(mismatch_state),
                mismatch_state,
            )

        missing_digest = [dict(entry) for entry in bundle["changed_paths"]]
        del missing_digest[0]["sha256"]
        missing_digest_state = self.make_closure(
            package, changed_paths=missing_digest
        )
        with self.assertRaisesRegex(ValueError, "invalid closure package entry"):
            MODULE.bind_accepted_manifest(
                package,
                parsed_manifest,
                entries,
                self.make_attestation(missing_digest_state),
                missing_digest_state,
            )

    def test_verify_package_rejects_launcher_source_byte_drift(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        state = self.make_closure(package)
        launcher = package / "desktop/launch-buzz-desktop"
        launcher.write_bytes(b"drift after freeze")
        launcher.chmod(0o755)
        with (
            mock.patch.object(
                MODULE, "check_closure", return_value=self.make_attestation(state)
            ),
            self.assertRaisesRegex(ValueError, "package source hash drift"),
        ):
            MODULE.verify_package(package, state)

    def test_desktop_installer_refuses_launcher_hash_mismatch(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        package = root / "package"
        desktop = package / "desktop"
        desktop.mkdir(mode=0o700, parents=True)
        app = desktop / "Buzz_0.5.8_amd64.AppImage"
        app.write_bytes(b"reviewed app")
        app.chmod(0o755)
        launcher = desktop / "launch-buzz-desktop"
        launcher.write_bytes(b"drifted launcher")
        launcher.chmod(0o755)
        state = root / "state.json"
        state.write_text("{}\n")
        state.chmod(0o600)

        installer = root / "install-reviewed-desktop"
        installer.write_bytes((SCRIPT.parent / installer.name).read_bytes())
        installer.chmod(0o755)
        expected_app_hash = hashlib.sha256(app.read_bytes()).hexdigest()
        expected_launcher_hash = hashlib.sha256(b"reviewed launcher").hexdigest()
        roles_log = root / "accepted-roles.log"
        verifier = root / "install-static-system.py"
        verifier.write_text(
            f"""#!/usr/bin/env python3
import sys
from pathlib import Path

package = Path(sys.argv[sys.argv.index("--package") + 1])
role = sys.argv[sys.argv.index("--role") + 1]
with Path({str(roles_log)!r}).open("a") as roles:
    roles.write(role + "\\n")
if role == "desktop_app":
    print(
        f"{{package / 'desktop/Buzz_0.5.8_amd64.AppImage'}}"
        "\t/home/victor/work/buzz-client/Buzz_0.5.8-fixed-050ac722_amd64.AppImage"
        "\t0755\t0755\t" + {expected_app_hash!r} + "\t" + "a" * 64
    )
else:
    print(
        f"{{package / 'desktop/launch-buzz-desktop'}}"
        "\t/home/victor/projects/buzz/scripts/launch_buzz_desktop.sh"
        "\t0755\t0700\t" + {expected_launcher_hash!r} + "\t" + "b" * 64
    )
"""
        )
        verifier.chmod(0o755)

        completed = subprocess.run(
            [str(installer), "--package", str(package), "--state", str(state)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(roles_log.exists(), completed.stderr)
        self.assertEqual(
            roles_log.read_text().splitlines(),
            ["desktop_app", "desktop_launcher"],
        )

    def test_desktop_previous_launcher_hash_comes_from_accepted_bundle(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        previous_hash = "b" * 64
        state = self.make_closure(
            package, fingerprints={"desktop_previous_launcher_sha256": previous_hash}
        )
        manifest, entries = MODULE.exact_manifest(package)
        with self.assertRaisesRegex(
            ValueError, "desktop_previous_launcher_sha256"
        ):
            MODULE.bind_accepted_manifest(
                package, manifest, entries, self.make_attestation(state), state
            )
        desktop_installer = (SCRIPT.parent / "install-reviewed-desktop").read_text()
        self.assertIn("--role desktop_launcher", desktop_installer)
        self.assertIn(
            '[[ $current_launcher_hash == "$launcher_hash" || $current_launcher_hash == "$previous_launcher_hash" ]]',
            desktop_installer,
        )
        rollback = (SCRIPT.parent / "rollback-reviewed-desktop").read_text()
        self.assertIn("buzz-desktop-launcher-rollback-v1", rollback)
        self.assertNotIn("readonly installed_hash=", rollback)
        self.assertNotIn("readonly rollback_hash=", rollback)

    def test_timestamped_backup_receipt_is_complete_before_install(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        backup = Path(temporary.name)
        backup_id = MODULE.timestamped_backup_id(
            "mempool-genesis-static-test",
            datetime(2026, 8, 25, 12, 34, 56, 123456, tzinfo=timezone.utc),
        )
        self.assertEqual(
            backup_id, "mempool-genesis-static-test-20260825T123456.123456Z"
        )
        self.assertIsNotNone(MODULE.BACKUP_ID.fullmatch(backup_id))
        receipt = {
            "schema": MODULE.RECEIPT_SCHEMA,
            "backup_id": backup_id,
            "package_id": "mempool-genesis-static-test",
            "install_state": "prepared",
            "previous": {target: {"exists": False} for target in MODULE.TARGETS},
            "installed": {target: "0" * 64 for target in MODULE.TARGETS},
        }
        with mock.patch.object(MODULE.os, "fchown"):
            MODULE.write_receipt(backup / "receipt.json", receipt)
        self.assertEqual(MODULE.load_json(backup / "receipt.json"), receipt)

    def test_rollback_marks_timestamped_receipt_rolled_back(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        backup_root = Path(temporary.name)
        backup_id = "mempool-genesis-static-test-20260825T123456.123456Z"
        backup = backup_root / backup_id
        backup.mkdir(mode=0o700)
        receipt_path = backup / "receipt.json"
        receipt = {
            "schema": MODULE.RECEIPT_SCHEMA,
            "backup_id": backup_id,
            "package_id": "mempool-genesis-static-test",
            "install_state": "installed",
            "previous": {target: {"exists": False} for target in MODULE.TARGETS},
            "installed": {target: "0" * 64 for target in MODULE.TARGETS},
        }
        receipt_path.write_text(json.dumps(receipt))
        receipt_path.chmod(0o600)
        with (
            mock.patch.object(MODULE, "BACKUP_ROOT", backup_root),
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(MODULE, "require_services_stopped"),
            mock.patch.object(MODULE, "require_directory"),
            mock.patch.object(MODULE, "require_regular"),
            mock.patch.object(MODULE, "target_metadata", return_value={"sha256": "0" * 64}),
            mock.patch.object(MODULE, "restore_changed") as restore,
            mock.patch.object(MODULE.subprocess, "run"),
            mock.patch.object(MODULE.os, "fchown"),
        ):
            MODULE.rollback(backup_id)
        restore.assert_called_once_with(list(MODULE.TARGETS), receipt["previous"], backup)
        self.assertEqual(MODULE.load_json(receipt_path)["install_state"], "rolled_back")

    def test_failed_install_writes_receipt_before_mutation_and_keeps_rollback_record(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        package = root / "package"
        package.mkdir(mode=0o700)
        target = root / "live" / "tool"
        source = package / "payload/tool"
        source.parent.mkdir(mode=0o700)
        source.write_bytes(b"reviewed payload")
        source.chmod(0o755)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        entry = {
            "owner": "static",
            "role": "static",
            "source": "payload/tool",
            "target": str(target),
            "source_mode": "0755",
            "install_mode": "0755",
            "status": "A",
            "sha256": digest,
        }
        backup_root = root / "backups"
        saw_prepared_receipt = False

        def fail_first_live_copy(*_args: object) -> None:
            nonlocal saw_prepared_receipt
            receipts = list(backup_root.glob("*/receipt.json"))
            self.assertEqual(len(receipts), 1)
            saw_prepared_receipt = MODULE.load_json(receipts[0])["install_state"] == "prepared"
            raise RuntimeError("simulated live-copy failure")

        targets = {str(target): ("payload/tool", 0o755)}
        with (
            mock.patch.object(MODULE, "TARGETS", targets),
            mock.patch.object(MODULE, "BACKUP_ROOT", backup_root),
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(MODULE.os, "uname", return_value=SimpleNamespace(nodename="framework-desktop")),
            mock.patch.object(
                MODULE,
                "verify_package",
                return_value=({"package_id": "mempool-genesis-static-test"}, [entry]),
            ),
            mock.patch.object(MODULE, "require_services_stopped"),
            mock.patch.object(MODULE, "require_directory"),
            mock.patch.object(MODULE, "prepare_directories", return_value=False),
            mock.patch.object(MODULE, "atomic_copy_fd", side_effect=fail_first_live_copy),
            mock.patch.object(MODULE, "restore_changed") as restore,
            mock.patch.object(MODULE.subprocess, "run"),
            mock.patch.object(MODULE.os, "fchown"),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated live-copy failure"):
                MODULE.install(package, root / "state.json")

        self.assertTrue(saw_prepared_receipt)
        restore.assert_called_once()
        receipts = list(backup_root.glob("*/receipt.json"))
        self.assertEqual(len(receipts), 1)
        self.assertEqual(MODULE.load_json(receipts[0])["install_state"], "rolled_back")


if __name__ == "__main__":
    unittest.main()
