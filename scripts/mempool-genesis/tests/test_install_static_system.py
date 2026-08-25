from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "install-static-system.py"
SPEC = importlib.util.spec_from_file_location("install_static_system", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class StaticManifestTests(unittest.TestCase):
    def make_package(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        package = Path(temporary.name)
        package.chmod(0o700)
        entries = []
        for target, (source_name, mode) in MODULE.TARGETS.items():
            source = package / source_name
            source.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source.write_bytes(target.encode())
            source.chmod(mode)
            entries.append(
                {
                    "source": source_name,
                    "target": target,
                    "mode": f"{mode:04o}",
                    "sha256": hashlib.sha256(target.encode()).hexdigest(),
                }
            )
        manifest = package / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": MODULE.SCHEMA,
                    "package_id": "mempool-genesis-static-test",
                    "entries": entries,
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
            manifest = json.loads((package / "manifest.json").read_text())
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
                f'{entry["status"]}\t{entry["sha256"]}\t{entry["path"]}\n'
                for entry in changed_paths
            ).encode()
        ).hexdigest()
        bundle = {
            "schema": "tier2-evidence-v2",
            "revision": 1,
            "candidate": {"mode": "files"},
            "changed_paths": changed_paths,
            "fingerprints": fingerprints or {},
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
        package_id, entries = MODULE.exact_manifest(package)
        self.assertEqual(package_id, "mempool-genesis-static-test")
        self.assertEqual(len(entries), len(MODULE.TARGETS))

    def test_rejects_duplicate_json_keys(self) -> None:
        with self.assertRaises(ValueError):
            json.loads('{"schema":"one","schema":"two"}', object_pairs_hook=MODULE.reject_duplicates)

    def test_rejects_manifest_target_drift(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        manifest = json.loads((package / "manifest.json").read_text())
        manifest["entries"][0]["target"] = "/etc/passwd"
        (package / "manifest.json").write_text(json.dumps(manifest))
        (package / "manifest.json").chmod(0o600)
        with self.assertRaises(ValueError):
            MODULE.exact_manifest(package)

    def test_closure_binding_requires_exact_package_source_set_and_hashes(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        manifest = json.loads((package / "manifest.json").read_text())
        sources = {
            str(package / entry["source"]): entry["sha256"] for entry in manifest["entries"]
        }
        state = self.make_closure(package)
        MODULE.bind_accepted_sources(state, sources, self.make_attestation(state))

        bundle = json.loads((package / "evidence.json").read_text())
        incomplete = bundle["changed_paths"][:-1]
        missing_state = self.make_closure(package, changed_paths=incomplete)
        with self.assertRaisesRegex(ValueError, "exactly"):
            MODULE.bind_accepted_sources(
                missing_state, sources, self.make_attestation(missing_state)
            )

        mismatched = [dict(entry) for entry in bundle["changed_paths"]]
        mismatched[0]["sha256"] = "0" * 64
        mismatch_state = self.make_closure(package, changed_paths=mismatched)
        with self.assertRaisesRegex(ValueError, "hash"):
            MODULE.bind_accepted_sources(
                mismatch_state, sources, self.make_attestation(mismatch_state)
            )

    def test_desktop_previous_launcher_hash_comes_from_accepted_bundle(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        previous_hash = "a" * 64
        state = self.make_closure(
            package, fingerprints={"desktop_previous_launcher_sha256": previous_hash}
        )
        self.assertEqual(
            MODULE.accepted_fingerprint(
                state,
                "desktop_previous_launcher_sha256",
                self.make_attestation(state),
            ),
            previous_hash,
        )
        with self.assertRaisesRegex(ValueError, "lacks fingerprint"):
            MODULE.accepted_fingerprint(
                state, "missing", self.make_attestation(state)
            )
        desktop_installer = (SCRIPT.parent / "install-reviewed-desktop").read_text()
        self.assertIn('launcher_hash=$(sha256sum -- "$source_launcher"', desktop_installer)
        self.assertIn("--name desktop_previous_launcher_sha256", desktop_installer)
        self.assertNotIn("readonly launcher_hash=", desktop_installer)
        self.assertNotIn("readonly old_launcher_hash=", desktop_installer)

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
        manifest = {
            "schema": MODULE.SCHEMA,
            "package_id": "mempool-genesis-static-test",
            "entries": [
                {
                    "source": "payload/tool",
                    "target": str(target),
                    "mode": "0755",
                    "sha256": digest,
                }
            ],
        }
        (package / "manifest.json").write_text(json.dumps(manifest))
        (package / "manifest.json").chmod(0o600)
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
            mock.patch.object(MODULE, "check_closure"),
            mock.patch.object(MODULE, "require_services_stopped"),
            mock.patch.object(MODULE, "bind_accepted_sources"),
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
