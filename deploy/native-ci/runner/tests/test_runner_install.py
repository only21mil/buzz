from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import subprocess
import tempfile
import unittest

RUNNER_DIR = Path(__file__).resolve().parents[1]
SOURCE_ROOT = RUNNER_DIR.parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RENDERER = load_module("render_runner_config", RUNNER_DIR / "render_runner_config.py")
FREEZER = load_module("freeze_package", RUNNER_DIR / "freeze_package.py")
INSTALLER = load_module("runner_install", RUNNER_DIR / "install.py")


class RunnerInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.source_root = self.base / "source"
        copied = self.source_root / "deploy/native-ci/runner"
        copied.parent.mkdir(mode=0o700, parents=True)
        shutil.copytree(
            RUNNER_DIR,
            copied,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        shutil.copy2(SOURCE_ROOT / "deploy/native-ci/package_source.py", copied.parent / "package_source.py")
        subprocess.run(["git", "init", "-q", str(self.source_root)], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.name", "Runner test"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.email", "runner@test.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "add", "deploy/native-ci"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "commit", "-qm", "fixture"], check=True)
        self.source_commit = FREEZER.git_output(self.source_root, "rev-parse", "HEAD")
        self.binary = self.base / "buzz-ci-runner"
        self.binary.write_bytes(b"test buzz-ci-runner binary\n")
        self.binary.chmod(0o755)
        self.provenance = self.base / "binary-provenance.json"
        self.provenance.write_text(
            json.dumps(
                {
                    "schema": "buzz-ci-binary-provenance-v1",
                    "binary": "buzz-ci-runner",
                    "source_commit": self.source_commit,
                    "profile": "release",
                    "sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        self.provenance.chmod(0o600)
        self.package = self.base / "package"
        self.runner_uid = os.geteuid()
        self.runner_gid = os.getegid()
        self.controld_uid = self.runner_uid + 1
        self.controld_gid = self.runner_gid + 1

    def freeze(self) -> dict[str, object]:
        return FREEZER.freeze_package(
            self.source_root,
            self.source_commit,
            self.binary,
            self.provenance,
            self.package,
            self.runner_uid,
            self.runner_gid,
            self.controld_uid,
            self.controld_gid,
        )

    def host_config(self, broker_uid: int = 0) -> dict[str, object]:
        return {
            "owner_pubkey": "11" * 32,
            "manifest_verification_key": "22" * 32,
            "relay_signer": "33" * 32,
            "broker_socket": "/run/buzzci/execd.sock",
            "broker_uid": broker_uid,
            "executor_program": "/usr/libexec/buzz-ci-executor",
            "evidence_directory": "/var/lib/buzzci/runner/evidence",
            "journal_directory": "/var/lib/buzzci/runner/journal",
            "max_argv_items": 32,
            "max_argv_bytes": 8192,
            "max_environment_items": 32,
            "max_environment_bytes": 8192,
            "max_output_bytes": 1048576,
        }

    def make_root(self, name: str = "root") -> Path:
        root = self.base / name
        root.mkdir(mode=0o700)
        for relative in (
            "etc/systemd/system",
            "usr/libexec",
            "usr/lib/tmpfiles.d",
            "usr/share/doc",
            "var/lib",
        ):
            current = root
            for component in Path(relative).parts:
                current /= component
                current.mkdir(mode=0o755, exist_ok=True)
        (root / "etc/passwd").write_text(
            f"buzzci-runner:x:{self.runner_uid}:{self.runner_gid}:runner:/nonexistent:/usr/sbin/nologin\n"
            f"buzzci-controld:x:{self.controld_uid}:{self.controld_gid}:controld:/nonexistent:/usr/sbin/nologin\n"
        )
        (root / "etc/group").write_text(
            f"buzzci-runner:x:{self.runner_gid}:\n"
            f"buzzci-controld:x:{self.controld_gid}:\n"
        )
        (root / "etc/passwd").chmod(0o644)
        (root / "etc/group").chmod(0o644)
        return root

    def target_receipt_snapshot(self, root: Path, transaction: Path) -> dict[str, object]:
        targets: dict[str, tuple[bytes, int, int, int]] = {}
        for target in INSTALLER.EXPECTED_TARGETS.values():
            path = INSTALLER.rooted(root, target)
            if path.exists():
                payload, metadata = INSTALLER.read_fd(path)
                targets[target] = (
                    payload,
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_uid,
                    metadata.st_gid,
                )
        receipt, receipt_meta = INSTALLER.read_fd(transaction / "receipt.json")
        directories = {
            directory: (
                stat.S_IMODE(INSTALLER.rooted(root, directory).lstat().st_mode),
                tuple(sorted(path.name for path in INSTALLER.rooted(root, directory).iterdir())),
            )
            for directory in INSTALLER.EXPECTED_DIRECTORIES
            if INSTALLER.rooted(root, directory).exists()
        }
        return {
            "targets": targets,
            "receipt": (
                receipt,
                stat.S_IMODE(receipt_meta.st_mode),
                receipt_meta.st_uid,
                receipt_meta.st_gid,
            ),
            "directories": directories,
        }

    def install_with_prior_tmpfiles(self, root_name: str) -> tuple[Path, dict[str, object], Path, dict[str, object]]:
        root = self.make_root(root_name)
        tmpfiles = root / "usr/lib/tmpfiles.d/buzzci-runner.conf"
        tmpfiles.write_bytes(b"prior tmpfiles payload\n")
        tmpfiles.chmod(0o644)
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        transaction = INSTALLER.backup_root_path(root, INSTALLER.DEFAULT_BACKUP_ROOT) / str(installed["backup_id"])
        receipt = json.loads((transaction / "receipt.json").read_text())
        record = next(
            item
            for item in receipt["inventory"]
            if item["target"] == "/usr/lib/tmpfiles.d/buzzci-runner.conf"
        )
        self.assertTrue(record["existed"])
        return root, installed, transaction, record

    def test_config_renderer_is_canonical_closed_and_nofollow(self) -> None:
        output = self.base / "runner-v1.json"
        RENDERER.render(output, self.runner_uid)
        self.assertEqual(
            output.read_bytes(),
            f'{{"controld_uid":{self.runner_uid},"schema_version":1}}\n'.encode(),
        )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        RENDERER.check(output, self.runner_uid, self.runner_uid)
        value = json.loads(output.read_bytes())
        self.assertNotIn("host", value)
        self.assertNotIn("capacity", value)

        active = json.loads(RENDERER.config_bytes(self.controld_uid, self.host_config()))
        self.assertEqual(active["host"]["broker_uid"], 0)
        with self.assertRaisesRegex(ValueError, "root execd socket"):
            RENDERER.config_bytes(self.controld_uid, self.host_config(broker_uid=1))

        linked = self.base / "linked.json"
        linked.symlink_to(output)
        with self.assertRaises(OSError):
            RENDERER.check(linked, self.runner_uid)

    def test_freeze_binds_source_binary_package_and_dormant_state(self) -> None:
        manifest = self.freeze()
        parsed, entries = INSTALLER.parse_manifest(self.package, self.base)
        self.assertEqual(parsed["source_commit"], self.source_commit)
        self.assertEqual(parsed["default_state"], INSTALLER.DEFAULT_STATE)
        self.assertEqual(parsed["peer_policy"], INSTALLER.PEER_POLICY)
        self.assertNotEqual(
            parsed["identities"]["runner"]["uid"],
            parsed["identities"]["controld"]["uid"],
        )
        self.assertEqual(parsed["package_digest"], manifest["package_digest"])
        self.assertEqual({entry.role for entry in entries}, set(INSTALLER.EXPECTED_TARGETS))
        binary = next(entry for entry in entries if entry.role == "binary")
        self.assertEqual(binary.sha256, hashlib.sha256(self.binary.read_bytes()).hexdigest())

    def test_freeze_rejects_shared_runner_and_controld_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "identities must be distinct"):
            FREEZER.freeze_package(
                self.source_root,
                self.source_commit,
                self.binary,
                self.provenance,
                self.package,
                self.runner_uid,
                self.runner_gid,
                self.runner_uid,
                self.runner_gid,
            )

    def test_render_runner_config_validates_host_fields(self) -> None:
        host = self.host_config()
        RENDERER.validate_host(host)

        def assert_invalid(value: dict[str, object], message: str) -> None:
            with self.subTest(value=value, message=message):
                with self.assertRaisesRegex(ValueError, message):
                    RENDERER.validate_host(value)

        missing = dict(host)
        missing.pop("owner_pubkey")
        assert_invalid(missing, "incomplete or unknown")
        assert_invalid({**host, "extra": 1}, "incomplete or unknown")

        for field in ("owner_pubkey", "manifest_verification_key", "relay_signer"):
            for drift in ("", "ZZ" * 32, "11" * 31):
                broken = dict(host)
                broken[field] = drift
                assert_invalid(broken, "public identities are invalid")

        for socket in ("", "buzzci/execd.sock", "/run/buzzci/other.sock"):
            broken = dict(host)
            broken["broker_socket"] = socket
            assert_invalid(broken, "root execd socket")

        for field in ("evidence_directory", "journal_directory"):
            broken = dict(host)
            broken[field] = "/tmp/state"
            assert_invalid(broken, "state paths are invalid")

        for executor in ("usr/libexec/buzz-ci-executor", "/usr/libexec/buzz-ci-executor\0"):
            broken = dict(host)
            broken["executor_program"] = executor
            assert_invalid(broken, "executor path is invalid")

        bounds = {
            "max_argv_items": 256,
            "max_argv_bytes": 65_536,
            "max_environment_items": 256,
            "max_environment_bytes": 65_536,
            "max_output_bytes": 16_777_216,
        }
        for field, maximum in bounds.items():
            for value in (0, maximum + 1, True):
                broken = dict(host)
                broken[field] = value
                assert_invalid(broken, f"bound is invalid: {field}")

        saturated = dict(host, **{field: maximum for field, maximum in bounds.items()})
        RENDERER.validate_host(saturated)

    def test_check_rejects_linked_asset_and_binary_provenance_drift(self) -> None:
        self.freeze()
        binary_asset = self.package / "assets/buzz-ci-runner"
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

    def test_check_validates_host_plan_without_mutation(self) -> None:
        self.freeze()
        root = self.make_root()

        def snapshot() -> dict[str, tuple[int, int, int, bytes | None]]:
            result: dict[str, tuple[int, int, int, bytes | None]] = {}
            for path in sorted(root.rglob("*")):
                metadata = path.lstat()
                payload = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
                result[str(path.relative_to(root))] = (
                    metadata.st_mode,
                    metadata.st_uid,
                    metadata.st_gid,
                    payload,
                )
            return result

        before = snapshot()
        completed = subprocess.run(
            [
                sys.executable,
                str(RUNNER_DIR / "install.py"),
                "check",
                "--package",
                str(self.package),
                "--root",
                str(root),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "checked")
        self.assertEqual(result["changed_targets"], sorted(INSTALLER.EXPECTED_TARGETS.values()))
        self.assertEqual(result["peer_policy"], INSTALLER.PEER_POLICY)
        self.assertFalse(result["enabled"])
        self.assertFalse(result["active"])
        self.assertFalse(result["provisioned"])
        self.assertFalse(result["host_block"])
        self.assertEqual(result["capacity"], 0)
        self.assertEqual(snapshot(), before)

        INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        before = snapshot()
        self.assertEqual(INSTALLER.check(self.package, root)["changed_targets"], [])
        self.assertEqual(snapshot(), before)

    def test_check_rejects_host_identity_and_target_path_drift(self) -> None:
        self.freeze()
        root = self.make_root()
        (root / "etc/group").write_text(f"buzzci-runner:x:{self.runner_gid}:\n")
        with self.assertRaisesRegex(ValueError, "controld identity"):
            INSTALLER.check(self.package, root)

        root = self.make_root("target-root")
        outside = self.base / "outside-check"
        outside.write_text("do not touch\n")
        (root / "usr/libexec/buzz-ci-runner").symlink_to(outside)
        with self.assertRaises(OSError):
            INSTALLER.check(self.package, root)
        self.assertEqual(outside.read_text(), "do not touch\n")

    def test_dry_run_install_idempotency_and_exact_rollback(self) -> None:
        self.freeze()
        root = self.make_root()
        dry_run = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, dry_run=True)
        self.assertEqual(dry_run["status"], "dry_run")
        self.assertEqual(len(dry_run["changed_targets"]), 6)
        self.assertFalse((root / "usr/libexec/buzz-ci-runner").exists())

        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(installed["status"], "installed")
        self.assertFalse(installed["enabled"])
        self.assertFalse(installed["active"])
        self.assertFalse(installed["provisioned"])
        self.assertFalse(installed["host_block"])
        self.assertEqual(installed["capacity"], 0)
        self.assertEqual(installed["peer_policy"], INSTALLER.PEER_POLICY)
        unchanged = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(unchanged["status"], "unchanged")
        self.assertEqual(unchanged["changed_targets"], [])

        preview = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
            dry_run=True,
        )
        self.assertEqual(preview["status"], "rollback_dry_run")
        rolled_back = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )
        self.assertEqual(rolled_back["status"], "rolled_back")
        for target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertFalse(INSTALLER.rooted(root, target).exists())
        self.assertFalse((root / "etc/buzzci").exists())
        self.assertFalse((root / "usr/share/doc/buzz-ci-runner").exists())

    def test_install_refuses_target_symlink_and_rollback_refuses_drift(self) -> None:
        self.freeze()
        root = self.make_root()
        outside = self.base / "outside"
        outside.write_text("do not touch")
        target = root / "usr/libexec/buzz-ci-runner"
        target.symlink_to(outside)
        with self.assertRaises(OSError):
            INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, dry_run=True)
        self.assertEqual(outside.read_text(), "do not touch")

        target.unlink()
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        target.write_text("drift")
        target.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "drift blocks rollback"):
            INSTALLER.rollback(
                self.package,
                root,
                INSTALLER.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
            )

    def test_late_corrupt_backup_refuses_before_any_rollback_mutation(self) -> None:
        self.freeze()
        root, installed, transaction, record = self.install_with_prior_tmpfiles("root-corrupt")
        before = self.target_receipt_snapshot(root, transaction)
        backup = transaction / str(record["backup"])
        backup.write_bytes(b"corrupt late backup\n")
        backup.chmod(0o600)

        with self.assertRaisesRegex(ValueError, "backup file digest drift"):
            INSTALLER.rollback(
                self.package,
                root,
                INSTALLER.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
            )

        self.assertEqual(self.target_receipt_snapshot(root, transaction), before)
        self.assertEqual(json.loads((transaction / "receipt.json").read_text())["state"], "installed")

    def test_backup_preflight_blocks_missing_wrong_mode_and_symlink_without_mutation(self) -> None:
        self.freeze()
        cases = ("missing", "mode", "symlink")
        for case in cases:
            with self.subTest(case=case):
                root, installed, transaction, record = self.install_with_prior_tmpfiles(f"root-{case}")
                before = self.target_receipt_snapshot(root, transaction)
                backup = transaction / str(record["backup"])
                if case == "missing":
                    backup.unlink()
                elif case == "mode":
                    backup.chmod(0o644)
                else:
                    original = backup.with_name(f"{backup.name}.original")
                    backup.rename(original)
                    backup.symlink_to(original)

                with self.assertRaises((OSError, ValueError)):
                    INSTALLER.rollback(
                        self.package,
                        root,
                        INSTALLER.DEFAULT_BACKUP_ROOT,
                        str(installed["backup_id"]),
                    )

                self.assertEqual(self.target_receipt_snapshot(root, transaction), before)
                self.assertEqual(json.loads((transaction / "receipt.json").read_text())["state"], "installed")

    def test_directory_removal_preflight_blocks_content_and_metadata_drift_without_mutation(self) -> None:
        self.freeze()
        for case in ("content", "mode"):
            with self.subTest(case=case):
                root = self.make_root(f"root-directory-{case}")
                installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                transaction = INSTALLER.backup_root_path(root, INSTALLER.DEFAULT_BACKUP_ROOT) / str(installed["backup_id"])
                directory = root / "usr/share/doc/buzz-ci-runner"
                if case == "content":
                    blocker = directory / "operator-note"
                    blocker.write_text("keep\n")
                    blocker.chmod(0o600)
                else:
                    directory.chmod(0o700)
                before = self.target_receipt_snapshot(root, transaction)

                with self.assertRaisesRegex(ValueError, "rollback directory"):
                    INSTALLER.rollback(
                        self.package,
                        root,
                        INSTALLER.DEFAULT_BACKUP_ROOT,
                        str(installed["backup_id"]),
                    )

                self.assertEqual(self.target_receipt_snapshot(root, transaction), before)
                self.assertEqual(json.loads((transaction / "receipt.json").read_text())["state"], "installed")

    def test_templates_keep_runner_and_control_resources_separate(self) -> None:
        service = (RUNNER_DIR / "templates/buzz-ci-runner.service").read_text()
        socket = (RUNNER_DIR / "templates/buzz-ci-runner.socket").read_text()
        tmpfiles = (RUNNER_DIR / "templates/buzzci-runner.tmpfiles").read_text()
        self.assertIn("/run/buzzci/runner-control.sock", socket)
        self.assertNotIn("/run/buzzci/execd.sock", socket)
        self.assertIn("SocketUser=buzzci-runner", socket)
        self.assertIn("SocketGroup=buzzci-controld", socket)
        self.assertIn("SocketMode=0620", socket)
        self.assertIn("ReadWritePaths=/var/lib/buzzci/runner", service)
        self.assertNotIn("/var/lib/buzzci/runner-output", service + tmpfiles)
        self.assertNotIn("systemctl", (RUNNER_DIR / "install.py").read_text())

    def test_schemas_are_strict_json(self) -> None:
        for name in (
            "runner-config.schema.json",
            "package-manifest.schema.json",
            "binary-provenance.schema.json",
        ):
            schema = json.loads((RUNNER_DIR / name).read_text())
            self.assertFalse(schema["additionalProperties"])
        runner_schema = json.loads((RUNNER_DIR / "runner-config.schema.json").read_text())
        self.assertEqual(runner_schema["properties"]["host"]["properties"]["broker_uid"], {"const": 0})
        manifest_schema = json.loads((RUNNER_DIR / "package-manifest.schema.json").read_text())
        self.assertEqual(manifest_schema["properties"]["peer_policy"]["const"], INSTALLER.PEER_POLICY)


if __name__ == "__main__":
    unittest.main()
