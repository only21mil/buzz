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
from unittest import mock

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


class SimulatedCrash(BaseException):
    pass


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
        subprocess.run(["git", "init", "-q", str(self.source_root)], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.name", "Runner test"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.email", "runner@test.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "add", "deploy/native-ci/runner"], check=True)
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

    def transactions(self, root: Path) -> list[Path]:
        backup_root = INSTALLER.backup_root_path(root, INSTALLER.DEFAULT_BACKUP_ROOT)
        return sorted(
            path
            for path in backup_root.iterdir()
            if (path / "transaction.json").exists()
        )

    def crash_at(self, phase: str, target: str | None = None):
        def boundary(observed_phase: str, observed_target: str | None = None) -> None:
            if observed_phase == phase and (target is None or observed_target == target):
                raise SimulatedCrash(f"{phase}:{target or ''}")

        return mock.patch.object(INSTALLER, "_phase_boundary", side_effect=boundary)

    def make_legacy_receipt_only(
        self,
        root: Path,
        backup_id: str,
        terminal_state: str,
    ) -> Path:
        transaction = INSTALLER.backup_root_path(root, INSTALLER.DEFAULT_BACKUP_ROOT) / backup_id
        state = json.loads((transaction / "transaction.json").read_text())
        legacy = INSTALLER.legacy_receipt_for(state, terminal_state)
        INSTALLER.atomic_write(
            transaction / "receipt.json",
            INSTALLER.canonical_json(legacy),
            0o600,
            root.stat().st_uid,
            root.stat().st_gid,
        )
        (transaction / "transaction.json").unlink()
        return transaction

    def test_config_renderer_is_canonical_closed_and_nofollow(self) -> None:
        output = self.base / "runner-v2.json"
        RENDERER.render(output, self.runner_uid, self.runner_gid)
        self.assertEqual(
            output.read_bytes(),
            f'{{"controld_gid":{self.runner_gid},"controld_uid":{self.runner_uid},"mode":"dormant","schema_version":2}}\n'.encode(),
        )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        RENDERER.check(output, self.runner_uid, self.runner_gid, self.runner_uid)
        value = json.loads(output.read_bytes())
        self.assertNotIn("host", value)
        self.assertNotIn("capacity", value)

        with self.assertRaises(TypeError):
            RENDERER.config_bytes(self.controld_uid, {"executor_program": "/bin/true"})

        linked = self.base / "linked.json"
        linked.symlink_to(output)
        with self.assertRaises(OSError):
            RENDERER.check(linked, self.runner_uid, self.runner_gid)

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

    def test_freeze_enforces_exact_private_modes_and_restores_umask(self) -> None:
        previous = os.umask(0)
        try:
            self.freeze()
            observed = os.umask(0)
        finally:
            os.umask(previous)
        self.assertEqual(observed, 0)
        self.assertEqual(stat.S_IMODE(self.package.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.package / "assets").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.package / "package-manifest.json").stat().st_mode), 0o600)
        for asset in (self.package / "assets").iterdir():
            self.assertIn(stat.S_IMODE(asset.stat().st_mode), {0o400, 0o500})

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
        retried = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(retried, installed)

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

        repeated = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )
        self.assertEqual(repeated, rolled_back)

    def test_legacy_v1_dry_run_is_read_only_then_real_rollback_migrates(self) -> None:
        self.freeze()
        root, installed, transaction, _record = self.install_with_prior_tmpfiles("legacy-root")
        transaction = self.make_legacy_receipt_only(root, str(installed["backup_id"]), "installed")
        before = self.target_receipt_snapshot(root, transaction)

        preview = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
            dry_run=True,
        )
        self.assertEqual(preview["status"], "rollback_dry_run")
        self.assertFalse((transaction / "transaction.json").exists())
        self.assertEqual(self.target_receipt_snapshot(root, transaction), before)

        rolled_back = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )
        self.assertEqual(rolled_back["status"], "rolled_back")
        self.assertEqual(json.loads((transaction / "transaction.json").read_text())["phase"], "rolled_back")
        receipt = json.loads((transaction / "receipt.json").read_text())
        self.assertEqual((receipt["schema"], receipt["state"]), (INSTALLER.RECEIPT_SCHEMA, "rolled_back"))
        tmpfiles = root / "usr/lib/tmpfiles.d/buzzci-runner.conf"
        self.assertEqual(tmpfiles.read_bytes(), b"prior tmpfiles payload\n")
        self.assertEqual(
            INSTALLER.rollback(
                self.package,
                root,
                INSTALLER.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
            ),
            rolled_back,
        )

    def test_legacy_v1_migration_and_mixed_rollback_restart_exactly(self) -> None:
        self.freeze()
        boundaries = (
            ("legacy_transaction_persisted", None),
            ("legacy_receipt_migrated", None),
            ("rollback_target_restored", sorted(INSTALLER.EXPECTED_TARGETS.values())[-1]),
        )
        for index, (phase, target) in enumerate(boundaries):
            with self.subTest(phase=phase, target=target):
                root = self.make_root(f"legacy-restart-{index}")
                installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                transaction = self.make_legacy_receipt_only(
                    root,
                    str(installed["backup_id"]),
                    "installed",
                )
                with self.crash_at(phase, target), self.assertRaises(SimulatedCrash):
                    INSTALLER.rollback(
                        self.package,
                        root,
                        INSTALLER.DEFAULT_BACKUP_ROOT,
                        str(installed["backup_id"]),
                    )
                self.assertTrue((transaction / "transaction.json").exists())
                resumed = INSTALLER.rollback(
                    self.package,
                    root,
                    INSTALLER.DEFAULT_BACKUP_ROOT,
                    str(installed["backup_id"]),
                )
                self.assertEqual(resumed["status"], "rolled_back")
                self.assertEqual(
                    json.loads((transaction / "transaction.json").read_text())["phase"],
                    "rolled_back",
                )
                for managed_target in INSTALLER.EXPECTED_TARGETS.values():
                    self.assertFalse(INSTALLER.rooted(root, managed_target).exists())

    def test_legacy_v1_receipt_only_mixed_state_resumes_old_rollback(self) -> None:
        self.freeze()
        root = self.make_root()
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        transaction = self.make_legacy_receipt_only(
            root,
            str(installed["backup_id"]),
            "installed",
        )
        restored_target = sorted(INSTALLER.EXPECTED_TARGETS.values())[-1]
        INSTALLER.unlink_target(INSTALLER.rooted(root, restored_target))

        preview = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
            dry_run=True,
        )
        self.assertEqual(preview["status"], "rollback_dry_run")
        self.assertFalse((transaction / "transaction.json").exists())

        with self.crash_at("legacy_transaction_persisted"), self.assertRaises(SimulatedCrash):
            INSTALLER.rollback(
                self.package,
                root,
                INSTALLER.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
            )
        state = json.loads((transaction / "transaction.json").read_text())
        self.assertEqual(state["phase"], "rollback_restoring")
        self.assertEqual(json.loads((transaction / "receipt.json").read_text())["schema"], INSTALLER.LEGACY_RECEIPT_SCHEMA)

        resumed = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )
        self.assertEqual(resumed["status"], "rolled_back")
        for managed_target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertFalse(INSTALLER.rooted(root, managed_target).exists())

    def test_legacy_v1_terminal_retry_stays_read_only(self) -> None:
        self.freeze()
        root = self.make_root()
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        rolled_back = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )
        transaction = self.make_legacy_receipt_only(root, str(installed["backup_id"]), "rolled_back")
        before = self.target_receipt_snapshot(root, transaction)
        repeated = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )
        self.assertEqual(repeated, rolled_back)
        self.assertFalse((transaction / "transaction.json").exists())
        self.assertEqual(self.target_receipt_snapshot(root, transaction), before)

    def test_legacy_v1_tamper_and_absent_evidence_refuse_without_migration(self) -> None:
        self.freeze()
        cases = ("receipt-tamper", "target-drift", "missing-backup", "missing-receipt")
        for case in cases:
            with self.subTest(case=case):
                root, installed, transaction, record = self.install_with_prior_tmpfiles(f"legacy-{case}")
                transaction = self.make_legacy_receipt_only(
                    root,
                    str(installed["backup_id"]),
                    "installed",
                )
                if case == "receipt-tamper":
                    receipt = json.loads((transaction / "receipt.json").read_text())
                    receipt["changed_targets"] = list(reversed(receipt["changed_targets"]))
                    INSTALLER.atomic_write(
                        transaction / "receipt.json",
                        INSTALLER.canonical_json(receipt),
                        0o600,
                        root.stat().st_uid,
                        root.stat().st_gid,
                    )
                elif case == "target-drift":
                    target = INSTALLER.rooted(root, str(record["target"]))
                    target.write_bytes(b"candidate drift\n")
                    target.chmod(0o644)
                elif case == "missing-backup":
                    (transaction / str(record["backup"])).unlink()
                else:
                    (transaction / "receipt.json").unlink()

                with self.assertRaises((OSError, ValueError)):
                    INSTALLER.rollback(
                        self.package,
                        root,
                        INSTALLER.DEFAULT_BACKUP_ROOT,
                        str(installed["backup_id"]),
                    )
                self.assertFalse((transaction / "transaction.json").exists())

    def test_transaction_is_durable_and_candidate_bound_before_target_mutation(self) -> None:
        manifest = self.freeze()
        root = self.make_root()
        with self.crash_at("install_prepared"), self.assertRaises(SimulatedCrash):
            INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)

        [transaction] = self.transactions(root)
        state_path = transaction / "transaction.json"
        state = json.loads(state_path.read_text())
        metadata = state_path.stat()
        self.assertEqual(state["phase"], "install_prepared")
        self.assertEqual(state["package_id"], manifest["package_id"])
        self.assertEqual(state["package_digest"], manifest["package_digest"])
        self.assertEqual(state["source_commit"], self.source_commit)
        self.assertEqual(
            state["transaction_digest"],
            INSTALLER.transaction_digest(state),
        )
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_uid, root.stat().st_uid)
        self.assertEqual(metadata.st_gid, root.stat().st_gid)
        self.assertFalse((transaction / "receipt.json").exists())
        for target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertFalse(INSTALLER.rooted(root, target).exists())
        for directory in INSTALLER.EXPECTED_DIRECTORIES:
            self.assertFalse(INSTALLER.rooted(root, directory).exists())

        resumed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(resumed["backup_id"], transaction.name)
        self.assertEqual(json.loads(state_path.read_text())["phase"], "installed")

    def test_install_restarts_at_phase_and_each_published_target_boundary(self) -> None:
        self.freeze()
        for phase in ("install_publishing", "installed_receipt_written", "installed"):
            with self.subTest(phase=phase):
                root = self.make_root(f"install-phase-{phase}")
                with self.crash_at(phase), self.assertRaises(SimulatedCrash):
                    INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                [transaction] = self.transactions(root)
                resumed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                self.assertEqual(resumed["backup_id"], transaction.name)
                self.assertEqual(resumed["status"], "installed")
                self.assertEqual(json.loads((transaction / "transaction.json").read_text())["phase"], "installed")

        for index, directory in enumerate(sorted(INSTALLER.EXPECTED_DIRECTORIES)):
            with self.subTest(created_directory=directory):
                root = self.make_root(f"install-directory-{index}")
                with self.crash_at("install_directory_created", directory), self.assertRaises(SimulatedCrash):
                    INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                [transaction] = self.transactions(root)
                self.assertEqual(
                    json.loads((transaction / "transaction.json").read_text())["phase"],
                    "install_publishing",
                )
                resumed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                self.assertEqual(resumed["backup_id"], transaction.name)

        for index, target in enumerate(sorted(INSTALLER.EXPECTED_TARGETS.values())):
            with self.subTest(published_target=target):
                root = self.make_root(f"install-target-{index}")
                with self.crash_at("install_target_published", target), self.assertRaises(SimulatedCrash):
                    INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                [transaction] = self.transactions(root)
                state = json.loads((transaction / "transaction.json").read_text())
                _manifest, entries = INSTALLER.parse_manifest(self.package, root)
                classifications = INSTALLER.target_classifications(root, state, entries)
                self.assertIn("candidate", classifications.values())
                if target != sorted(INSTALLER.EXPECTED_TARGETS.values())[-1]:
                    self.assertIn("prior", classifications.values())
                resumed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                self.assertEqual(resumed["backup_id"], transaction.name)
                self.assertEqual(
                    set(INSTALLER.target_classifications(root, json.loads((transaction / "transaction.json").read_text()), entries).values()),
                    {"candidate"},
                )

    def test_rollback_restarts_at_phase_target_and_directory_boundaries(self) -> None:
        self.freeze()
        for phase in (
            "rollback_prepared",
            "rollback_restoring",
            "rolled_back_receipt_written",
            "rolled_back",
        ):
            with self.subTest(phase=phase):
                root = self.make_root(f"rollback-phase-{phase}")
                installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                with self.crash_at(phase), self.assertRaises(SimulatedCrash):
                    INSTALLER.rollback(
                        self.package,
                        root,
                        INSTALLER.DEFAULT_BACKUP_ROOT,
                        str(installed["backup_id"]),
                    )
                resumed = INSTALLER.rollback(
                    self.package,
                    root,
                    INSTALLER.DEFAULT_BACKUP_ROOT,
                    str(installed["backup_id"]),
                )
                repeated = INSTALLER.rollback(
                    self.package,
                    root,
                    INSTALLER.DEFAULT_BACKUP_ROOT,
                    str(installed["backup_id"]),
                )
                self.assertEqual(repeated, resumed)

        rollback_order = list(reversed(sorted(INSTALLER.EXPECTED_TARGETS.values())))
        for index, target in enumerate(rollback_order):
            with self.subTest(restored_target=target):
                root = self.make_root(f"rollback-target-{index}")
                installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                with self.crash_at("rollback_target_restored", target), self.assertRaises(SimulatedCrash):
                    INSTALLER.rollback(
                        self.package,
                        root,
                        INSTALLER.DEFAULT_BACKUP_ROOT,
                        str(installed["backup_id"]),
                    )
                transaction = self.transactions(root)[0]
                state = json.loads((transaction / "transaction.json").read_text())
                _manifest, entries = INSTALLER.parse_manifest(self.package, root)
                classifications = INSTALLER.target_classifications(root, state, entries)
                self.assertIn("prior", classifications.values())
                if target != rollback_order[-1]:
                    self.assertIn("candidate", classifications.values())
                INSTALLER.rollback(
                    self.package,
                    root,
                    INSTALLER.DEFAULT_BACKUP_ROOT,
                    str(installed["backup_id"]),
                )
                for managed_target in INSTALLER.EXPECTED_TARGETS.values():
                    self.assertFalse(INSTALLER.rooted(root, managed_target).exists())

        for index, directory in enumerate(reversed(sorted(INSTALLER.EXPECTED_DIRECTORIES))):
            with self.subTest(removed_directory=directory):
                root = self.make_root(f"rollback-directory-{index}")
                installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
                with self.crash_at("rollback_directory_removed", directory), self.assertRaises(SimulatedCrash):
                    INSTALLER.rollback(
                        self.package,
                        root,
                        INSTALLER.DEFAULT_BACKUP_ROOT,
                        str(installed["backup_id"]),
                    )
                INSTALLER.rollback(
                    self.package,
                    root,
                    INSTALLER.DEFAULT_BACKUP_ROOT,
                    str(installed["backup_id"]),
                )
                for managed_directory in INSTALLER.EXPECTED_DIRECTORIES:
                    self.assertFalse(INSTALLER.rooted(root, managed_directory).exists())

    def test_mixed_rollback_restores_present_and_absent_baselines_on_retry(self) -> None:
        self.freeze()
        root = self.make_root()
        prior_target = root / "usr/lib/tmpfiles.d/buzzci-runner.conf"
        prior_target.write_bytes(b"operator prior tmpfiles\n")
        prior_target.chmod(0o640)
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        first_target = list(reversed(sorted(INSTALLER.EXPECTED_TARGETS.values())))[2]
        with self.crash_at("rollback_target_restored", first_target), self.assertRaises(SimulatedCrash):
            INSTALLER.rollback(
                self.package,
                root,
                INSTALLER.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
            )
        transaction = self.transactions(root)[0]
        state = json.loads((transaction / "transaction.json").read_text())
        _manifest, entries = INSTALLER.parse_manifest(self.package, root)
        self.assertEqual(
            set(INSTALLER.target_classifications(root, state, entries).values()),
            {"candidate", "prior"},
        )
        INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )
        self.assertEqual(prior_target.read_bytes(), b"operator prior tmpfiles\n")
        self.assertEqual(stat.S_IMODE(prior_target.stat().st_mode), 0o640)
        for target in INSTALLER.EXPECTED_TARGETS.values():
            if target != "/usr/lib/tmpfiles.d/buzzci-runner.conf":
                self.assertFalse(INSTALLER.rooted(root, target).exists())

    def test_receipt_state_mismatch_and_candidate_binding_refuse_recovery(self) -> None:
        self.freeze()
        root = self.make_root()
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        [transaction] = self.transactions(root)
        state = json.loads((transaction / "transaction.json").read_text())
        receipt = INSTALLER.receipt_for(state, "rolled_back")
        INSTALLER.atomic_write(
            transaction / "receipt.json",
            INSTALLER.canonical_json(receipt),
            0o600,
            root.stat().st_uid,
            root.stat().st_gid,
        )
        with self.assertRaisesRegex(ValueError, "receipt/state mismatch"):
            INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        with self.assertRaisesRegex(ValueError, "receipt/state mismatch"):
            INSTALLER.rollback(
                self.package,
                root,
                INSTALLER.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
            )

        root = self.make_root("candidate-binding-root")
        with self.crash_at("install_prepared"), self.assertRaises(SimulatedCrash):
            INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        [transaction] = self.transactions(root)
        state = json.loads((transaction / "transaction.json").read_text())
        state["package_digest"] = "f" * 64
        state["transaction_digest"] = INSTALLER.transaction_digest(state)
        INSTALLER.atomic_write(
            transaction / "transaction.json",
            INSTALLER.canonical_json(state),
            0o600,
            root.stat().st_uid,
            root.stat().st_gid,
        )
        with self.assertRaisesRegex(ValueError, "bound to another candidate"):
            INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)

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

    def test_transaction_refuses_drift_in_target_that_was_already_candidate(self) -> None:
        self.freeze()
        root = self.make_root()
        _manifest, entries = INSTALLER.parse_manifest(self.package, root)
        binary = next(entry for entry in entries if entry.role == "binary")
        uid, gid, install_mode = INSTALLER.desired_metadata(root, binary)
        INSTALLER.atomic_write(
            INSTALLER.rooted(root, binary.target),
            (self.package / binary.source).read_bytes(),
            install_mode,
            uid,
            gid,
        )
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertNotIn(binary.target, installed["changed_targets"])
        INSTALLER.rooted(root, binary.target).write_bytes(b"unmanaged drift\n")
        INSTALLER.rooted(root, binary.target).chmod(install_mode)
        with self.assertRaisesRegex(ValueError, "unchanged package target drift"):
            INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        with self.assertRaisesRegex(ValueError, "unchanged package target drift"):
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
        self.assertIn("User=buzzci-runner", service)
        self.assertIn("SupplementaryGroups=buzzci-execd", service)
        self.assertNotIn("CapabilityBoundingSet", service)
        self.assertNotIn("User=root", service)
        self.assertIn("ReadWritePaths=/var/lib/buzzci/runner", service)
        self.assertNotIn("executor", service.lower())
        self.assertNotIn("/var/lib/buzzci/runner-output", service + tmpfiles)
        self.assertNotIn("systemctl", (RUNNER_DIR / "install.py").read_text())

    def test_runner_state_has_no_evidence_roots(self) -> None:
        lines = (RUNNER_DIR / "templates/buzzci-runner.tmpfiles").read_text().splitlines()
        self.assertEqual(lines, [
            "d /run/buzzci 0711 root root -",
            "d /var/lib/buzzci/runner 0700 buzzci-runner buzzci-runner -",
        ])

    def test_closed_config_cannot_select_local_execution_or_evidence_persistence(self) -> None:
        config = RENDERER.config_bytes(self.controld_uid, self.controld_gid)
        self.assertEqual(
            json.loads(config),
            {
                "schema_version": 2,
                "controld_uid": self.controld_uid,
                "controld_gid": self.controld_gid,
                "mode": "dormant",
            },
        )
        for forbidden in (b"host", b"executor", b"evidence", b"journal"):
            self.assertNotIn(forbidden, config)

    def test_schemas_are_strict_json(self) -> None:
        for name in (
            "runner-config.schema.json",
            "package-manifest.schema.json",
            "binary-provenance.schema.json",
        ):
            schema = json.loads((RUNNER_DIR / name).read_text())
            self.assertFalse(schema["additionalProperties"])
        runner_schema = json.loads((RUNNER_DIR / "runner-config.schema.json").read_text())
        self.assertIn("mode", runner_schema["properties"])
        self.assertIn("lane_manifest_digest", runner_schema["properties"])
        manifest_schema = json.loads((RUNNER_DIR / "package-manifest.schema.json").read_text())
        self.assertEqual(manifest_schema["properties"]["peer_policy"]["const"], INSTALLER.PEER_POLICY)


if __name__ == "__main__":
    unittest.main()
