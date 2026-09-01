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

CONTROLD_DIR = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RENDERER = load_module("render_controld_config", CONTROLD_DIR / "render_controld_config.py")
FREEZER = load_module("freeze_package", CONTROLD_DIR / "freeze_package.py")
INSTALLER = load_module("controld_install", CONTROLD_DIR / "install.py")


class SimulatedProcessExit(BaseException):
    pass


class ControldInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.source_root = self.base / "source"
        copied = self.source_root / "deploy/native-ci/controld"
        copied.parent.mkdir(mode=0o700, parents=True)
        shutil.copytree(CONTROLD_DIR, copied, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy2(CONTROLD_DIR.parent / "package_source.py", self.source_root / "deploy/native-ci/package_source.py")
        subprocess.run(["git", "init", "-q", str(self.source_root)], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.name", "Controld test"], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "config", "user.email", "controld@test.invalid"], check=True)
        subprocess.run([
            "git", "-C", str(self.source_root), "add",
            "deploy/native-ci/controld", "deploy/native-ci/package_source.py",
        ], check=True)
        subprocess.run(["git", "-C", str(self.source_root), "commit", "-qm", "fixture"], check=True)
        self.source_commit = FREEZER.git_output(self.source_root, "rev-parse", "HEAD")
        self.binary = self.base / "buzz-ci-controld"
        self.binary.write_bytes(b"test buzz-ci-controld binary\n")
        self.binary.chmod(0o755)
        self.provenance = self.base / "binary-provenance.json"
        self.provenance.write_text(json.dumps({
            "schema": "buzz-ci-binary-provenance-v1",
            "binary": "buzz-ci-controld",
            "source_commit": self.source_commit,
            "profile": "release",
            "sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
        }, sort_keys=True, separators=(",", ":")) + "\n")
        self.provenance.chmod(0o600)
        self.package = self.base / "package"
        self.controld_uid = os.geteuid()
        self.controld_gid = os.getegid()
        if self.controld_uid == 0 or self.controld_gid == 0:
            self.skipTest("fake-root tests require a non-root invoking identity")

    def freeze(self, source_root: Path | None = None, package: Path | None = None) -> dict[str, object]:
        return FREEZER.freeze_package(
            source_root or self.source_root, self.source_commit, self.binary, self.provenance,
            package or self.package, self.controld_uid, self.controld_gid,
        )

    def replace_frozen_config(
        self, package: Path, value: dict[str, object] | bytes,
    ) -> None:
        manifest_path = package / "package-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        entry = next(item for item in manifest["entries"] if item["role"] == "config")
        payload = value if isinstance(value, bytes) else INSTALLER.canonical_json(value)
        asset = package / entry["source"]
        asset.chmod(0o600)
        asset.write_bytes(payload)
        asset.chmod(0o400)
        entry["sha256"] = hashlib.sha256(payload).hexdigest()
        del manifest["package_digest"]
        manifest["package_digest"] = hashlib.sha256(
            INSTALLER.canonical_json(manifest)
        ).hexdigest()
        manifest_path.write_bytes(INSTALLER.canonical_json(manifest))
        manifest_path.chmod(0o600)

    def make_root(self, name: str = "root") -> Path:
        root = self.base / name
        root.mkdir(mode=0o700)
        for relative in ("etc/systemd/system", "usr/libexec", "usr/lib/tmpfiles.d", "usr/share/doc", "var/lib"):
            current = root
            for component in Path(relative).parts:
                current /= component
                current.mkdir(mode=0o755, exist_ok=True)
        (root / "etc/passwd").write_text(
            f"buzzci-controld:x:{self.controld_uid}:{self.controld_gid}:controller:/nonexistent:/usr/sbin/nologin\n"
        )
        (root / "etc/group").write_text(f"buzzci-controld:x:{self.controld_gid}:\n")
        (root / "etc/passwd").chmod(0o644)
        (root / "etc/group").chmod(0o644)
        return root

    def restarted_installer(self, suffix: str):
        return load_module(f"controld_install_restart_{suffix}", CONTROLD_DIR / "install.py")

    def transaction(self, installer, root: Path, backup_id: str) -> Path:
        return installer.backup_root_path(root, installer.DEFAULT_BACKUP_ROOT) / backup_id

    def tree_digest(self, root: Path) -> str:
        rows: list[object] = []

        def metadata_row(relative: str, metadata: os.stat_result, payload_digest: str | None) -> list[object]:
            return [
                relative,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_atime_ns,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
                payload_digest,
            ]

        def visit(path: Path, relative: str) -> None:
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NOATIME", 0)
                fd = os.open(path, flags)
                try:
                    names = sorted(os.listdir(fd), key=lambda name: name.encode())
                    metadata = os.fstat(fd)
                finally:
                    os.close(fd)
                rows.append(metadata_row(relative, metadata, None))
                for name in names:
                    visit(path / name, f"{relative}/{name}" if relative else name)
            elif stat.S_ISREG(metadata.st_mode):
                payload, metadata = INSTALLER.read_fd(path)
                rows.append(metadata_row(relative, metadata, hashlib.sha256(payload).hexdigest()))
            elif stat.S_ISLNK(metadata.st_mode):
                rows.append(metadata_row(relative, metadata, os.readlink(path)))
            else:
                rows.append(metadata_row(relative, metadata, None))

        visit(root, "")
        return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()

    def legacy_transaction(self, installer, package: Path, root: Path) -> tuple[dict[str, object], Path]:
        installed = installer.install(package, root, installer.DEFAULT_BACKUP_ROOT)
        transaction = self.transaction(installer, root, str(installed["backup_id"]))
        (transaction / "state.json").unlink()
        self.assertFalse((transaction / "state.json").exists())
        return installed, transaction

    def test_renderer_is_canonical_capacity_zero_absolute_and_nofollow(self) -> None:
        output = self.base / "controld-v2.json"
        RENDERER.render(output)
        self.assertEqual(
            output.read_bytes(),
            b'{"acceptance_binding":"/var/lib/buzzci/activation-controller/controld-acceptance-v2.json","capacity":0,"schema_version":2,"store_root":"/var/lib/buzzci/controld"}\n',
        )
        self.assertEqual(
            hashlib.sha256(output.read_bytes()).hexdigest(),
            "7377f5ff0afc5e449e5b98cf02f99509601f2b2b5647d4159879eb556801534f",
        )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        RENDERER.check(output, expected_uid=self.controld_uid)
        with self.assertRaisesRegex(ValueError, "exact provider field set"):
            RENDERER.config_bytes(capacity=1)
        with self.assertRaisesRegex(ValueError, "absolute normalized"):
            RENDERER.config_bytes("relative/store")
        with self.assertRaisesRegex(ValueError, "fixed receipt"):
            RENDERER.config_bytes(acceptance_binding=None)
        with self.assertRaisesRegex(ValueError, "fixed receipt"):
            RENDERER.config_bytes(acceptance_binding="/var/lib/buzzci/controld/acceptance.json")
        linked = self.base / "linked.json"
        linked.symlink_to(output)
        with self.assertRaises(OSError):
            RENDERER.check(linked)

    def test_renderer_accepts_only_complete_capacity_one_bindings(self) -> None:
        digest = "11" * 32
        active = {
            "relay_url": "wss://relay.example.test",
            "relay_http_origin": "https://relay.example.test",
            "channel_id": "123e4567-e89b-12d3-a456-426614174099",
            "poll_interval_millis": 100,
            "runner_socket": RENDERER.RUNNER_SOCKET,
            "runner_uid": 62001,
            "runner_gid": 62001,
            "runner_connect_timeout_millis": 500,
            "runner_io_timeout_millis": 1000,
            "runner_transport_attempts": 2,
            "lane_manifest_digest": digest,
            "lane_epoch": 1,
            "audience_digest": digest,
            "isolation_profile_digest": digest,
            "workflow_id": "native-ci",
            "workflow_digest": digest,
            "jobs": [{
                "job_id": "test", "name": "test", "required": True,
                "skip_policy": "forbid", "selected_job_instance": "test", "also_reruns": [],
                "artifacts": [{
                    "artifact_id": "result", "name": "result.json",
                    "media_type": "application/json", "relative_name": "result.json",
                    "max_bytes": 32768,
                }],
            }],
            "keyholder_socket": RENDERER.KEYHOLDER_SOCKET,
            "keyholder_uid": 62003,
            "keyholder_gid": 62003,
            "keyholder_selectors": {
                name: {"public_key": digest, "generation": index}
                for index, name in enumerate(("ci_event", "nip98", "manifest"), start=1)
            },
            "keyholder_timeout_millis": 500,
            "keyholder_transport_attempts": 2,
        }
        encoded = RENDERER.config_bytes(
            capacity=1,
            active=active,
            acceptance_binding=RENDERER.ACCEPTANCE_BINDING,
        )
        self.assertEqual(json.loads(encoded), {
            "schema_version": 2,
            "capacity": 1,
            "store_root": RENDERER.STORE_ROOT,
            "acceptance_binding": RENDERER.ACCEPTANCE_BINDING,
            **active,
        })
        staged = RENDERER.config_bytes(acceptance_binding=RENDERER.ACCEPTANCE_BINDING)
        self.assertEqual(json.loads(staged)["acceptance_binding"], RENDERER.ACCEPTANCE_BINDING)
        self.assertNotIn(b"scenario_sha256", encoded)
        self.assertNotIn(b"activation_package_digest", encoded)
        cyclic = dict(active)
        cyclic["acceptance"] = {"scenario_sha256": digest}
        with self.assertRaisesRegex(ValueError, "exact provider field set"):
            RENDERER.config_bytes(
                capacity=1,
                active=cyclic,
                acceptance_binding=RENDERER.ACCEPTANCE_BINDING,
            )
        partial = dict(active)
        del partial["lane_manifest_digest"]
        with self.assertRaisesRegex(ValueError, "exact provider field set"):
            RENDERER.config_bytes(
                capacity=1,
                active=partial,
                acceptance_binding=RENDERER.ACCEPTANCE_BINDING,
            )

    def test_freeze_binds_source_binary_manifest_and_dormant_contract(self) -> None:
        manifest = self.freeze()
        parsed, entries = INSTALLER.parse_manifest(self.package, self.base)
        self.assertEqual(parsed["source_commit"], self.source_commit)
        self.assertEqual(parsed["default_state"], INSTALLER.DEFAULT_STATE)
        self.assertEqual(parsed["daemon_contract"], INSTALLER.DAEMON_CONTRACT)
        self.assertEqual(parsed["package_digest"], manifest["package_digest"])
        self.assertEqual({entry.role for entry in entries}, set(INSTALLER.EXPECTED_TARGETS))
        binary = next(entry for entry in entries if entry.role == "binary")
        self.assertEqual(binary.sha256, hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertNotIn("socket", {entry.role for entry in entries})
        self.assertEqual(stat.S_IMODE(self.package.lstat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.package / "assets").lstat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.package / "package-manifest.json").lstat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.package / "binary-provenance.json").lstat().st_mode), 0o600)
        for entry in entries:
            self.assertEqual(
                stat.S_IMODE((self.package / entry.source).lstat().st_mode),
                entry.source_mode,
            )

    def test_installer_rejects_missing_or_mismatched_acceptance_binding(self) -> None:
        cases = {
            "missing": {
                "schema_version": 2,
                "capacity": 0,
                "store_root": RENDERER.STORE_ROOT,
            },
            "mismatched": {
                "schema_version": 2,
                "capacity": 0,
                "store_root": RENDERER.STORE_ROOT,
                "acceptance_binding": "/var/lib/buzzci/controld/acceptance.json",
            },
            "tampered": INSTALLER.canonical_json(INSTALLER.CONTROLD_CONFIG)[:-1] + b" \n",
        }
        for label, value in cases.items():
            with self.subTest(label=label):
                package = self.base / f"package-{label}"
                self.freeze(package=package)
                self.replace_frozen_config(package, value)
                with self.assertRaisesRegex(ValueError, "canonical acceptance-bound"):
                    INSTALLER.parse_manifest(package, self.base)

    def test_freeze_from_fresh_umask_0077_checkout_needs_no_source_chmod(self) -> None:
        checkout = self.base / "private-checkout"
        prior_umask = os.umask(0o077)
        try:
            subprocess.run(["git", "clone", "-q", str(self.source_root), str(checkout)], check=True)
        finally:
            os.umask(prior_umask)
        self.assertEqual(
            stat.S_IMODE((checkout / "deploy/native-ci/controld/README.md").lstat().st_mode),
            0o600,
        )
        self.assertEqual(
            stat.S_IMODE((checkout / "deploy/native-ci/controld/freeze_package.py").lstat().st_mode),
            0o700,
        )
        private_package = self.base / "private-package"
        manifest = self.freeze(checkout, private_package)
        self.assertEqual(manifest["source_commit"], self.source_commit)
        self.assertEqual(stat.S_IMODE(private_package.lstat().st_mode), 0o700)

    def test_freezer_rejects_unsafe_mode_and_link_drift(self) -> None:
        unsafe = self.base / "unsafe-checkout"
        linked = self.base / "linked-checkout"
        subprocess.run(["git", "clone", "-q", str(self.source_root), str(unsafe)], check=True)
        subprocess.run(["git", "clone", "-q", str(self.source_root), str(linked)], check=True)
        (unsafe / "deploy/native-ci/controld/README.md").chmod(0o664)
        with self.assertRaisesRegex(ValueError, "unsafe permissions"):
            self.freeze(unsafe, self.base / "unsafe-package")
        source = linked / "deploy/native-ci/controld/README.md"
        replacement = linked / "README-replacement"
        replacement.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(replacement)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            self.freeze(linked, self.base / "linked-package")

    def test_package_refuses_symlink_and_provenance_drift(self) -> None:
        self.freeze()
        binary_asset = self.package / "assets/buzz-ci-controld"
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

    def test_check_is_read_only_and_reports_machine_state(self) -> None:
        self.freeze()
        root = self.make_root()

        def snapshot() -> dict[str, tuple[int, bytes | None]]:
            return {
                str(path.relative_to(root)): (
                    path.lstat().st_mode,
                    path.read_bytes() if stat.S_ISREG(path.lstat().st_mode) else None,
                )
                for path in sorted(root.rglob("*"))
            }

        before = snapshot()
        checked = INSTALLER.check(self.package, root)
        self.assertEqual(snapshot(), before)
        self.assertEqual(checked["status"], "checked")
        self.assertEqual(checked["daemon_contract"], INSTALLER.DAEMON_CONTRACT)
        for key, value in INSTALLER.DEFAULT_STATE.items():
            self.assertEqual(checked[key], value)
        self.assertEqual(set(checked["changed_targets"]), set(INSTALLER.EXPECTED_TARGETS.values()))

    def test_host_identity_must_match_exactly(self) -> None:
        self.freeze()
        root = self.make_root()
        (root / "etc/passwd").write_text("buzzci-controld:x:42:42:wrong:/nonexistent:/usr/sbin/nologin\n")
        with self.assertRaisesRegex(ValueError, "does not match"):
            INSTALLER.check(self.package, root)

    def test_dry_run_install_idempotence_and_rollback(self) -> None:
        self.freeze()
        root = self.make_root()
        dry_run = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, dry_run=True)
        self.assertEqual(dry_run["status"], "dry_run")
        self.assertFalse((root / "etc/buzzci").exists())
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(installed["status"], "installed")
        for target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertTrue(INSTALLER.rooted(root, target).is_file())
        config = root / "etc/buzzci/controld-v2.json"
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        self.assertEqual(json.loads(config.read_bytes()), INSTALLER.CONTROLD_CONFIG)
        self.assertFalse(
            (root / INSTALLER.ACCEPTANCE_BINDING.lstrip("/")).exists(),
            "standalone dormant install must not synthesize an activation receipt",
        )
        unchanged = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(unchanged["status"], "unchanged")
        rolled_back = INSTALLER.rollback(
            self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, str(installed["backup_id"]),
        )
        self.assertEqual(rolled_back["status"], "rolled_back")
        for target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertFalse(INSTALLER.rooted(root, target).exists())

    def test_install_resumes_after_restart_at_every_durable_phase_boundary(self) -> None:
        boundaries = (
            ("state", "preparing"),
            ("state", "install_prepared"),
            ("state", "installing"),
            ("receipt", "installed"),
            ("state", "installed"),
        )
        for index, (kind, phase) in enumerate(boundaries):
            with self.subTest(kind=kind, phase=phase):
                package = self.base / f"phase-package-{index}"
                self.freeze(package=package)
                root = self.make_root(f"phase-root-{index}")
                installer = self.restarted_installer(f"install_phase_{index}_a")
                original = installer.atomic_write
                fired = False

                def crash_after_write(target, payload, mode_value, uid, gid):
                    nonlocal fired
                    original(target, payload, mode_value, uid, gid)
                    if fired or target.name != ("receipt.json" if kind == "receipt" else "state.json"):
                        return
                    document = json.loads(payload)
                    marker = document.get("state") if kind == "receipt" else document.get("phase")
                    if marker == phase:
                        fired = True
                        raise SimulatedProcessExit(f"restart after {kind} {phase}")

                with mock.patch.object(installer, "atomic_write", side_effect=crash_after_write):
                    with self.assertRaises(SimulatedProcessExit):
                        installer.install(package, root, installer.DEFAULT_BACKUP_ROOT)
                self.assertTrue(fired)

                restarted = self.restarted_installer(f"install_phase_{index}_b")
                retried = restarted.install(package, root, restarted.DEFAULT_BACKUP_ROOT)
                expected_status = "unchanged" if kind == "state" and phase == "installed" else "installed"
                self.assertEqual(retried["status"], expected_status)
                for target in restarted.EXPECTED_TARGETS.values():
                    self.assertTrue(restarted.rooted(root, target).is_file())

    def test_install_resumes_mixed_candidate_and_absent_baseline(self) -> None:
        self.freeze()
        root = self.make_root()
        installer = self.restarted_installer("mixed_install_a")
        original = installer.atomic_write
        fired = False

        def crash_after_first_target(target, payload, mode_value, uid, gid):
            nonlocal fired
            original(target, payload, mode_value, uid, gid)
            if not fired and str(target).startswith(str(root)) and str(target).removeprefix(str(root)) in installer.EXPECTED_TARGETS.values():
                fired = True
                raise SimulatedProcessExit("restart after first target publication")

        with mock.patch.object(installer, "atomic_write", side_effect=crash_after_first_target):
            with self.assertRaises(SimulatedProcessExit):
                installer.install(self.package, root, installer.DEFAULT_BACKUP_ROOT)
        self.assertTrue(fired)
        present = [installer.rooted(root, target).exists() for target in installer.EXPECTED_TARGETS.values()]
        self.assertIn(True, present)
        self.assertIn(False, present)

        restarted = self.restarted_installer("mixed_install_b")
        retried = restarted.install(self.package, root, restarted.DEFAULT_BACKUP_ROOT)
        self.assertEqual(retried["status"], "installed")
        self.assertEqual(
            restarted.install(self.package, root, restarted.DEFAULT_BACKUP_ROOT)["status"],
            "unchanged",
        )

    def test_rollback_resumes_after_restart_at_every_durable_phase_boundary(self) -> None:
        boundaries = ("rolling_back", "first_target", "rolled_back_receipt", "rolled_back_state")
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                package = self.base / f"rollback-package-{index}"
                self.freeze(package=package)
                root = self.make_root(f"rollback-root-{index}")
                installer = self.restarted_installer(f"rollback_phase_{index}_a")
                installed = installer.install(package, root, installer.DEFAULT_BACKUP_ROOT)
                fired = False

                if boundary == "first_target":
                    original_unlink = installer.unlink_file

                    def crash_after_unlink(path):
                        nonlocal fired
                        original_unlink(path)
                        if not fired:
                            fired = True
                            raise SimulatedProcessExit("restart after first target restoration")

                    patcher = mock.patch.object(installer, "unlink_file", side_effect=crash_after_unlink)
                else:
                    original_write = installer.atomic_write

                    def crash_after_marker(target, payload, mode_value, uid, gid):
                        nonlocal fired
                        original_write(target, payload, mode_value, uid, gid)
                        if fired:
                            return
                        document = json.loads(payload) if target.name in {"state.json", "receipt.json"} else {}
                        matches = (
                            boundary == "rolling_back" and target.name == "state.json" and document.get("phase") == "rolling_back"
                        ) or (
                            boundary == "rolled_back_receipt" and target.name == "receipt.json" and document.get("state") == "rolled_back"
                        ) or (
                            boundary == "rolled_back_state" and target.name == "state.json" and document.get("phase") == "rolled_back"
                        )
                        if matches:
                            fired = True
                            raise SimulatedProcessExit(f"restart after {boundary}")

                    patcher = mock.patch.object(installer, "atomic_write", side_effect=crash_after_marker)

                with patcher:
                    with self.assertRaises(SimulatedProcessExit):
                        installer.rollback(
                            package,
                            root,
                            installer.DEFAULT_BACKUP_ROOT,
                            str(installed["backup_id"]),
                        )
                self.assertTrue(fired)

                restarted = self.restarted_installer(f"rollback_phase_{index}_b")
                retried = restarted.rollback(
                    package,
                    root,
                    restarted.DEFAULT_BACKUP_ROOT,
                    str(installed["backup_id"]),
                )
                self.assertEqual(retried["status"], "rolled_back")
                self.assertEqual(
                    restarted.rollback(
                        package,
                        root,
                        restarted.DEFAULT_BACKUP_ROOT,
                        str(installed["backup_id"]),
                    ),
                    retried,
                )
                for target in restarted.EXPECTED_TARGETS.values():
                    self.assertFalse(restarted.rooted(root, target).exists())

    def test_rollback_resumes_mixed_present_and_candidate_targets(self) -> None:
        self.freeze()
        root = self.make_root()
        prior = root / "usr/lib/tmpfiles.d/buzzci-controld.conf"
        prior.write_text("prior\n")
        prior.chmod(0o640)
        installer = self.restarted_installer("mixed_rollback_a")
        installed = installer.install(self.package, root, installer.DEFAULT_BACKUP_ROOT)
        original = installer.atomic_write
        fired = False

        def crash_after_prior_restore(target, payload, mode_value, uid, gid):
            nonlocal fired
            original(target, payload, mode_value, uid, gid)
            if not fired and target == prior and payload == b"prior\n":
                fired = True
                raise SimulatedProcessExit("restart after present baseline restoration")

        with mock.patch.object(installer, "atomic_write", side_effect=crash_after_prior_restore):
            with self.assertRaises(SimulatedProcessExit):
                installer.rollback(
                    self.package,
                    root,
                    installer.DEFAULT_BACKUP_ROOT,
                    str(installed["backup_id"]),
                )
        self.assertTrue(fired)
        restarted = self.restarted_installer("mixed_rollback_b")
        restarted.rollback(
            self.package,
            root,
            restarted.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )
        self.assertEqual(prior.read_bytes(), b"prior\n")
        self.assertEqual(stat.S_IMODE(prior.stat().st_mode), 0o640)

    def test_legacy_rollback_dry_run_preserves_complete_trees_and_timestamps(self) -> None:
        self.freeze()
        root = self.make_root()
        installed, transaction = self.legacy_transaction(INSTALLER, self.package, root)
        before = (self.tree_digest(self.package), self.tree_digest(root))

        result = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
            dry_run=True,
        )

        self.assertEqual(result["status"], "rollback_dry_run")
        self.assertEqual(result["restored_targets"], installed["changed_targets"])
        self.assertEqual((self.tree_digest(self.package), self.tree_digest(root)), before)
        self.assertFalse((transaction / "state.json").exists())
        self.assertEqual(json.loads((transaction / "receipt.json").read_text())["state"], "installed")

    def test_current_install_and_rollback_dry_runs_preserve_complete_trees(self) -> None:
        self.freeze()
        root = self.make_root()
        before_install_plan = (self.tree_digest(self.package), self.tree_digest(root))
        install_plan = INSTALLER.install(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            dry_run=True,
        )
        self.assertEqual(install_plan["status"], "dry_run")
        self.assertEqual((self.tree_digest(self.package), self.tree_digest(root)), before_install_plan)

        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        before_rollback_plan = (self.tree_digest(self.package), self.tree_digest(root))
        rollback_plan = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
            dry_run=True,
        )
        self.assertEqual(rollback_plan["status"], "rollback_dry_run")
        self.assertEqual((self.tree_digest(self.package), self.tree_digest(root)), before_rollback_plan)

    def test_tampered_legacy_dry_run_refuses_without_tree_mutation(self) -> None:
        self.freeze()
        root = self.make_root()
        installed, transaction = self.legacy_transaction(INSTALLER, self.package, root)
        receipt_path = transaction / "receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["inventory"][0]["target"] = receipt["inventory"][1]["target"]
        receipt_path.write_bytes(INSTALLER.canonical_json(receipt))
        receipt_path.chmod(0o600)
        before = (self.tree_digest(self.package), self.tree_digest(root))

        with self.assertRaisesRegex(ValueError, "inventory entry"):
            INSTALLER.rollback(
                self.package,
                root,
                INSTALLER.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
                dry_run=True,
            )

        self.assertEqual((self.tree_digest(self.package), self.tree_digest(root)), before)
        self.assertFalse((transaction / "state.json").exists())

    def test_real_legacy_rollback_persists_validated_migration(self) -> None:
        self.freeze()
        root = self.make_root()
        prior = root / "usr/lib/tmpfiles.d/buzzci-controld.conf"
        prior.write_text("legacy prior\n")
        prior.chmod(0o640)
        installed, transaction = self.legacy_transaction(INSTALLER, self.package, root)

        result = INSTALLER.rollback(
            self.package,
            root,
            INSTALLER.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )

        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(json.loads((transaction / "state.json").read_text())["phase"], "rolled_back")
        self.assertEqual(json.loads((transaction / "receipt.json").read_text())["state"], "rolled_back")
        self.assertEqual(prior.read_bytes(), b"legacy prior\n")
        self.assertEqual(stat.S_IMODE(prior.stat().st_mode), 0o640)

    def test_real_legacy_migration_interruption_retries_exactly(self) -> None:
        self.freeze()
        root = self.make_root()
        installed, transaction = self.legacy_transaction(INSTALLER, self.package, root)
        installer = self.restarted_installer("legacy_migration_a")
        original = installer.write_transaction_state
        fired = False

        def crash_after_migration(path, state, install_root):
            nonlocal fired
            original(path, state, install_root)
            if not fired and state["phase"] == "installed":
                fired = True
                raise SimulatedProcessExit("restart after validated legacy migration")

        with mock.patch.object(installer, "write_transaction_state", side_effect=crash_after_migration):
            with self.assertRaises(SimulatedProcessExit):
                installer.rollback(
                    self.package,
                    root,
                    installer.DEFAULT_BACKUP_ROOT,
                    str(installed["backup_id"]),
                )
        self.assertTrue(fired)
        self.assertEqual(json.loads((transaction / "state.json").read_text())["phase"], "installed")
        self.assertEqual(json.loads((transaction / "receipt.json").read_text())["state"], "installed")

        restarted = self.restarted_installer("legacy_migration_b")
        result = restarted.rollback(
            self.package,
            root,
            restarted.DEFAULT_BACKUP_ROOT,
            str(installed["backup_id"]),
        )
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(
            restarted.rollback(
                self.package,
                root,
                restarted.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
            ),
            result,
        )

    def test_rollback_refuses_receipt_state_and_package_mismatch(self) -> None:
        self.freeze()
        root = self.make_root()
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        transaction = self.transaction(INSTALLER, root, str(installed["backup_id"]))
        receipt_path = transaction / "receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["state"] = "rolled_back"
        receipt_path.write_bytes(INSTALLER.canonical_json(receipt))
        receipt_path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "receipt/state mismatch"):
            INSTALLER.rollback(
                self.package,
                root,
                INSTALLER.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
            )

        receipt["state"] = "installed"
        receipt_path.write_bytes(INSTALLER.canonical_json(receipt))
        receipt_path.chmod(0o600)
        state_path = transaction / "state.json"
        state = json.loads(state_path.read_text())
        state["package_digest"] = "0" * 64
        state_path.write_bytes(INSTALLER.canonical_json(state))
        state_path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "package or phase binding mismatch"):
            INSTALLER.rollback(
                self.package,
                root,
                INSTALLER.DEFAULT_BACKUP_ROOT,
                str(installed["backup_id"]),
            )

    def test_rollback_refuses_installed_target_drift(self) -> None:
        self.freeze()
        root = self.make_root()
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        service = root / "etc/systemd/system/buzz-ci-controld.service"
        service.write_text("drift\n")
        service.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "drift blocks rollback"):
            INSTALLER.rollback(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, str(installed["backup_id"]))

    def test_rollback_preflights_prior_backup_digest(self) -> None:
        self.freeze()
        root = self.make_root()
        prior = root / "usr/lib/tmpfiles.d/buzzci-controld.conf"
        prior.write_text("prior\n")
        prior.chmod(0o644)
        installed = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        transaction = INSTALLER.backup_root_path(root, INSTALLER.DEFAULT_BACKUP_ROOT) / str(installed["backup_id"])
        receipt = json.loads((transaction / "receipt.json").read_text())
        record = next(item for item in receipt["inventory"] if item["target"] == "/usr/lib/tmpfiles.d/buzzci-controld.conf")
        backup = transaction / str(record["backup"])
        backup.write_text("corrupt\n")
        backup.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "backup file digest drift"):
            INSTALLER.rollback(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, str(installed["backup_id"]))
        self.assertEqual((root / "etc/buzzci/controld-v2.json").read_bytes(), RENDERER.config_bytes())

    def test_templates_support_bounded_activation_while_remaining_disabled(self) -> None:
        service = (CONTROLD_DIR / "templates/buzz-ci-controld.service").read_text()
        acceptance = (CONTROLD_DIR / "templates/buzz-ci-controld-acceptance.socket").read_text()
        tmpfiles = (CONTROLD_DIR / "templates/buzzci-controld.tmpfiles").read_text()
        self.assertNotIn("[Install]", service)
        self.assertNotIn("[Install]", acceptance)
        self.assertIn("PrivateNetwork=no", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", service)
        self.assertIn("Restart=on-failure", service)
        self.assertNotIn("ListenStream", service)
        self.assertIn("ListenStream=/run/buzzci/controld-acceptance.sock", acceptance)
        self.assertIn("FileDescriptorName=buzz-ci-controld-acceptance", acceptance)
        self.assertIn("SocketGroup=buzzci-ctl", acceptance)
        self.assertIn("SocketMode=0620", acceptance)
        self.assertIn("DirectoryMode=0711", acceptance)
        self.assertNotIn("/run/buzzci/execd.sock", service + acceptance + tmpfiles)
        self.assertEqual(
            [line for line in tmpfiles.splitlines() if line and not line.startswith("#")],
            ["d /var/lib/buzzci/controld 0700 buzzci-controld buzzci-controld -"],
        )

    def test_json_schemas_are_strict_and_parseable(self) -> None:
        for name in ("binary-provenance.schema.json", "package-manifest.schema.json"):
            schema = json.loads((CONTROLD_DIR / name).read_text())
            self.assertFalse(schema["additionalProperties"])
        package_schema = json.loads((CONTROLD_DIR / "package-manifest.schema.json").read_text())
        self.assertEqual(
            package_schema["properties"]["daemon_contract"]["const"]["acceptance_binding"],
            RENDERER.ACCEPTANCE_BINDING,
        )
        config_schema = json.loads((CONTROLD_DIR / "controld-config.schema.json").read_text())
        self.assertEqual(config_schema["$defs"]["dormant"]["properties"]["capacity"]["const"], 0)
        self.assertEqual(config_schema["$defs"]["active"]["properties"]["capacity"]["const"], 1)
        self.assertIn("acceptance_binding", config_schema["$defs"]["dormant"]["required"])
        self.assertFalse(config_schema["$defs"]["dormant"]["additionalProperties"])
        self.assertFalse(config_schema["$defs"]["active"]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
