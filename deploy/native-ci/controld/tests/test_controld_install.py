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

    def test_renderer_is_canonical_capacity_zero_absolute_and_nofollow(self) -> None:
        output = self.base / "controld-v1.json"
        RENDERER.render(output)
        self.assertEqual(output.read_bytes(), b'{"capacity":0,"schema_version":1,"store_root":"/var/lib/buzzci/controld"}\n')
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        RENDERER.check(output, expected_uid=self.controld_uid)
        with self.assertRaisesRegex(ValueError, "exact provider field set"):
            RENDERER.config_bytes(capacity=1)
        with self.assertRaisesRegex(ValueError, "absolute normalized"):
            RENDERER.config_bytes("relative/store")
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
        encoded = RENDERER.config_bytes(capacity=1, active=active)
        self.assertEqual(json.loads(encoded), {"schema_version": 1, "capacity": 1, "store_root": RENDERER.STORE_ROOT, **active})
        partial = dict(active)
        del partial["lane_manifest_digest"]
        with self.assertRaisesRegex(ValueError, "exact provider field set"):
            RENDERER.config_bytes(capacity=1, active=partial)

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
        config = root / "etc/buzzci/controld-v1.json"
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        unchanged = INSTALLER.install(self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT)
        self.assertEqual(unchanged["status"], "unchanged")
        rolled_back = INSTALLER.rollback(
            self.package, root, INSTALLER.DEFAULT_BACKUP_ROOT, str(installed["backup_id"]),
        )
        self.assertEqual(rolled_back["status"], "rolled_back")
        for target in INSTALLER.EXPECTED_TARGETS.values():
            self.assertFalse(INSTALLER.rooted(root, target).exists())

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
        self.assertEqual((root / "etc/buzzci/controld-v1.json").read_bytes(), RENDERER.config_bytes())

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
        self.assertNotIn("/run/buzzci/execd.sock", service + acceptance + tmpfiles)
        self.assertEqual(
            [line for line in tmpfiles.splitlines() if line and not line.startswith("#")],
            ["d /var/lib/buzzci/controld 0700 buzzci-controld buzzci-controld -"],
        )

    def test_json_schemas_are_strict_and_parseable(self) -> None:
        for name in ("binary-provenance.schema.json", "package-manifest.schema.json"):
            schema = json.loads((CONTROLD_DIR / name).read_text())
            self.assertFalse(schema["additionalProperties"])
        config_schema = json.loads((CONTROLD_DIR / "controld-config.schema.json").read_text())
        self.assertEqual(config_schema["$defs"]["dormant"]["properties"]["capacity"]["const"], 0)
        self.assertEqual(config_schema["$defs"]["active"]["properties"]["capacity"]["const"], 1)
        self.assertFalse(config_schema["$defs"]["dormant"]["additionalProperties"])
        self.assertFalse(config_schema["$defs"]["active"]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
