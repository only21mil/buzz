from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "install-simple.py"
SPEC = importlib.util.spec_from_file_location("install_simple", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SHIPPED_EXPECTED_IDENTITY = (
    MODULE.EXPECTED_PACKAGE_ID,
    MODULE.EXPECTED_MANIFEST_SHA256,
    MODULE.EXPECTED_PACKAGE_FINGERPRINT,
)


TARGETS = [
    "/usr/local/libexec/buzz/verify-installed-agent",
    "/usr/local/libexec/buzz/buzz-agent-key-handoff",
    "/usr/local/libexec/buzz/export-managed-agent-key",
    "/usr/local/sbin/buzz-install-agent-key",
    "/usr/local/sbin/install-enrollment-map",
    "/etc/sudoers.d/buzz-agent-key-handoff",
    "/etc/systemd/system/buzz-agent@.service",
    "/home/victor/work/buzz-client/Buzz_0.5.8-fixed-050ac722_amd64.AppImage",
    "/home/victor/projects/buzz/scripts/launch_buzz_desktop.sh",
]

MODES = {
    "/etc/sudoers.d/buzz-agent-key-handoff": "0440",
    "/etc/systemd/system/buzz-agent@.service": "0644",
    "/home/victor/projects/buzz/scripts/launch_buzz_desktop.sh": "0700",
}

SOURCES = [
    "system/verify-installed-agent",
    "bin/buzz-agent-key-handoff",
    "bin/export-managed-agent-key",
    "bin/buzz-install-agent-key",
    "system/install-enrollment-map",
    "system/buzz-agent-key-handoff.sudoers",
    "system/buzz-agent@.service",
    "desktop/Buzz_0.5.8_amd64.AppImage",
    "desktop/launch-buzz-desktop",
]


class InstallSimpleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "root"
        self.package = self.base / "package"
        self.root.mkdir()
        self.package.mkdir()
        self.uid = os.getuid()
        self.gid = os.getgid()
        for target in TARGETS:
            (self.root / target.lstrip("/")).parent.mkdir(parents=True, exist_ok=True)
        (self.root / "etc/buzz-agents").mkdir(parents=True, exist_ok=True)
        self.entries: list[dict[str, object]] = []
        for index, target in enumerate(TARGETS):
            source_name = SOURCES[index]
            source = self.package / source_name
            source.parent.mkdir(parents=True, exist_ok=True)
            payload = f"reviewed payload {index}\n".encode()
            source.write_bytes(payload)
            self.entries.append(
                {
                    "owner": "desktop" if target.startswith("/home/") else "static",
                    "role": (
                        "desktop_app"
                        if target.endswith(".AppImage")
                        else "desktop_launcher"
                        if target.endswith("launch_buzz_desktop.sh")
                        else "static"
                    ),
                    "source": source_name,
                    "target": target,
                    "source_mode": "0755" if target.startswith("/home/") else MODES.get(target, "0755"),
                    "status": "A",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "install_mode": MODES.get(target, "0755"),
                }
            )
        self.write_manifest()
        self.bind_fixture_identity()

    def tearDown(self) -> None:
        (
            MODULE.EXPECTED_PACKAGE_ID,
            MODULE.EXPECTED_MANIFEST_SHA256,
            MODULE.EXPECTED_PACKAGE_FINGERPRINT,
        ) = SHIPPED_EXPECTED_IDENTITY
        self.temporary.cleanup()

    def write_manifest(
        self,
        fingerprint: str | None = None,
        package_id: str = "mempool-genesis-simple-test",
    ) -> None:
        launcher_hash = next(
            entry["sha256"]
            for entry in self.entries
            if entry["role"] == "desktop_launcher"
        )
        manifest = {
            "schema": MODULE.SCHEMA,
            "package_id": package_id,
            "entries": self.entries,
            "desktop_launcher_sha256": launcher_hash,
            "desktop_previous_launcher_sha256": "a" * 64,
            "package_fingerprint": fingerprint or MODULE.package_fingerprint(self.entries),
        }
        (self.package / MODULE.MANIFEST_NAME).write_text(json.dumps(manifest))

    def bind_fixture_identity(self) -> None:
        """Bind generated positive fixtures without changing shipped defaults."""
        manifest_path = self.package / MODULE.MANIFEST_NAME
        MODULE.EXPECTED_PACKAGE_ID = "mempool-genesis-simple-test"
        MODULE.EXPECTED_MANIFEST_SHA256 = MODULE.sha256_file(manifest_path)
        MODULE.EXPECTED_PACKAGE_FINGERPRINT = MODULE.package_fingerprint(self.entries)

    def run_install(self, **kwargs: object) -> int:
        output = io.StringIO()
        with redirect_stdout(output):
            result = MODULE.install(
                self.package,
                self.package / MODULE.MANIFEST_NAME,
                root=self.root,
                owner_uid=self.uid,
                owner_gid=self.gid,
                **kwargs,
            )
        self.output = output.getvalue()
        return result

    def installed_path(self, target: str) -> Path:
        return Path(os.path.realpath(self.root / target.lstrip("/")))

    def assert_nothing_installed(self) -> None:
        for target in TARGETS:
            self.assertFalse(os.path.lexists(self.root / target.lstrip("/")), target)
        self.assertFalse((self.root / "etc/buzz-agents/credentials").exists())

    def test_hash_mismatch_is_refused(self) -> None:
        (self.package / str(self.entries[3]["source"])).write_text("changed")
        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: package source hash mismatch", self.output)
        self.assert_nothing_installed()

    def test_fingerprint_mismatch_is_refused(self) -> None:
        self.write_manifest("0" * 64)
        MODULE.EXPECTED_MANIFEST_SHA256 = MODULE.sha256_file(
            self.package / MODULE.MANIFEST_NAME
        )
        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: package fingerprint mismatch", self.output)
        self.assert_nothing_installed()

    def test_self_consistent_non_reviewed_package_is_refused_before_write(self) -> None:
        source = self.package / str(self.entries[0]["source"])
        payload = b"substituted payload\n"
        source.write_bytes(payload)
        self.entries[0]["sha256"] = hashlib.sha256(payload).hexdigest()
        self.write_manifest(package_id="mempool-genesis-substituted")

        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: manifest SHA-256 mismatch", self.output)
        self.assert_nothing_installed()

    def test_non_reviewed_package_id_is_refused(self) -> None:
        self.write_manifest(package_id="mempool-genesis-substituted")
        MODULE.EXPECTED_MANIFEST_SHA256 = MODULE.sha256_file(
            self.package / MODULE.MANIFEST_NAME
        )

        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: package ID mismatch", self.output)
        self.assert_nothing_installed()

    def test_non_reviewed_fingerprint_is_refused(self) -> None:
        source = self.package / str(self.entries[0]["source"])
        payload = b"substituted payload\n"
        source.write_bytes(payload)
        self.entries[0]["sha256"] = hashlib.sha256(payload).hexdigest()
        self.write_manifest()
        MODULE.EXPECTED_MANIFEST_SHA256 = MODULE.sha256_file(
            self.package / MODULE.MANIFEST_NAME
        )

        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: reviewed package fingerprint mismatch", self.output)
        self.assert_nothing_installed()

    def test_preexisting_target_is_refused(self) -> None:
        target = self.root / TARGETS[4].lstrip("/")
        target.write_text("existing")
        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: target already exists", self.output)
        self.assertEqual(target.read_text(), "existing")
        for other in TARGETS:
            if other != TARGETS[4]:
                self.assertFalse(os.path.lexists(self.root / other.lstrip("/")))
        self.assertFalse((self.root / "etc/buzz-agents/credentials").exists())

    def test_user_writable_resolved_parent_is_refused(self) -> None:
        parent = (self.root / TARGETS[0].lstrip("/")).parent
        real_stat = Path.stat

        def user_owned(path: Path, *args: object, **kwargs: object) -> os.stat_result:
            metadata = real_stat(path, *args, **kwargs)
            if path == parent:
                values = list(metadata)
                values[4] = self.uid + 1
                return os.stat_result(values)
            return metadata

        with mock.patch.object(Path, "stat", autospec=True, side_effect=user_owned):
            self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: target parent is not root-owned", self.output)
        self.assert_nothing_installed()

    def test_usrmerge_symlinked_parent_is_accepted(self) -> None:
        real_usr = self.base / "real-usr"
        (real_usr / "local/libexec/buzz").mkdir(parents=True)
        (real_usr / "local/sbin").mkdir(parents=True)
        shutil.rmtree(self.root / "usr")
        (self.root / "usr").symlink_to(real_usr, target_is_directory=True)
        self.assertEqual(self.run_install(), 0)
        self.assertTrue(self.output.endswith("INSTALL OK\n"))
        target = real_usr / "local/libexec/buzz/verify-installed-agent"
        self.assertEqual(target.read_bytes(), b"reviewed payload 0\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)

    def test_happy_path_installs_all_entries(self) -> None:
        self.assertEqual(self.run_install(), 0)
        self.assertTrue(self.output.endswith("INSTALL OK\n"))
        for index, (entry, target) in enumerate(zip(self.entries, TARGETS)):
            installed = self.installed_path(target)
            self.assertEqual(installed.read_bytes(), f"reviewed payload {index}\n".encode())
            self.assertEqual(
                stat.S_IMODE(installed.stat().st_mode), int(str(entry["install_mode"]), 8)
            )
        credential_dir = self.root / "etc/buzz-agents/credentials"
        self.assertTrue(credential_dir.is_dir())
        self.assertEqual(stat.S_IMODE(credential_dir.stat().st_mode), 0o700)

    def test_mid_install_failure_rolls_back_created_files(self) -> None:
        real_install_one = MODULE.install_one
        calls = 0

        def fail_midway(*args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 5:
                raise OSError("injected failure")
            real_install_one(*args, **kwargs)

        with mock.patch.object(MODULE, "install_one", side_effect=fail_midway):
            self.assertEqual(self.run_install(), 1)
        self.assertIn("ROLLBACK CLEANUP removed=", self.output)
        self.assertIn("left=['none']", self.output)
        self.assertTrue(self.output.endswith("INSTALL ROLLED BACK: injected failure\n"))
        self.assert_nothing_installed()


if __name__ == "__main__":
    unittest.main()
