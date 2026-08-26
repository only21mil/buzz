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
    "/home/victor/work/buzz-client/Buzz_0.5.8-mempool-genesis_amd64.AppImage",
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
        self.package.mkdir(mode=0o700)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.desktop_uid = 4242 if self.uid != 4242 else 4243
        self.desktop_gid = 4342 if self.gid != 4342 else 4343
        for target in TARGETS:
            (self.root / target.lstrip("/")).parent.mkdir(parents=True, exist_ok=True)
        (self.root / "etc/buzz-agents").mkdir(parents=True, exist_ok=True)
        self.parent_owners = {
            Path(os.path.realpath((self.root / target.lstrip("/")).parent)): (
                (self.desktop_uid, self.desktop_gid)
                if target.startswith("/home/")
                else (0, 0)
            )
            for target in TARGETS
        }
        self.parent_owners[Path(os.path.realpath(self.root / "etc/buzz-agents"))] = (
            0,
            0,
        )
        self.entries: list[dict[str, object]] = []
        for index, target in enumerate(TARGETS):
            source_name = SOURCES[index]
            source = self.package / source_name
            source.parent.mkdir(parents=True, exist_ok=True)
            payload = f"reviewed payload {index}\n".encode()
            source_mode = (
                "0755" if target.startswith("/home/") else MODES.get(target, "0755")
            )
            source.write_bytes(payload)
            source.chmod(int(source_mode, 8))
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
                    "source_mode": source_mode,
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
        manifest_path = self.package / MODULE.MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest))
        manifest_path.chmod(0o600)

    def bind_fixture_identity(self) -> None:
        """Bind generated positive fixtures without changing shipped defaults."""
        manifest_path = self.package / MODULE.MANIFEST_NAME
        MODULE.EXPECTED_PACKAGE_ID = "mempool-genesis-simple-test"
        MODULE.EXPECTED_MANIFEST_SHA256 = MODULE.sha256_file(manifest_path)
        MODULE.EXPECTED_PACKAGE_FINGERPRINT = MODULE.package_fingerprint(self.entries)

    def run_install(self, **kwargs: object) -> int:
        output = io.StringIO()
        real_stat = Path.stat

        def fixture_fchown(_fd: int, uid: int, _gid: int) -> None:
            if uid == 0 and os.getuid() != 0:
                raise PermissionError("non-root fixture cannot chown to root")

        def fixture_stat(
            path: Path, *args: object, **stat_kwargs: object
        ) -> os.stat_result:
            metadata = real_stat(path, *args, **stat_kwargs)
            owner = self.parent_owners.get(path)
            if owner is not None:
                values = list(metadata)
                values[4], values[5] = owner
                return os.stat_result(values)
            return metadata

        with (
            redirect_stdout(output),
            mock.patch.object(Path, "stat", autospec=True, side_effect=fixture_stat),
            mock.patch.object(os, "fchown", side_effect=fixture_fchown) as fchown,
            mock.patch.object(os, "chown") as chown,
            mock.patch.dict(os.environ, {"MG_INSTALL_TEST": "1"}),
        ):
            result = MODULE.install(
                self.package,
                self.package / MODULE.MANIFEST_NAME,
                root=self.root,
                **kwargs,
            )
        self.output = output.getvalue()
        self.fchown_calls = fchown.call_args_list
        self.chown_calls = chown.call_args_list
        return result

    def run_check(self) -> int:
        output = io.StringIO()
        real_stat = Path.stat

        def fixture_stat(
            path: Path, *args: object, **stat_kwargs: object
        ) -> os.stat_result:
            metadata = real_stat(path, *args, **stat_kwargs)
            owner = self.parent_owners.get(path)
            if owner is not None:
                values = list(metadata)
                values[4], values[5] = owner
                return os.stat_result(values)
            return metadata

        with (
            redirect_stdout(output),
            mock.patch.object(Path, "stat", autospec=True, side_effect=fixture_stat),
        ):
            result = MODULE.check(
                self.package,
                self.package / MODULE.MANIFEST_NAME,
                root=self.root,
            )
        self.output = output.getvalue()
        return result

    def installed_path(self, target: str) -> Path:
        return Path(os.path.realpath(self.root / target.lstrip("/")))

    def assert_nothing_installed(self) -> None:
        for target in TARGETS:
            self.assertFalse(os.path.lexists(self.root / target.lstrip("/")), target)
        self.assertFalse((self.root / "etc/buzz-agents/credentials").exists())

    def test_check_good_fixture_is_all_clear_and_writes_nothing(self) -> None:
        self.assertEqual(self.run_check(), 0)
        self.assertIn("PINNED IDENTITY: MET", self.output)
        self.assertEqual(self.output.count("TARGET "), len(TARGETS))
        self.assertEqual(self.output.count("owner-expectation="), len(TARGETS))
        self.assertIn("PREFLIGHT OK: real install would proceed", self.output)
        self.assertNotIn("PREFLIGHT BLOCKERS:", self.output)
        self.assert_nothing_installed()

    def test_check_preexisting_target_is_a_blocker(self) -> None:
        target = self.root / TARGETS[4].lstrip("/")
        target.write_text("existing")

        self.assertEqual(self.run_check(), 1)
        self.assertIn(f"TARGET {TARGETS[4]}; EXISTS;", self.output)
        self.assertIn("PREFLIGHT BLOCKERS:", self.output)
        self.assertIn(f"target already exists: {TARGETS[4]}", self.output)
        self.assertEqual(target.read_text(), "existing")

    def test_check_wrong_owner_parent_is_unmet(self) -> None:
        parent = (self.root / TARGETS[0].lstrip("/")).parent
        self.parent_owners[Path(os.path.realpath(parent))] = (
            self.desktop_uid,
            self.desktop_gid,
        )

        self.assertEqual(self.run_check(), 1)
        target_line = next(
            line for line in self.output.splitlines() if line.startswith(f"TARGET {TARGETS[0]};")
        )
        self.assertIn("owner-expectation=static->root parent UNMET", target_line)
        self.assertIn("target parent is not root-owned", self.output)
        self.assert_nothing_installed()

    def test_check_reports_pinned_identity_mismatch(self) -> None:
        MODULE.EXPECTED_MANIFEST_SHA256 = "0" * 64

        self.assertEqual(self.run_check(), 1)
        self.assertIn(
            "PINNED IDENTITY: UNMET (manifest SHA-256 mismatch)", self.output
        )
        self.assertIn("PREFLIGHT BLOCKERS:", self.output)
        self.assertIn("- manifest SHA-256 mismatch", self.output)
        self.assertEqual(self.output.count("TARGET "), len(TARGETS))
        self.assert_nothing_installed()

    def test_hash_mismatch_is_refused(self) -> None:
        (self.package / str(self.entries[3]["source"])).write_text("changed")
        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: package source hash mismatch", self.output)
        self.assert_nothing_installed()

    def test_source_symlink_is_refused_before_write(self) -> None:
        source = self.package / SOURCES[3]
        attacker = self.package / "attacker-receiver"
        attacker.write_bytes(source.read_bytes())
        attacker.chmod(0o755)
        source.unlink()
        source.symlink_to(attacker)

        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: cannot open package source", self.output)
        self.assert_nothing_installed()

    def test_source_hardlink_is_refused_before_write(self) -> None:
        source = self.package / SOURCES[5]
        os.link(source, self.package / "hardlinked-sudoers")

        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: unsafe package source", self.output)
        self.assert_nothing_installed()

    def test_source_mode_mismatch_is_refused_before_write(self) -> None:
        (self.package / SOURCES[3]).chmod(0o700)

        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: unsafe package source", self.output)
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

    def test_static_parent_not_owned_by_root_is_refused(self) -> None:
        parent = (self.root / TARGETS[0].lstrip("/")).parent
        self.parent_owners[Path(os.path.realpath(parent))] = (
            self.desktop_uid,
            self.desktop_gid,
        )
        self.assertEqual(self.run_install(), 1)
        self.assertIn("INSTALL REFUSED: target parent is not root-owned", self.output)
        self.assert_nothing_installed()

    def test_desktop_parent_owned_by_root_is_refused(self) -> None:
        parent = (self.root / TARGETS[-1].lstrip("/")).parent
        self.parent_owners[Path(os.path.realpath(parent))] = (0, 0)
        self.assertEqual(self.run_install(), 1)
        self.assertIn(
            "INSTALL REFUSED: desktop target parent is root-owned", self.output
        )
        self.assert_nothing_installed()

    def test_resolved_target_collision_is_refused(self) -> None:
        shared_parent = self.base / "shared-target-parent"
        shared_parent.mkdir()
        (self.root / "alias-one").symlink_to(shared_parent, target_is_directory=True)
        (self.root / "alias-two").symlink_to(shared_parent, target_is_directory=True)
        entries = [
            {"owner": "desktop", "target": "/alias-one/colliding-target"},
            {"owner": "desktop", "target": "/alias-two/colliding-target"},
        ]
        self.parent_owners[shared_parent] = (self.desktop_uid, self.desktop_gid)
        real_stat = Path.stat

        def fixture_stat(
            path: Path, *args: object, **stat_kwargs: object
        ) -> os.stat_result:
            metadata = real_stat(path, *args, **stat_kwargs)
            owner = self.parent_owners.get(path)
            if owner is not None:
                values = list(metadata)
                values[4], values[5] = owner
                return os.stat_result(values)
            return metadata

        with (
            mock.patch.object(Path, "stat", autospec=True, side_effect=fixture_stat),
            self.assertRaisesRegex(ValueError, "resolved target collision"),
        ):
            MODULE.preflight_targets(entries, self.root)

    def test_usrmerge_symlinked_parent_is_accepted(self) -> None:
        real_usr = self.base / "real-usr"
        (real_usr / "local/libexec/buzz").mkdir(parents=True)
        (real_usr / "local/sbin").mkdir(parents=True)
        shutil.rmtree(self.root / "usr")
        (self.root / "usr").symlink_to(real_usr, target_is_directory=True)
        self.parent_owners.update(
            {
                real_usr / "local/libexec/buzz": (0, 0),
                real_usr / "local/sbin": (0, 0),
            }
        )
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
        installed_owners = [call.args[1:] for call in self.fchown_calls]
        self.assertEqual(
            installed_owners,
            [(0, 0)] * 7 + [(self.desktop_uid, self.desktop_gid)] * 2,
        )
        self.assertEqual(
            self.chown_calls,
            [mock.call(self.root / "etc/buzz-agents/credentials", 0, 0)],
        )
        credential_dir = self.root / "etc/buzz-agents/credentials"
        self.assertTrue(credential_dir.is_dir())
        self.assertEqual(stat.S_IMODE(credential_dir.stat().st_mode), 0o700)

    def test_unchanged_sources_verify_repeatably_then_install(self) -> None:
        first_entries, first_sources = MODULE.load_and_verify_manifest(
            self.package, self.package / MODULE.MANIFEST_NAME
        )
        second_entries, second_sources = MODULE.load_and_verify_manifest(
            self.package, self.package / MODULE.MANIFEST_NAME
        )

        self.assertEqual(first_entries, second_entries)
        self.assertEqual(first_sources, second_sources)
        self.assertEqual(self.run_install(), 0)
        for entry in self.entries:
            target = self.installed_path(str(entry["target"]))
            self.assertEqual(
                hashlib.sha256(target.read_bytes()).hexdigest(), entry["sha256"]
            )

    def test_receiver_mutation_after_verification_cannot_reach_root_targets(self) -> None:
        source = self.package / SOURCES[3]
        target = self.installed_path(TARGETS[3])
        reviewed = source.read_bytes()
        attacker = b"attacker-controlled receiver\n"
        attacked = False
        real_target_exists = MODULE.target_exists

        def mutate_after_preflight(path: Path) -> bool:
            nonlocal attacked
            if not attacked:
                attacked = True
                source.write_bytes(attacker)
            return real_target_exists(path)

        with mock.patch.object(
            MODULE, "target_exists", side_effect=mutate_after_preflight
        ):
            self.assertEqual(self.run_install(), 0)

        self.assertTrue(attacked)
        self.assertEqual(target.read_bytes(), reviewed)
        for static_target in TARGETS[:7]:
            self.assertNotEqual(self.installed_path(static_target).read_bytes(), attacker)

    def test_sudoers_symlink_swap_after_verification_cannot_reach_root_targets(self) -> None:
        source = self.package / SOURCES[5]
        target = self.installed_path(TARGETS[5])
        reviewed = source.read_bytes()
        attacker = b"victor ALL=(root) NOPASSWD: ALL\n"
        attacker_source = self.package / "attacker-sudoers"
        attacker_source.write_bytes(attacker)
        attacker_source.chmod(0o440)
        attacked = False
        real_target_exists = MODULE.target_exists

        def swap_after_preflight(path: Path) -> bool:
            nonlocal attacked
            if not attacked:
                attacked = True
                source.unlink()
                source.symlink_to(attacker_source)
            return real_target_exists(path)

        with mock.patch.object(MODULE, "target_exists", side_effect=swap_after_preflight):
            self.assertEqual(self.run_install(), 0)

        self.assertTrue(attacked)
        self.assertEqual(target.read_bytes(), reviewed)
        for static_target in TARGETS[:7]:
            self.assertNotEqual(self.installed_path(static_target).read_bytes(), attacker)

    def test_static_chown_test_escape_requires_explicit_flag(self) -> None:
        source = self.package / SOURCES[0]
        payload = source.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        target = self.base / "static-test-target"
        with (
            mock.patch.object(os, "getuid", return_value=1000),
            mock.patch.object(os, "fchown", side_effect=PermissionError("denied")),
            mock.patch.dict(os.environ, {}, clear=True),
            self.assertRaises(PermissionError),
        ):
            MODULE.install_one(payload, digest, target, 0o755, 0, 0)
        self.assertFalse(target.exists())

        with (
            mock.patch.object(os, "getuid", return_value=1000),
            mock.patch.object(os, "fchown", side_effect=PermissionError("denied")),
            mock.patch.dict(os.environ, {"MG_INSTALL_TEST": "1"}, clear=True),
        ):
            MODULE.install_one(payload, digest, target, 0o755, 0, 0)
        self.assertEqual(target.read_bytes(), payload)

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
