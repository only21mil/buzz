from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parents[1]
TOOL = HERE / "migrate.py"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.root = base / "root"
        self.proc = base / "proc"
        self.sys = base / "sys"
        self.control = base / "control"
        self.archive = "/var/lib/buzzci-legacy-archive/test-v1"
        self.uid = os.getuid()
        self.gid = os.getgid()
        self._make_layout()
        self.systemctl = self._make_systemctl()

    def path(self, logical: str) -> Path:
        return self.root / logical.removeprefix("/")

    def directory(self, logical: str, mode: int) -> Path:
        path = self.path(logical)
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)
        return path

    def file(self, logical: str, payload: bytes, mode: int) -> Path:
        path = self.path(logical)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(mode)
        return path

    def _make_layout(self) -> None:
        self.root.mkdir(mode=0o700)
        self.directory("/var/lib", 0o755)
        self.directory("/var/lib/buzzci", 0o700)
        self.directory("/var/lib/buzzci/activation/receipts/cleanup", 0o700)
        self.directory("/var/lib/buzzci/activation/receipts/dns", 0o700)
        self.file("/var/lib/buzzci/activation/state-v1.json", b"legacy activation\n", 0o600)
        self.directory("/var/lib/buzzci/fixtures/qualification.git/objects", 0o700)
        self.file("/var/lib/buzzci/fixtures/qualification.git/HEAD", b"ref: refs/heads/main\n", 0o644)
        self.directory("/var/lib/buzzci/lease01/leases", 0o700)
        self.file("/var/lib/buzzci/lease01.img", b"sparse-image-fixture\n", 0o600)
        self.directory("/var/lib/buzzci/leases", 0o700)
        self.directory("/var/lib/buzzci/principals", 0o711)
        self.directory("/var/lib/buzzci/principals/ctl", 0o700)
        self.directory("/var/lib/buzzci/seccomp/v1/sha256", 0o700)
        self.directory("/var/lib/buzzci/seccomp/v1", 0o700)
        self.directory("/var/lib/buzzci/seccomp", 0o700)
        self.directory("/etc/buzzci", 0o755)
        self.directory("/etc/buzzci/authority", 0o700)
        self.file("/etc/buzzci/authority/authority-v1.json", b"authority\n", 0o400)
        self.file("/etc/buzzci/authority/host-adapters-v1.json", b"adapters\n", 0o400)
        self.file("/etc/buzzci/harness.env", b"HARNESS=legacy\n", 0o400)
        self.directory("/etc/buzzci/qualification-cases", 0o755)
        self.file("/etc/systemd/system/buzz-ci-execd.service", b"[Service]\nExecStart=/legacy\n", 0o644)
        self.file("/etc/systemd/system/buzz-ci-execd.socket", b"[Socket]\nListenStream=/run/buzzci/execd.sock\n", 0o644)
        self.directory("/etc/systemd/system/sockets.target.wants", 0o755)
        os.symlink(
            "/etc/systemd/system/buzz-ci-execd.socket",
            self.path("/etc/systemd/system/sockets.target.wants/buzz-ci-execd.socket"),
        )
        self.directory("/etc/systemd/system/buzz-ci-execd.service.d", 0o755)
        self.file("/etc/systemd/system/buzz-ci-execd.service.d/10-host-adapters.conf", b"[Service]\nEnvironment=LEGACY=1\n", 0o644)
        self.file("/usr/lib/tmpfiles.d/buzzci-control.conf", b"d /run/buzzci 0711 root root -\n", 0o644)
        (self.proc / "self").mkdir(parents=True)
        (self.proc / "self/mountinfo").write_text("36 25 0:32 / / rw,relatime - ext4 /dev/root rw\n", encoding="utf-8")
        (self.proc / "swaps").write_text("Filename Type Size Used Priority\n", encoding="utf-8")
        (self.proc / "locks").write_text("", encoding="utf-8")
        (self.proc / "100/fd").mkdir(parents=True)
        (self.proc / "100/map_files").mkdir()
        (self.sys / "class/block").mkdir(parents=True)
        self.control.mkdir(mode=0o700)

    def _make_systemctl(self) -> Path:
        state = self.control / "systemctl-state.json"
        state.write_bytes(
            canonical(
                {
                    "buzz-ci-execd.socket": {"LoadState": "loaded", "ActiveState": "active", "SubState": "listening", "UnitFileState": "enabled", "FragmentPath": "/etc/systemd/system/buzz-ci-execd.socket", "DropInPaths": ""},
                    "buzz-ci-execd.service": {"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "static", "FragmentPath": "/etc/systemd/system/buzz-ci-execd.service", "DropInPaths": "/etc/systemd/system/buzz-ci-execd.service.d/10-host-adapters.conf /usr/lib/systemd/system/service.d/10-timeout-abort.conf"},
                }
            )
        )
        script = self.control / "systemctl"
        script.write_text(
            """#!/usr/bin/python3
import json, pathlib, sys
state_path = pathlib.Path(%(state)r)
root = pathlib.Path(%(root)r)
state = json.loads(state_path.read_text())
args = sys.argv[1:]
def save():
    state_path.write_text(json.dumps(state, sort_keys=True, separators=(',', ':')) + '\\n')
if args[0] == 'show':
    unit = args[1]
    item = state[unit]
    for key in ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'FragmentPath', 'DropInPaths'):
        print(key + '=' + item[key])
elif args[0] == 'stop':
    unit = args[1]; state[unit]['ActiveState'] = 'inactive'; state[unit]['SubState'] = 'dead'; save()
elif args[0] == 'disable':
    unit = args[1]
    if state[unit]['UnitFileState'] != 'static': state[unit]['UnitFileState'] = 'disabled'
    save()
elif args[0] == 'enable':
    unit = args[1]; state[unit]['UnitFileState'] = 'enabled'; save()
elif args[0] == 'start':
    unit = args[1]; state[unit]['ActiveState'] = 'active'; state[unit]['SubState'] = 'listening' if unit.endswith('.socket') else 'running'; save()
elif args[0] == 'daemon-reload':
    for unit in state:
        path = root / 'etc/systemd/system' / unit
        if not path.exists():
            state[unit].update({'LoadState':'not-found','ActiveState':'inactive','SubState':'dead','UnitFileState':'','FragmentPath':'','DropInPaths':''})
        else:
            state[unit]['LoadState'] = 'loaded'
            state[unit]['FragmentPath'] = '/etc/systemd/system/' + unit
            state[unit]['DropInPaths'] = ''
            if unit.endswith('.service'):
                state[unit]['UnitFileState'] = 'static'
                state[unit]['DropInPaths'] = '/etc/systemd/system/buzz-ci-execd.service.d/10-host-adapters.conf /usr/lib/systemd/system/service.d/10-timeout-abort.conf'
    save()
else:
    print('unsupported', args, file=sys.stderr); sys.exit(2)
""" % {"state": str(state), "root": str(self.root)},
            encoding="utf-8",
        )
        script.chmod(0o700)
        return script

    def command(self, action: str, *extra: str) -> list[str]:
        return [
            "python3", str(TOOL),
            "--root", str(self.root),
            "--proc-root", str(self.proc),
            "--sys-root", str(self.sys),
            "--archive-root", self.archive,
            "--systemctl", str(self.systemctl),
            action, *extra,
        ]

    def run(self, action: str, *extra: str, success: bool = True) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(self.command(action, *extra), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if success and result.returncode != 0:
            raise AssertionError(result.stderr.decode())
        if not success and result.returncode == 0:
            raise AssertionError("command unexpectedly passed")
        return result

    def plan_file(self) -> tuple[Path, bytes]:
        raw = self.run("plan").stdout
        path = self.control / "plan.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        return path, raw


class MigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def migrate(self, *, fail_after: int = -1) -> dict[str, object]:
        plan, raw = self.fixture.plan_file()
        args = ["--plan", str(plan), "--approve-migration", digest(raw)]
        if fail_after >= 0:
            args += ["--fail-after-moves", str(fail_after)]
        result = self.fixture.run("migrate", *args, success=fail_after < 0)
        return json.loads(result.stdout) if result.stdout else {}

    def test_check_plan_migrate_and_exact_rollback(self) -> None:
        check = json.loads(self.fixture.run("check").stdout)
        self.assertEqual((check["result"], check["plan"]["schema"]), ("PASS", "buzz-ci-legacy-state-migration-plan-v1"))
        lease = self.fixture.path("/var/lib/buzzci/lease01.img")
        inode = lease.stat().st_ino
        migration = self.migrate()
        archived = self.fixture.path(self.fixture.archive + "/items/rootfs/var/lib/buzzci/lease01.img")
        self.assertFalse(lease.exists())
        self.assertEqual(archived.stat().st_ino, inode)
        self.assertEqual(stat.S_IMODE(self.fixture.path("/var/lib/buzzci").stat().st_mode), 0o711)
        receipt = Path(migration["receipt"])
        raw = receipt.read_bytes()
        rolled = json.loads(
            self.fixture.run("rollback", "--receipt", str(receipt), "--approve-rollback", digest(raw)).stdout
        )
        self.assertEqual(rolled["state"], "rolled_back")
        self.assertEqual(lease.stat().st_ino, inode)
        self.assertEqual(stat.S_IMODE(self.fixture.path("/var/lib/buzzci").stat().st_mode), 0o700)
        rebuilt = self.fixture.run("plan").stdout
        self.assertEqual(json.loads(rebuilt)["archive_items"], check["plan"]["archive_items"])

    def test_crash_resume_in_both_directions(self) -> None:
        plan, raw = self.fixture.plan_file()
        args = ["--plan", str(plan), "--approve-migration", digest(raw)]
        self.fixture.run("migrate", *args, "--fail-after-moves", "3", success=False)
        migration = json.loads(self.fixture.run("migrate", *args).stdout)
        receipt = Path(migration["receipt"])
        receipt_raw = receipt.read_bytes()
        rollback_args = ["--receipt", str(receipt), "--approve-rollback", digest(receipt_raw)]
        self.fixture.run("rollback", *rollback_args, "--fail-after-moves", "2", success=False)
        result = json.loads(self.fixture.run("rollback", *rollback_args).stdout)
        self.assertEqual(result["state"], "rolled_back")

    def test_resume_after_last_move_before_each_terminal_receipt(self) -> None:
        plan, raw = self.fixture.plan_file()
        move_count = len(json.loads(raw)["archive_items"])
        migration_args = ["--plan", str(plan), "--approve-migration", digest(raw)]
        self.fixture.run("migrate", *migration_args, "--fail-after-moves", str(move_count), success=False)
        migration = json.loads(self.fixture.run("migrate", *migration_args).stdout)
        receipt = Path(migration["receipt"])
        receipt_raw = receipt.read_bytes()
        rollback_args = ["--receipt", str(receipt), "--approve-rollback", digest(receipt_raw)]
        self.fixture.run("rollback", *rollback_args, "--fail-after-moves", str(move_count), success=False)
        result = json.loads(self.fixture.run("rollback", *rollback_args).stdout)
        self.assertEqual(result["state"], "rolled_back")

    def test_approval_and_post_plan_drift_fail_closed(self) -> None:
        plan, raw = self.fixture.plan_file()
        self.fixture.run("migrate", "--plan", str(plan), "--approve-migration", "0" * 64, success=False)
        harness = self.fixture.path("/etc/buzzci/harness.env")
        harness.chmod(0o600)
        harness.write_bytes(b"changed\n")
        harness.chmod(0o400)
        self.fixture.run("migrate", "--plan", str(plan), "--approve-migration", digest(raw), success=False)
        self.assertFalse(self.fixture.path(self.fixture.archive).exists())

    def test_unknown_symlink_hardlink_and_special_nodes_are_rejected(self) -> None:
        mutations = [
            lambda f: f.file("/var/lib/buzzci/unknown", b"x", 0o600),
            lambda f: os.symlink("state-v1.json", f.path("/var/lib/buzzci/activation/link")),
            lambda f: os.link(f.path("/etc/buzzci/harness.env"), f.path("/etc/buzzci/authority/hardlink")),
            lambda f: os.mkfifo(f.path("/var/lib/buzzci/fixtures/fifo"), 0o600),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                if index:
                    self.temporary.cleanup()
                    self.temporary = tempfile.TemporaryDirectory()
                    self.fixture = Fixture(Path(self.temporary.name))
                mutate(self.fixture)
                self.fixture.run("plan", success=False)

    def test_mount_open_and_loop_use_are_rejected(self) -> None:
        cases = ("mount", "open", "loop")
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                if index:
                    self.temporary.cleanup()
                    self.temporary = tempfile.TemporaryDirectory()
                    self.fixture = Fixture(Path(self.temporary.name))
                if case == "mount":
                    (self.fixture.proc / "self/mountinfo").write_text(
                        "40 36 0:40 / /var/lib/buzzci/lease01 rw - ext4 /dev/loop0 rw\n", encoding="utf-8"
                    )
                elif case == "open":
                    os.symlink(
                        self.fixture.path("/var/lib/buzzci/lease01.img"),
                        self.fixture.proc / "100/fd/9",
                    )
                else:
                    backing = self.fixture.sys / "class/block/loop0/loop/backing_file"
                    backing.parent.mkdir(parents=True)
                    backing.write_text("/var/lib/buzzci/lease01.img\n", encoding="utf-8")
                self.fixture.run("plan", success=False)

    def test_plan_refuses_non_private_approval_file(self) -> None:
        plan, raw = self.fixture.plan_file()
        plan.chmod(0o644)
        self.fixture.run("migrate", "--plan", str(plan), "--approve-migration", digest(raw), success=False)

    def test_unknown_etc_buzzci_entry_and_new_state_block_rollback(self) -> None:
        self.fixture.file("/etc/buzzci/unplanned.json", b"{}\n", 0o600)
        self.fixture.run("plan", success=False)
        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))
        migration = self.migrate()
        receipt = Path(migration["receipt"])
        receipt_raw = receipt.read_bytes()
        self.fixture.file("/etc/buzzci/runner-v2.json", b"{}\n", 0o600)
        self.fixture.run(
            "rollback",
            "--receipt", str(receipt),
            "--approve-rollback", digest(receipt_raw),
            success=False,
        )

    def test_existing_migration_receipt_drift_is_not_overwritten(self) -> None:
        migration = self.migrate()
        receipt = Path(migration["receipt"])
        value = json.loads(receipt.read_bytes())
        value["result"] = "FAIL"
        drifted = canonical(value)
        receipt.write_bytes(drifted)
        receipt.chmod(0o600)
        plan = self.fixture.control / "plan.json"
        plan_raw = plan.read_bytes()
        self.fixture.run(
            "migrate",
            "--plan", str(plan),
            "--approve-migration", digest(plan_raw),
            success=False,
        )
        self.assertEqual(receipt.read_bytes(), drifted)

    def test_approved_hostile_rollback_receipt_cannot_expand_the_allowlist(self) -> None:
        migration = self.migrate()
        receipt = Path(migration["receipt"])
        value = json.loads(receipt.read_bytes())
        value["normalized_directories"][0]["path"] = "/etc"
        hostile = canonical(value)
        receipt.write_bytes(hostile)
        receipt.chmod(0o600)
        self.fixture.run(
            "rollback",
            "--receipt", str(receipt),
            "--approve-rollback", digest(hostile),
            success=False,
        )
        self.assertEqual(stat.S_IMODE(self.fixture.path("/var/lib/buzzci").stat().st_mode), 0o711)
        self.assertFalse(self.fixture.path("/var/lib/buzzci/lease01.img").exists())


if __name__ == "__main__":
    unittest.main()
