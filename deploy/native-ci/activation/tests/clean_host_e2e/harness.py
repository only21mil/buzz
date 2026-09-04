#!/usr/bin/env python3
"""Run capacity-one acceptance behind a disposable offline KVM boundary."""

from __future__ import annotations

import argparse
import base64
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable

SCHEMA = "buzz-ci-clean-host-e2e-vm-contract/v4"
EVIDENCE_SCHEMA = "buzz-ci-clean-host-e2e-evidence/v4"
STAGE_SCHEMA = "buzz-ci-clean-host-e2e-stage/v3"
STATE_SCHEMA = "buzz-ci-clean-host-e2e-vm-state/v3"
FRAME_SCHEMA = "buzz-ci-clean-host-e2e-frame/v2"
PROGRESS_SCHEMA = "buzz-ci-clean-host-e2e-progress/v1"
PACKAGE_NAMES = ("runner", "controld", "keyholder", "execd", "activation")
PRIOR_PACKAGE_NAMES = ("execd", "activation")
PRIOR_ACTIVATION_PROOF_KEYS = frozenset({
    "activation_id", "package_digest", "receipt_state", "rollback_cleanup_sha256", "execd_reinstall",
})
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON = 1024 * 1024
MAX_FRAME = 4 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_TREE_FILES = 1024
TRANSFER_SIZE = 8 * 1024 * 1024
TIMING_PATH = Path(__file__).with_name("timing-contract.json")
TIMING_CONTRACT = json.loads(TIMING_PATH.read_bytes())
STAGE_STOP_ORDER = (
    "buzz-ci-controld-acceptance.socket", "buzz-ci-controld.service",
    "buzz-ci-acceptance-control.socket", "buzz-ci-acceptance-control.service",
    "buzz-ci-runner.service", "buzz-ci-runner.socket", "buzz-ci-execd.service",
    "buzz-ci-execd.socket", "buzz-ci-executor.service", "buzz-ci-executor.socket",
    "buzz-ci-keyholder.service", "buzz-ci-keyholder.socket",
)
STAGE_ZERO_UNITS = STAGE_STOP_ORDER[:4]
STAGE_PROGRESS_SUBPHASES = (
    "package_load", "live_driver", "scenario_binding", "generated_plan", "tmpfiles_plan",
    "receipt_read", "preflight", "fixed_package_install", "fixed_package_verify",
    "new_receipt_capture", "recovery_targets_install", "preparing_receipt_write",
    "staged_apply", "sysusers", "tmpfiles", "generated_apply", "daemon_reload",
    "installed_unit_readback", "persistent_target_disable",
    *(f"stop:{unit}" for unit in STAGE_STOP_ORDER),
    "persistent_target_stop", "zero_readback", "captured_ledger_removal",
    "identity_readback", "access_group_readback", "managed_target_readback",
    "generated_readback", "staged_receipt_write",
    *(f"start:{unit}" for unit in STAGE_ZERO_UNITS),
    "staged_zero_readback", "rollback_retirement_completion", "stage_complete",
)
if len(STAGE_PROGRESS_SUBPHASES) != 46:
    raise RuntimeError("stage progress operation inventory differs")
PROGRESS_PHASES = (
    "boot_cloud_init", "guest_started", "ceremony", "install", "relay_ready",
    "preinstall_units_clean", "package_units_validated", "principals_created",
    "seccomp_ready", "runner_installed", "controld_installed", "keyholder_installed",
    "execd_installed", "installed_units_verified",
    "prior_controller_check", "prior_controller_stage", "prior_controller_activate",
    "prior_rollback", "reinstall", "execd_reinstalled",
    "controller_check", "controller_stage",
    *(f"controller_stage:{name}" for name in STAGE_PROGRESS_SUBPHASES),
    "controller_activate", "canary", "receipt_verifier", "rollback", "cleanup",
    "cleanup_return", "verifier", "complete",
)
PROGRESS_EVENTS = ("start", "timeout", "complete")
PROGRESS_ORDER = {name: index for index, name in enumerate(PROGRESS_PHASES)}
for _stage_subphase in STAGE_PROGRESS_SUBPHASES:
    PROGRESS_ORDER[f"controller_stage:{_stage_subphase}"] = PROGRESS_ORDER["controller_stage"]
MAX_PROGRESS_RECORDS = 32
MAX_PROGRESS = 16 * 1024
SECCOMP_SHA256 = "2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4"
PLATFORM_SYSTEMD = {
    "schema_version": "buzz-ci-systemd-platform-binding/v1",
    "platform_id": "fedora-44-systemd-259",
    "service_drop_ins": [{
        "owner": "platform",
        "path": "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
        "sha256": "ae6b234f92bc22f1201a7572b59b454c9809f33c80d13f361b9674e1801acc37",
    }],
}
TOOLS = {
    "qemu": "/usr/bin/qemu-system-x86_64",
    "qemu_img": "/usr/bin/qemu-img",
    "bwrap": "/usr/bin/bwrap",
    "xorriso": "/usr/bin/xorriso",
    "cloud_localds": "/usr/bin/cloud-localds",
}
FROZEN_ASSETS = (
    "harness.py", "guest_entry.py", "timing-contract.json", "local_tls_relay.py",
    "receipt_verifier.py", "expected-stages.json",
)
GUEST_ASSETS = tuple(name for name in FROZEN_ASSETS if name != "harness.py")
# Opt-in loopback-relay fault modes (local_tls_relay.py RELAY_FAULTS). The
# candidate phase file always carries `relay_fault`; None is the standard run.
RELAY_FAULTS = ("stale-terminal-publication-recovery", "stale-terminal-replay-before-grant")
REQUIRED_CANDIDATE = (
    "deploy/native-ci/runner/install.py",
    "deploy/native-ci/controld/install.py",
    "deploy/native-ci/keyholder/install.py",
    "deploy/native-ci/execd/install.py",
    "deploy/native-ci/activation/controller.py",
    "deploy/native-ci/activation/package.py",
)
RUN_OWNERSHIP = "run-ownership.json"
RUN_OWNERSHIP_PENDING_PREFIX = ".run-ownership."
RUN_OWNERSHIP_PENDING_SUFFIX = ".pending"
PUBLICATION_SCHEMA = "buzz-ci-clean-host-e2e-publication/v1"
CLAIM_LOCK_TIMEOUT = 30.0
CLAIM_LOCK_POLL = 0.01


class HarnessError(RuntimeError):
    """Fail-closed harness rejection."""


class CleanupDurabilityError(HarnessError):
    """Cleanup stopped before destructive writes because quarantine was not durable."""


@dataclass(frozen=True)
class DirectoryIdentity:
    device: int
    inode: int


@dataclass(frozen=True)
class StateIdentity(DirectoryIdentity):
    """Filesystem identity of the exact prepared state selected for a run."""

    marker_sha256: str


def publication_checkpoint(_name: str, _staging: Path, _results: Path) -> None:
    """Test seam for result-publication interruption checkpoints."""


def cleanup_checkpoint(_name: str, _path: Path, _descriptor: int) -> None:
    """Test seam for cleanup namespace-race checkpoints."""


def claim_checkpoint(_name: str, _path: Path, _descriptor: int) -> None:
    """Test seam for run-state claim interruption checkpoints."""


def run_binding(contract: dict[str, object], results: Path) -> dict[str, str]:
    original = Path(os.path.abspath(Path(contract["state"])))
    final = Path(os.path.abspath(results))
    claimed = original.with_name(f".{original.name}.terminal-run")
    staging = final.with_name(f".{final.name}.clean-host-staging")
    journal = final.with_name(f".{final.name}.clean-host-publication.json")
    if any(
        left == right or left.is_relative_to(right) or right.is_relative_to(left)
        for left in (final, staging, journal)
        for right in (original, claimed)
    ):
        raise HarnessError("result publication path overlaps VM state")
    return {
        "contract_sha256": hashlib.sha256(canonical(contract)).hexdigest(),
        "original_state": str(original),
        "claimed_state": str(claimed),
        "results": str(final),
        "staging": str(staging),
        "journal": str(journal),
    }


def publication_record(
    binding: dict[str, str], phase: str, outcome: dict[str, object] | None = None,
    staging_identity: DirectoryIdentity | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": PUBLICATION_SCHEMA,
        "phase": phase,
        **binding,
    }
    if staging_identity is not None:
        value["staging_identity"] = {
            "device": staging_identity.device,
            "inode": staging_identity.inode,
        }
    if outcome is not None:
        value["outcome"] = outcome
    return value


def parse_directory_identity(value: object) -> DirectoryIdentity:
    if (
        not isinstance(value, dict)
        or set(value) != {"device", "inode"}
        or not isinstance(value.get("device"), int)
        or not isinstance(value.get("inode"), int)
        or value["device"] < 0
        or value["inode"] <= 0
    ):
        raise HarnessError("directory identity record differs")
    return DirectoryIdentity(value["device"], value["inode"])


def write_new_private_json(path: Path, value: object) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
    try:
        raw = canonical(value)
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise HarnessError(f"private record write was incomplete: {path.name}")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_parent(path)


def fsync_parent(path: Path) -> None:
    parent_fd = open_absolute(path.parent, directory=True)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def rename_noreplace(source: Path, target: Path) -> None:
    rename_noreplace_at(-100, os.fsencode(source), -100, os.fsencode(target), str(target))


def rename_noreplace_at(
    source_fd: int, source: bytes, target_fd: int, target: bytes, target_label: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise HarnessError("atomic no-replace rename is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(source_fd, source, target_fd, target, 1) != 0:
        number = ctypes.get_errno()
        if number == errno.ENOSYS:
            raise HarnessError("atomic no-replace rename is unavailable")
        raise OSError(number, os.strerror(number), target_label)


def replace_private_json(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.new-{os.urandom(8).hex()}")
    write_new_private_json(temporary, value)
    try:
        os.replace(temporary, path)
        fsync_parent(path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_publication(binding: dict[str, str]) -> dict[str, object] | None:
    journal = Path(binding["journal"])
    try:
        journal.lstat()
    except FileNotFoundError:
        return None
    value = load_json(journal)
    if not isinstance(value, dict) or value.get("schema_version") != PUBLICATION_SCHEMA:
        raise HarnessError("result publication journal differs")
    identity = parse_directory_identity(value.get("staging_identity"))
    common = publication_record(binding, "running", staging_identity=identity)
    if any(value.get(name) != item for name, item in common.items() if name != "phase"):
        raise HarnessError("result publication binding differs")
    if value.get("phase") == "running" and set(value) == set(common):
        return value
    ready = publication_record(binding, "ready", value.get("outcome"), identity)
    if value.get("phase") == "ready" and isinstance(value.get("outcome"), dict) and set(value) == set(ready):
        return value
    raise HarnessError("result publication phase differs")


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def timing_sha256() -> str:
    validate_timing_contract()
    return hashlib.sha256(canonical(TIMING_CONTRACT)).hexdigest()


def timing_terms_seconds(terms: object) -> int:
    leaves = TIMING_CONTRACT.get("leaf_seconds")
    if (
        not isinstance(leaves, dict)
        or not isinstance(terms, dict)
        or any(
            name not in leaves
            or not isinstance(count, int) or isinstance(count, bool) or count <= 0
            for name, count in terms.items()
        )
    ):
        raise HarnessError("frozen VM timing terms differ")
    return sum(int(leaves[name]) * count for name, count in terms.items())


def phase_seconds(phase: str) -> int:
    phases = TIMING_CONTRACT.get("phase_terms")
    inventory = TIMING_CONTRACT.get("command_inventory")
    if not isinstance(phases, dict) or not isinstance(inventory, dict) or phase not in phases or phase not in inventory:
        raise HarnessError("unknown VM timing phase")
    return timing_terms_seconds(phases[phase]) + timing_terms_seconds(inventory[phase])


def validate_timing_contract() -> None:
    leaves = TIMING_CONTRACT.get("leaf_seconds")
    phases = TIMING_CONTRACT.get("phase_terms")
    inventory = TIMING_CONTRACT.get("command_inventory")
    roles = TIMING_CONTRACT.get("role_phases")
    expected_phases = {
        "boot_cloud_init", "ceremony", "install", "prior_controller_check",
        "prior_controller_stage", "prior_controller_activate", "prior_rollback",
        "reinstall", "controller_check", "controller_stage", "controller_activate",
        "canary", "receipt_verifier", "rollback", "cleanup", "verifier", "poweroff",
    }
    expected_roles = {
        "ceremony": ["boot_cloud_init", "ceremony", "poweroff"],
        "candidate": [
            "boot_cloud_init", "install", "prior_controller_check", "prior_controller_stage",
            "prior_controller_activate", "prior_rollback", "reinstall",
            "controller_check", "controller_stage",
            "controller_activate", "canary", "receipt_verifier", "rollback",
            "cleanup", "poweroff",
        ],
        "verifier": ["boot_cloud_init", "verifier", "poweroff"],
    }
    if (
        set(TIMING_CONTRACT) != {
            "schema_version", "leaf_seconds", "phase_terms", "command_inventory",
            "role_phases",
        }
        or TIMING_CONTRACT.get("schema_version") != "buzz-ci-clean-host-e2e-timing/v2"
        or not isinstance(leaves, dict)
        or set(leaves) != {
            "cloud_init_margin", "command_default", "controller_check",
            "controller_stage", "controller_activate", "driver_operation",
            "canary_orchestration_margin", "receipt_verifier", "rollback",
            "unit_stop", "relay_ready_window", "relay_probe", "phase_margin",
            "verifier_local_work", "guest_command_reap", "poweroff", "host_reap",
        }
        or any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in leaves.values())
        or not isinstance(phases, dict)
        or set(phases) != expected_phases
        or not isinstance(inventory, dict)
        or set(inventory) != expected_phases
        or roles != expected_roles
    ):
        raise HarnessError("frozen VM timing contract is internally inconsistent")
    for terms in phases.values():
        timing_terms_seconds(terms)
    for terms in inventory.values():
        timing_terms_seconds(terms)


REAP_TIMEOUT = int(TIMING_CONTRACT["leaf_seconds"]["host_reap"])


def watchdog_seconds(boot_role: str) -> int:
    validate_timing_contract()
    roles = TIMING_CONTRACT["role_phases"]
    if not isinstance(roles, dict) or boot_role not in roles:
        raise HarnessError("unknown VM boot timing role")
    return sum(phase_seconds(phase) for phase in roles[boot_role]) + REAP_TIMEOUT


def asset_source(here: Path, name: str) -> Path:
    if name in {"harness.py", "guest_entry.py", "timing-contract.json", "local_tls_relay.py"}:
        return here / name
    if name == "receipt_verifier.py":
        return here.parents[2] / "acceptance" / "verify-receipt.py"
    if name == "expected-stages.json":
        return here.parents[2] / "acceptance" / "expected-stages.json"
    raise HarnessError("unknown frozen asset")


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise HarnessError("duplicate JSON field")
        value[key] = item
    return value


def load_json(path: Path, maximum: int = MAX_JSON) -> object:
    raw = read_regular(path, maximum)
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise HarnessError(f"invalid JSON: {path.name}") from error


def read_fd(fd: int, name: str, maximum: int = MAX_FILE) -> bytes:
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise HarnessError(f"unsafe input file: {name}")
        raw = b""
        while chunk := os.read(fd, min(1024 * 1024, maximum + 1 - len(raw))):
            raw += chunk
            if len(raw) > maximum:
                raise HarnessError(f"oversized input file: {name}")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        ):
            raise HarnessError(f"input changed while read: {name}")
        return raw
    except BaseException:
        raise


def open_absolute(path: Path, *, directory: bool = False) -> int:
    absolute = Path(os.path.abspath(path))
    if not absolute.is_absolute() or any(part in {"", ".", ".."} for part in absolute.parts[1:]):
        raise HarnessError("input path is invalid")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, part in enumerate(absolute.parts[1:]):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if index < len(absolute.parts[1:]) - 1 or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def read_regular(path: Path, maximum: int = MAX_FILE) -> bytes:
    fd = open_absolute(path)
    try:
        return read_fd(fd, path.name, maximum)
    finally:
        os.close(fd)


def safe_directory(path: Path, *, create: bool = False) -> Path:
    absolute = Path(os.path.abspath(path))
    if create:
        parent = absolute.parent
        parent_metadata = parent.lstat()
        if (
            Path(os.path.realpath(parent)) != parent
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise HarnessError("private directory parent is unsafe")
        absolute.mkdir(mode=0o700, exist_ok=False)
    metadata = absolute.lstat()
    if (
        Path(os.path.realpath(absolute)) != absolute
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise HarnessError("private directory identity or mode differs")
    return absolute


def create_prepare_directory(path: Path) -> tuple[Path, DirectoryIdentity]:
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    parent_metadata = parent.lstat()
    if (
        Path(os.path.realpath(parent)) != parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise HarnessError("private directory parent is unsafe")
    absolute.mkdir(mode=0o700, exist_ok=False)
    metadata = absolute.lstat()
    identity = DirectoryIdentity(metadata.st_dev, metadata.st_ino)
    try:
        if (
            Path(os.path.realpath(absolute)) != absolute
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise HarnessError("private directory identity or mode differs")
        return absolute, identity
    except BaseException:
        destroy_identified_directory(absolute, identity, "new prepare state directory")
        raise


def safe_input_directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    fd = open_absolute(absolute, directory=True)
    try:
        metadata = os.fstat(fd)
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise HarnessError(f"input directory is writable by another identity: {absolute.name}")
    finally:
        os.close(fd)
    return absolute


def safe_input_file(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    fd = open_absolute(absolute)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise HarnessError(f"input file metadata is unsafe: {absolute.name}")
    finally:
        os.close(fd)
    return absolute


def normalized_relative(relative: Path) -> str:
    value = PurePosixPath(relative.as_posix())
    if value.is_absolute() or any(part in {"", ".", ".."} for part in value.parts):
        raise HarnessError("input tree contains an escaping path")
    return value.as_posix()


def tree_records(root: Path) -> list[tuple[str, int, bytes]]:
    records: list[tuple[str, int, bytes]] = []
    total = 0
    root_fd = open_absolute(root, directory=True)
    try:
        root_metadata = os.fstat(root_fd)
        if root_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise HarnessError("package root is writable by another identity")

        def walk(directory_fd: int, prefix: PurePosixPath) -> None:
            nonlocal total
            with os.scandir(directory_fd) as iterator:
                names = sorted(entry.name for entry in iterator)
            for name in names:
                relative_path = prefix / name
                relative = normalized_relative(Path(relative_path.as_posix()))
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                try:
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                except OSError as error:
                    raise HarnessError(f"package path is not one regular file: {relative}") from error
                try:
                    metadata = os.fstat(child_fd)
                    if stat.S_ISDIR(metadata.st_mode):
                        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                            raise HarnessError(f"unsafe package directory: {relative}")
                        walk(child_fd, relative_path)
                        continue
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise HarnessError(f"package path is not one regular file: {relative}")
                    raw = read_fd(child_fd, name)
                    total += len(raw)
                    if len(records) >= MAX_TREE_FILES or total > MAX_FILE:
                        raise HarnessError("package tree exceeds the fixed bound")
                    records.append((relative, stat.S_IMODE(metadata.st_mode), raw))
                finally:
                    os.close(child_fd)

        walk(root_fd, PurePosixPath())
    finally:
        os.close(root_fd)
    if not records:
        raise HarnessError("package tree is empty")
    records.sort(key=lambda item: item[0])
    return records


def tree_digest(records: list[tuple[str, int, bytes]]) -> str:
    digest = hashlib.sha256()
    for relative, mode, raw in records:
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(f"{mode:04o}".encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(raw).digest())
    return digest.hexdigest()


def materialize_tree(records: list[tuple[str, int, bytes]], target: Path) -> None:
    target.mkdir(mode=0o700)
    for relative, mode, raw in records:
        path = target / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
        try:
            os.fchmod(fd, mode)
            view = memoryview(raw)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)


def reap_process_group(process: subprocess.Popen[bytes], *, wait_seconds: float = 10) -> None:
    """Unconditionally kill, reap, and prove absence of a spawned process group."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + wait_seconds
    while process.poll() is None and time.monotonic() < deadline:
        try:
            select.select([], [], [], min(0.05, max(0.001, deadline - time.monotonic())))
        except BaseException:
            pass
    if process.poll() is None:
        raise HarnessError("spawned process could not be reaped")
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return
    except PermissionError as error:
        raise HarnessError("spawned process-group absence cannot be proved") from error
    raise HarnessError("spawned process group remains after reap")


def bounded(
    argv: list[str], timeout: int = 30, maximum: int = MAX_JSON, *, cwd: Path | None = None,
) -> bytes:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            argv, stdout=stdout, stderr=stderr, start_new_session=True, cwd=cwd,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if stdout.tell() > maximum or stderr.tell() > maximum:
                    raise HarnessError(f"bounded command output exceeded limit: {Path(argv[0]).name}")
                if time.monotonic() >= deadline:
                    raise HarnessError(f"bounded command timed out: {Path(argv[0]).name}")
                time.sleep(0.01)
            if stdout.tell() > maximum or stderr.tell() > maximum:
                raise HarnessError(f"bounded command output exceeded limit: {Path(argv[0]).name}")
            if process.returncode != 0:
                raise HarnessError(f"bounded command failed: {Path(argv[0]).name}")
            stdout.seek(0)
            return stdout.read(maximum + 1)
        finally:
            reap_process_group(process)


def file_sha256(path: Path) -> str:
    fd = open_absolute(path)
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 16 * 1024 * 1024 * 1024:
            raise HarnessError(f"unsafe digest input: {path.name}")
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        ):
            raise HarnessError(f"digest input changed while read: {path.name}")
        return digest.hexdigest()
    finally:
        os.close(fd)


def current_harness_sha256() -> str:
    return file_sha256(Path(__file__).resolve())


def timing_asset_sha256() -> str:
    return file_sha256(TIMING_PATH.resolve())


def capabilities() -> dict[str, object]:
    missing = [path for path in TOOLS.values() if not Path(path).is_file()]
    kvm = Path("/dev/kvm")
    if not kvm.exists() or not stat.S_ISCHR(kvm.stat().st_mode) or not os.access(kvm, os.R_OK | os.W_OK):
        missing.append("/dev/kvm")
    if missing:
        raise HarnessError("safe KVM capability unavailable: " + ",".join(missing))
    kvm_fd = os.open(kvm, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    os.close(kvm_fd)
    with tempfile.TemporaryDirectory(prefix="buzzci-kvm-capability.") as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o700)
        bounded(bwrap_prefix(scratch) + ["--", "/usr/bin/true"], timeout=10, maximum=4096)
        sandboxed_version = bounded(
            bwrap_prefix(scratch) + ["--", TOOLS["qemu"], "--version"],
            timeout=10, maximum=4096,
        ).decode().splitlines()[0]
    qemu_version = bounded([TOOLS["qemu"], "--version"], maximum=4096).decode().splitlines()[0]
    if sandboxed_version != qemu_version:
        raise HarnessError("sandboxed QEMU identity differs")
    return {
        "status": "ready",
        "boundary": "bubblewrap+qemu-kvm",
        "network": "unshared-and-no-nic",
        "qemu_version": qemu_version,
        "tool_sha256": {name: file_sha256(Path(path)) for name, path in TOOLS.items()},
        "harness_sha256": current_harness_sha256(),
        "timing_asset_sha256": timing_asset_sha256(),
        "timing": TIMING_CONTRACT,
        "timing_sha256": timing_sha256(),
    }


def copy_bound(source: Path, target: Path, expected_sha256: str) -> None:
    if HEX64.fullmatch(expected_sha256) is None:
        raise HarnessError("expected file digest is invalid")
    source_fd = open_absolute(source)
    target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
    digest = hashlib.sha256()
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise HarnessError("bound source is not one regular file")
        while chunk := os.read(source_fd, 1024 * 1024):
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(target_fd, view):]
        os.fchmod(target_fd, 0o400)
        os.fsync(target_fd)
        after = os.fstat(source_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        ):
            raise HarnessError("bound source changed while copied")
        if digest.hexdigest() != expected_sha256:
            raise HarnessError("bound source digest differs")
    finally:
        os.close(source_fd)
        os.close(target_fd)


def bwrap_prefix(state: Path, *, writable_files: tuple[str, ...] = ()) -> list[str]:
    allowed_writable = {
        "ceremony.qcow2", "candidate.qcow2", "verifier.qcow2",
        "transfer.raw", "evidence.bin", "progress.bin",
    }
    if len(set(writable_files)) != len(writable_files) or any(name not in allowed_writable for name in writable_files):
        raise HarnessError("Bubblewrap writable-file allowlist differs")
    prefix = [
        TOOLS["bwrap"], "--unshare-all", "--unshare-net", "--die-with-parent", "--new-session",
        "--ro-bind", "/usr", "/usr", "--proc", "/proc", "--dev", "/dev",
        "--dev-bind", "/dev/kvm", "/dev/kvm",
        "--tmpfs", "/tmp", "--tmpfs", "/run", "--dir", "/etc",
        "--dir", "/work", "--ro-bind", str(state), "/work",
        "--chdir", "/work",
    ]
    for name in writable_files:
        prefix.extend(["--bind", str(state / name), f"/work/{name}"])
    for target, source in (("/bin", "usr/bin"), ("/sbin", "usr/sbin"), ("/lib", "usr/lib"), ("/lib64", "usr/lib64")):
        prefix.extend(["--symlink", source, target])
    if Path("/etc/ld.so.cache").is_file():
        prefix.extend(["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"])
    return prefix


def qemu_command(
    state: Path, *, overlay: str, evidence: bool, transfer: str | None = None,
) -> list[str]:
    if overlay not in {"ceremony.qcow2", "candidate.qcow2", "verifier.qcow2"}:
        raise HarnessError("unknown VM overlay")
    if transfer not in {None, "read-write", "read-only"}:
        raise HarnessError("unknown evidence-transfer mode")
    writable_files = [overlay, "progress.bin"]
    if transfer == "read-write":
        writable_files.append("transfer.raw")
    if evidence:
        writable_files.append("evidence.bin")
    command = bwrap_prefix(state, writable_files=tuple(writable_files)) + [
        "--", TOOLS["qemu"], "-nodefaults", "-no-user-config", "-enable-kvm",
        "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", "2048",
        "-display", "none", "-serial", "none", "-monitor", "none", "-nic", "none",
        "-no-reboot", "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-drive", f"file=/work/{overlay},if=none,format=qcow2,cache=none,id=os",
        "-device", "virtio-blk-pci,drive=os,bootindex=1",
        "-drive", "file=/work/stage.iso,media=cdrom,readonly=on",
        "-drive", "file=/work/seed.iso,media=cdrom,readonly=on",
        "-device", "virtio-serial-pci",
        "-chardev", "file,id=progress,path=/work/progress.bin",
        "-device", "virtserialport,chardev=progress,name=buzzci.progress",
    ]
    if transfer is not None:
        readonly = ",readonly=on" if transfer == "read-only" else ""
        command.extend([
            "-drive", f"file=/work/transfer.raw,if=none,format=raw,cache=none,id=transfer{readonly}",
            "-device", "virtio-blk-pci,drive=transfer,serial=buzzci-transfer",
        ])
    if evidence:
        command.extend([
            "-chardev", "file,id=evidence,path=/work/evidence.bin",
            "-device", "virtserialport,chardev=evidence,name=buzzci.evidence",
        ])
    return command


def qemu_img_create(state: Path, name: str, backing: str) -> None:
    if name not in {"ceremony.qcow2", "candidate.qcow2", "verifier.qcow2"} or backing not in {"base.qcow2", "trusted.qcow2"}:
        raise HarnessError("unknown VM image role")
    bounded([
        TOOLS["qemu_img"], "create", "-q", "-f", "qcow2", "-F", "qcow2",
        "-b", backing, name,
    ], cwd=state)
    (state / name).chmod(0o600)


def qemu_image_info(state: Path, name: str) -> dict[str, object]:
    value = json.loads(bounded([
        TOOLS["qemu_img"], "info", "--output=json", "--backing-chain", name,
    ], cwd=state, maximum=64 * 1024), object_pairs_hook=reject_duplicates)
    if not isinstance(value, list) or not value or any(not isinstance(item, dict) for item in value):
        raise HarnessError("qcow2 image metadata differs")
    return value[0]


def validate_flat_qcow2(state: Path, name: str) -> dict[str, object]:
    info = qemu_image_info(state, name)

    def contains_external_reference(value: object) -> bool:
        forbidden = {
            "backing-filename", "full-backing-filename", "backing-filename-format",
            "data-file", "data-file-raw", "data_file", "data_file_raw",
        }
        if isinstance(value, dict):
            return any(key in forbidden or contains_external_reference(item) for key, item in value.items())
        if isinstance(value, list):
            return any(contains_external_reference(item) for item in value)
        return False

    if (
        info.get("format") != "qcow2"
        or contains_external_reference(info)
        or not isinstance(info.get("virtual-size"), int)
        or not 1024 * 1024 <= info["virtual-size"] <= 64 * 1024 * 1024 * 1024
    ):
        raise HarnessError("qcow2 backing, data file, format, or virtual size differs")
    chain = json.loads(bounded([
        TOOLS["qemu_img"], "info", "--output=json", "--backing-chain", name,
    ], cwd=state, maximum=64 * 1024), object_pairs_hook=reject_duplicates)
    if not isinstance(chain, list) or len(chain) != 1:
        raise HarnessError("qcow2 backing chain is not flat")
    return info


def flatten_ceremony(state: Path) -> str:
    bounded([
        TOOLS["qemu_img"], "convert", "-q", "-O", "qcow2", "ceremony.qcow2", "trusted.qcow2",
    ], cwd=state, timeout=180)
    (state / "trusted.qcow2").chmod(0o400)
    validate_flat_qcow2(state, "trusted.qcow2")
    digest = file_sha256(state / "trusted.qcow2")
    (state / "ceremony.qcow2").unlink()
    (state / "base.qcow2").unlink()
    if (state / "ceremony.qcow2").exists() or (state / "base.qcow2").exists():
        raise HarnessError("ceremony image residue remains")
    return digest


def create_transfer(state: Path) -> None:
    fd = os.open(state / "transfer.raw", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        os.ftruncate(fd, TRANSFER_SIZE)
        os.fsync(fd)
    finally:
        os.close(fd)


def validate_transfer(state: Path) -> None:
    fd = open_absolute(state / "transfer.raw")
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != TRANSFER_SIZE
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
        ):
            raise HarnessError("fixed-capacity evidence transfer metadata differs")
    finally:
        os.close(fd)


def make_iso(source: Path, output: Path, label: str) -> None:
    bounded([
        TOOLS["xorriso"], "-as", "mkisofs", "-quiet", "-J", "-R",
        "-uid", "0", "-gid", "0",
        "-V", label, "-o", str(output), str(source),
    ], timeout=60)
    output.chmod(0o400)


def make_seed(state: Path, instance_id: str) -> None:
    seed = state / "seed-source"
    seed.mkdir(mode=0o700)
    (seed / "meta-data").write_text(f"instance-id: {instance_id}\nlocal-hostname: buzzci-e2e\n")
    user_data = f"""#cloud-config
mounts:
  - [LABEL=BUZZCI_STAGE, /mnt/buzzci-stage, iso9660, 'ro,nosuid,nodev,noexec', '0', '0']
runcmd:
  - [python3, /mnt/buzzci-stage/guest_entry.py, /mnt/buzzci-stage/phase.json]
power_state:
  mode: poweroff
  timeout: {phase_seconds("poweroff")}
  condition: true
"""
    (seed / "user-data").write_text(user_data)
    bounded([TOOLS["cloud_localds"], str(state / "seed.iso"), str(seed / "user-data"), str(seed / "meta-data")])
    (state / "seed.iso").chmod(0o400)
    shutil.rmtree(seed)


def stage_common(state: Path, stage: Path, phase: dict[str, object]) -> None:
    for name in GUEST_ASSETS:
        raw = read_regular(state / "frozen-assets" / name, 2 * 1024 * 1024)
        target = stage / name
        target.write_bytes(raw)
        target.chmod(0o444)
    (stage / "phase.json").write_bytes(canonical(phase))
    (stage / "phase.json").chmod(0o444)


def parse_progress(raw: bytes, boot_role: str) -> dict[str, object]:
    if not raw:
        return {"status": "missing", "records": []}
    if len(raw) > MAX_PROGRESS:
        return {"status": "invalid", "reason": "oversize", "records": []}
    records: list[dict[str, object]] = []
    offset = 0
    last_elapsed = -1
    last_order = -1
    try:
        while offset < len(raw):
            if len(raw) - offset < 36:
                raise HarnessError("truncated")
            length = struct.unpack(">I", raw[offset:offset + 4])[0]
            if length <= 0 or length > 512 or offset + 4 + length + 32 > len(raw):
                raise HarnessError("frame-length")
            payload_start = offset + 4
            payload = raw[payload_start:payload_start + length]
            digest = raw[payload_start + length:payload_start + length + 32]
            if hashlib.sha256(payload).digest() != digest:
                raise HarnessError("digest")
            value = json.loads(payload, object_pairs_hook=reject_duplicates)
            if (
                not isinstance(value, dict)
                or set(value) != {"schema_version", "boot", "sequence", "phase", "event", "elapsed_ms"}
                or value.get("schema_version") != PROGRESS_SCHEMA
                or value.get("boot") != boot_role
                or not isinstance(value.get("sequence"), int)
                or isinstance(value.get("sequence"), bool)
                or value.get("sequence") != len(records)
                or value.get("phase") not in PROGRESS_ORDER
                or value.get("event") not in PROGRESS_EVENTS
                or not isinstance(value.get("elapsed_ms"), int)
                or isinstance(value.get("elapsed_ms"), bool)
                or value["elapsed_ms"] < 0
                or value["elapsed_ms"] > watchdog_seconds(boot_role) * 1000
                or value["elapsed_ms"] < last_elapsed
                or canonical(value) != payload
            ):
                raise HarnessError("record")
            order = PROGRESS_ORDER[str(value["phase"])]
            if (
                order < last_order
                or value["event"] == "complete" and value["phase"] != "complete"
                or value["phase"] == "complete" and value["event"] != "complete"
            ):
                raise HarnessError("order")
            if value["event"] == "timeout" and order != last_order:
                raise HarnessError("stale-timeout")
            records.append(value)
            if len(records) > MAX_PROGRESS_RECORDS:
                raise HarnessError("record-cap")
            last_elapsed = int(value["elapsed_ms"])
            last_order = order
            offset = payload_start + length + 32
    except (HarnessError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return {
            "status": "invalid", "reason": str(error) or type(error).__name__,
            "records": records,
        }
    allowed = {
        "ceremony": {"boot_cloud_init", "guest_started", "ceremony", "complete"},
        "candidate": {
            "boot_cloud_init", "guest_started", "install", "relay_ready",
            "preinstall_units_clean", "package_units_validated", "principals_created",
            "seccomp_ready", "runner_installed", "controld_installed", "keyholder_installed",
            "execd_installed", "installed_units_verified",
            "prior_controller_check", "prior_controller_stage", "prior_controller_activate",
            "prior_rollback", "reinstall", "execd_reinstalled",
            "controller_check", "controller_stage",
            *(f"controller_stage:{name}" for name in STAGE_PROGRESS_SUBPHASES),
            "controller_activate", "canary", "receipt_verifier", "rollback", "cleanup",
            "cleanup_return", "complete",
        },
        "verifier": {"boot_cloud_init", "guest_started", "verifier", "complete"},
    }
    if boot_role not in allowed or any(str(record["phase"]) not in allowed[boot_role] for record in records):
        return {"status": "invalid", "reason": "boot-phase", "records": records}
    return {"status": "valid", "records": records}


def progress_snapshot(path: Path, boot_role: str) -> dict[str, object]:
    try:
        metadata = path.stat()
        if metadata.st_size > MAX_PROGRESS:
            return {"status": "invalid", "reason": "oversize", "records": []}
        return parse_progress(read_regular(path, MAX_PROGRESS), boot_role)
    except FileNotFoundError:
        return {"status": "missing", "reason": "absent", "records": []}
    except (HarnessError, OSError):
        return {"status": "invalid", "reason": "unreadable", "records": []}


def progress_failure(boot_role: str, progress: dict[str, object], *, timed_out: bool) -> HarnessError:
    records = progress.get("records")
    safe_records = records if isinstance(records, list) else []
    timeout_record = next(
        (record for record in reversed(safe_records) if isinstance(record, dict) and record.get("event") == "timeout"),
        None,
    )
    latest = safe_records[-1] if safe_records and isinstance(safe_records[-1], dict) else None
    cleanup_returned = latest is not None and latest.get("phase") == "cleanup_return"
    operational = next((
        record for record in reversed(safe_records)
        if isinstance(record, dict)
        and record.get("phase") not in {"rollback", "cleanup", "cleanup_return"}
    ), None)
    reported = operational if latest is not None and latest.get("phase") in {
        "rollback", "cleanup", "cleanup_return",
    } else latest
    phase = str((timeout_record or reported or latest or {}).get("phase", "boot_cloud_init"))
    if phase == "guest_started":
        phase = "boot_cloud_init"
    detail = {
        "status": progress.get("status", "invalid"),
        "phase": phase,
        "records": len(safe_records),
        "last_sequence": latest.get("sequence") if latest else None,
        "last_elapsed_ms": latest.get("elapsed_ms") if latest else None,
        "cleanup_returned": cleanup_returned,
    }
    if progress.get("status") == "invalid":
        detail["reason"] = progress.get("reason", "invalid")
    failure = "watchdog timeout" if timed_out else "inner timeout" if timeout_record is not None else "guest failure"
    return HarnessError(f"{boot_role} {phase} {failure}; progress={canonical(detail).decode().strip()}")


def progress_completed(progress: dict[str, object]) -> bool:
    records = progress.get("records")
    if progress.get("status") != "valid" or not isinstance(records, list) or not records:
        return False
    terminal = [
        index for index, record in enumerate(records)
        if isinstance(record, dict)
        and record.get("phase") == "complete"
        and record.get("event") == "complete"
    ]
    return (
        terminal == [len(records) - 1]
        and not any(
            isinstance(record, dict) and record.get("event") == "timeout"
            for record in records
        )
    )


def boot(
    state: Path, timeout: int, *, overlay: str,
    evidence_expected: bool, transfer: str | None = None,
) -> dict[str, object] | None:
    boot_role = {
        "ceremony.qcow2": "ceremony",
        "candidate.qcow2": "candidate",
        "verifier.qcow2": "verifier",
    }[overlay]
    if timeout != watchdog_seconds(boot_role):
        raise HarnessError("VM watchdog differs from frozen timing contract")
    evidence = state / "evidence.bin"
    progress_path = state / "progress.bin"
    try:
        evidence.unlink()
    except FileNotFoundError:
        pass
    if evidence_expected:
        evidence_fd = os.open(
            evidence,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        os.close(evidence_fd)
    progress_fd = os.open(
        progress_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    os.close(progress_fd)
    process = subprocess.Popen(
        qemu_command(state, overlay=overlay, evidence=evidence_expected, transfer=transfer), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    try:
        deadline = time.monotonic() + timeout
        timed_out = False
        while process.poll() is None:
            if evidence_expected and evidence.exists() and evidence.stat().st_size > MAX_FRAME + 36:
                raise HarnessError("guest evidence exceeded its bound")
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.05)
        progress = progress_snapshot(progress_path, boot_role)
        code = process.poll()
    finally:
        reap_process_group(process, wait_seconds=REAP_TIMEOUT)
    if timed_out:
        raise progress_failure(boot_role, progress, timed_out=True)
    if code != 0:
        raise progress_failure(boot_role, progress, timed_out=False)
    if not progress_completed(progress):
        raise progress_failure(boot_role, progress, timed_out=False)
    if not evidence_expected:
        if evidence.exists():
            raise HarnessError("candidate phase unexpectedly reached an evidence channel")
        return None
    raw = read_regular(evidence, MAX_FRAME + 36)
    return parse_frame(raw)


def parse_frame(raw: bytes) -> dict[str, object]:
    if len(raw) < 36:
        raise HarnessError("evidence frame is truncated")
    length = struct.unpack(">I", raw[:4])[0]
    if length == 0 or length > MAX_FRAME or len(raw) != 4 + length + 32:
        raise HarnessError("evidence frame length differs")
    payload = raw[4:4 + length]
    if hashlib.sha256(payload).digest() != raw[-32:]:
        raise HarnessError("evidence frame digest differs")
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise HarnessError("evidence frame JSON is invalid") from error
    if not isinstance(value, dict) or value.get("schema_version") != FRAME_SCHEMA:
        raise HarnessError("evidence frame schema differs")
    return value


def clean_transient(state: Path) -> None:
    for name in ("stage.iso", "seed.iso", "evidence.bin", "progress.bin"):
        try:
            (state / name).unlink()
        except FileNotFoundError:
            pass


def state_identity(state: Path) -> StateIdentity:
    state = safe_directory(state)
    metadata = state.lstat()
    marker_raw = read_regular(state / "state.json", MAX_JSON)
    return StateIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        marker_sha256=hashlib.sha256(marker_raw).hexdigest(),
    )


def state_identity_fd(directory_fd: int) -> StateIdentity:
    metadata = os.fstat(directory_fd)
    marker_fd = os.open(
        "state.json", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd,
    )
    try:
        marker_raw = read_fd(marker_fd, "state.json", MAX_JSON)
    finally:
        os.close(marker_fd)
    return StateIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        marker_sha256=hashlib.sha256(marker_raw).hexdigest(),
    )


def directory_identity(path: Path) -> DirectoryIdentity:
    metadata = safe_directory(path).lstat()
    return DirectoryIdentity(metadata.st_dev, metadata.st_ino)


def identity_matches(metadata: os.stat_result, expected: DirectoryIdentity) -> bool:
    return (metadata.st_dev, metadata.st_ino) == (expected.device, expected.inode)


def sanitize_regular_fd(descriptor: int) -> None:
    held = os.fstat(descriptor)
    if not stat.S_ISREG(held.st_mode):
        return
    os.fchmod(descriptor, 0o600)
    writable = os.open(f"/proc/self/fd/{descriptor}", os.O_WRONLY | os.O_CLOEXEC)
    try:
        current = os.fstat(writable)
        if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
            raise HarnessError("cleanup file descriptor identity changed")
        os.fchmod(writable, 0o600)
        os.ftruncate(writable, 0)
        os.fsync(writable)
        os.fchmod(writable, 0)
        os.fsync(writable)
    finally:
        os.close(writable)


def clear_directory_fd(directory_fd: int) -> None:
    with os.scandir(directory_fd) as iterator:
        names = sorted(entry.name for entry in iterator)
    first_error: BaseException | None = None
    for name in names:
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(before.st_mode):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        elif stat.S_ISREG(before.st_mode):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        else:
            flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            item_fd = os.open(name, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            continue
        try:
            held = os.fstat(item_fd)
            if not identity_matches(held, DirectoryIdentity(before.st_dev, before.st_ino)):
                raise HarnessError("cleanup member changed before descriptor acquisition")
            cleanup_checkpoint(
                "clear-directory-member", Path(f"/proc/self/fd/{directory_fd}") / name, item_fd,
            )
            try:
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                member_error: BaseException | None = HarnessError("cleanup member was displaced")
            else:
                member_error = None
                if not identity_matches(current, DirectoryIdentity(held.st_dev, held.st_ino)):
                    member_error = HarnessError("cleanup member was replaced")
            try:
                if stat.S_ISDIR(held.st_mode):
                    sanitize_directory_fd(item_fd)
                elif stat.S_ISREG(held.st_mode):
                    sanitize_regular_fd(item_fd)
                    if name == RUN_OWNERSHIP:
                        cleanup_checkpoint(
                            "after-run-ownership-zero",
                            Path(f"/proc/self/fd/{directory_fd}") / name,
                            item_fd,
                        )
            except BaseException as error:
                if first_error is None:
                    first_error = error
            if member_error is not None and first_error is None:
                first_error = member_error
        finally:
            os.close(item_fd)
    if first_error is not None:
        raise first_error


def sanitize_directory_fd(directory_fd: int) -> None:
    primary: BaseException | None = None
    try:
        clear_directory_fd(directory_fd)
    except BaseException as error:
        primary = error
    try:
        os.fsync(directory_fd)
        os.fchmod(directory_fd, 0)
        os.fsync(directory_fd)
    except BaseException as error:
        if primary is None:
            raise
        raise HarnessError(f"directory sanitization failed: {error}") from primary
    if primary is not None:
        raise primary


def raise_cleanup_failure(label: str, primary: BaseException | None, cleanup: BaseException) -> None:
    if primary is None:
        raise HarnessError(f"{label} sanitization failed: {cleanup}") from cleanup
    raise HarnessError(f"{label} failed and sanitization failed: {cleanup}") from primary


def destroy_identified_directory(
    path: Path, expected: DirectoryIdentity, label: str,
    verify_cleanup_authority: Callable[[int], None] | None = None,
) -> None:
    directory_fd = open_absolute(path, directory=True)
    quarantine = path.with_name(f".{path.name}.tombstone-{os.urandom(16).hex()}")
    primary: BaseException | None = None
    durability_failure: BaseException | None = None
    try:
        if not identity_matches(os.fstat(directory_fd), expected):
            raise HarnessError(f"refusing to destroy a replaced {label}")
        if verify_cleanup_authority is not None:
            verify_cleanup_authority(directory_fd)
        try:
            rename_noreplace(path, quarantine)
            observed = quarantine.lstat()
            if (
                not identity_matches(observed, expected)
                or not identity_matches(os.fstat(directory_fd), expected)
            ):
                raise HarnessError(f"refusing to destroy a replaced {label}")
            try:
                fsync_parent(path)
            except BaseException as error:
                durability_failure = error
                raise
            cleanup_checkpoint("before-directory-tombstone-retention", quarantine, directory_fd)
            current = quarantine.lstat()
            if not identity_matches(current, expected):
                raise HarnessError(f"{label} tombstone was replaced")
        except BaseException as error:
            primary = error
        if durability_failure is not None:
            raise CleanupDurabilityError(
                f"{label} tombstone durability failed: {durability_failure}",
            ) from primary
        if verify_cleanup_authority is not None:
            cleanup_checkpoint(
                "before-owned-directory-sanitization", quarantine, directory_fd,
            )
            verify_cleanup_authority(directory_fd)
        try:
            sanitize_directory_fd(directory_fd)
        except BaseException as cleanup_error:
            raise_cleanup_failure(label, primary, cleanup_error)
        try:
            fsync_parent(path)
        except BaseException as cleanup_error:
            raise_cleanup_failure(label, primary, cleanup_error)
        if primary is not None:
            raise primary
    finally:
        os.close(directory_fd)


def destroy_state(state: Path, expected: StateIdentity | None = None) -> None:
    marker = state / "state.json"
    try:
        state.lstat()
    except FileNotFoundError:
        return
    state = safe_directory(state)
    if not marker.is_file():
        raise HarnessError("refusing to destroy an unrecognized state directory")
    observed = state_identity(state)
    if expected is not None and observed != expected:
        raise HarnessError("refusing to destroy a replaced VM state directory")
    value = load_json(marker)
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema_version", "challenge", "image_sha256", "qemu_sha256", "qemu_img_sha256",
            "qemu_version", "tool_sha256", "harness_sha256", "harness_asset_sha256",
            "timing_asset_sha256", "timing", "timing_sha256", "trusted_image_sha256",
        }
        or value.get("schema_version") != STATE_SCHEMA
        or not isinstance(value.get("challenge"), str) or HEX64.fullmatch(value["challenge"]) is None
        or any(not isinstance(value.get(name), str) or HEX64.fullmatch(value[name]) is None for name in (
            "image_sha256", "qemu_sha256", "qemu_img_sha256",
        ))
        or value.get("trusted_image_sha256") is not None
        and (not isinstance(value["trusted_image_sha256"], str) or HEX64.fullmatch(value["trusted_image_sha256"]) is None)
        or not isinstance(value.get("qemu_version"), str) or not value["qemu_version"]
        or not isinstance(value.get("tool_sha256"), dict) or set(value["tool_sha256"]) != set(TOOLS)
        or not isinstance(value.get("harness_asset_sha256"), dict) or set(value["harness_asset_sha256"]) != set(FROZEN_ASSETS)
        or not isinstance(value.get("harness_sha256"), str) or HEX64.fullmatch(value["harness_sha256"]) is None
        or value.get("timing_asset_sha256") != value["harness_asset_sha256"].get("timing-contract.json")
        or value.get("timing") != TIMING_CONTRACT
        or value.get("timing_sha256") != timing_sha256()
    ):
        raise HarnessError("refusing to destroy an unrecognized state directory")
    identity = expected or observed
    destroy_identified_directory(state, identity, "VM state directory")


def prepare(arguments: argparse.Namespace) -> dict[str, object]:
    proof = capabilities()
    if file_sha256(Path(TOOLS["qemu"])) != arguments.qemu_sha256:
        raise HarnessError("QEMU digest differs")
    if file_sha256(Path(TOOLS["qemu_img"])) != arguments.qemu_img_sha256:
        raise HarnessError("qemu-img digest differs")
    if not 1 <= arguments.controld_uid <= 0xFFFFFFFF or not 1 <= arguments.controld_gid <= 0xFFFFFFFF:
        raise HarnessError("controld identity is invalid")
    image = Path(os.path.abspath(arguments.image))
    if Path(os.path.realpath(image)) != image:
        raise HarnessError("base image path must not contain symbolic links")
    here = Path(__file__).resolve().parent
    asset_digests = {name: file_sha256(asset_source(here, name)) for name in FROZEN_ASSETS}
    state, created_identity = create_prepare_directory(arguments.state)
    try:
        challenge = os.urandom(32).hex()
        state_record = {
            "schema_version": STATE_SCHEMA,
            "challenge": challenge,
            "image_sha256": arguments.image_sha256,
            "qemu_sha256": arguments.qemu_sha256,
            "qemu_img_sha256": arguments.qemu_img_sha256,
            "qemu_version": proof["qemu_version"],
            "tool_sha256": proof["tool_sha256"],
            "harness_sha256": proof["harness_sha256"],
            "harness_asset_sha256": asset_digests,
            "timing_asset_sha256": proof["timing_asset_sha256"],
            "timing": TIMING_CONTRACT,
            "timing_sha256": proof["timing_sha256"],
            "trusted_image_sha256": None,
        }
        (state / "state.json").write_bytes(canonical(state_record))
        (state / "state.json").chmod(0o400)
        frozen = state / "frozen-assets"
        frozen.mkdir(mode=0o700)
        for name, digest in asset_digests.items():
            copy_bound(asset_source(here, name), frozen / name, digest)
        copy_bound(image, state / "base.qcow2", arguments.image_sha256)
        validate_flat_qcow2(state, "base.qcow2")
        qemu_img_create(state, "ceremony.qcow2", "base.qcow2")
        stage = state / "stage"
        stage.mkdir(mode=0o700)
        stage_common(state, stage, {
            "schema_version": "buzz-ci-clean-host-e2e-guest-phase/v3",
            "phase": "ceremony", "challenge": challenge,
            "controld_uid": arguments.controld_uid, "controld_gid": arguments.controld_gid,
            "timing": TIMING_CONTRACT, "timing_sha256": timing_sha256(),
        })
        make_iso(stage, state / "stage.iso", "BUZZCI_STAGE")
        shutil.rmtree(stage)
        make_seed(state, "buzzci-ceremony-" + challenge[:16])
        frame = boot(state, watchdog_seconds("ceremony"), overlay="ceremony.qcow2", evidence_expected=True)
        expected = {"schema_version", "phase", "challenge", "outcome", "public_binding", "raw_key_absence"}
        if set(frame) != expected or frame["phase"] != "ceremony" or frame["challenge"] != challenge or frame["outcome"] != "pass":
            raise HarnessError("key ceremony evidence differs")
        if frame["raw_key_absence"] is not True or not isinstance(frame["public_binding"], dict):
            raise HarnessError("key ceremony did not prove raw-key destruction")
        public_path = state / "public-binding.json"
        public_path.write_bytes(canonical(frame["public_binding"]))
        public_path.chmod(0o444)
        clean_transient(state)
        trusted_digest = flatten_ceremony(state)
        state_record["trusted_image_sha256"] = trusted_digest
        marker = state / "state.json"
        marker.chmod(0o600)
        marker.write_bytes(canonical(state_record))
        marker.chmod(0o400)
        return {
            "status": "prepared", "state": str(state), "public_binding": str(public_path),
            "raw_key_absence": True, "harness_sha256": proof["harness_sha256"],
            "timing_asset_sha256": proof["timing_asset_sha256"],
            "timing_sha256": proof["timing_sha256"], "timing": TIMING_CONTRACT,
        }
    except BaseException:
        destroy_identified_directory(state, created_identity, "new prepare state directory")
        raise


def validate_prepared_state(state: Path) -> dict[str, object]:
    """Revalidate every prepared host input before a trusted VM use."""
    state = safe_directory(state)
    state_record = load_json(state / "state.json")
    if (
        not isinstance(state_record, dict)
        or set(state_record) != {
            "schema_version", "challenge", "image_sha256", "qemu_sha256", "qemu_img_sha256",
            "qemu_version", "tool_sha256", "harness_sha256", "harness_asset_sha256",
            "timing_asset_sha256", "timing", "timing_sha256", "trusted_image_sha256",
        }
        or state_record.get("schema_version") != STATE_SCHEMA
    ):
        raise HarnessError("VM state binding differs")
    if file_sha256(Path(TOOLS["qemu"])) != state_record.get("qemu_sha256"):
        raise HarnessError("QEMU changed after key ceremony")
    if file_sha256(Path(TOOLS["qemu_img"])) != state_record.get("qemu_img_sha256"):
        raise HarnessError("qemu-img changed after key ceremony")
    tool_digests = state_record.get("tool_sha256")
    if (
        not isinstance(tool_digests, dict)
        or set(tool_digests) != set(TOOLS)
        or any(not isinstance(digest, str) or HEX64.fullmatch(digest) is None for digest in tool_digests.values())
    ):
        raise HarnessError("VM harness tool binding differs")
    if any(file_sha256(Path(TOOLS[name])) != digest for name, digest in tool_digests.items()):
        raise HarnessError("VM harness tool changed after key ceremony")
    if (
        state_record.get("harness_sha256") != current_harness_sha256()
        or state_record.get("timing_asset_sha256") != timing_asset_sha256()
        or state_record.get("timing") != TIMING_CONTRACT
        or state_record.get("timing_sha256") != timing_sha256()
    ):
        raise HarnessError("prepared harness or timing contract changed after key ceremony")
    asset_digests = state_record.get("harness_asset_sha256")
    if (
        not isinstance(asset_digests, dict)
        or set(asset_digests) != set(FROZEN_ASSETS)
        or any(not isinstance(digest, str) or HEX64.fullmatch(digest) is None for digest in asset_digests.values())
        or any(file_sha256(state / "frozen-assets" / name) != digest for name, digest in asset_digests.items())
    ):
        raise HarnessError("frozen harness asset binding differs")
    trusted_digest = state_record.get("trusted_image_sha256")
    if not isinstance(trusted_digest, str) or HEX64.fullmatch(trusted_digest) is None:
        raise HarnessError("trusted ceremony image binding differs")
    if file_sha256(state / "trusted.qcow2") != trusted_digest:
        raise HarnessError("trusted ceremony image changed after preparation")
    validate_flat_qcow2(state, "trusted.qcow2")
    return state_record


def validate_contract_envelope(value: object) -> dict[str, object]:
    required = {
        "schema_version", "state", "candidate_root", "candidate_sha", "harness_sha256",
        "timing_asset_sha256", "timing", "timing_sha256", "scenario", "seccomp_source", "packages",
        "platform_systemd", "prior_packages", "prior_scenario",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != SCHEMA:
        raise HarnessError("run contract shape differs")
    if not isinstance(value.get("state"), str) or not value["state"]:
        raise HarnessError("run contract state path differs")
    if not isinstance(value.get("candidate_sha"), str) or HEX40.fullmatch(value["candidate_sha"]) is None:
        raise HarnessError("candidate SHA is invalid")
    if (
        value.get("harness_sha256") != current_harness_sha256()
        or value.get("timing_asset_sha256") != timing_asset_sha256()
        or value.get("timing") != TIMING_CONTRACT
        or value.get("timing_sha256") != timing_sha256()
    ):
        raise HarnessError("run contract harness or timing binding differs")
    if value.get("platform_systemd") != PLATFORM_SYSTEMD:
        raise HarnessError("run contract systemd platform binding differs")
    return value


def scenario_bytes(value: object, label: str) -> bytes:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"} or HEX64.fullmatch(str(value["sha256"])) is None:
        raise HarnessError(f"{label} descriptor differs")
    raw = read_regular(safe_input_file(Path(str(value["path"]))), MAX_JSON)
    if hashlib.sha256(raw).hexdigest() != value["sha256"]:
        raise HarnessError(f"{label} digest differs")
    scenario_value = decode_result_json(raw, "scenario.json")
    driver = scenario_value.get("driver") if isinstance(scenario_value, dict) else None
    if (
        not isinstance(driver, dict)
        or driver.get("timeout_seconds") != TIMING_CONTRACT["leaf_seconds"]["driver_operation"]
    ):
        raise HarnessError(f"{label} driver timeout differs from frozen timing contract")
    return raw


def package_tree_records(packages: object, names: tuple[str, ...], label: str) -> dict[str, list[tuple[str, int, bytes]]]:
    if not isinstance(packages, dict) or set(packages) != set(names):
        raise HarnessError(f"{label} set differs")
    records: dict[str, list[tuple[str, int, bytes]]] = {}
    for name in names:
        descriptor = packages[name]
        if not isinstance(descriptor, dict) or set(descriptor) != {"path", "tree_sha256"} or HEX64.fullmatch(str(descriptor["tree_sha256"])) is None:
            raise HarnessError(f"{label} descriptor differs: {name}")
        item_records = tree_records(safe_input_directory(Path(str(descriptor["path"]))))
        if tree_digest(item_records) != descriptor["tree_sha256"]:
            raise HarnessError(f"{label} tree digest differs: {name}")
        records[name] = item_records
    return records


def prior_activation_binding(records: dict[str, list[tuple[str, int, bytes]]]) -> dict[str, str]:
    """The prior activation identity the verifier boot must find in the pending evidence."""
    manifest_raw = next(
        (raw for relative, _mode, raw in records.get("prior/activation", []) if relative == "activation-manifest.json"),
        None,
    )
    if manifest_raw is None:
        raise HarnessError("prior activation manifest is absent")
    manifest = decode_result_json(manifest_raw, "activation-manifest.json")
    if not isinstance(manifest, dict):
        raise HarnessError("prior activation manifest differs")
    activation_id = manifest.get("activation_id")
    package_digest = manifest.get("package_digest")
    if (
        not isinstance(activation_id, str) or not activation_id
        or not isinstance(package_digest, str) or HEX64.fullmatch(package_digest) is None
    ):
        raise HarnessError("prior activation identity differs")
    current_raw = next(
        (raw for relative, _mode, raw in records.get("activation", []) if relative == "activation-manifest.json"),
        None,
    )
    current = decode_result_json(current_raw, "activation-manifest.json") if current_raw is not None else None
    if (
        not isinstance(current, dict)
        or current.get("activation_id") == activation_id
        or current.get("package_digest") == package_digest
    ):
        raise HarnessError("prior activation does not differ from the candidate activation")
    return {"activation_id": activation_id, "package_digest": package_digest}


def validate_contract_value(
    value: dict[str, object], *, selected_state: Path | None = None,
) -> tuple[
    dict[str, object], Path, dict[str, list[tuple[str, int, bytes]]], bytes, bytes, bytes,
]:
    validate_contract_envelope(value)
    state = selected_state if selected_state is not None else safe_directory(Path(value["state"]))
    state_record = validate_prepared_state(state)
    if (
        state_record["harness_sha256"] != value["harness_sha256"]
        or state_record["timing_asset_sha256"] != value["timing_asset_sha256"]
        or state_record["timing_sha256"] != value["timing_sha256"]
    ):
        raise HarnessError("prepared state differs from run contract harness binding")
    if selected_state is None:
        try:
            (state / RUN_OWNERSHIP).lstat()
        except FileNotFoundError:
            pass
        else:
            raise HarnessError("VM state is already owned by a terminal run")
    candidate = safe_input_directory(Path(str(value["candidate_root"])))
    resolved = bounded(["/usr/bin/git", "-C", str(candidate), "rev-parse", f"{value['candidate_sha']}^{{commit}}"] ).decode().strip()
    if resolved != value["candidate_sha"]:
        raise HarnessError("candidate commit object differs")
    candidate_harness = bounded([
        "/usr/bin/git", "-C", str(candidate), "show",
        f"{value['candidate_sha']}:deploy/native-ci/activation/tests/clean_host_e2e/harness.py",
    ], maximum=2 * 1024 * 1024)
    if hashlib.sha256(candidate_harness).hexdigest() != value["harness_sha256"]:
        raise HarnessError("candidate commit harness binding differs")
    candidate_timing = bounded([
        "/usr/bin/git", "-C", str(candidate), "show",
        f"{value['candidate_sha']}:deploy/native-ci/activation/tests/clean_host_e2e/timing-contract.json",
    ], maximum=MAX_JSON)
    try:
        candidate_timing_value = json.loads(candidate_timing, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise HarnessError("candidate commit timing asset JSON differs") from error
    if (
        hashlib.sha256(candidate_timing).hexdigest() != value["timing_asset_sha256"]
        or candidate_timing_value != TIMING_CONTRACT
    ):
        raise HarnessError("candidate commit timing asset binding differs")
    for relative in REQUIRED_CANDIDATE:
        if not bounded(["/usr/bin/git", "-C", str(candidate), "cat-file", "-e", f"{value['candidate_sha']}:{relative}"], maximum=1024) == b"":
            raise HarnessError("candidate prerequisite probe returned output")
    records = package_tree_records(value["packages"], PACKAGE_NAMES, "package")
    for name, item_records in package_tree_records(value["prior_packages"], PRIOR_PACKAGE_NAMES, "prior package").items():
        records[f"prior/{name}"] = item_records
    prior_activation_binding(records)
    scenario_raw = scenario_bytes(value["scenario"], "scenario")
    prior_scenario_raw = scenario_bytes(value["prior_scenario"], "prior scenario")
    seccomp = value["seccomp_source"]
    if not isinstance(seccomp, dict) or set(seccomp) != {"path", "sha256"} or seccomp.get("sha256") != SECCOMP_SHA256:
        raise HarnessError("seccomp source descriptor differs")
    seccomp_raw = read_regular(safe_input_file(Path(str(seccomp["path"]))), 16 * 1024 * 1024)
    if hashlib.sha256(seccomp_raw).hexdigest() != SECCOMP_SHA256:
        raise HarnessError("seccomp source digest differs")
    return value, state, records, scenario_raw, seccomp_raw, prior_scenario_raw


def validate_contract(
    path: Path,
) -> tuple[
    dict[str, object], Path, dict[str, list[tuple[str, int, bytes]]], bytes, bytes,
]:
    return validate_contract_value(validate_contract_envelope(load_json(path)))


def state_identity_record(expected: StateIdentity) -> dict[str, object]:
    return {
        "device": expected.device,
        "inode": expected.inode,
        "marker_sha256": expected.marker_sha256,
    }


def run_ownership_record(
    binding: dict[str, str], expected: StateIdentity,
) -> dict[str, object]:
    ownership = publication_record(binding, "running")
    ownership.pop("schema_version")
    ownership.pop("phase")
    ownership["schema_version"] = "buzz-ci-clean-host-e2e-run-ownership/v2"
    ownership["state_identity"] = state_identity_record(expected)
    return ownership


def read_run_ownership(directory_fd: int) -> object:
    descriptor = os.open(
        RUN_OWNERSHIP, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        raw = read_fd(descriptor, RUN_OWNERSHIP, MAX_JSON)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise HarnessError(f"invalid JSON: {RUN_OWNERSHIP}") from error
    if canonical(value) != raw:
        raise HarnessError("run ownership encoding differs")
    return value


def run_ownership_pending_name(
    ownership: dict[str, object], expected: StateIdentity,
) -> str:
    digest = hashlib.sha256(
        canonical(ownership) + canonical(state_identity_record(expected)),
    ).hexdigest()
    return f"{RUN_OWNERSHIP_PENDING_PREFIX}{digest}{RUN_OWNERSHIP_PENDING_SUFFIX}"


def run_ownership_pending_names(directory_fd: int) -> set[str]:
    fresh_fd = os.open(
        ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        with os.scandir(fresh_fd) as iterator:
            return {
                entry.name for entry in iterator
                if entry.name.startswith(RUN_OWNERSHIP_PENDING_PREFIX)
            }
    finally:
        os.close(fresh_fd)


def write_all(descriptor: int, raw: bytes, label: str) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise HarnessError(f"private record write was incomplete: {label}")
        offset += written


def write_pending_run_ownership(
    directory_fd: int, pending_name: str, ownership: dict[str, object],
    acquired: Callable[[], None],
) -> bool:
    existed = False
    try:
        descriptor = os.open(
            pending_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
    except FileExistsError:
        existed = True
        descriptor = os.open(
            pending_name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in {0, 0o400, 0o600}
        ):
            raise HarnessError("run ownership pending record differs")
        acquired()
        claim_checkpoint(
            "after-ownership-pending-open",
            Path(f"/proc/self/fd/{directory_fd}") / pending_name,
            descriptor,
        )
        os.fchmod(descriptor, 0o600)
        writable = os.open(f"/proc/self/fd/{descriptor}", os.O_WRONLY | os.O_CLOEXEC)
        raw = canonical(ownership)
        try:
            os.ftruncate(writable, 0)
            write_all(writable, raw, pending_name)
            os.fsync(writable)
        finally:
            os.close(writable)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if read_fd(descriptor, pending_name, MAX_JSON) != raw:
            raise HarnessError("run ownership pending record readback differs")
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)
    return existed


def discard_pending_run_ownership(directory_fd: int, pending_name: str) -> None:
    descriptor = os.open(
        pending_name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        expected = os.fstat(descriptor)
        if not stat.S_ISREG(expected.st_mode) or expected.st_uid != os.geteuid() or expected.st_nlink != 1:
            raise HarnessError("run ownership pending record differs")
        sanitize_regular_fd(descriptor)
        current = os.stat(pending_name, dir_fd=directory_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            raise HarnessError("run ownership pending record was replaced")
        os.unlink(pending_name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(descriptor)


def publish_run_ownership(
    directory_fd: int, ownership: dict[str, object], expected: StateIdentity,
    acquired: Callable[[], None],
) -> bool:
    if state_identity_fd(directory_fd) != expected:
        raise HarnessError("run ownership state identity differs")
    pending_name = run_ownership_pending_name(ownership, expected)
    pending_names = run_ownership_pending_names(directory_fd)
    foreign = pending_names - {pending_name}
    if foreign:
        raise HarnessError("run ownership pending transaction differs")
    try:
        os.stat(RUN_OWNERSHIP, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        pending_existed = write_pending_run_ownership(
            directory_fd, pending_name, ownership, acquired,
        )
        try:
            rename_noreplace_at(
                directory_fd, os.fsencode(pending_name),
                directory_fd, os.fsencode(RUN_OWNERSHIP), RUN_OWNERSHIP,
            )
        except BaseException:
            try:
                acknowledged = (
                    canonical(read_run_ownership(directory_fd)) == canonical(ownership)
                    and pending_name not in run_ownership_pending_names(directory_fd)
                )
            except BaseException:
                acknowledged = False
            if not acknowledged:
                raise
        os.fsync(directory_fd)
        return pending_existed
    if canonical(read_run_ownership(directory_fd)) != canonical(ownership):
        raise HarnessError("VM state ownership differs")
    acquired()
    if pending_name in pending_names:
        discard_pending_run_ownership(directory_fd, pending_name)
    return True


def verify_run_ownership_cleanup_authority(
    directory_fd: int, ownership: dict[str, object], expected: StateIdentity,
) -> None:
    if state_identity_fd(directory_fd) != expected:
        raise HarnessError("run ownership cleanup state identity differs")
    pending_name = run_ownership_pending_name(ownership, expected)
    pending_names = run_ownership_pending_names(directory_fd)
    if pending_names - {pending_name}:
        raise HarnessError("run ownership cleanup pending transaction differs")
    try:
        canonical_ownership = canonical(read_run_ownership(directory_fd))
    except FileNotFoundError:
        if pending_names != {pending_name}:
            raise HarnessError("run ownership cleanup authority is absent")
        descriptor = os.open(
            pending_name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) not in {0, 0o400, 0o600}
            ):
                raise HarnessError("run ownership cleanup pending record differs")
        finally:
            os.close(descriptor)
        return
    if canonical_ownership != canonical(ownership):
        raise HarnessError("run ownership cleanup authority differs")


def destroy_run_state(
    state: Path, expected: StateIdentity, binding: dict[str, str],
) -> None:
    ownership = run_ownership_record(binding, expected)

    def verify(directory_fd: int) -> None:
        verify_run_ownership_cleanup_authority(
            directory_fd, ownership, expected,
        )

    destroy_identified_directory(
        state, expected, "VM state directory", verify,
    )


def path_matches_identity(path: Path, expected: DirectoryIdentity) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return identity_matches(metadata, expected)


def sanitize_selected_state(
    state: Path, claimed: Path, expected: StateIdentity, directory_fd: int,
    primary: BaseException, ownership: dict[str, object],
) -> None:
    def verify(candidate_fd: int) -> None:
        verify_run_ownership_cleanup_authority(candidate_fd, ownership, expected)

    cleanup_errors: list[BaseException] = []
    located = False
    for path in (claimed, state):
        try:
            matches = path_matches_identity(path, expected)
        except BaseException as error:
            cleanup_errors.append(error)
            continue
        if not matches:
            continue
        located = True
        try:
            destroy_identified_directory(
                path, expected, "selected VM state directory", verify,
            )
        except BaseException as error:
            cleanup_errors.append(error)
        break
    durability_failed = any(isinstance(error, CleanupDurabilityError) for error in cleanup_errors)
    if not durability_failed and (not located or cleanup_errors):
        fresh_fd: int | None = None
        try:
            fresh_fd = os.open(
                ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            cleanup_checkpoint(
                "before-owned-directory-sanitization",
                Path(f"/proc/self/fd/{fresh_fd}"), fresh_fd,
            )
            verify(fresh_fd)
            sanitize_directory_fd(fresh_fd)
        except BaseException as error:
            cleanup_errors.append(error)
        finally:
            if fresh_fd is not None:
                os.close(fresh_fd)
    if cleanup_errors:
        detail = "; ".join(str(error) or type(error).__name__ for error in cleanup_errors)
        raise HarnessError(f"terminal run cleanup failed: {detail}") from primary


def acquire_claim_lock(binding: dict[str, str]) -> int:
    state = Path(binding["original_state"])
    parent_fd = open_absolute(state.parent, directory=True)
    deadline = time.monotonic() + CLAIM_LOCK_TIMEOUT
    try:
        while True:
            try:
                fcntl.flock(parent_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as error:
                if time.monotonic() >= deadline:
                    raise HarnessError("timed out waiting for terminal run state lock") from error
                time.sleep(CLAIM_LOCK_POLL)
        claim_checkpoint("after-claim-lock", state, parent_fd)
        return parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def release_claim_lock(parent_fd: int) -> None:
    try:
        fcntl.flock(parent_fd, fcntl.LOCK_UN)
    finally:
        os.close(parent_fd)


def _claim_run_state_locked(
    binding: dict[str, str], parent_fd: int,
) -> tuple[Path, StateIdentity, bool]:
    """Claim or resume the exact contract-bound prepared state."""
    state = Path(binding["original_state"])
    claimed = Path(binding["claimed_state"])
    state_present = False
    claimed_present = False
    try:
        state.lstat()
        state_present = True
    except FileNotFoundError:
        pass
    try:
        claimed.lstat()
        claimed_present = True
    except FileNotFoundError:
        pass
    if state_present and claimed_present:
        raise HarnessError("original and claimed VM state both exist")
    if not state_present and not claimed_present:
        raise FileNotFoundError(state)
    selected = safe_directory(claimed if claimed_present else state)
    validate_prepared_state(selected)
    directory_fd = open_absolute(selected, directory=True)
    cleanup_allowed = False
    try:
        expected = state_identity_fd(directory_fd)
        if state_identity(selected) != expected:
            raise HarnessError("prepared VM state changed during selection")
        ownership = run_ownership_record(binding, expected)
        def acquired() -> None:
            nonlocal cleanup_allowed
            if state_identity_fd(directory_fd) != expected:
                raise HarnessError("run ownership state identity differs")
            cleanup_allowed = True

        ownership_existed = publish_run_ownership(
            directory_fd, ownership, expected, acquired,
        )
        if claimed_present:
            claim_checkpoint("resumed-claim", claimed, directory_fd)
            validate_prepared_state(claimed)
            if state_identity(claimed) != expected:
                raise HarnessError("claimed VM state changed during resume")
            return claimed, expected, True

        lost_acknowledgement = False
        current = os.stat(state.name, dir_fd=parent_fd, follow_symlinks=False)
        if not identity_matches(current, expected):
            raise HarnessError("prepared VM state changed before run ownership")
        claim_checkpoint("before-claim-rename", state, directory_fd)
        current = os.stat(state.name, dir_fd=parent_fd, follow_symlinks=False)
        if not identity_matches(current, expected):
            raise HarnessError("prepared VM state changed before run ownership")
        try:
            rename_noreplace_at(
                parent_fd, os.fsencode(state.name), parent_fd, os.fsencode(claimed.name),
                str(claimed),
            )
        except BaseException:
            try:
                original_missing = not path_matches_identity(state, expected) and not state.exists()
                claim_is_selected = path_matches_identity(claimed, expected)
            except BaseException:
                raise
            if not original_missing or not claim_is_selected:
                raise
            lost_acknowledgement = True
        os.fsync(parent_fd)
        claim_checkpoint("after-claim-rename", claimed, directory_fd)
        try:
            state_metadata = state.lstat()
        except FileNotFoundError:
            pass
        else:
            if identity_matches(state_metadata, expected):
                raise HarnessError("prepared VM state remained after run ownership transfer")
            raise HarnessError("prepared VM state path was replaced during run ownership transfer")
        if not path_matches_identity(claimed, expected):
            raise HarnessError("prepared VM state changed during run ownership transfer")
        validate_prepared_state(claimed)
        if state_identity(claimed) != expected or state_identity_fd(directory_fd) != expected:
            raise HarnessError("prepared VM state changed during run ownership transfer")
        return claimed, expected, ownership_existed or lost_acknowledgement
    except BaseException as claim_error:
        if cleanup_allowed:
            sanitize_selected_state(
                state, claimed, expected, directory_fd, claim_error, ownership,
            )
        raise
    finally:
        os.close(directory_fd)


def claim_run_state(binding: dict[str, str]) -> tuple[Path, StateIdentity, bool]:
    parent_fd = acquire_claim_lock(binding)
    try:
        return _claim_run_state_locked(binding, parent_fd)
    finally:
        release_claim_lock(parent_fd)


def terminal_run(contract_path: Path, results: Path, relay_fault: str | None = None) -> dict[str, object]:
    """Own cleanup from prepared-state selection through terminal run exit."""
    value = validate_contract_envelope(load_json(contract_path))
    binding = run_binding(value, results)
    parent_fd = acquire_claim_lock(binding)
    try:
        return _terminal_run_locked(value, binding, results, parent_fd, relay_fault)
    finally:
        release_claim_lock(parent_fd)


def _terminal_run_locked(
    value: dict[str, object], binding: dict[str, str], results: Path, parent_fd: int,
    relay_fault: str | None = None,
) -> dict[str, object]:
    publication = load_publication(binding)
    try:
        claimed, expected, resumed = _claim_run_state_locked(binding, parent_fd)
    except FileNotFoundError:
        if publication is not None and publication.get("phase") == "ready":
            return finish_publication(value, binding, publication["outcome"])
        if publication is not None:
            cleanup_publication(binding)
            raise HarnessError("interrupted terminal run had no remaining VM state")
        try:
            Path(binding["results"]).lstat()
        except FileNotFoundError:
            pass
        else:
            return validate_result_set(value, Path(binding["results"]))
        raise
    if resumed and publication is not None:
        cleanup_errors: list[BaseException] = []
        try:
            destroy_run_state(claimed, expected, binding)
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
        if publication.get("phase") != "ready" or cleanup_errors:
            try:
                cleanup_publication(binding)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            detail = "; ".join(str(error) or type(error).__name__ for error in cleanup_errors)
            raise HarnessError(f"terminal run cleanup failed: {detail}")
        if publication.get("phase") == "ready":
            return finish_publication(value, binding, publication["outcome"])
        raise HarnessError("interrupted terminal result staging was cleaned")
    handed_to_run = False
    try:
        contract, state, records, scenario_raw, seccomp_raw, prior_scenario_raw = validate_contract_value(
            value, selected_state=claimed,
        )
        handed_to_run = True
        return run_vm(
            contract, state, records, scenario_raw, seccomp_raw, results,
            prior_scenario_raw=prior_scenario_raw,
            expected_state=expected, binding=binding, resumed=resumed,
            relay_fault=relay_fault,
        )
    except BaseException as run_error:
        if handed_to_run:
            raise
        cleanup_errors: list[BaseException] = []
        try:
            destroy_run_state(claimed, expected, binding)
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
        if publication is not None or resumed:
            try:
                cleanup_publication(binding)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            detail = "; ".join(str(error) or type(error).__name__ for error in cleanup_errors)
            raise HarnessError(f"terminal run cleanup failed: {detail}") from run_error
        raise


def unlink_identified_file(path: Path) -> None:
    try:
        descriptor = open_absolute(path)
    except FileNotFoundError:
        return
    quarantine = path.with_name(f".{path.name}.tombstone-{os.urandom(16).hex()}")
    primary: BaseException | None = None
    try:
        expected = os.fstat(descriptor)
        if not stat.S_ISREG(expected.st_mode):
            raise HarnessError("private record is not a regular file")
        try:
            rename_noreplace(path, quarantine)
            observed = quarantine.lstat()
            if (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino):
                raise HarnessError("private record was replaced before cleanup")
            cleanup_checkpoint("before-file-tombstone-retention", quarantine, descriptor)
            current = quarantine.lstat()
            if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
                raise HarnessError("private record tombstone was replaced")
        except BaseException as error:
            primary = error
        try:
            sanitize_regular_fd(descriptor)
        except BaseException as cleanup_error:
            raise_cleanup_failure("private record cleanup", primary, cleanup_error)
        try:
            fsync_parent(path)
        except BaseException as cleanup_error:
            raise_cleanup_failure("private record cleanup", primary, cleanup_error)
        if primary is not None:
            raise primary
    finally:
        os.close(descriptor)


def cleanup_publication(binding: dict[str, str]) -> None:
    staging = Path(binding["staging"])
    journal = Path(binding["journal"])
    publication = load_publication(binding)
    try:
        staging.lstat()
    except FileNotFoundError:
        pass
    else:
        if publication is None:
            raise HarnessError("refusing to remove unjournaled result staging")
        destroy_identified_directory(
            staging,
            parse_directory_identity(publication["staging_identity"]),
            "private result staging directory",
        )
    try:
        journal.lstat()
    except FileNotFoundError:
        pass
    else:
        unlink_identified_file(journal)


def start_publication(
    binding: dict[str, str], resumed: bool,
) -> tuple[Path, dict[str, object] | None, DirectoryIdentity]:
    final = Path(binding["results"])
    staging = Path(binding["staging"])
    publication = load_publication(binding)
    try:
        final.lstat()
    except FileNotFoundError:
        pass
    else:
        if publication is not None and publication.get("phase") == "ready":
            return final, publication["outcome"], parse_directory_identity(publication["staging_identity"])
        raise FileExistsError(final)
    if publication is not None:
        if not resumed:
            raise HarnessError("result publication journal exists without resumed state")
        try:
            staging.lstat()
        except FileNotFoundError as error:
            raise HarnessError("result publication staging is missing") from error
        staging = safe_directory(staging)
        identity = parse_directory_identity(publication["staging_identity"])
        if directory_identity(staging) != identity:
            raise HarnessError("result publication staging identity differs")
        if publication.get("phase") == "ready":
            return staging, publication["outcome"], identity
        raise HarnessError("interrupted terminal result staging requires cleanup")
    try:
        staging.lstat()
    except FileNotFoundError:
        staging = safe_directory(staging, create=True)
    else:
        if resumed:
            staging = safe_directory(staging)
            raise HarnessError("interrupted unjournaled result staging requires cleanup")
        raise FileExistsError(staging)
    identity = directory_identity(staging)
    write_new_private_json(
        Path(binding["journal"]),
        publication_record(binding, "running", staging_identity=identity),
    )
    return staging, None, identity


def validate_result_set(
    contract: dict[str, object], directory: Path, outcome: dict[str, object] | None = None,
    expected_identity: DirectoryIdentity | None = None,
) -> dict[str, object]:
    directory = safe_directory(directory)
    directory_fd = open_absolute(directory, directory=True)
    try:
        held_identity = DirectoryIdentity(os.fstat(directory_fd).st_dev, os.fstat(directory_fd).st_ino)
        if expected_identity is not None and held_identity != expected_identity:
            raise HarnessError("result publication directory identity differs")
        return validate_result_set_fd(contract, directory_fd, outcome)
    finally:
        os.close(directory_fd)


def read_result_member(directory_fd: int, name: str) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        return read_fd(descriptor, name, MAX_JSON)
    finally:
        os.close(descriptor)


def decode_result_json(raw: bytes, name: str) -> object:
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise HarnessError(f"invalid result JSON: {name}") from error


def validate_result_set_fd(
    contract: dict[str, object], directory_fd: int, outcome: dict[str, object] | None,
) -> dict[str, object]:
    expected_names = {"acceptance-receipt.json", "verifier.json", "evidence-manifest.json"}
    if {entry.name for entry in os.scandir(directory_fd)} != expected_names:
        raise HarnessError("result publication file set differs")
    receipt_raw = read_result_member(directory_fd, "acceptance-receipt.json")
    verifier_raw = read_result_member(directory_fd, "verifier.json")
    evidence_raw = read_result_member(directory_fd, "evidence-manifest.json")
    evidence = decode_result_json(evidence_raw, "evidence-manifest.json")
    if canonical(evidence) != evidence_raw:
        raise HarnessError("evidence manifest encoding differs")
    expected_manifest = {
        "schema_version", "candidate_sha", "image_sha256", "tool_sha256",
        "harness_sha256", "harness_asset_sha256", "timing_asset_sha256",
        "timing", "timing_sha256",
        "package_tree_sha256", "scenario_sha256",
        "prior_package_tree_sha256", "prior_scenario_sha256", "prior_activation",
        "seccomp_source_sha256", "transfer_bytes", "transfer_sha256",
        "receipt_sha256", "verifier_sha256", "dormant_proof",
    }
    packages = contract.get("packages")
    expected_packages = (
        {name: packages[name]["tree_sha256"] for name in PACKAGE_NAMES}
        if isinstance(packages, dict) and set(packages) == set(PACKAGE_NAMES)
        else evidence.get("package_tree_sha256") if isinstance(evidence, dict) else None
    )
    prior_packages = contract.get("prior_packages")
    expected_prior_packages = (
        {name: prior_packages[name]["tree_sha256"] for name in PRIOR_PACKAGE_NAMES}
        if isinstance(prior_packages, dict) and set(prior_packages) == set(PRIOR_PACKAGE_NAMES)
        else evidence.get("prior_package_tree_sha256") if isinstance(evidence, dict) else None
    )
    prior_scenario = contract.get("prior_scenario")
    expected_prior_scenario = (
        prior_scenario.get("sha256") if isinstance(prior_scenario, dict)
        else evidence.get("prior_scenario_sha256") if isinstance(evidence, dict) else None
    )
    if (
        not isinstance(evidence, dict)
        or set(evidence) != expected_manifest
        or evidence.get("schema_version") != EVIDENCE_SCHEMA
        or evidence.get("candidate_sha") != contract["candidate_sha"]
        or evidence.get("harness_sha256") != contract["harness_sha256"]
        or evidence.get("timing_asset_sha256") != contract["timing_asset_sha256"]
        or evidence.get("timing") != TIMING_CONTRACT
        or evidence.get("timing_sha256") != contract["timing_sha256"]
        or evidence.get("scenario_sha256") != contract["scenario"]["sha256"]
        or evidence.get("seccomp_source_sha256") != SECCOMP_SHA256
        or evidence.get("transfer_bytes") != TRANSFER_SIZE
        or not isinstance(evidence.get("image_sha256"), str)
        or HEX64.fullmatch(evidence["image_sha256"]) is None
        or not isinstance(evidence.get("transfer_sha256"), str)
        or HEX64.fullmatch(evidence["transfer_sha256"]) is None
        or not isinstance(evidence.get("tool_sha256"), dict)
        or set(evidence["tool_sha256"]) != set(TOOLS)
        or any(not isinstance(digest, str) or HEX64.fullmatch(digest) is None for digest in evidence["tool_sha256"].values())
        or not isinstance(evidence.get("harness_asset_sha256"), dict)
        or set(evidence["harness_asset_sha256"]) != set(FROZEN_ASSETS)
        or any(not isinstance(digest, str) or HEX64.fullmatch(digest) is None for digest in evidence["harness_asset_sha256"].values())
        or evidence["harness_asset_sha256"].get("harness.py") != evidence.get("harness_sha256")
        or evidence["harness_asset_sha256"].get("timing-contract.json") != evidence.get("timing_asset_sha256")
        or evidence.get("package_tree_sha256") != expected_packages
        or evidence.get("prior_package_tree_sha256") != expected_prior_packages
        or evidence.get("prior_scenario_sha256") != expected_prior_scenario
        or not isinstance(expected_prior_scenario, str)
        or HEX64.fullmatch(expected_prior_scenario) is None
        or evidence.get("receipt_sha256") != hashlib.sha256(receipt_raw).hexdigest()
        or evidence.get("verifier_sha256") != hashlib.sha256(verifier_raw).hexdigest()
    ):
        raise HarnessError("evidence manifest binding differs")
    frame = {
        "schema_version": FRAME_SCHEMA,
        "phase": "run",
        "challenge": "0" * 64,
        "outcome": "pass",
        "receipt_base64": base64.b64encode(receipt_raw).decode(),
        "verifier_base64": base64.b64encode(verifier_raw).decode(),
        "dormant_proof": evidence["dormant_proof"],
        "prior_activation": evidence["prior_activation"],
    }
    validate_final_frame(frame, contract, "0" * 64)
    replay_frozen_verifier(contract, receipt_raw, evidence)
    expected_outcome = {
        "status": "pass",
        "candidate_sha": contract["candidate_sha"],
        "harness_sha256": evidence["harness_sha256"],
        "timing_asset_sha256": evidence["timing_asset_sha256"],
        "timing_sha256": evidence["timing_sha256"],
        "receipt_sha256": evidence["receipt_sha256"],
        "verifier_sha256": evidence["verifier_sha256"],
        "evidence_manifest_sha256": hashlib.sha256(evidence_raw).hexdigest(),
        "dormant_proof": evidence["dormant_proof"],
        "vm_state_absent": True,
    }
    if outcome is not None and outcome != expected_outcome:
        raise HarnessError("result publication outcome differs")
    return expected_outcome


def replay_frozen_verifier(
    contract: dict[str, object], receipt_raw: bytes, evidence: dict[str, object],
) -> None:
    here = Path(__file__).resolve().parent
    verifier_path = asset_source(here, "receipt_verifier.py")
    stages_path = asset_source(here, "expected-stages.json")
    verifier_raw = read_regular(verifier_path, MAX_FILE)
    stages_raw = read_regular(stages_path, MAX_JSON)
    asset_digests = evidence["harness_asset_sha256"]
    if (
        hashlib.sha256(verifier_raw).hexdigest() != asset_digests["receipt_verifier.py"]
        or hashlib.sha256(stages_raw).hexdigest() != asset_digests["expected-stages.json"]
    ):
        raise HarnessError("frozen receipt verifier assets differ")
    scenario_descriptor = contract.get("scenario")
    if not isinstance(scenario_descriptor, dict) or set(scenario_descriptor) != {"path", "sha256"}:
        raise HarnessError("scenario descriptor differs during verifier replay")
    scenario_raw = read_regular(safe_input_file(Path(str(scenario_descriptor["path"]))), MAX_JSON)
    if hashlib.sha256(scenario_raw).hexdigest() != scenario_descriptor["sha256"]:
        raise HarnessError("scenario differs during verifier replay")
    scenario = decode_result_json(scenario_raw, "scenario.json")
    receipt = decode_result_json(receipt_raw, "acceptance-receipt.json")
    stages = decode_result_json(stages_raw, "expected-stages.json")
    namespace: dict[str, object] = {"__name__": "frozen_receipt_verifier", "__file__": str(verifier_path)}
    try:
        exec(compile(verifier_raw, str(verifier_path), "exec"), namespace)
        namespace["verify"](receipt, scenario, stages)
    except Exception as error:
        raise HarnessError("frozen receipt verifier rejected result set") from error


def finish_publication(
    contract: dict[str, object], binding: dict[str, str], outcome: dict[str, object],
) -> dict[str, object]:
    final = Path(binding["results"])
    staging = Path(binding["staging"])
    publication = load_publication(binding)
    if publication is None or publication.get("phase") != "ready":
        raise HarnessError("ready result publication journal is missing")
    expected = parse_directory_identity(publication["staging_identity"])
    try:
        final.lstat()
    except FileNotFoundError:
        directory_fd = open_absolute(staging, directory=True)
        quarantine = staging.with_name(f".{staging.name}.publish-{os.urandom(16).hex()}")
        try:
            if not identity_matches(os.fstat(directory_fd), expected):
                raise HarnessError("result staging changed before publication")
            rename_noreplace(staging, quarantine)
            if (
                not identity_matches(quarantine.lstat(), expected)
                or not identity_matches(os.fstat(directory_fd), expected)
            ):
                raise HarnessError("result staging changed during publication quarantine")
            validate_result_set_fd(contract, directory_fd, outcome)
            rename_noreplace(quarantine, final)
            if (
                not identity_matches(final.lstat(), expected)
                or not identity_matches(os.fstat(directory_fd), expected)
            ):
                rejected = final.with_name(f".{final.name}.rejected-{os.urandom(16).hex()}")
                try:
                    rename_noreplace(final, rejected)
                except BaseException:
                    pass
                raise HarnessError("published result identity differs")
            fsync_parent(final)
        finally:
            os.close(directory_fd)
    else:
        try:
            staging.lstat()
        except FileNotFoundError:
            pass
        else:
            raise HarnessError("published and staged result sets both exist")
        validate_result_set(contract, final, outcome, expected)
    try:
        Path(binding["journal"]).lstat()
    except FileNotFoundError:
        pass
    else:
        unlink_identified_file(Path(binding["journal"]))
    return outcome


def create_run_stage(
    contract: dict[str, object], state: Path,
    records: dict[str, list[tuple[str, int, bytes]]], scenario_raw: bytes, seccomp_raw: bytes,
    prior_scenario_raw: bytes, relay_fault: str | None = None,
) -> None:
    if relay_fault is not None and relay_fault not in RELAY_FAULTS:
        raise HarnessError("relay fault mode differs")
    stage = state / "stage"
    stage.mkdir(mode=0o700)
    candidate_tar = stage / "candidate.tar"
    bounded([
        "/usr/bin/git", "-C", str(contract["candidate_root"]), "archive", "--format=tar",
        "--prefix=deploy/native-ci/", f"--output={candidate_tar}",
        f"{contract['candidate_sha']}:deploy/native-ci",
    ], timeout=60)
    candidate_tar.chmod(0o400)
    inputs = stage / "inputs"
    inputs.mkdir(mode=0o700)
    for name in PACKAGE_NAMES:
        materialize_tree(records[name], inputs / name)
    prior = inputs / "prior"
    prior.mkdir(mode=0o700)
    for name in PRIOR_PACKAGE_NAMES:
        materialize_tree(records[f"prior/{name}"], prior / name)
    (prior / "scenario.json").write_bytes(prior_scenario_raw)
    (prior / "scenario.json").chmod(0o400)
    (inputs / "scenario.json").write_bytes(scenario_raw)
    (inputs / "scenario.json").chmod(0o400)
    (inputs / "seccomp.json").write_bytes(seccomp_raw)
    (inputs / "seccomp.json").chmod(0o400)
    public_raw = read_regular(state / "public-binding.json", MAX_JSON)
    (inputs / "public-binding.json").write_bytes(public_raw)
    (inputs / "public-binding.json").chmod(0o400)
    descriptor = {
        "schema_version": STAGE_SCHEMA,
        "candidate_sha": contract["candidate_sha"],
        "harness_sha256": contract["harness_sha256"],
        "timing_asset_sha256": contract["timing_asset_sha256"],
        "timing_sha256": contract["timing_sha256"],
        "candidate_tar_sha256": file_sha256(candidate_tar),
        "scenario_sha256": contract["scenario"]["sha256"],
        "seccomp_source_sha256": SECCOMP_SHA256,
        "public_binding_sha256": hashlib.sha256(public_raw).hexdigest(),
        "package_tree_sha256": {name: tree_digest(records[name]) for name in PACKAGE_NAMES},
        "platform_systemd": contract["platform_systemd"],
        "prior_package_tree_sha256": {name: tree_digest(records[f"prior/{name}"]) for name in PRIOR_PACKAGE_NAMES},
        "prior_scenario_sha256": contract["prior_scenario"]["sha256"],
    }
    (stage / "descriptor.json").write_bytes(canonical(descriptor))
    (stage / "descriptor.json").chmod(0o444)
    state_record = load_json(state / "state.json")
    stage_common(state, stage, {
        "schema_version": "buzz-ci-clean-host-e2e-guest-phase/v3",
        "phase": "run", "challenge": state_record["challenge"],
        "descriptor_sha256": hashlib.sha256(canonical(descriptor)).hexdigest(),
        "timing": TIMING_CONTRACT, "timing_sha256": timing_sha256(),
        "relay_fault": relay_fault,
    })
    make_iso(stage, state / "stage.iso", "BUZZCI_STAGE")
    shutil.rmtree(stage)
    make_seed(state, "buzzci-run-" + str(state_record["challenge"])[:16])


def create_verify_stage(
    contract: dict[str, object], state: Path, scenario_raw: bytes,
    prior_binding: dict[str, str],
) -> None:
    validate_prepared_state(state)
    clean_transient(state)
    stage = state / "stage"
    stage.mkdir(mode=0o700)
    scenario_path = stage / "scenario.json"
    scenario_path.write_bytes(scenario_raw)
    scenario_path.chmod(0o400)
    state_record = load_json(state / "state.json")
    assets = state_record["harness_asset_sha256"]
    stage_common(state, stage, {
        "schema_version": "buzz-ci-clean-host-e2e-guest-phase/v3",
        "phase": "verify", "challenge": state_record["challenge"],
        "candidate_sha": contract["candidate_sha"],
        "scenario_sha256": contract["scenario"]["sha256"],
        "trusted_verifier_sha256": assets["receipt_verifier.py"],
        "expected_stages_sha256": assets["expected-stages.json"],
        "prior_activation_id": prior_binding["activation_id"],
        "prior_package_digest": prior_binding["package_digest"],
        "timing": TIMING_CONTRACT, "timing_sha256": timing_sha256(),
    })
    make_iso(stage, state / "stage.iso", "BUZZCI_STAGE")
    shutil.rmtree(stage)
    make_seed(state, "buzzci-verify-" + str(state_record["challenge"])[:16])


def validate_final_frame(
    frame: dict[str, object], contract: dict[str, object], challenge: str,
    prior_binding: dict[str, str] | None = None,
) -> tuple[bytes, bytes, dict[str, object]]:
    expected = {
        "schema_version", "phase", "challenge", "outcome", "receipt_base64", "verifier_base64",
        "dormant_proof", "prior_activation",
    }
    if set(frame) != expected or frame["phase"] != "run" or frame["challenge"] != challenge or frame["outcome"] != "pass":
        raise HarnessError("final evidence frame differs")
    prior_activation = frame["prior_activation"]
    if (
        not isinstance(prior_activation, dict)
        or set(prior_activation) != PRIOR_ACTIVATION_PROOF_KEYS
        or prior_activation.get("receipt_state") != "rolled_back"
        or prior_activation.get("execd_reinstall") != "installed"
        or not isinstance(prior_activation.get("activation_id"), str)
        or not prior_activation["activation_id"]
        or any(
            not isinstance(prior_activation.get(name), str) or HEX64.fullmatch(prior_activation[name]) is None
            for name in ("package_digest", "rollback_cleanup_sha256")
        )
        or prior_binding is not None and any(
            prior_activation.get(name) != prior_binding[name] for name in ("activation_id", "package_digest")
        )
    ):
        raise HarnessError("final prior activation proof differs")
    try:
        receipt_raw = base64.b64decode(frame["receipt_base64"], validate=True)
        verifier_raw = base64.b64decode(frame["verifier_base64"], validate=True)
    except (TypeError, ValueError) as error:
        raise HarnessError("final evidence encoding differs") from error
    if not receipt_raw or len(receipt_raw) > MAX_JSON or not verifier_raw or len(verifier_raw) > MAX_JSON:
        raise HarnessError("final evidence size differs")
    try:
        receipt = json.loads(receipt_raw, object_pairs_hook=reject_duplicates)
        verifier = json.loads(verifier_raw, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise HarnessError("final evidence JSON differs") from error
    proof = frame["dormant_proof"]
    if (
        not isinstance(receipt, dict)
        or set(receipt) != {
            "schema_version", "outcome", "scenario_sha256", "integrated_candidate_sha",
            "run_id", "checks", "zero_transition",
        }
        or canonical(receipt) != receipt_raw
        or receipt.get("schema_version") != "buzz-ci-capacity-one-acceptance-receipt/v2"
        or receipt.get("outcome") != "pass"
        or receipt.get("integrated_candidate_sha") != contract["candidate_sha"]
        or receipt.get("scenario_sha256") != contract["scenario"]["sha256"]
        or verifier != {"outcome": "pass", "status": "verified"}
        or canonical(verifier) != verifier_raw
        or not isinstance(proof, dict)
        or set(proof) != {
            "configs_sha256", "units_sha256", "sockets_absent", "processes_absent",
            "encrypted_credentials_absent", "relay_residue_absent",
        }
        or any(proof.get(name) is not True for name in (
            "sockets_absent", "processes_absent", "encrypted_credentials_absent", "relay_residue_absent",
        ))
        or any(not isinstance(proof.get(name), str) or HEX64.fullmatch(proof[name]) is None for name in ("configs_sha256", "units_sha256"))
    ):
        raise HarnessError("final receipt identity or dormant proof differs")
    return receipt_raw, verifier_raw, proof


def run_vm(
    contract: dict[str, object], state: Path, records: dict[str, list[tuple[str, int, bytes]]],
    scenario_raw: bytes, seccomp_raw: bytes, results_arg: Path,
    *, prior_scenario_raw: bytes = b"", expected_state: StateIdentity | None = None,
    binding: dict[str, str] | None = None, resumed: bool = False,
    relay_fault: str | None = None,
) -> dict[str, object]:
    if expected_state is None:
        expected_state = state_identity(state)
    owned_state = binding is not None
    if binding is None:
        binding = run_binding({**contract, "state": str(state)}, results_arg)
    results: Path | None = None
    outcome: dict[str, object] | None = None
    run_error: BaseException | None = None
    try:
        results, recovered, results_identity = start_publication(binding, resumed)
        if recovered is not None:
            outcome = recovered
        else:
            challenge = str(load_json(state / "state.json")["challenge"])
            if any((state / name).exists() for name in ("candidate.qcow2", "verifier.qcow2", "transfer.raw")):
                raise HarnessError("prior VM run residue exists")
            qemu_img_create(state, "candidate.qcow2", "trusted.qcow2")
            create_transfer(state)
            create_run_stage(contract, state, records, scenario_raw, seccomp_raw, prior_scenario_raw, relay_fault)
            boot(
                state, watchdog_seconds("candidate"), overlay="candidate.qcow2",
                evidence_expected=False, transfer="read-write",
            )
            (state / "candidate.qcow2").unlink()
            if (state / "candidate.qcow2").exists():
                raise HarnessError("candidate VM overlay remains before evidence transfer")
            if (state / "evidence.bin").exists():
                raise HarnessError("candidate VM reached verifier evidence storage")
            validate_transfer(state)
            validate_prepared_state(state)
            prior_binding = prior_activation_binding(records)
            qemu_img_create(state, "verifier.qcow2", "trusted.qcow2")
            create_verify_stage(contract, state, scenario_raw, prior_binding)
            validate_prepared_state(state)
            frame = boot(
                state, watchdog_seconds("verifier"), overlay="verifier.qcow2",
                evidence_expected=True, transfer="read-only",
            )
            if frame is None:
                raise HarnessError("verification guest returned no evidence")
            validate_transfer(state)
            receipt_raw, verifier_raw, proof = validate_final_frame(frame, contract, challenge, prior_binding)
            receipt_path = results / "acceptance-receipt.json"
            verifier_path = results / "verifier.json"
            state_record = load_json(state / "state.json")
            receipt_digest = hashlib.sha256(receipt_raw).hexdigest()
            verifier_digest = hashlib.sha256(verifier_raw).hexdigest()
            evidence_manifest = {
                "schema_version": EVIDENCE_SCHEMA,
                "candidate_sha": contract["candidate_sha"],
                "harness_sha256": state_record["harness_sha256"],
                "timing_asset_sha256": state_record["timing_asset_sha256"],
                "image_sha256": state_record["image_sha256"],
                "tool_sha256": state_record["tool_sha256"],
                "harness_asset_sha256": state_record["harness_asset_sha256"],
                "timing": state_record["timing"],
                "timing_sha256": state_record["timing_sha256"],
                "package_tree_sha256": {name: tree_digest(records[name]) for name in PACKAGE_NAMES},
                "scenario_sha256": contract["scenario"]["sha256"],
                "prior_package_tree_sha256": {name: tree_digest(records[f"prior/{name}"]) for name in PRIOR_PACKAGE_NAMES},
                "prior_scenario_sha256": contract["prior_scenario"]["sha256"],
                "prior_activation": frame["prior_activation"],
                "seccomp_source_sha256": SECCOMP_SHA256,
                "transfer_bytes": TRANSFER_SIZE,
                "transfer_sha256": file_sha256(state / "transfer.raw"),
                "receipt_sha256": receipt_digest,
                "verifier_sha256": verifier_digest,
                "dormant_proof": proof,
            }
            evidence_path = results / "evidence-manifest.json"
            receipt_path.write_bytes(receipt_raw)
            receipt_path.chmod(0o400)
            publication_checkpoint("after-first-file", results, Path(binding["results"]))
            verifier_path.write_bytes(verifier_raw)
            verifier_path.chmod(0o400)
            evidence_path.write_bytes(canonical(evidence_manifest))
            evidence_path.chmod(0o400)
            outcome = {
                "status": "pass", "candidate_sha": contract["candidate_sha"],
                "harness_sha256": state_record["harness_sha256"],
                "timing_asset_sha256": state_record["timing_asset_sha256"],
                "timing_sha256": state_record["timing_sha256"],
                "receipt_sha256": receipt_digest, "verifier_sha256": verifier_digest,
                "evidence_manifest_sha256": hashlib.sha256(canonical(evidence_manifest)).hexdigest(),
                "dormant_proof": proof, "vm_state_absent": True,
            }
            publication_checkpoint("after-third-file", results, Path(binding["results"]))
            validate_result_set(contract, results, outcome, results_identity)
            replace_private_json(
                Path(binding["journal"]),
                publication_record(binding, "ready", outcome, results_identity),
            )
    except BaseException as error:
        run_error = error

    cleanup_errors: list[BaseException] = []
    try:
        if owned_state:
            destroy_run_state(state, expected_state, binding)
        else:
            destroy_state(state, expected_state)
    except BaseException as error:
        cleanup_errors.append(error)
    if run_error is not None or cleanup_errors:
        try:
            cleanup_publication(binding)
        except BaseException as error:
            cleanup_errors.append(error)
    if cleanup_errors:
        detail = "; ".join(str(error) or type(error).__name__ for error in cleanup_errors)
        raise HarnessError(f"terminal run cleanup failed: {detail}") from run_error
    if run_error is not None:
        raise run_error.with_traceback(run_error.__traceback__)
    if outcome is None:
        raise HarnessError("terminal run produced no outcome")
    return finish_publication(contract, binding, outcome)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("capabilities")
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--state", type=Path, required=True)
    prepare_parser.add_argument("--image", type=Path, required=True)
    prepare_parser.add_argument("--image-sha256", required=True)
    prepare_parser.add_argument("--qemu-sha256", required=True)
    prepare_parser.add_argument("--qemu-img-sha256", required=True)
    prepare_parser.add_argument("--controld-uid", type=int, required=True)
    prepare_parser.add_argument("--controld-gid", type=int, required=True)
    for name in ("preflight", "run"):
        child = sub.add_parser(name)
        child.add_argument("--contract", type=Path, required=True)
        if name == "run":
            child.add_argument("--results", type=Path, required=True)
            child.add_argument(
                "--relay-fault", choices=RELAY_FAULTS, default=None,
                help="arm one loopback-relay fault mode; absent means the standard lifecycle",
            )
    arguments = parser.parse_args()
    try:
        if arguments.action == "capabilities":
            result = capabilities()
        elif arguments.action == "prepare":
            result = prepare(arguments)
        else:
            if arguments.action == "run":
                result = terminal_run(arguments.contract, arguments.results, arguments.relay_fault)
            else:
                contract, _state, _records, _scenario_raw, _seccomp_raw, _prior_scenario_raw = validate_contract(arguments.contract)
                result = {
                    "status": "ready", "candidate_sha": contract["candidate_sha"],
                    "boundary": "bubblewrap+qemu-kvm",
                    "harness_sha256": contract["harness_sha256"],
                    "timing_asset_sha256": contract["timing_asset_sha256"],
                    "timing": contract["timing"], "timing_sha256": contract["timing_sha256"],
                }
        sys.stdout.buffer.write(canonical(result))
        return 0
    except (OSError, ValueError, HarnessError, subprocess.SubprocessError) as error:
        sys.stderr.buffer.write(canonical({"status": "error", "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
