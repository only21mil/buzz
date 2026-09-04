#!/usr/bin/env python3
"""Trusted guest-side key ceremony and activation acceptance executor."""

from __future__ import annotations

import base64
import fcntl
import grp
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

PHASE_SCHEMA = "buzz-ci-clean-host-e2e-guest-phase/v3"
FRAME_SCHEMA = "buzz-ci-clean-host-e2e-frame/v2"
PROGRESS_SCHEMA = "buzz-ci-clean-host-e2e-progress/v1"
BINDING_SCHEMA = "buzz-ci-clean-host-e2e-public-binding/v3"
STAGE_SCHEMA = "buzz-ci-clean-host-e2e-stage/v3"
PENDING_SCHEMA = "buzz-ci-clean-host-e2e-pending-evidence/v3"
STATE_ROOT = Path("/var/lib/buzzci-e2e")
RELAY_ROOT = Path("/var/lib/buzzci-e2e-relay")
# local_tls_relay.py RELAY_FAULTS; the harness `run --relay-fault` choices.
FAULT_STALE_TERMINAL = "stale-terminal-publication-recovery"
FAULT_REPLAY_BEFORE_GRANT = "stale-terminal-replay-before-grant"
RELAY_FAULTS = frozenset({FAULT_STALE_TERMINAL, FAULT_REPLAY_BEFORE_GRANT})
REPLAY_FAULT_RECORD_KEYS = frozenset({
    "mode", "grants_expired_at", "refused_event_ids", "queried_event_ids", "replayed_event_id",
})
# buzz-ci-controld store.rs SNAPSHOT_NAME under the frozen controld store_root.
CONTROLD_SNAPSHOT = Path("/var/lib/buzzci/controld/control-store-v1.json")
MAX_CONTROLD_SNAPSHOT = 8 * 1024 * 1024
EVIDENCE_DEVICE = Path("/dev/virtio-ports/buzzci.evidence")
PROGRESS_DEVICE = Path("/dev/virtio-ports/buzzci.progress")
TRANSFER_DEVICE = Path("/dev/vdb")
KEY_NAMES = ("ci-event", "nip98", "manifest", "acceptance-actor")
PACKAGE_NAMES = ("runner", "controld", "keyholder", "execd", "activation")
PRIOR_PACKAGE_NAMES = ("execd", "activation")
PRIOR_ACTIVATION_PROOF_KEYS = frozenset({
    "activation_id", "package_digest", "receipt_state", "rollback_cleanup_sha256", "execd_reinstall",
})
ACTIVATION_RECEIPT_PATH = Path("/var/lib/buzzci/activation-controller/receipt-v1.json")
ROLLBACK_CLEANUP_PATH = Path("/var/lib/buzzci/activation-controller/rollback-cleanup-v1.json")
EXECD_PACKAGE_STATE = Path("/var/lib/buzzci/execd-v2/package")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VIRTIO_PORT_TARGET = re.compile(r"^\.\./(vport[0-9]+p[0-9]+)$")
MAX_JSON = 1024 * 1024
MAX_COMMAND = 4 * 1024 * 1024
STAGE_PROGRESS_MAX = 128
STAGE_PROGRESS_MAGIC = b"BSP\x02"
STAGE_PROGRESS_TERMINALS = {
    0x80: (46, "stage_complete"),
    0x81: (6, "stage_unchanged"),
}
MAX_TREE_FILES = 1024
MAX_TREE_BYTES = 64 * 1024 * 1024
TRANSFER_SIZE = 8 * 1024 * 1024
TRANSFER_MAGIC = b"BUZZCI-EVIDENCE\0"
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
PLATFORM_SYSTEMD_SOURCE = Path(
    "deploy/native-ci/activation/platform/fedora-44-systemd-259/10-timeout-abort.conf"
)
SCRATCH_ROOT = Path("/run")
SWAPS_PATH = Path("/proc/swaps")
UNITS = (
    "buzz-ci-capacity-one.target", "buzz-ci-controld.service",
    "buzz-ci-controld-acceptance.socket", "buzz-ci-acceptance-control.service",
    "buzz-ci-acceptance-control.socket", "buzz-ci-runner.service",
    "buzz-ci-runner.socket", "buzz-ci-execd.service", "buzz-ci-execd.socket",
    "buzz-ci-executor.service", "buzz-ci-executor.socket",
    "buzz-ci-keyholder.service", "buzz-ci-keyholder.socket",
)
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
if (
    len(STAGE_PROGRESS_SUBPHASES) != 46
    or STAGE_PROGRESS_SUBPHASES[STAGE_PROGRESS_TERMINALS[0x81][0] - 1] != "receipt_read"
    or STAGE_PROGRESS_SUBPHASES[STAGE_PROGRESS_TERMINALS[0x80][0] - 1] != "stage_complete"
):
    raise RuntimeError("stage progress operation inventory differs")
SOCKETS = (
    "/run/buzzci/acceptance-control.sock", "/run/buzzci/controld-acceptance.sock",
    "/run/buzzci/runner-control.sock", "/run/buzzci/execd.sock",
    "/run/buzzci/executor.sock", "/run/buzzci/keyholder.sock",
)
CA_BACKENDS = (
    (
        "update-ca-certificates",
        Path("/usr/local/share/ca-certificates/buzzci-disposable-e2e.crt"),
        ("update-ca-certificates",),
        ("update-ca-certificates", "--fresh"),
    ),
    (
        "update-ca-trust",
        Path("/etc/pki/ca-trust/source/anchors/buzzci-disposable-e2e.crt"),
        ("update-ca-trust", "extract"),
        ("update-ca-trust", "extract"),
    ),
)
TIMING_PATH = Path(__file__).with_name("timing-contract.json")
TIMING_CONTRACT = json.loads(TIMING_PATH.read_bytes())
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
_PROGRESS_BOOT: str | None = None
_PROGRESS_SEQUENCE = 0
_PROGRESS_STARTED = 0.0
_PROGRESS_LAST_PHASE: str | None = None
_ACTIVE_PHASE: str | None = None
_PHASE_DEADLINE: float | None = None
_OBSERVED_COMMAND_TERMS: dict[str, int] = {}


class GuestError(RuntimeError):
    pass


class StageCommandFailure(GuestError):
    """Carry only authenticated stage position into cleanup policy."""

    def __init__(self, message: str, subphase: str | None):
        super().__init__(message)
        self.subphase = subphase
        self.rollback_required = subphase not in frozenset(
            STAGE_PROGRESS_SUBPHASES[:3]
        )


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def timing_sha256() -> str:
    return hashlib.sha256(canonical(TIMING_CONTRACT)).hexdigest()


def timing_leaf(name: str) -> int:
    leaves = TIMING_CONTRACT.get("leaf_seconds")
    value = leaves.get(name) if isinstance(leaves, dict) else None
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise GuestError("guest timing leaf differs")
    return value


def timing_terms_seconds(terms: object) -> int:
    if not isinstance(terms, dict) or any(
        not isinstance(name, str)
        or not isinstance(count, int) or isinstance(count, bool) or count <= 0
        for name, count in terms.items()
    ):
        raise GuestError("guest timing terms differ")
    return sum(timing_leaf(name) * count for name, count in terms.items())


def phase_seconds(phase: str) -> int:
    phases = TIMING_CONTRACT.get("phase_terms")
    inventory = TIMING_CONTRACT.get("command_inventory")
    if not isinstance(phases, dict) or not isinstance(inventory, dict) or phase not in phases or phase not in inventory:
        raise GuestError("guest timing phase differs")
    return timing_terms_seconds(phases[phase]) + timing_terms_seconds(inventory[phase])


def canary_command_seconds() -> int:
    terms = TIMING_CONTRACT.get("phase_terms", {}).get("canary", {})
    if not isinstance(terms, dict):
        raise GuestError("guest canary timing differs")
    return timing_leaf("driver_operation") * int(terms.get("driver_operation", 0)) + timing_leaf("canary_orchestration_margin")


def open_progress_device() -> int:
    try:
        directory_fd = open_absolute(PROGRESS_DEVICE.parent, directory=True)
        try:
            target = os.readlink(PROGRESS_DEVICE.name, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        match = VIRTIO_PORT_TARGET.fullmatch(target)
        if match is None:
            raise GuestError("progress transport link target is unsafe")
        dev_fd = open_absolute(PROGRESS_DEVICE.parent.parent, directory=True)
        try:
            descriptor = os.open(
                match.group(1), os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=dev_fd,
            )
        finally:
            os.close(dev_fd)
        if not stat.S_ISCHR(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise GuestError("progress transport target is not a character device")
        return descriptor
    except OSError as error:
        raise GuestError("progress transport is unavailable") from error


def emit_progress(phase: str, event: str = "start") -> None:
    """Emit a bounded diagnostic frame; the host requires terminal completion."""
    global _PROGRESS_LAST_PHASE, _PROGRESS_SEQUENCE
    if _PROGRESS_BOOT is None:
        return
    order = PROGRESS_ORDER.get(phase)
    last_order = PROGRESS_ORDER.get(_PROGRESS_LAST_PHASE, -1)
    if (
        order is None
        or event not in PROGRESS_EVENTS
        or order < last_order
        or event == "timeout" and order != last_order
        or event == "complete" and phase != "complete"
        or phase == "complete" and event != "complete"
    ):
        raise GuestError("guest progress order differs")
    value = {
        "schema_version": PROGRESS_SCHEMA,
        "boot": _PROGRESS_BOOT,
        "sequence": _PROGRESS_SEQUENCE,
        "phase": phase,
        "event": event,
        "elapsed_ms": max(0, int((time.monotonic() - _PROGRESS_STARTED) * 1000)),
    }
    payload = canonical(value)
    if len(payload) > 512:
        return
    frame = struct.pack(">I", len(payload)) + payload + hashlib.sha256(payload).digest()
    try:
        descriptor = open_progress_device()
        try:
            view = memoryview(frame)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    return
                view = view[written:]
        finally:
            os.close(descriptor)
    except BaseException:
        return
    _PROGRESS_SEQUENCE += 1
    _PROGRESS_LAST_PHASE = phase


def emit_timeout_progress() -> None:
    phase = _PROGRESS_LAST_PHASE
    if phase is None or _ACTIVE_PHASE is not None and PROGRESS_ORDER[_ACTIVE_PHASE] > PROGRESS_ORDER[phase]:
        phase = _ACTIVE_PHASE
    if phase is not None:
        emit_progress(phase, "timeout")


def verify_command_inventory() -> None:
    if _ACTIVE_PHASE is None:
        return
    inventory = TIMING_CONTRACT.get("command_inventory")
    expected = inventory.get(_ACTIVE_PHASE) if isinstance(inventory, dict) else None
    if not isinstance(expected, dict) or _OBSERVED_COMMAND_TERMS != expected:
        raise GuestError(f"guest command inventory differs: {_ACTIVE_PHASE}")


def abandon_command_inventory() -> None:
    global _ACTIVE_PHASE, _PHASE_DEADLINE, _OBSERVED_COMMAND_TERMS
    _ACTIVE_PHASE = None
    _PHASE_DEADLINE = None
    _OBSERVED_COMMAND_TERMS = {}


def record_command_timing(terms: dict[str, int] | None = None) -> None:
    if _ACTIVE_PHASE is None:
        raise GuestError("guest command has no active timing phase")
    values = {"command_default": 1} if terms is None else terms
    for name, count in {**values, "guest_command_reap": values.get("guest_command_reap", 0) + 1}.items():
        if count <= 0:
            continue
        timing_leaf(name)
        _OBSERVED_COMMAND_TERMS[name] = _OBSERVED_COMMAND_TERMS.get(name, 0) + count


def begin_phase(phase: str, *, emit_event: bool = True) -> None:
    global _ACTIVE_PHASE, _PHASE_DEADLINE, _OBSERVED_COMMAND_TERMS
    verify_command_inventory()
    _ACTIVE_PHASE = phase
    _PHASE_DEADLINE = time.monotonic() + phase_seconds(phase)
    _OBSERVED_COMMAND_TERMS = {}
    if emit_event:
        emit_progress(phase)


def complete_progress() -> None:
    global _ACTIVE_PHASE, _PHASE_DEADLINE, _OBSERVED_COMMAND_TERMS
    verify_command_inventory()
    _ACTIVE_PHASE = "complete"
    _PHASE_DEADLINE = None
    _OBSERVED_COMMAND_TERMS = {}
    emit_progress("complete", "complete")


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GuestError("duplicate JSON field")
        result[key] = value
    return result


def open_absolute(path: Path, *, directory: bool = False) -> int:
    absolute = Path(os.path.abspath(path))
    if not absolute.is_absolute() or any(part in {"", ".", ".."} for part in absolute.parts[1:]):
        raise GuestError("staged path is invalid")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = absolute.parts[1:]
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if index < len(parts) - 1 or directory:
                flags |= os.O_DIRECTORY
            child = os.open(
                part, flags, dir_fd=current,
            )
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def read_open_file(fd: int, name: str, maximum: int) -> bytes:
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise GuestError(f"unsafe staged file: {name}")
        raw = b""
        while chunk := os.read(fd, min(1024 * 1024, maximum + 1 - len(raw))):
            raw += chunk
            if len(raw) > maximum:
                raise GuestError(f"oversized staged file: {name}")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        ):
            raise GuestError(f"staged file changed while read: {name}")
        return raw
    except BaseException:
        raise


def read_file(path: Path, maximum: int = MAX_JSON) -> bytes:
    fd = open_absolute(path)
    try:
        return read_open_file(fd, path.name, maximum)
    finally:
        os.close(fd)


def load_json(path: Path) -> object:
    try:
        return json.loads(read_file(path), object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise GuestError(f"invalid staged JSON: {path.name}") from error


def parse_status(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuestError(f"{label} status differs") from error
    if not isinstance(value, dict):
        raise GuestError(f"{label} status differs")
    return value


def parse_verdict(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuestError("strict verifier verdict JSON differs") from error
    expected = {"outcome": "pass", "status": "verified"}
    if value != expected or canonical(value) != raw:
        raise GuestError("strict verifier verdict differs")
    return expected


def reap_process_group(process: subprocess.Popen[bytes], *, wait_seconds: float = 10) -> None:
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
        raise GuestError("guest process could not be reaped")
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return
    except PermissionError as error:
        raise GuestError("guest process-group absence cannot be proved") from error
    raise GuestError("guest process group remains after reap")


def command(
    argv: list[str], *, stdin: bytes | None = None, timeout: int | None = None,
    allow_failure: bool = False, timing_terms: dict[str, int] | None = None,
    inventory: bool = True, uid: int | None = None, gid: int | None = None,
    supplementary_gids: list[int] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    if timeout is None:
        timeout = timing_leaf("command_default")
    if inventory:
        record_command_timing(timing_terms)
    phase_deadline = _PHASE_DEADLINE
    guest_reap = timing_leaf("guest_command_reap")
    if phase_deadline is not None and time.monotonic() >= phase_deadline - guest_reap:
        if _ACTIVE_PHASE is not None:
            emit_timeout_progress()
        raise GuestError(f"guest command timed out: {Path(argv[0]).name}")
    with (
        tempfile.TemporaryFile(dir=SCRATCH_ROOT) as input_file,
        tempfile.TemporaryFile(dir=SCRATCH_ROOT) as stdout,
        tempfile.TemporaryFile(dir=SCRATCH_ROOT) as stderr,
    ):
        if stdin is not None:
            input_file.write(stdin)
            input_file.seek(0)
        process = subprocess.Popen(
            argv, stdin=input_file if stdin is not None else subprocess.DEVNULL,
            stdout=stdout, stderr=stderr, start_new_session=True,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            user=uid,
            group=gid,
            extra_groups=supplementary_gids,
        )
        try:
            deadline = time.monotonic() + timeout
            if phase_deadline is not None:
                deadline = min(deadline, phase_deadline - guest_reap)
            while process.poll() is None:
                if stdout.tell() > MAX_COMMAND or stderr.tell() > MAX_COMMAND:
                    raise GuestError(f"guest command output exceeded bound: {Path(argv[0]).name}")
                if time.monotonic() >= deadline:
                    if _ACTIVE_PHASE is not None:
                        emit_timeout_progress()
                    raise GuestError(f"guest command timed out: {Path(argv[0]).name}")
                time.sleep(0.01)
            stdout.seek(0)
            stderr.seek(0)
            result = subprocess.CompletedProcess(argv, process.returncode, stdout.read(MAX_COMMAND + 1), stderr.read(MAX_COMMAND + 1))
        finally:
            reap_process_group(process, wait_seconds=guest_reap)
    if len(result.stdout) > MAX_COMMAND or len(result.stderr) > MAX_COMMAND:
        raise GuestError(f"guest command output exceeded bound: {Path(argv[0]).name}")
    if result.returncode != 0 and not allow_failure:
        raise GuestError(f"guest command failed: {Path(argv[0]).name}")
    return result


def parse_stage_progress(raw: bytes, *, require_complete: bool) -> str | None:
    if len(raw) > STAGE_PROGRESS_MAX or not raw.startswith(STAGE_PROGRESS_MAGIC):
        return None
    body = raw[len(STAGE_PROGRESS_MAGIC):]
    if len(body) % 2 != 0 or (require_complete and len(body) < 2):
        return None
    terminal: tuple[int, str] | None = None
    if require_complete:
        code, complement = body[-2:]
        terminal = STAGE_PROGRESS_TERMINALS.get(code)
        if terminal is None or complement != code ^ 0xFF:
            return None
        body = body[:-2]
    last = 0
    for offset in range(0, len(body), 2):
        ordinal, complement = body[offset], body[offset + 1]
        if ordinal != last + 1 or complement != ordinal ^ 0xFF or ordinal > len(STAGE_PROGRESS_SUBPHASES):
            return None
        last = ordinal
    if terminal is not None:
        expected_ordinal, terminal_name = terminal
        if last != expected_ordinal:
            return None
        return terminal_name
    return STAGE_PROGRESS_SUBPHASES[last - 1] if last else ""


def stage_success_matches_progress(raw: bytes, terminal: str) -> bool:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
        canonical_raw = canonical(value)
    except (UnicodeDecodeError, json.JSONDecodeError, GuestError, TypeError, ValueError):
        return False
    expected_status = {
        "stage_complete": "staged",
        "stage_unchanged": "unchanged",
    }.get(terminal)
    return (
        expected_status is not None
        and isinstance(value, dict)
        and canonical_raw == raw
        and value.get("status") == expected_status
        and value.get("state") == "staged_zero"
        and type(value.get("capacity")) is int
        and value["capacity"] == 0
    )


def stage_command(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess[bytes]:
    record_command_timing({"controller_stage": 1})
    phase_deadline = _PHASE_DEADLINE
    guest_reap = timing_leaf("guest_command_reap")
    read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    process: subprocess.Popen[bytes] | None = None
    failure: str | None = None
    result: subprocess.CompletedProcess[bytes] | None = None
    progress = bytearray()
    try:
        with (
            tempfile.TemporaryFile(dir=SCRATCH_ROOT) as stdout,
            tempfile.TemporaryFile(dir=SCRATCH_ROOT) as stderr,
        ):
            process = subprocess.Popen(
                [*argv, "--stage-progress-fd", str(write_descriptor)],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
                env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                pass_fds=(write_descriptor,),
            )
            os.close(write_descriptor)
            write_descriptor = -1
            deadline = time.monotonic() + timeout
            if phase_deadline is not None:
                deadline = min(deadline, phase_deadline - guest_reap)
            while process.poll() is None:
                if stdout.tell() > MAX_COMMAND or stderr.tell() > MAX_COMMAND:
                    failure = "guest command output exceeded bound"
                    break
                if time.monotonic() >= deadline:
                    failure = "guest command timed out"
                    break
                time.sleep(0.01)
            reap_process_group(process, wait_seconds=guest_reap)
            stdout.seek(0)
            stderr.seek(0)
            result = subprocess.CompletedProcess(
                argv,
                process.returncode,
                stdout.read(MAX_COMMAND + 1),
                stderr.read(MAX_COMMAND + 1),
            )
        while len(progress) <= STAGE_PROGRESS_MAX:
            try:
                chunk = os.read(read_descriptor, STAGE_PROGRESS_MAX + 1 - len(progress))
            except BlockingIOError:
                break
            if not chunk:
                break
            progress.extend(chunk)
    finally:
        try:
            if write_descriptor >= 0:
                os.close(write_descriptor)
            if process is not None and process.poll() is None:
                reap_process_group(process, wait_seconds=guest_reap)
        finally:
            os.close(read_descriptor)
    if result is None:
        raise StageCommandFailure("guest command failed: controller_stage", None)
    if len(result.stdout) > MAX_COMMAND or len(result.stderr) > MAX_COMMAND:
        failure = "guest command output exceeded bound"
    successful = failure is None and result.returncode == 0
    subphase = parse_stage_progress(bytes(progress), require_complete=successful)
    if successful and (
        subphase not in {"stage_complete", "stage_unchanged"}
        or not stage_success_matches_progress(result.stdout, subphase)
    ):
        successful = False
        failure = "guest command progress rejected"
        subphase = None
    if not successful:
        if subphase:
            emit_progress(
                f"controller_stage:{subphase}",
                "timeout" if failure == "guest command timed out" else "start",
            )
        raise StageCommandFailure(
            f"{failure or 'guest command failed'}: controller_stage", subphase,
        )
    return result


def require_guest() -> None:
    if os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise GuestError("guest entry requires root under systemd")
    for name in (
        "openssl", "pgrep", "python3", "systemctl", "systemd-creds",
        "systemd-sysusers", "systemd-tmpfiles", "swapoff",
    ):
        if shutil.which(name) is None:
            raise GuestError(f"guest prerequisite is absent: {name}")
    ca_backend()


def disable_swap() -> None:
    command(["swapoff", "-a"])
    swaps = SWAPS_PATH.read_text().splitlines()
    if len(swaps) != 1 or not swaps[0].startswith("Filename"):
        raise GuestError("guest swap remains enabled")


def ca_backend() -> tuple[Path, tuple[str, ...], tuple[str, ...]]:
    matches = [backend for backend in CA_BACKENDS if shutil.which(backend[0]) is not None]
    if len(matches) != 1:
        raise GuestError("guest CA backend is absent or ambiguous")
    _tool, anchor, install, remove = matches[0]
    if not anchor.parent.is_dir():
        raise GuestError("guest CA anchor directory is absent")
    return anchor, install, remove


def evidence_device_present() -> bool:
    try:
        directory_fd = open_absolute(EVIDENCE_DEVICE.parent, directory=True)
    except FileNotFoundError:
        return False
    try:
        try:
            os.stat(EVIDENCE_DEVICE.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True
    finally:
        os.close(directory_fd)


def open_evidence_device() -> int:
    try:
        directory_fd = open_absolute(EVIDENCE_DEVICE.parent, directory=True)
        try:
            target = os.readlink(EVIDENCE_DEVICE.name, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        raise GuestError("evidence transport link is unavailable") from error
    match = VIRTIO_PORT_TARGET.fullmatch(target)
    if match is None:
        raise GuestError("evidence transport link target is unsafe")
    try:
        dev_fd = open_absolute(EVIDENCE_DEVICE.parent.parent, directory=True)
        try:
            fd = os.open(
                match.group(1),
                os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=dev_fd,
            )
        finally:
            os.close(dev_fd)
    except OSError as error:
        raise GuestError("evidence transport target is unavailable") from error
    try:
        metadata = os.fstat(fd)
    except OSError as error:
        os.close(fd)
        raise GuestError("evidence transport target metadata is unavailable") from error
    if not stat.S_ISCHR(metadata.st_mode):
        os.close(fd)
        raise GuestError("evidence transport target is not a character device")
    return fd


def validate_evidence_device() -> None:
    fd = open_evidence_device()
    os.close(fd)


def emit(value: dict[str, object]) -> None:
    value = {"schema_version": FRAME_SCHEMA, **value}
    payload = canonical(value)
    if not payload or len(payload) > MAX_JSON:
        raise GuestError("evidence frame exceeds bound")
    frame = struct.pack(">I", len(payload)) + payload + hashlib.sha256(payload).digest()
    fd = open_evidence_device()
    try:
        view = memoryview(frame)
        while view:
            try:
                written = os.write(fd, view)
            except OSError as error:
                raise GuestError("evidence frame write failed") from error
            if written <= 0:
                raise GuestError("evidence frame write made no progress")
            view = view[written:]
    finally:
        os.close(fd)


def encode_transfer(value: dict[str, object]) -> bytes:
    payload = canonical(value)
    if not payload or len(payload) > MAX_COMMAND:
        raise GuestError("evidence transfer payload exceeds bound")
    header = TRANSFER_MAGIC + struct.pack(">I", len(payload)) + hashlib.sha256(payload).digest()
    if len(header) + len(payload) > TRANSFER_SIZE:
        raise GuestError("evidence transfer exceeds fixed capacity")
    return header + payload + bytes(TRANSFER_SIZE - len(header) - len(payload))


def decode_transfer(raw: bytes) -> dict[str, object]:
    header_size = len(TRANSFER_MAGIC) + 4 + 32
    if len(raw) != TRANSFER_SIZE or raw[:len(TRANSFER_MAGIC)] != TRANSFER_MAGIC:
        raise GuestError("evidence transfer framing differs")
    length = struct.unpack(">I", raw[len(TRANSFER_MAGIC):len(TRANSFER_MAGIC) + 4])[0]
    if length == 0 or length > MAX_COMMAND or header_size + length > TRANSFER_SIZE:
        raise GuestError("evidence transfer length differs")
    expected = raw[len(TRANSFER_MAGIC) + 4:header_size]
    payload = raw[header_size:header_size + length]
    if hashlib.sha256(payload).digest() != expected or any(raw[header_size + length:]):
        raise GuestError("evidence transfer digest or padding differs")
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuestError("evidence transfer JSON differs") from error
    if not isinstance(value, dict):
        raise GuestError("evidence transfer object differs")
    return value


def transfer_capacity(fd: int) -> int:
    metadata = os.fstat(fd)
    if not stat.S_ISBLK(metadata.st_mode):
        raise GuestError("evidence transfer is not a block device")
    try:
        raw = fcntl.ioctl(fd, 0x80081272, struct.pack("Q", 0))
    except OSError as error:
        raise GuestError("evidence transfer capacity is unavailable") from error
    capacity = struct.unpack("Q", raw)[0]
    if capacity != TRANSFER_SIZE:
        raise GuestError("evidence transfer capacity differs")
    return capacity


def write_transfer(value: dict[str, object]) -> None:
    fd = os.open(TRANSFER_DEVICE, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        transfer_capacity(fd)
        view = memoryview(encode_transfer(value))
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def read_transfer() -> dict[str, object]:
    fd = os.open(TRANSFER_DEVICE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        transfer_capacity(fd)
        chunks: list[bytes] = []
        size = 0
        while size < TRANSFER_SIZE:
            chunk = os.read(fd, min(1024 * 1024, TRANSFER_SIZE - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size != TRANSFER_SIZE or os.read(fd, 1):
            raise GuestError("evidence transfer read bound differs")
        return decode_transfer(b"".join(chunks))
    finally:
        os.close(fd)


def write_exclusive(path: Path, raw: bytes, mode: int) -> None:
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def openssl_key(path: Path) -> str:
    pem = command(["openssl", "ecparam", "-name", "secp256k1", "-genkey", "-noout"]).stdout
    path.write_bytes(pem)
    path.chmod(0o400)
    public_der = command(["openssl", "ec", "-in", str(path), "-pubout", "-outform", "DER"]).stdout
    public = public_der[-65:]
    text = command(["openssl", "ec", "-in", str(path), "-text", "-noout"]).stdout.decode()
    match = re.search(r"priv:\s*((?:[0-9a-f]{2}:?|\s)+)pub:", text, re.I)
    if len(public) != 65 or public[0] != 4 or match is None:
        raise GuestError("OpenSSL secp256k1 output differs")
    raw = bytes.fromhex("".join(re.findall(r"[0-9a-f]{2}", match.group(1), re.I)))
    if len(raw) != 32:
        raise GuestError("OpenSSL private scalar length differs")
    path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o400)
    return public[1:33].hex()


def encrypt(source: Path, name: str, target_root: Path) -> None:
    target = target_root / name
    command(["systemd-creds", "encrypt", f"--name={name}", str(source), str(target)])
    target.chmod(0o400)
    metadata = target.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o400:
        raise GuestError("encrypted credential metadata differs")


def ceremony(phase: dict[str, object]) -> dict[str, object]:
    begin_phase("ceremony")
    uid = phase.get("controld_uid")
    gid = phase.get("controld_gid")
    if not isinstance(uid, int) or isinstance(uid, bool) or not 1 <= uid <= 0xFFFFFFFF:
        raise GuestError("controld UID differs")
    if not isinstance(gid, int) or isinstance(gid, bool) or not 1 <= gid <= 0xFFFFFFFF:
        raise GuestError("controld GID differs")
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=False)
    credential_root = Path("/etc/credstore.encrypted/buzzci-keyholder")
    credential_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    relay_credential_root = Path("/etc/credstore.encrypted/buzzci-e2e-relay")
    relay_credential_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    raw_root = Path(tempfile.mkdtemp(prefix="buzzci-e2e-keys.", dir="/run"))
    raw_root.chmod(0o700)
    public: dict[str, str] = {}
    try:
        for name in KEY_NAMES:
            raw = raw_root / f"{name}.key"
            public[name] = openssl_key(raw)
            encrypt(raw, f"{name}.key", credential_root)
            raw.unlink()
            if raw.exists():
                raise GuestError("raw signing key remains after encryption")
        ca_key = raw_root / "ca.key"
        relay_key = raw_root / "relay.key"
        command(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(ca_key)])
        command(["openssl", "req", "-x509", "-new", "-key", str(ca_key), "-subj", "/CN=Buzz CI disposable VM CA", "-days", "1", "-out", str(STATE_ROOT / "ca.crt")])
        command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(relay_key), "-subj", "/CN=relay.test.invalid", "-addext", "subjectAltName=DNS:relay.test.invalid", "-out", str(raw_root / "relay.csr")])
        command(["openssl", "x509", "-req", "-in", str(raw_root / "relay.csr"), "-CA", str(STATE_ROOT / "ca.crt"), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1", "-copy_extensions", "copy", "-out", str(STATE_ROOT / "relay.crt")])
        encrypt(relay_key, "relay.key", relay_credential_root)
        for path in tuple(raw_root.iterdir()):
            path.unlink()
        os.sync()
        if tuple(raw_root.iterdir()):
            raise GuestError("raw ceremony files remain")
        raw_root.rmdir()
    except BaseException:
        shutil.rmtree(raw_root, ignore_errors=True)
        raise
    binding = {
        "schema_version": BINDING_SCHEMA,
        "relay_url": "wss://relay.test.invalid:3443",
        "relay_http_origin": "https://relay.test.invalid:3443",
        "acceptance_actor": {"public_key": public["acceptance-actor"], "generation": 1},
        "keyholder_public_spec": {
            "schema_version": 2,
            "peer": {
                "uid": uid, "gid": gid,
                "allowed_operations": [
                    "describe", "sign_ci_event", "nip98_authorize", "sign_manifest",
                    "describe_acceptance", "sign_acceptance_mutation",
                ],
            },
            "selectors": {
                "ci_event": {"public_key": public["ci-event"], "generation": 1},
                "nip98": {"public_key": public["nip98"], "generation": 1},
                "manifest": {"public_key": public["manifest"], "generation": 1},
            },
            "nip98_origin": "https://relay.test.invalid:3443",
            "acceptance": {
                "binding_receipt_path": "/var/lib/buzzci/activation-controller/controld-acceptance-v2.json",
                "credential_selector": "acceptance-actor.key",
            },
        },
    }
    binding_path = STATE_ROOT / "public-binding.json"
    binding_path.write_bytes(canonical(binding))
    binding_path.chmod(0o444)
    result = {
        "phase": "ceremony", "challenge": phase["challenge"], "outcome": "pass",
        "public_binding": binding, "raw_key_absence": True,
    }
    complete_progress()
    return result


def normalized(relative: Path) -> str:
    value = PurePosixPath(relative.as_posix())
    if value.is_absolute() or any(part in {"", ".", ".."} for part in value.parts):
        raise GuestError("staged path escapes its root")
    return value.as_posix()


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    count = 0
    total = 0
    root_fd = open_absolute(root, directory=True)
    try:
        def walk(directory_fd: int, prefix: PurePosixPath) -> None:
            nonlocal count, total
            with os.scandir(directory_fd) as iterator:
                names = sorted(entry.name for entry in iterator)
            for name in names:
                relative_path = prefix / name
                relative = normalized(Path(relative_path.as_posix()))
                try:
                    child_fd = os.open(
                        name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                except OSError as error:
                    raise GuestError(f"staged tree member differs: {relative}") from error
                try:
                    metadata = os.fstat(child_fd)
                    if stat.S_ISDIR(metadata.st_mode):
                        walk(child_fd, relative_path)
                        continue
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise GuestError(f"staged tree member differs: {relative}")
                    raw = read_open_file(child_fd, name, MAX_TREE_BYTES)
                    count += 1
                    total += len(raw)
                    if count > MAX_TREE_FILES or total > MAX_TREE_BYTES:
                        raise GuestError("staged tree exceeds bound")
                    digest.update(relative.encode())
                    digest.update(b"\0")
                    digest.update(f"{stat.S_IMODE(metadata.st_mode):04o}".encode())
                    digest.update(b"\0")
                    digest.update(hashlib.sha256(raw).digest())
                finally:
                    os.close(child_fd)

        walk(root_fd, PurePosixPath())
    finally:
        os.close(root_fd)
    return digest.hexdigest()


def extract_candidate(archive_raw: bytes, target: Path) -> None:
    target.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:") as handle:
        members = handle.getmembers()
        if not members or len(members) > 4096:
            raise GuestError("candidate archive inventory differs")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                raise GuestError("candidate archive path escapes")
            if path.parts[:2] != ("deploy", "native-ci"):
                raise GuestError("candidate archive scope differs")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise GuestError("candidate archive contains an unsafe member")
        handle.extractall(target, filter="data")


def package_manifest(package: Path, name: str) -> dict[str, object]:
    manifest_name = "activation-manifest.json" if name == "activation" else "package-manifest.json"
    value = load_json(package / manifest_name)
    if not isinstance(value, dict):
        raise GuestError(f"{name} manifest shape differs")
    return value


def open_package_member(package: Path, source: object) -> tuple[int, Path]:
    if not isinstance(source, str):
        raise GuestError("package member path is not a string")
    relative = PurePosixPath(source)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise GuestError("package member path escapes")
    directory = open_absolute(package, directory=True)
    try:
        for part in relative.parts[:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = child
        fd = os.open(
            relative.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
        return fd, package / Path(*relative.parts)
    except OSError as error:
        raise GuestError("package member contains an escaping or symbolic path") from error
    finally:
        os.close(directory)


def package_member(package: Path, source: object) -> Path:
    fd, path = open_package_member(package, source)
    os.close(fd)
    return path


def read_package_member(package: Path, source: object, maximum: int = MAX_JSON) -> bytes:
    fd, path = open_package_member(package, source)
    try:
        return read_open_file(fd, path.name, maximum)
    finally:
        os.close(fd)


def validate_ceremony_identities(
    public_spec: object,
    activation: dict[str, object],
    keyholder_manifest: dict[str, object],
    controld_active: dict[str, object],
) -> None:
    activation_identities = activation.get("identities", {})
    activation_controld = activation_identities.get("controld", {}) if isinstance(activation_identities, dict) else {}
    activation_keyholder = activation_identities.get("keyholder", {}) if isinstance(activation_identities, dict) else {}
    keyholder_identities = keyholder_manifest.get("identities", {})
    public_peer = public_spec.get("peer", {}) if isinstance(public_spec, dict) else {}
    if (
        not isinstance(public_spec, dict)
        or (public_peer.get("uid"), public_peer.get("gid"))
        != (activation_controld.get("uid"), activation_controld.get("gid"))
        or (public_peer.get("uid"), public_peer.get("gid"))
        != (keyholder_identities.get("controld_uid"), keyholder_identities.get("controld_gid"))
        or (controld_active.get("keyholder_uid"), controld_active.get("keyholder_gid"))
        != (activation_keyholder.get("uid"), activation_keyholder.get("gid"))
        or (controld_active.get("keyholder_uid"), controld_active.get("keyholder_gid"))
        != (keyholder_identities.get("keyholder_uid"), keyholder_identities.get("keyholder_gid"))
    ):
        raise GuestError("activation controld provider differs from ceremony binding")


def valid_identity(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 0xFFFFFFFF


def prepared_controld_identity(public: dict[str, object], activation: dict[str, object]) -> tuple[int, int]:
    """Return the controld uid and gid that `prepare` recorded, never a literal.

    The key ceremony writes the exact `--controld-uid` and `--controld-gid` given
    to `prepare` into the public binding as the keyholder peer, and the host
    binds that file into the stage descriptor. The activation manifest must
    carry the same identity with no supplementary groups.
    """
    public_spec = public.get("keyholder_public_spec") if isinstance(public, dict) else None
    peer = public_spec.get("peer") if isinstance(public_spec, dict) else None
    if not isinstance(peer, dict) or not valid_identity(peer.get("uid")) or not valid_identity(peer.get("gid")):
        raise GuestError("prepared controld identity differs")
    identities = activation.get("identities")
    controld = identities.get("controld") if isinstance(identities, dict) else None
    if (
        not isinstance(controld, dict)
        or (controld.get("uid"), controld.get("gid")) != (peer["uid"], peer["gid"])
        or controld.get("supplementary_groups")
    ):
        raise GuestError("installed acceptance identities differ")
    return peer["uid"], peer["gid"]


def qualification_credentials(activation: dict[str, object]) -> tuple[int, int, list[int]]:
    identities = activation.get("identities", {})
    qualification = identities.get("qualification", {}) if isinstance(identities, dict) else {}
    access_group = activation.get("access_group", {})
    if (
        not isinstance(qualification, dict)
        or not isinstance(access_group, dict)
        or not valid_identity(qualification.get("uid"))
        or not valid_identity(qualification.get("gid"))
        or qualification.get("supplementary_groups") != ["buzzci-execd"]
        or access_group.get("group") != "buzzci-execd"
        or access_group.get("members") != ["buzzci-ctl", "buzzci-runner"]
        or isinstance(access_group.get("gid"), bool)
        or not isinstance(access_group.get("gid"), int)
        or not 1 <= access_group["gid"] <= 0xFFFF_FFFF
    ):
        raise GuestError("qualification credentials differ from the frozen manifest")
    return qualification["uid"], qualification["gid"], [access_group["gid"]]


def assert_live_acceptance_roles(
    activation: dict[str, object], public: dict[str, object],
) -> tuple[int, int, list[int]]:
    controld_uid, controld_gid = prepared_controld_identity(public, activation)
    credentials = qualification_credentials(activation)
    actor_uid, actor_gid, _supplementary_gids = credentials
    controld_account = pwd.getpwnam("buzzci-controld")
    actor_account = pwd.getpwnam("buzzci-ctl")
    if (
        (controld_account.pw_uid, controld_account.pw_gid) != (controld_uid, controld_gid)
        or (actor_account.pw_uid, actor_account.pw_gid) != (actor_uid, actor_gid)
    ):
        raise GuestError("installed acceptance identities differ")

    socket_metadata = Path("/run/buzzci/controld-acceptance.sock").lstat()
    if (
        not stat.S_ISSOCK(socket_metadata.st_mode)
        or (socket_metadata.st_uid, socket_metadata.st_gid) != (0, actor_gid)
        or stat.S_IMODE(socket_metadata.st_mode) != 0o620
    ):
        raise GuestError("controld acceptance socket credentials differ")

    binding = load_json(Path("/var/lib/buzzci/activation-controller/controld-acceptance-v2.json"))
    keyholder = load_json(Path("/etc/buzzci/keyholder-v2.json"))
    if (
        binding.get("schema_version") != "buzz-ci-activation-acceptance-binding/v2"
        or (binding.get("keyholder_peer_uid"), binding.get("keyholder_peer_gid"))
        != (controld_uid, controld_gid)
        or (binding.get("acceptance_peer_uid"), binding.get("acceptance_peer_gid"))
        != (actor_uid, actor_gid)
        or (keyholder.get("peer", {}).get("uid"), keyholder.get("peer", {}).get("gid"))
        != (controld_uid, controld_gid)
    ):
        raise GuestError("acceptance role binding differs")

    expected_supplementary = manifest_supplementary_gids(activation, "controld")
    controld_processes = []
    for process_root in Path("/proc").iterdir():
        if not process_root.name.isdigit():
            continue
        try:
            if (process_root / "exe").resolve() != Path("/usr/libexec/buzz-ci-controld"):
                continue
            status_lines = (process_root / "status").read_text().splitlines()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        status = dict(line.split(":", 1) for line in status_lines if ":" in line)
        try:
            uid_fields = status["Uid"].split()
            gid_fields = status["Gid"].split()
            supplementary = live_supplementary_gids(status["Groups"], controld_gid)
        except (KeyError, ValueError) as error:
            raise GuestError("live controld credentials differ") from error
        controld_processes.append((uid_fields, gid_fields, supplementary))
    if controld_processes != [([str(controld_uid)] * 4, [str(controld_gid)] * 4, expected_supplementary)]:
        raise GuestError("live controld credentials differ")
    return credentials


def manifest_supplementary_gids(activation: dict[str, object], role: str) -> set[int]:
    """Resolve the activation manifest's supplementary group names for one role to gids."""
    identities = activation.get("identities")
    identity = identities.get(role) if isinstance(identities, dict) else None
    names = identity.get("supplementary_groups") if isinstance(identity, dict) else None
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise GuestError("installed acceptance identities differ")
    return {grp.getgrnam(name).gr_gid for name in names}


def live_supplementary_gids(groups_record: str, primary_gid: int) -> set[int]:
    """Return a /proc status `Groups` record as a gid set without the primary gid.

    systemd starts a `User=` service with initgroups semantics, so the kernel
    supplementary list carries the primary gid even when the unit sets no
    SupplementaryGroups=. The primary gid grants nothing beyond `Gid`, so the
    comparison against the manifest's `supplementary_groups` drops it and keeps
    every other entry. Raises ValueError for a record that is not decimal gids.
    """
    return {int(field) for field in groups_record.split()} - {primary_gid}


def run_capacity_one_canary(
    activation: dict[str, object], scenario: bytes, public: dict[str, object],
) -> bytes:
    uid, gid, supplementary_gids = assert_live_acceptance_roles(activation, public)
    return command(
        ["/usr/libexec/buzz-ci-capacity-one-canary"],
        stdin=scenario,
        timeout=canary_command_seconds(),
        timing_terms={},
        uid=uid,
        gid=gid,
        supplementary_gids=supplementary_gids,
    ).stdout


def run_prior_canary_expecting_stale_terminal(
    activation: dict[str, object], scenario: bytes, public: dict[str, object],
) -> None:
    """Replay-before-grant fault only: drive the prior activation's canary. The
    relay expires its grant when the run's terminal status arrives, so the
    terminal publish (and the re-signed one after the read-back) is refused as
    an unauthorized signer, controld closes, the canary fails, and the run's
    terminal publication stays pending with the request still at the head of
    the relay queue: the state production carried from 2026-09-03 into M12."""
    uid, gid, supplementary_gids = assert_live_acceptance_roles(activation, public)
    result = command(
        ["/usr/libexec/buzz-ci-capacity-one-canary"],
        stdin=scenario,
        timeout=timing_leaf("driver_operation") + timing_leaf("canary_orchestration_margin"),
        allow_failure=True,
        inventory=False,
        uid=uid,
        gid=gid,
        supplementary_gids=supplementary_gids,
    )
    try:
        receipt = json.loads(result.stdout, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuestError("prior canary receipt unreadable under the replay fault") from error
    if result.returncode != 1 or not isinstance(receipt, dict) or receipt.get("outcome") != "fail":
        raise GuestError("prior canary did not fail under the replay fault")
    prove_stale_terminal_left_pending()


def replay_fault_record() -> dict[str, object]:
    """Read and shape-check the relay's replay-before-grant record."""
    try:
        record = load_json(RELAY_ROOT / "fault-fired.json")
    except FileNotFoundError as error:
        raise GuestError("relay fault did not fire") from error
    if (
        not isinstance(record, dict) or set(record) != REPLAY_FAULT_RECORD_KEYS
        or record["mode"] != FAULT_REPLAY_BEFORE_GRANT
        or not isinstance(record["grants_expired_at"], int) or isinstance(record["grants_expired_at"], bool)
        or record["grants_expired_at"] <= 0
        or any(
            not isinstance(record[name], list)
            or any(not isinstance(item, str) or HEX64.fullmatch(item) is None for item in record[name])
            for name in ("refused_event_ids", "queried_event_ids")
        )
        or not record["refused_event_ids"]
        or any(item not in record["refused_event_ids"] for item in record["queried_event_ids"])
        or record["replayed_event_id"] is not None and (
            not isinstance(record["replayed_event_id"], str) or HEX64.fullmatch(record["replayed_event_id"]) is None
        )
    ):
        raise GuestError("relay fault record differs: grant expiry was not recorded")
    return record


def controld_terminal_publications() -> tuple[dict[str, object], dict[str, object]]:
    """Return (snapshot, run:terminal publications) from the controld store."""
    try:
        snapshot = json.loads(read_file(CONTROLD_SNAPSHOT, MAX_CONTROLD_SNAPSHOT), object_pairs_hook=reject_duplicates)
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuestError("controld snapshot unreadable after canary") from error
    publications = snapshot.get("publications") if isinstance(snapshot, dict) else None
    if not isinstance(publications, dict):
        raise GuestError("controld snapshot differs")
    return snapshot, {key: value for key, value in publications.items() if key.endswith(":run:terminal")}


def prove_stale_terminal_left_pending() -> None:
    """After the prior canary under the replay fault: the relay expired the
    grant and refused the terminal publish and its re-signed replacement
    (read back in between), and the controld store holds exactly one
    run:terminal publication, still Pending, whose event is the last refused
    id. No deferral marker exists: the prior activation's grant was approved,
    so that refusal is terminal, as it was in production."""
    record = replay_fault_record()
    if record["replayed_event_id"] is not None or not record["queried_event_ids"]:
        raise GuestError("relay fault record differs: prior terminal was not refused and read back")
    snapshot, terminal = controld_terminal_publications()
    if len(terminal) != 1 or snapshot.get("deferred_publications"):
        raise GuestError("prior canary left an unexpected terminal publication state")
    pending = next(iter(terminal.values()))
    signed = pending.get("Pending") if isinstance(pending, dict) and set(pending) == {"Pending"} else None
    if not isinstance(signed, dict) or signed.get("event_id") != record["refused_event_ids"][-1] or signed.get("kind") != 46101:
        raise GuestError("prior terminal publication is not the pending refused event")


def prove_relay_fault_recovery(relay_fault: str | None) -> None:
    """After the canary, require the armed relay fault to have fired and the
    controld snapshot to show the recovery: every terminal run publication
    ``Accepted``, and for the replay-before-grant fault the pending terminal
    accepted under the candidate grant with no deferral left. Plain file
    reads; no guest command."""
    if relay_fault is None:
        return
    if relay_fault == FAULT_REPLAY_BEFORE_GRANT:
        record = replay_fault_record()
        # The prior canary refused the terminal and its re-sign (the same id
        # when re-signed within the second); the candidate startup refused the
        # exact retry and its re-sign; the last refused id is the one the grant
        # approval replayed and the relay accepted.
        if (
            len(record["refused_event_ids"]) < 3 or not record["queried_event_ids"]
            or record["replayed_event_id"] is None or record["replayed_event_id"] != record["refused_event_ids"][-1]
        ):
            raise GuestError("relay fault record differs: pending terminal was not replayed after the grant")
        replayed = record["replayed_event_id"]
    else:
        try:
            record = load_json(RELAY_ROOT / "fault-fired.json")
        except FileNotFoundError as error:
            raise GuestError("relay fault did not fire") from error
        if (
            not isinstance(record, dict) or set(record) != {"mode", "refused_event_id", "queried"}
            or record["mode"] != relay_fault
            or not isinstance(record["refused_event_id"], str) or HEX64.fullmatch(record["refused_event_id"]) is None
            or record["queried"] is not True
        ):
            raise GuestError("relay fault record differs: refused publication was not read back")
        replayed = None
    snapshot, terminal = controld_terminal_publications()
    if snapshot.get("deferred_publications"):
        raise GuestError("controld snapshot still defers a publication after the canary")
    # The canary runs an attempt and a rerun, so every accepted request has its
    # own run:terminal key (the replay fault adds the prior activation's run);
    # the fault hit the first one and all must be Accepted.
    if not terminal or any(not isinstance(value, dict) or set(value) != {"Accepted"} for value in terminal.values()):
        raise GuestError("terminal run publication is not accepted after relay fault")
    accepted_ids = set()
    for accepted in (value["Accepted"] for value in terminal.values()):
        signed = accepted.get("signed") if isinstance(accepted, dict) else None
        relay_event_id = accepted.get("relay_event_id") if isinstance(accepted, dict) else None
        if (
            not isinstance(signed, dict) or not isinstance(relay_event_id, str) or HEX64.fullmatch(relay_event_id) is None
            or signed.get("event_id") != relay_event_id or signed.get("kind") != 46101
            or not isinstance(signed.get("signed_event"), dict) or signed["signed_event"].get("id") != relay_event_id
        ):
            raise GuestError("terminal run publication record is inconsistent after relay fault")
        accepted_ids.add(relay_event_id)
    if replayed is not None and (len(terminal) < 3 or replayed not in accepted_ids):
        raise GuestError("replayed terminal publication is not the accepted one after relay fault")


def verify_platform_systemd(platform_systemd: object) -> None:
    """Reject a clean-host image that differs from the frozen platform files."""
    if platform_systemd != PLATFORM_SYSTEMD:
        raise GuestError("systemd platform binding differs inside guest")
    for record in PLATFORM_SYSTEMD["service_drop_ins"]:
        raw = read_file(Path(record["path"]), MAX_JSON)
        if hashlib.sha256(raw).hexdigest() != record["sha256"]:
            raise GuestError(f"systemd platform file digest differs inside guest: {record['path']}")


def cross_bind(stage: Path, descriptor: dict[str, object]) -> tuple[Path, dict[str, object], dict[str, object], str]:
    platform_systemd = descriptor.get("platform_systemd")
    verify_platform_systemd(platform_systemd)
    candidate_tar = stage / "candidate.tar"
    candidate_raw = read_file(candidate_tar, MAX_TREE_BYTES)
    if hashlib.sha256(candidate_raw).hexdigest() != descriptor.get("candidate_tar_sha256"):
        raise GuestError("candidate archive digest differs inside guest")
    inputs = stage / "inputs"
    for name in PACKAGE_NAMES:
        if tree_digest(inputs / name) != descriptor["package_tree_sha256"].get(name):
            raise GuestError(f"package digest differs inside guest: {name}")
    for name in PRIOR_PACKAGE_NAMES:
        if tree_digest(inputs / "prior" / name) != descriptor["prior_package_tree_sha256"].get(name):
            raise GuestError(f"prior package digest differs inside guest: {name}")
    scenario_raw = read_file(inputs / "scenario.json")
    if hashlib.sha256(scenario_raw).hexdigest() != descriptor.get("scenario_sha256"):
        raise GuestError("scenario digest differs inside guest")
    prior_scenario_raw = read_file(inputs / "prior" / "scenario.json")
    if hashlib.sha256(prior_scenario_raw).hexdigest() != descriptor.get("prior_scenario_sha256"):
        raise GuestError("prior scenario digest differs inside guest")
    seccomp_raw = read_file(inputs / "seccomp.json", 16 * 1024 * 1024)
    if hashlib.sha256(seccomp_raw).hexdigest() != descriptor.get("seccomp_source_sha256") or descriptor.get("seccomp_source_sha256") != SECCOMP_SHA256:
        raise GuestError("seccomp source digest differs inside guest")
    binding_raw = read_file(inputs / "public-binding.json")
    if hashlib.sha256(binding_raw).hexdigest() != descriptor.get("public_binding_sha256"):
        raise GuestError("public binding digest differs inside guest")
    if binding_raw != read_file(STATE_ROOT / "public-binding.json"):
        raise GuestError("public binding differs from key ceremony")
    candidate = STATE_ROOT / "candidate"
    extract_candidate(candidate_raw, candidate)
    tracked_platform = read_file(candidate / PLATFORM_SYSTEMD_SOURCE, MAX_JSON)
    if hashlib.sha256(tracked_platform).hexdigest() != PLATFORM_SYSTEMD["service_drop_ins"][0]["sha256"]:
        raise GuestError("candidate systemd platform source differs inside guest")
    candidate_harness = read_file(
        candidate / "deploy/native-ci/activation/tests/clean_host_e2e/harness.py",
        2 * 1024 * 1024,
    )
    if hashlib.sha256(candidate_harness).hexdigest() != descriptor.get("harness_sha256"):
        raise GuestError("candidate harness digest differs inside guest")
    candidate_timing = read_file(
        candidate / "deploy/native-ci/activation/tests/clean_host_e2e/timing-contract.json",
        MAX_JSON,
    )
    try:
        candidate_timing_value = json.loads(candidate_timing, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise GuestError("candidate timing asset JSON differs inside guest") from error
    if (
        hashlib.sha256(candidate_timing).hexdigest() != descriptor.get("timing_asset_sha256")
        or hashlib.sha256(read_file(TIMING_PATH, MAX_JSON)).hexdigest() != descriptor.get("timing_asset_sha256")
        or candidate_timing_value != TIMING_CONTRACT
    ):
        raise GuestError("candidate timing asset binding differs inside guest")
    candidate_sha = descriptor.get("candidate_sha")
    if not isinstance(candidate_sha, str) or HEX40.fullmatch(candidate_sha) is None:
        raise GuestError("candidate binding differs")
    manifests = {name: package_manifest(inputs / name, name) for name in PACKAGE_NAMES}
    prior_manifests = {name: package_manifest(inputs / "prior" / name, name) for name in PRIOR_PACKAGE_NAMES}
    for name, manifest in manifests.items():
        if manifest.get("source_commit") != candidate_sha:
            raise GuestError(f"package source commit differs: {name}")
    for name, manifest in prior_manifests.items():
        if manifest.get("source_commit") != candidate_sha:
            raise GuestError(f"prior package source commit differs: {name}")
    activation = manifests["activation"]
    prior_activation = prior_manifests["activation"]
    for label, activation_value, execd_value in (
        ("activation", activation, manifests["execd"]),
        ("prior activation", prior_activation, prior_manifests["execd"]),
    ):
        if activation_value.get("platform_systemd") != platform_systemd:
            raise GuestError(f"{label} package systemd platform binding differs")
        binding = execd_value.get("activation_binding")
        if (
            not isinstance(binding, dict)
            or binding.get("source_commit") != candidate_sha
            or binding.get("package_digest") != activation_value.get("package_digest")
            or binding.get("activation_id") != activation_value.get("activation_id")
        ):
            raise GuestError(f"execd package differs from {label} package")
    validate_prior_activation(prior_activation, activation)
    activation_digest = activation.get("package_digest")
    activation_id = activation.get("activation_id")
    scenario = validate_scenario_binding(scenario_raw, candidate_sha, activation, "scenario")
    validate_scenario_binding(prior_scenario_raw, candidate_sha, prior_activation, "prior scenario")
    public = json.loads(binding_raw, object_pairs_hook=reject_duplicates)
    keyholder_entry = next((item for item in manifests["keyholder"].get("entries", []) if item.get("role") == "config"), None)
    if not isinstance(keyholder_entry, dict):
        raise GuestError("keyholder config package entry is absent")
    keyholder_config = json.loads(
        read_package_member(inputs / "keyholder", keyholder_entry["source"]),
        object_pairs_hook=reject_duplicates,
    )
    if keyholder_config != public.get("keyholder_public_spec"):
        raise GuestError("keyholder package differs from ceremony public keys")
    public_spec = public.get("keyholder_public_spec")
    channel_ids: list[object] = []
    for label, package, activation_value in (
        ("activation", inputs / "activation", activation),
        ("prior activation", inputs / "prior" / "activation", prior_activation),
    ):
        if activation_value.get("acceptance_template", {}).get("actor") != public.get("acceptance_actor"):
            raise GuestError(f"{label} actor differs from ceremony public key")
        controld_entry = next((item for item in activation_value.get("entries", []) if item.get("role") == "controld_config"), None)
        if not isinstance(controld_entry, dict):
            raise GuestError(f"{label} controld config entry is absent")
        controld_active = json.loads(
            read_package_member(package, controld_entry.get("active_source")),
            object_pairs_hook=reject_duplicates,
        )
        validate_ceremony_identities(
            public_spec, activation_value, manifests["keyholder"], controld_active,
        )
        if (
            not isinstance(public_spec, dict)
            or controld_active.get("relay_url") != public.get("relay_url")
            or controld_active.get("relay_http_origin") != public.get("relay_http_origin")
            or controld_active.get("keyholder_selectors") != public_spec.get("selectors")
        ):
            raise GuestError(f"{label} controld provider differs from ceremony binding")
        channel_ids.append(controld_active.get("channel_id"))
    channel_id = channel_ids[0]
    if not isinstance(channel_id, str) or not channel_id:
        raise GuestError("activation controld channel id is absent")
    if channel_ids[1] != channel_id:
        raise GuestError("prior activation controld channel differs")
    return candidate, scenario, public, channel_id


def validate_scenario_binding(
    scenario_raw: bytes, candidate_sha: str, activation: dict[str, object], label: str,
) -> dict[str, object]:
    scenario = json.loads(scenario_raw, object_pairs_hook=reject_duplicates)
    fixture = scenario.get("fixture") if isinstance(scenario, dict) else None
    driver = scenario.get("driver") if isinstance(scenario, dict) else None
    if (
        not isinstance(fixture, dict)
        or not isinstance(driver, dict)
        or driver.get("timeout_seconds") != timing_leaf("driver_operation")
        or fixture.get("integrated_candidate_sha") != candidate_sha
        or fixture.get("activation_package_digest") != activation.get("package_digest")
        or fixture.get("activation_id") != activation.get("activation_id")
    ):
        raise GuestError(f"{label} differs from candidate or activation package")
    return scenario


def validate_prior_activation(prior: dict[str, object], current: dict[str, object]) -> None:
    """The prior activation must be a distinct package that shares every installed component."""
    if (
        not isinstance(prior.get("activation_id"), str)
        or not isinstance(prior.get("package_digest"), str)
        or HEX64.fullmatch(prior["package_digest"]) is None
        or prior["activation_id"] == current.get("activation_id")
        or prior["package_digest"] == current.get("package_digest")
    ):
        raise GuestError("prior activation does not differ from the candidate activation")

    def component_packages(manifest: dict[str, object]) -> dict[object, tuple[object, object]]:
        components = manifest.get("components")
        if not isinstance(components, list):
            raise GuestError("activation components differ")
        return {
            item.get("name"): (item.get("package_manifest_sha256"), item.get("package_digest"))
            for item in components
            if isinstance(item, dict) and "package_digest" in item
        }

    if (
        not component_packages(prior)
        or component_packages(prior) != component_packages(current)
        or prior.get("identities") != current.get("identities")
        or prior.get("access_group") != current.get("access_group")
    ):
        raise GuestError("prior activation binds different component packages or principals")


def provision_seccomp(source: Path) -> None:
    raw = read_file(source, 16 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != SECCOMP_SHA256:
        raise GuestError("external seccomp source differs")
    root = Path("/usr/share/containers")
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    target = root / "seccomp.json"
    if target.exists() and read_file(target, 16 * 1024 * 1024) != raw:
        raise GuestError("base image seccomp source conflicts")
    if not target.exists():
        target.write_bytes(raw)
    target.chmod(0o644)
    metadata = target.lstat()
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o644:
        raise GuestError("external seccomp source metadata differs")


def create_principals(activation: Path) -> None:
    manifest = package_manifest(activation, "activation")
    entry = next((item for item in manifest.get("entries", []) if item.get("role") == "sysusers"), None)
    if not isinstance(entry, dict):
        raise GuestError("activation sysusers entry is absent")
    source = package_member(activation, entry["source"])
    if hashlib.sha256(read_file(source)).hexdigest() != entry.get("sha256"):
        raise GuestError("activation sysusers digest differs")
    command(["systemd-sysusers", str(source)])


def install_components(candidate: Path, inputs: Path, execd_package: Path) -> None:
    for name in ("runner", "controld"):
        command(["python3", str(candidate / f"deploy/native-ci/{name}/install.py"), "install", "--package", str(inputs / name)])
        emit_progress(f"{name}_installed")
    command(["python3", str(candidate / "deploy/native-ci/keyholder/install.py"), "install", "--package", str(inputs / "keyholder")])
    emit_progress("keyholder_installed")
    command(["python3", str(candidate / "deploy/native-ci/execd/install.py"), "install", "--package", str(execd_package)])
    emit_progress("execd_installed")
    command(["systemctl", "daemon-reload"])


def prior_rollback_proof(manifest: dict[str, object], rollback_stdout: bytes) -> dict[str, object]:
    """Read back the controller's terminal rollback of the prior activation."""
    status = parse_status(rollback_stdout, "controller rollback")
    receipt = load_json(ACTIVATION_RECEIPT_PATH)
    marker_raw = read_file(ROLLBACK_CLEANUP_PATH)
    marker = json.loads(marker_raw, object_pairs_hook=reject_duplicates)
    activation_id = manifest.get("activation_id")
    package_digest = manifest.get("package_digest")
    if (
        status.get("state") != "rolled_back"
        or status.get("activation_id") != activation_id
        or not isinstance(receipt, dict)
        or receipt.get("state") != "rolled_back"
        or receipt.get("activation_id") != activation_id
        or receipt.get("package_digest") != package_digest
        or not isinstance(marker, dict)
        or marker.get("activation_id") != activation_id
        or marker.get("package_digest") != package_digest
    ):
        raise GuestError("prior activation rollback proof differs")
    return {
        "activation_id": activation_id,
        "package_digest": package_digest,
        "receipt_state": "rolled_back",
        "rollback_cleanup_sha256": hashlib.sha256(marker_raw).hexdigest(),
        "execd_reinstall": "pending",
    }


def retire_execd_package_state() -> None:
    """After the execd rollback verb, move the terminal package state aside as the runbook does."""
    try:
        if not stat.S_ISREG(os.lstat(EXECD_PACKAGE_STATE / "rollback-v1.json").st_mode):
            raise GuestError("prior execd rollback receipt differs")
    except FileNotFoundError as error:
        raise GuestError("prior execd rollback receipt is absent") from error
    retired = EXECD_PACKAGE_STATE.with_name(
        EXECD_PACKAGE_STATE.name + ".retired-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
    )
    os.rename(EXECD_PACKAGE_STATE, retired)
    if os.path.lexists(EXECD_PACKAGE_STATE) or not retired.is_dir():
        raise GuestError("prior execd package state retirement differs")


def reinstall_execd(candidate: Path, prior_package: Path, package: Path) -> str:
    """Take the next execd package on a host whose central receipt is rolled back."""
    installer = str(candidate / "deploy/native-ci/execd/install.py")
    rolled_back = parse_status(
        command(["python3", installer, "rollback", "--package", str(prior_package)]).stdout,
        "execd rollback",
    )
    if rolled_back.get("state") != "rolled_back":
        raise GuestError("prior execd package rollback differs")
    retire_execd_package_state()
    dry_run = parse_status(
        command(["python3", installer, "install", "--dry-run", "--package", str(package)]).stdout,
        "execd dry run",
    )
    if dry_run.get("status") != "dry_run" or dry_run.get("activation_receipt") != "rolled_back":
        raise GuestError("execd dry run on the rolled-back host differs")
    installed = parse_status(
        command(["python3", installer, "install", "--package", str(package)]).stdout,
        "execd install",
    )
    if installed.get("status") != "installed" or installed.get("activation_receipt") != "rolled_back":
        raise GuestError("execd reinstall on the rolled-back host differs")
    command(["systemctl", "daemon-reload"])
    return "installed"


def expected_unit_fragments(inputs: Path, package_names: tuple[str, ...]) -> dict[str, dict[str, str]]:
    expected: dict[str, dict[str, str]] = {}
    systemd_roots = ("/etc/systemd/system/", "/usr/lib/systemd/system/")
    unit_name = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.@-]*\.(?:service|socket|target)$")
    drop_in_name = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9_-])?\.conf$")
    for name in package_names:
        package = inputs / name
        manifest = package_manifest(package, name)
        entries = manifest.get("entries")
        if not isinstance(entries, list):
            raise GuestError(f"{name} package entries differ")
        for entry in entries:
            if not isinstance(entry, dict):
                raise GuestError(f"{name} package entry differs")
            target = entry.get("target")
            if not isinstance(target, str):
                continue
            root = next((value for value in systemd_roots if target.startswith(value)), None)
            if root is None:
                continue
            source = package_member(package, entry.get("source"))
            digest = entry.get("sha256")
            if not isinstance(digest, str) or HEX64.fullmatch(digest) is None or hashlib.sha256(read_file(source)).hexdigest() != digest:
                raise GuestError(f"package systemd unit digest differs: {target}")
            parts = target.removeprefix(root).split("/")
            if any(part in {"", ".", ".."} for part in parts):
                raise GuestError("package systemd unit inventory differs")
            if len(parts) == 2:
                parent, drop_in = parts
                if (
                    not parent.endswith(".d")
                    or unit_name.fullmatch(parent[:-2]) is None
                    or drop_in_name.fullmatch(drop_in) is None
                ):
                    raise GuestError("package systemd unit inventory differs")
                continue
            if len(parts) != 1 or unit_name.fullmatch(parts[0]) is None:
                raise GuestError("package systemd unit inventory differs")
            unit = parts[0]
            binding = {"fragment_path": target, "sha256": digest}
            if unit in expected and expected[unit] != binding:
                raise GuestError(f"package systemd unit binding conflicts: {unit}")
            expected[unit] = binding
    return expected


def prove_installed_units(expected: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    observed = unit_state()
    for unit, binding in expected.items():
        state = observed[unit]
        if state["LoadState"] != "loaded" or state["FragmentPath"] != binding["fragment_path"]:
            raise GuestError(f"installed systemd fragment differs: {unit}")
        if hashlib.sha256(read_file(Path(binding["fragment_path"]))).hexdigest() != binding["sha256"]:
            raise GuestError(f"installed systemd fragment digest differs: {unit}")
    for unit in set(UNITS) - set(expected):
        if observed[unit]["LoadState"] != "not-found":
            raise GuestError(f"unexpected systemd fragment exists: {unit}")
    return observed


def tree_state(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    try:
        root_fd = open_absolute(root, directory=True)
    except FileNotFoundError:
        return result
    try:
        def walk(directory_fd: int, prefix: PurePosixPath) -> None:
            with os.scandir(directory_fd) as iterator:
                names = sorted(entry.name for entry in iterator)
            for name in names:
                relative = prefix / name
                try:
                    child_fd = os.open(
                        name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                except OSError as error:
                    raise GuestError("config tree contains an unsafe member") from error
                try:
                    metadata = os.fstat(child_fd)
                    if stat.S_ISDIR(metadata.st_mode):
                        walk(child_fd, relative)
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        raise GuestError("config tree contains a non-regular member")
                    result[relative.as_posix()] = {
                        "sha256": hashlib.sha256(read_open_file(child_fd, name, MAX_JSON)).hexdigest(),
                        "mode": stat.S_IMODE(metadata.st_mode),
                        "uid": metadata.st_uid,
                        "gid": metadata.st_gid,
                    }
                finally:
                    os.close(child_fd)

        walk(root_fd, PurePosixPath())
    finally:
        os.close(root_fd)
    return result


SYSTEMD_UNIT_PROPERTIES = (
    "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID",
    "InvocationID", "FragmentPath",
)
RELAY_PROPERTIES = ("LoadState", "ActiveState", "MainPID")


def parse_systemd_properties(
    process: subprocess.CompletedProcess[bytes], properties: tuple[str, ...],
    *, optional: tuple[str, ...] = (), error: str,
) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = process.stdout.decode().splitlines()
    except (AttributeError, UnicodeDecodeError) as exception:
        raise GuestError(error) from exception
    if not isinstance(process.stderr, bytes) or process.stderr or not lines:
        raise GuestError(error)
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key not in properties or key in values:
            raise GuestError(error)
        values[key] = value
    optional_set = set(optional)
    required = set(properties) - optional_set
    if not optional_set <= set(properties) or not required <= set(values):
        raise GuestError(error)
    for key in optional:
        values.setdefault(key, "0")
    return values


def systemd_unit_values(
    unit: str, process: subprocess.CompletedProcess[bytes],
) -> dict[str, str]:
    error = f"systemd unit readback failed: {unit}"
    optional = ("MainPID",) if unit.endswith((".socket", ".target")) else ()
    values = parse_systemd_properties(
        process, SYSTEMD_UNIT_PROPERTIES, optional=optional, error=error,
    )
    if (
        re.fullmatch(r"0|[1-9][0-9]*", values["MainPID"]) is None
        or values["ActiveState"] == "inactive" and values["MainPID"] != "0"
        or process.returncode != 0 and values["LoadState"] != "not-found"
    ):
        raise GuestError(error)
    return values


def unit_state() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for unit in UNITS:
        process = command([
            "systemctl", "show", unit,
            "--property=" + ",".join(SYSTEMD_UNIT_PROPERTIES),
        ], allow_failure=True)
        result[unit] = systemd_unit_values(unit, process)
    return result


def relay_mapping_present() -> bool:
    hosts = Path("/etc/hosts")
    lines = hosts.read_text().splitlines()
    mappings = [line.split() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    for fields in mappings:
        if "relay.test.invalid" in fields[1:] and fields[0] != "127.0.0.1":
            raise GuestError("relay hostname has a conflicting base-image mapping")
    return any(fields and fields[0] == "127.0.0.1" and "relay.test.invalid" in fields[1:] for fields in mappings)


def relay_public_config(public: dict[str, object], channel_id: str) -> dict[str, object]:
    """Roster the loopback relay enforces, shaped like the production prerequisites.

    The relay stores a ``POST /events`` only when the event pubkey equals the
    NIP-98 token pubkey and is a member of the private channel; a kind-46107
    grant needs the owner or admin role; the accepted read and evidence writes
    need a static or granted CI signer. So the acceptance actor is a channel
    admin, the ci-event key a channel member, and the nip98 key a static signer
    with no channel membership. Production must provide the same three facts
    for its channel before the canary.
    """
    selectors = public["keyholder_public_spec"]["selectors"]
    return {
        "origin": public["relay_http_origin"],
        "channel": {
            "id": channel_id,
            "visibility": "private",
            "members": {
                public["acceptance_actor"]["public_key"]: "admin",
                selectors["ci_event"]["public_key"]: "member",
            },
        },
        "ci_status_signer_pubkeys": [selectors["nip98"]["public_key"]],
    }


def start_relay(public: dict[str, object], channel_id: str, relay_fault: str | None = None) -> None:
    ca_target, ca_install, _ca_remove = ca_backend()
    hosts = Path("/etc/hosts")
    if not relay_mapping_present():
        with hosts.open("a") as handle:
            handle.write("127.0.0.1 relay.test.invalid\n")
    shutil.copyfile(STATE_ROOT / "ca.crt", ca_target)
    ca_target.chmod(0o644)
    command(list(ca_install))
    config = STATE_ROOT / "relay-public.json"
    config.write_bytes(canonical(relay_public_config(public, channel_id)))
    config.chmod(0o444)
    relay_root = RELAY_ROOT
    relay_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    if relay_fault is not None:
        # Armed before the unit starts; the relay reads it once at startup.
        (relay_root / "fault").write_bytes(relay_fault.encode() + b"\n")
        (relay_root / "fault").chmod(0o400)
    unit = Path("/run/systemd/system/buzzci-e2e-relay.service")
    unit.write_text(
        "[Unit]\nDescription=Disposable Buzz CI E2E relay\n"
        "[Service]\nType=simple\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n"
        "ReadWritePaths=/var/lib/buzzci-e2e-relay\n"
        "LoadCredentialEncrypted=relay.key:/etc/credstore.encrypted/buzzci-e2e-relay/relay.key\n"
        "ExecStart=/usr/bin/python3 /mnt/buzzci-stage/local_tls_relay.py "
        "--certificate=/var/lib/buzzci-e2e/relay.crt "
        "--private-key=/run/credentials/buzzci-e2e-relay.service/relay.key "
        "--public-config=/var/lib/buzzci-e2e/relay-public.json "
        "--object-root=/var/lib/buzzci-e2e-relay/objects "
        "--fault-flag=/var/lib/buzzci-e2e-relay/fault\n"
    )
    unit.chmod(0o444)
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "start", "buzzci-e2e-relay.service"])
    deadline = time.monotonic() + timing_leaf("relay_ready_window")
    record_command_timing({})
    while time.monotonic() < deadline:
        probe = command(["openssl", "s_client", "-connect", "relay.test.invalid:3443", "-servername", "relay.test.invalid", "-CAfile", str(STATE_ROOT / "ca.crt"), "-brief"], stdin=b"", timeout=timing_leaf("relay_probe"), allow_failure=True, inventory=False)
        if probe.returncode == 0:
            return
        time.sleep(0.1)
    raise GuestError("loopback relay did not become ready")


def cleanup(candidate: Path, activation_package: Path, attempted_stage: bool, hosts_added: bool) -> list[str]:
    errors: list[str] = []
    if attempted_stage:
        begin_phase("rollback")
        rollback_inventory_complete = True
        try:
            installed = Path("/usr/libexec/buzz-ci-activation-controller")
            controller = installed if installed.is_file() else candidate / "deploy/native-ci/activation/controller.py"
            if command([str(controller), "rollback", "--package", str(activation_package)], timeout=timing_leaf("rollback"), allow_failure=True, timing_terms={"rollback": 1}).returncode != 0:
                errors.append("controller rollback failed")
        except BaseException:
            errors.append("controller rollback could not run")
            rollback_inventory_complete = False
        if not rollback_inventory_complete:
            abandon_command_inventory()
    begin_phase("cleanup")
    for unit in UNITS:
        try:
            command(["systemctl", "stop", unit], timeout=timing_leaf("unit_stop"), allow_failure=True, timing_terms={"unit_stop": 1})
        except BaseException:
            errors.append(f"unit stop could not run: {unit}")
    try:
        command(["systemctl", "stop", "buzzci-e2e-relay.service"], timeout=timing_leaf("unit_stop"), allow_failure=True, timing_terms={"unit_stop": 1})
    except BaseException:
        errors.append("relay stop could not run")
    for root in (Path("/etc/credstore.encrypted/buzzci-keyholder"), Path("/etc/credstore.encrypted/buzzci-e2e-relay")):
        shutil.rmtree(root, ignore_errors=True)
        if root.exists():
            errors.append("encrypted test credential residue remains")
    relay_root = Path("/var/lib/buzzci-e2e-relay")
    shutil.rmtree(relay_root, ignore_errors=True)
    if relay_root.exists():
        errors.append("relay object residue remains")
    relay_unit = Path("/run/systemd/system/buzzci-e2e-relay.service")
    try:
        relay_unit.unlink()
        command(["systemctl", "daemon-reload"])
    except FileNotFoundError:
        pass
    except BaseException:
        errors.append("relay unit removal failed")
    if hosts_added:
        try:
            hosts = Path("/etc/hosts")
            lines = hosts.read_text().splitlines()
            hosts.write_text("\n".join(line for line in lines if line.strip() != "127.0.0.1 relay.test.invalid") + "\n")
            if relay_mapping_present():
                errors.append("relay host mapping residue remains")
        except BaseException:
            errors.append("relay host mapping removal failed")
    try:
        ca_target, _ca_install, ca_remove = ca_backend()
        ca_target.unlink()
        command(list(ca_remove))
    except FileNotFoundError:
        pass
    except GuestError:
        errors.append("test CA removal failed")
    return errors


def dormant_proof(configs: dict[str, dict[str, object]], units: dict[str, dict[str, str]]) -> dict[str, object]:
    current_configs = tree_state(Path("/etc/buzzci"))
    if current_configs != configs:
        raise GuestError("rollback did not restore dormant configs")
    current_units = unit_state()
    for unit, value in current_units.items():
        if value["ActiveState"] != "inactive" or value["MainPID"] != "0":
            raise GuestError(f"unit remains active: {unit}")
        if (value["LoadState"], value["UnitFileState"]) != (units[unit]["LoadState"], units[unit]["UnitFileState"]):
            raise GuestError(f"unit load/enable state differs: {unit}")
    if any(Path(path).exists() for path in SOCKETS):
        raise GuestError("socket residue remains")
    relay = command([
        "systemctl", "show", "buzzci-e2e-relay.service",
        "--property=" + ",".join(RELAY_PROPERTIES),
    ], allow_failure=True)
    relay_values = parse_systemd_properties(
        relay, RELAY_PROPERTIES, error="relay unit residue remains",
    )
    if relay_values != {"LoadState": "not-found", "ActiveState": "inactive", "MainPID": "0"}:
        raise GuestError("relay unit residue remains")
    process = command(["pgrep", "-a", "-f", "buzz-ci-(runner|controld|execd|executor|keyholder|acceptance)|local_tls_relay.py"], allow_failure=True)
    if process.returncode == 0 and process.stdout.strip():
        raise GuestError("Buzz CI process residue remains")
    return {
        "configs_sha256": hashlib.sha256(canonical(current_configs)).hexdigest(),
        "units_sha256": hashlib.sha256(canonical(current_units)).hexdigest(),
        "sockets_absent": True, "processes_absent": True,
        "encrypted_credentials_absent": True,
        "relay_residue_absent": True,
    }


def run_acceptance(phase: dict[str, object], stage: Path) -> dict[str, object]:
    begin_phase("install")
    descriptor = load_json(stage / "descriptor.json")
    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != {
            "schema_version", "candidate_sha", "harness_sha256", "timing_asset_sha256", "timing_sha256",
            "candidate_tar_sha256", "scenario_sha256", "seccomp_source_sha256",
            "public_binding_sha256", "package_tree_sha256", "platform_systemd",
            "prior_package_tree_sha256", "prior_scenario_sha256",
        }
        or descriptor.get("schema_version") != STAGE_SCHEMA
        or descriptor.get("timing_sha256") != phase.get("timing_sha256")
        or not isinstance(descriptor.get("harness_sha256"), str)
        or HEX64.fullmatch(descriptor["harness_sha256"]) is None
        or not isinstance(descriptor.get("timing_asset_sha256"), str)
        or HEX64.fullmatch(descriptor["timing_asset_sha256"]) is None
    ):
        raise GuestError("stage descriptor schema differs")
    if hashlib.sha256(canonical(descriptor)).hexdigest() != phase.get("descriptor_sha256"):
        raise GuestError("stage descriptor digest differs")
    candidate, _scenario, public, channel_id = cross_bind(stage, descriptor)
    relay_fault = phase.get("relay_fault")
    if relay_fault is not None and relay_fault not in RELAY_FAULTS:
        raise GuestError("relay fault mode differs")
    inputs = stage / "inputs"
    activation_package = inputs / "activation"
    prior_inputs = inputs / "prior"
    prior_activation = prior_inputs / "activation"
    rollback_package = prior_activation
    prior_proof: dict[str, object] | None = None
    attempted_stage = False
    configs: dict[str, dict[str, object]] | None = None
    units: dict[str, dict[str, str]] | None = None
    receipt_raw: bytes | None = None
    verifier_raw: bytes | None = None
    primary: BaseException | None = None
    hosts_added = False
    try:
        hosts_added = not relay_mapping_present()
        start_relay(public, channel_id, relay_fault)
        emit_progress("relay_ready")
        preinstall_units = unit_state()
        if any(state["LoadState"] != "not-found" for state in preinstall_units.values()):
            raise GuestError("clean host already contains a package-owned unit")
        emit_progress("preinstall_units_clean")
        component_units = expected_unit_fragments(inputs, ("runner", "controld", "keyholder", "execd"))
        activation_units = expected_unit_fragments(inputs, ("activation",))
        expected_units = dict(component_units)
        for unit, binding in activation_units.items():
            if unit in expected_units and expected_units[unit] != binding:
                raise GuestError(f"activation unit conflicts with component package: {unit}")
            expected_units[unit] = binding
        if set(expected_units) != set(UNITS):
            raise GuestError("package systemd unit set differs")
        emit_progress("package_units_validated")
        create_principals(activation_package)
        emit_progress("principals_created")
        provision_seccomp(inputs / "seccomp.json")
        emit_progress("seccomp_ready")
        install_components(candidate, inputs, prior_inputs / "execd")
        configs = tree_state(Path("/etc/buzzci"))
        units = prove_installed_units(component_units)
        emit_progress("installed_units_verified")
        controller = candidate / "deploy/native-ci/activation/controller.py"
        installed_controller = "/usr/libexec/buzz-ci-activation-controller"
        begin_phase("prior_controller_check")
        command(["python3", str(controller), "check", "--package", str(prior_activation)], timeout=timing_leaf("controller_check"), timing_terms={"controller_check": 1})
        begin_phase("prior_controller_stage")
        attempted_stage = True
        command(
            ["python3", str(controller), "stage", "--package", str(prior_activation), "--scenario", str(prior_inputs / "scenario.json")],
            timeout=timing_leaf("controller_stage"), timing_terms={"controller_stage": 1},
        )
        prove_installed_units(expected_units)
        begin_phase("prior_controller_activate")
        command([installed_controller, "activate", "--package", str(prior_activation)], timeout=timing_leaf("controller_activate"), timing_terms={"controller_activate": 1})
        if relay_fault == FAULT_REPLAY_BEFORE_GRANT:
            # Outside the frozen command inventory: the failing prior canary
            # exists only in this fault mode and must leave the pending
            # terminal that the candidate activation replays before its grant.
            run_prior_canary_expecting_stale_terminal(
                package_manifest(prior_activation, "activation"), read_file(prior_inputs / "scenario.json"), public,
            )
        begin_phase("prior_rollback")
        rolled_back = command([installed_controller, "rollback", "--package", str(prior_activation)], timeout=timing_leaf("rollback"), timing_terms={"rollback": 1})
        prior_proof = prior_rollback_proof(package_manifest(prior_activation, "activation"), rolled_back.stdout)
        attempted_stage = False
        rollback_package = activation_package
        begin_phase("reinstall")
        prior_proof["execd_reinstall"] = reinstall_execd(candidate, prior_inputs / "execd", inputs / "execd")
        prove_installed_units(component_units)
        emit_progress("execd_reinstalled")
        begin_phase("controller_check")
        command(["python3", str(controller), "check", "--package", str(activation_package)], timeout=timing_leaf("controller_check"), timing_terms={"controller_check": 1})
        begin_phase("controller_stage")
        try:
            stage_command(
                ["python3", str(controller), "stage", "--package", str(activation_package), "--scenario", str(inputs / "scenario.json")],
                timeout=timing_leaf("controller_stage"),
            )
        except StageCommandFailure as error:
            attempted_stage = error.rollback_required
            raise
        except BaseException:
            attempted_stage = True
            raise
        else:
            attempted_stage = True
        prove_installed_units(expected_units)
        begin_phase("controller_activate")
        command(["/usr/libexec/buzz-ci-activation-controller", "activate", "--package", str(activation_package)], timeout=timing_leaf("controller_activate"), timing_terms={"controller_activate": 1})
        begin_phase("canary")
        receipt_raw = run_capacity_one_canary(
            package_manifest(activation_package, "activation"),
            read_file(inputs / "scenario.json"),
            public,
        )
        prove_relay_fault_recovery(relay_fault)
        receipt_path = STATE_ROOT / "acceptance-receipt.json"
        receipt_path.write_bytes(receipt_raw)
        receipt_path.chmod(0o400)
        begin_phase("receipt_verifier")
        verifier_raw = command(["/usr/libexec/buzz-ci-verify-acceptance-receipt", str(inputs / "scenario.json"), str(receipt_path)], timeout=timing_leaf("receipt_verifier"), timing_terms={"receipt_verifier": 1}).stdout
        parse_verdict(verifier_raw)
    except BaseException as error:
        primary = error
        abandon_command_inventory()
    cleanup_errors = cleanup(candidate, rollback_package, attempted_stage, hosts_added)
    proof: dict[str, object] | None = None
    if configs is not None and units is not None:
        try:
            proof = dormant_proof(configs, units)
        except BaseException as error:
            cleanup_errors.append(str(error))
    shutil.rmtree(candidate, ignore_errors=True)
    for path in (STATE_ROOT / "acceptance-receipt.json", STATE_ROOT / "relay-public.json", STATE_ROOT / "ca.crt", STATE_ROOT / "relay.crt"):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    if not cleanup_errors:
        emit_progress("cleanup_return")
    if (
        primary is not None or cleanup_errors or receipt_raw is None or verifier_raw is None
        or proof is None or prior_proof is None or prior_proof.get("execd_reinstall") != "installed"
    ):
        message = str(primary) if primary is not None else "acceptance evidence incomplete"
        if cleanup_errors:
            message += "; " + "; ".join(cleanup_errors)
        raise GuestError(message)
    pending = {
        "schema_version": PENDING_SCHEMA,
        "challenge": phase["challenge"],
        "candidate_sha": descriptor["candidate_sha"],
        "scenario_sha256": descriptor["scenario_sha256"],
        "receipt_base64": base64.b64encode(receipt_raw).decode(),
        "dormant_proof": proof,
        "prior_activation": prior_proof,
    }
    write_transfer(pending)
    complete_progress()
    return pending


def verify_pending(phase: dict[str, object], stage: Path) -> dict[str, object]:
    begin_phase("verifier")
    pending = read_transfer()
    if (
        not isinstance(pending, dict)
        or set(pending) != {
            "schema_version", "challenge", "candidate_sha", "scenario_sha256",
            "receipt_base64", "dormant_proof", "prior_activation",
        }
        or pending.get("schema_version") != PENDING_SCHEMA
        or pending.get("challenge") != phase["challenge"]
        or pending.get("candidate_sha") != phase.get("candidate_sha")
        or pending.get("scenario_sha256") != phase.get("scenario_sha256")
        or hashlib.sha256(read_file(stage / "scenario.json")).hexdigest() != phase.get("scenario_sha256")
    ):
        raise GuestError("pending evidence binding differs")
    try:
        receipt_raw = base64.b64decode(pending["receipt_base64"], validate=True)
    except (TypeError, ValueError) as error:
        raise GuestError("pending evidence encoding differs") from error
    if not receipt_raw or len(receipt_raw) > MAX_COMMAND:
        raise GuestError("pending receipt size differs")
    try:
        receipt = json.loads(receipt_raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuestError("pending receipt JSON differs") from error
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version", "outcome", "scenario_sha256", "integrated_candidate_sha",
        "run_id", "checks", "zero_transition",
    } or receipt.get("schema_version") != "buzz-ci-capacity-one-acceptance-receipt/v2":
        raise GuestError("pending receipt closed schema differs")
    receipt_path = STATE_ROOT / "verify-receipt.json"
    receipt_path.write_bytes(canonical(receipt))
    receipt_path.chmod(0o400)
    verifier_raw = read_file(stage / "receipt_verifier.py", MAX_COMMAND)
    stages_raw = read_file(stage / "expected-stages.json", MAX_JSON)
    if (
        hashlib.sha256(verifier_raw).hexdigest() != phase.get("trusted_verifier_sha256")
        or hashlib.sha256(stages_raw).hexdigest() != phase.get("expected_stages_sha256")
    ):
        raise GuestError("trusted verifier asset digest differs")
    try:
        trusted_binary = STATE_ROOT / "trusted-verifier.py"
        stages_path = STATE_ROOT / "expected-stages.json"
        write_exclusive(trusted_binary, verifier_raw, 0o500)
        write_exclusive(stages_path, stages_raw, 0o644)
        spec = importlib.util.spec_from_file_location("buzzci_frozen_receipt_verifier", trusted_binary)
        if spec is None or spec.loader is None:
            raise GuestError("trusted verifier loader differs")
        verifier_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier_module)
        expected_stages = verifier_module.load_expected_stages(stages_path, 0, 0)
        verifier_module.verify(
            verifier_module.load_json(receipt_path),
            verifier_module.load_json(stage / "scenario.json"),
            expected_stages,
        )
        verifier = {"outcome": "pass", "status": "verified"}
    except (AttributeError, ImportError, OSError, ValueError) as error:
        raise GuestError("trusted verifier rejected pending receipt") from error
    if verifier != {"outcome": "pass", "status": "verified"}:
        raise GuestError("independent verifier replay did not pass")
    if (
        receipt.get("outcome") != "pass"
        or receipt.get("integrated_candidate_sha") != phase.get("candidate_sha")
        or receipt.get("scenario_sha256") != phase.get("scenario_sha256")
        or not isinstance(pending.get("dormant_proof"), dict)
        or set(pending["dormant_proof"]) != {
            "configs_sha256", "units_sha256", "sockets_absent", "processes_absent",
            "encrypted_credentials_absent", "relay_residue_absent",
        }
        or any(pending["dormant_proof"].get(name) is not True for name in (
            "sockets_absent", "processes_absent", "encrypted_credentials_absent", "relay_residue_absent",
        ))
    ):
        raise GuestError("independent receipt identity differs")
    prior_activation = pending.get("prior_activation")
    if (
        not isinstance(prior_activation, dict)
        or set(prior_activation) != PRIOR_ACTIVATION_PROOF_KEYS
        or prior_activation.get("activation_id") != phase.get("prior_activation_id")
        or prior_activation.get("package_digest") != phase.get("prior_package_digest")
        or prior_activation.get("receipt_state") != "rolled_back"
        or prior_activation.get("execd_reinstall") != "installed"
        or not isinstance(prior_activation.get("rollback_cleanup_sha256"), str)
        or HEX64.fullmatch(prior_activation["rollback_cleanup_sha256"]) is None
    ):
        raise GuestError("prior activation proof differs")
    receipt_path.unlink()
    trusted_binary.unlink()
    stages_path.unlink()
    result = {
        "phase": "run", "challenge": phase["challenge"], "outcome": "pass",
        "receipt_base64": base64.b64encode(canonical(receipt)).decode(),
        "verifier_base64": base64.b64encode(canonical({"outcome": "pass", "status": "verified"})).decode(),
        "dormant_proof": pending["dormant_proof"],
        "prior_activation": prior_activation,
    }
    complete_progress()
    return result


def main(argv: list[str]) -> int:
    global _PROGRESS_BOOT, _PROGRESS_LAST_PHASE, _PROGRESS_SEQUENCE, _PROGRESS_STARTED
    if len(argv) != 1:
        return 2
    try:
        phase = load_json(Path(argv[0]))
        if not isinstance(phase, dict) or phase.get("schema_version") != PHASE_SCHEMA:
            raise GuestError("guest phase schema differs")
        if not isinstance(phase.get("challenge"), str) or HEX64.fullmatch(phase["challenge"]) is None:
            raise GuestError("guest challenge differs")
        if phase.get("timing") != TIMING_CONTRACT or phase.get("timing_sha256") != timing_sha256():
            raise GuestError("guest timing contract differs")
        _PROGRESS_BOOT = {"ceremony": "ceremony", "run": "candidate", "verify": "verifier"}.get(str(phase.get("phase")))
        if _PROGRESS_BOOT is None:
            raise GuestError("guest phase differs")
        _PROGRESS_SEQUENCE = 0
        _PROGRESS_STARTED = time.monotonic()
        _PROGRESS_LAST_PHASE = None
        begin_phase("boot_cloud_init", emit_event=False)
        require_guest()
        disable_swap()
        emit_progress("guest_started")
        if phase.get("phase") == "ceremony":
            if set(phase) != {
                "schema_version", "phase", "challenge", "controld_uid", "controld_gid",
                "timing", "timing_sha256",
            }:
                raise GuestError("ceremony phase fields differ")
            validate_evidence_device()
            if TRANSFER_DEVICE.exists():
                raise GuestError("ceremony must not have an evidence-transfer device")
            result = ceremony(phase)
            emit(result)
        elif phase.get("phase") == "run":
            if set(phase) != {
                "schema_version", "phase", "challenge", "descriptor_sha256",
                "timing", "timing_sha256", "relay_fault",
            }:
                raise GuestError("candidate phase fields differ")
            if phase["relay_fault"] is not None and phase["relay_fault"] not in RELAY_FAULTS:
                raise GuestError("relay fault mode differs")
            if evidence_device_present():
                raise GuestError("candidate execution must not have an evidence transport")
            transfer_fd = os.open(TRANSFER_DEVICE, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                transfer_capacity(transfer_fd)
            finally:
                os.close(transfer_fd)
            run_acceptance(phase, Path(argv[0]).parent)
            return 0
        elif phase.get("phase") == "verify":
            if set(phase) != {
                "schema_version", "phase", "challenge", "candidate_sha",
                "scenario_sha256", "trusted_verifier_sha256", "expected_stages_sha256",
                "prior_activation_id", "prior_package_digest",
                "timing", "timing_sha256",
            }:
                raise GuestError("verification phase fields differ")
            validate_evidence_device()
            transfer_fd = os.open(TRANSFER_DEVICE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                transfer_capacity(transfer_fd)
            finally:
                os.close(transfer_fd)
            if any(
                not isinstance(phase[name], str) or HEX64.fullmatch(phase[name]) is None
                for name in ("trusted_verifier_sha256", "expected_stages_sha256")
            ):
                raise GuestError("trusted verifier binding differs")
            result = verify_pending(phase, Path(argv[0]).parent)
            emit(result)
        else:
            raise GuestError("guest phase differs")
        return 0
    except BaseException:
        # Console output is deliberately empty; the host accepts only a complete pass frame.
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
