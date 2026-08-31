#!/usr/bin/env python3
"""Run capacity-one acceptance behind a disposable offline KVM boundary."""

from __future__ import annotations

import argparse
import base64
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

SCHEMA = "buzz-ci-clean-host-e2e-vm-contract/v2"
STATE_SCHEMA = "buzz-ci-clean-host-e2e-vm-state/v2"
FRAME_SCHEMA = "buzz-ci-clean-host-e2e-frame/v2"
PACKAGE_NAMES = ("runner", "controld", "keyholder", "execd", "activation")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON = 1024 * 1024
MAX_FRAME = 4 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_TREE_FILES = 1024
TRANSFER_SIZE = 8 * 1024 * 1024
PREPARE_TIMEOUT = 180
RUN_TIMEOUT = 900
SECCOMP_SHA256 = "2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4"
TOOLS = {
    "qemu": "/usr/bin/qemu-system-x86_64",
    "qemu_img": "/usr/bin/qemu-img",
    "bwrap": "/usr/bin/bwrap",
    "xorriso": "/usr/bin/xorriso",
    "cloud_localds": "/usr/bin/cloud-localds",
}
FROZEN_ASSETS = (
    "guest_entry.py", "local_tls_relay.py", "receipt_verifier.py", "expected-stages.json",
)
REQUIRED_CANDIDATE = (
    "deploy/native-ci/runner/install.py",
    "deploy/native-ci/controld/install.py",
    "deploy/native-ci/keyholder/install.py",
    "deploy/native-ci/execd/install.py",
    "deploy/native-ci/activation/controller.py",
    "deploy/native-ci/activation/package.py",
)


class HarnessError(RuntimeError):
    """Fail-closed harness rejection."""


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def asset_source(here: Path, name: str) -> Path:
    if name in {"guest_entry.py", "local_tls_relay.py"}:
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


def bwrap_prefix(state: Path) -> list[str]:
    prefix = [
        TOOLS["bwrap"], "--unshare-all", "--unshare-net", "--die-with-parent", "--new-session",
        "--ro-bind", "/usr", "/usr", "--proc", "/proc", "--dev", "/dev",
        "--dev-bind", "/dev/kvm", "/dev/kvm",
        "--tmpfs", "/tmp", "--tmpfs", "/run", "--dir", "/etc",
        "--dir", "/work", "--bind", str(state), "/work",
        "--chdir", "/work",
    ]
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
    command = bwrap_prefix(state) + [
        "--", TOOLS["qemu"], "-nodefaults", "-no-user-config", "-enable-kvm",
        "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", "2048",
        "-display", "none", "-serial", "none", "-monitor", "none", "-nic", "none",
        "-no-reboot", "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-drive", f"file=/work/{overlay},if=virtio,format=qcow2,cache=none",
        "-drive", "file=/work/stage.iso,media=cdrom,readonly=on",
        "-drive", "file=/work/seed.iso,media=cdrom,readonly=on",
    ]
    if transfer is not None:
        readonly = ",readonly=on" if transfer == "read-only" else ""
        command.extend([
            "-drive", f"file=/work/transfer.raw,if=none,format=raw,cache=none,id=transfer{readonly}",
            "-device", "virtio-blk-pci,drive=transfer,serial=buzzci-transfer",
        ])
    if evidence:
        command.extend([
            "-device", "virtio-serial-pci",
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
        "-V", label, "-o", str(output), str(source),
    ], timeout=60)
    output.chmod(0o400)


def make_seed(state: Path, instance_id: str) -> None:
    seed = state / "seed-source"
    seed.mkdir(mode=0o700)
    (seed / "meta-data").write_text(f"instance-id: {instance_id}\nlocal-hostname: buzzci-e2e\n")
    user_data = """#cloud-config
mounts:
  - [LABEL=BUZZCI_STAGE, /mnt/buzzci-stage, iso9660, 'ro,nosuid,nodev,noexec', '0', '0']
runcmd:
  - [python3, /mnt/buzzci-stage/guest_entry.py, /mnt/buzzci-stage/phase.json]
power_state:
  mode: poweroff
  timeout: 30
  condition: true
"""
    (seed / "user-data").write_text(user_data)
    bounded([TOOLS["cloud_localds"], str(state / "seed.iso"), str(seed / "user-data"), str(seed / "meta-data")])
    (state / "seed.iso").chmod(0o400)
    shutil.rmtree(seed)


def stage_common(state: Path, stage: Path, phase: dict[str, object]) -> None:
    for name in FROZEN_ASSETS:
        raw = read_regular(state / "frozen-assets" / name, 2 * 1024 * 1024)
        target = stage / name
        target.write_bytes(raw)
        target.chmod(0o444)
    (stage / "phase.json").write_bytes(canonical(phase))
    (stage / "phase.json").chmod(0o444)


def boot(
    state: Path, timeout: int, *, overlay: str,
    evidence_expected: bool, transfer: str | None = None,
) -> dict[str, object] | None:
    evidence = state / "evidence.bin"
    try:
        evidence.unlink()
    except FileNotFoundError:
        pass
    process = subprocess.Popen(
        qemu_command(state, overlay=overlay, evidence=evidence_expected, transfer=transfer), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    try:
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if evidence_expected and evidence.exists() and evidence.stat().st_size > MAX_FRAME + 36:
                raise HarnessError("guest evidence exceeded its bound")
            if time.monotonic() >= deadline:
                raise HarnessError("guest watchdog expired")
            time.sleep(0.05)
        code = process.returncode
    finally:
        reap_process_group(process)
    if code != 0:
        raise HarnessError("isolated guest exited without accepted evidence")
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
    for name in ("stage.iso", "seed.iso", "evidence.bin"):
        try:
            (state / name).unlink()
        except FileNotFoundError:
            pass


def destroy_state(state: Path) -> None:
    marker = state / "state.json"
    if not state.exists():
        return
    state = safe_directory(state)
    if not marker.is_file():
        raise HarnessError("refusing to destroy an unrecognized state directory")
    value = load_json(marker)
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema_version", "challenge", "image_sha256", "qemu_sha256", "qemu_img_sha256",
            "qemu_version", "tool_sha256", "harness_asset_sha256", "trusted_image_sha256",
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
    ):
        raise HarnessError("refusing to destroy an unrecognized state directory")
    shutil.rmtree(state)
    if state.exists():
        raise HarnessError("VM state remains after cleanup")


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
    state = safe_directory(arguments.state, create=True)
    challenge = os.urandom(32).hex()
    state_record = {
        "schema_version": STATE_SCHEMA,
        "challenge": challenge,
        "image_sha256": arguments.image_sha256,
        "qemu_sha256": arguments.qemu_sha256,
        "qemu_img_sha256": arguments.qemu_img_sha256,
        "qemu_version": proof["qemu_version"],
        "tool_sha256": proof["tool_sha256"],
        "harness_asset_sha256": asset_digests,
        "trusted_image_sha256": None,
    }
    (state / "state.json").write_bytes(canonical(state_record))
    (state / "state.json").chmod(0o400)
    try:
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
            "schema_version": "buzz-ci-clean-host-e2e-guest-phase/v2",
            "phase": "ceremony", "challenge": challenge,
            "controld_uid": arguments.controld_uid, "controld_gid": arguments.controld_gid,
        })
        make_iso(stage, state / "stage.iso", "BUZZCI_STAGE")
        shutil.rmtree(stage)
        make_seed(state, "buzzci-ceremony-" + challenge[:16])
        frame = boot(state, PREPARE_TIMEOUT, overlay="ceremony.qcow2", evidence_expected=True)
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
        return {"status": "prepared", "state": str(state), "public_binding": str(public_path), "raw_key_absence": True}
    except BaseException:
        destroy_state(state)
        raise


def validate_contract(path: Path) -> tuple[dict[str, object], Path, dict[str, list[tuple[str, int, bytes]]]]:
    value = load_json(path)
    required = {"schema_version", "state", "candidate_root", "candidate_sha", "scenario", "seccomp_source", "packages"}
    if not isinstance(value, dict) or set(value) != required or value["schema_version"] != SCHEMA:
        raise HarnessError("run contract shape differs")
    if not isinstance(value["candidate_sha"], str) or HEX40.fullmatch(value["candidate_sha"]) is None:
        raise HarnessError("candidate SHA is invalid")
    state = safe_directory(Path(str(value["state"])))
    state_record = load_json(state / "state.json")
    if not isinstance(state_record, dict) or state_record.get("schema_version") != STATE_SCHEMA:
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
    candidate = safe_input_directory(Path(str(value["candidate_root"])))
    resolved = bounded(["/usr/bin/git", "-C", str(candidate), "rev-parse", f"{value['candidate_sha']}^{{commit}}"] ).decode().strip()
    if resolved != value["candidate_sha"]:
        raise HarnessError("candidate commit object differs")
    for relative in REQUIRED_CANDIDATE:
        if not bounded(["/usr/bin/git", "-C", str(candidate), "cat-file", "-e", f"{value['candidate_sha']}:{relative}"], maximum=1024) == b"":
            raise HarnessError("candidate prerequisite probe returned output")
    packages = value["packages"]
    if not isinstance(packages, dict) or set(packages) != set(PACKAGE_NAMES):
        raise HarnessError("package set differs")
    records: dict[str, list[tuple[str, int, bytes]]] = {}
    for name in PACKAGE_NAMES:
        descriptor = packages[name]
        if not isinstance(descriptor, dict) or set(descriptor) != {"path", "tree_sha256"} or HEX64.fullmatch(str(descriptor["tree_sha256"])) is None:
            raise HarnessError(f"package descriptor differs: {name}")
        item_records = tree_records(safe_input_directory(Path(str(descriptor["path"]))))
        if tree_digest(item_records) != descriptor["tree_sha256"]:
            raise HarnessError(f"package tree digest differs: {name}")
        records[name] = item_records
    scenario = value["scenario"]
    if not isinstance(scenario, dict) or set(scenario) != {"path", "sha256"} or HEX64.fullmatch(str(scenario["sha256"])) is None:
        raise HarnessError("scenario descriptor differs")
    scenario_raw = read_regular(safe_input_file(Path(str(scenario["path"]))), MAX_JSON)
    if hashlib.sha256(scenario_raw).hexdigest() != scenario["sha256"]:
        raise HarnessError("scenario digest differs")
    seccomp = value["seccomp_source"]
    if not isinstance(seccomp, dict) or set(seccomp) != {"path", "sha256"} or seccomp.get("sha256") != SECCOMP_SHA256:
        raise HarnessError("seccomp source descriptor differs")
    seccomp_raw = read_regular(safe_input_file(Path(str(seccomp["path"]))), 16 * 1024 * 1024)
    if hashlib.sha256(seccomp_raw).hexdigest() != SECCOMP_SHA256:
        raise HarnessError("seccomp source digest differs")
    return value, state, records, scenario_raw, seccomp_raw


def create_run_stage(
    contract: dict[str, object], state: Path,
    records: dict[str, list[tuple[str, int, bytes]]], scenario_raw: bytes, seccomp_raw: bytes,
) -> None:
    stage = state / "stage"
    stage.mkdir(mode=0o700)
    candidate_tar = stage / "candidate.tar"
    bounded([
        "/usr/bin/git", "-C", str(contract["candidate_root"]), "archive", "--format=tar",
        f"--output={candidate_tar}", contract["candidate_sha"], "--", "deploy/native-ci",
    ], timeout=60)
    candidate_tar.chmod(0o400)
    inputs = stage / "inputs"
    inputs.mkdir(mode=0o700)
    for name in PACKAGE_NAMES:
        materialize_tree(records[name], inputs / name)
    (inputs / "scenario.json").write_bytes(scenario_raw)
    (inputs / "scenario.json").chmod(0o400)
    (inputs / "seccomp.json").write_bytes(seccomp_raw)
    (inputs / "seccomp.json").chmod(0o400)
    public_raw = read_regular(state / "public-binding.json", MAX_JSON)
    (inputs / "public-binding.json").write_bytes(public_raw)
    (inputs / "public-binding.json").chmod(0o400)
    descriptor = {
        "schema_version": "buzz-ci-clean-host-e2e-stage/v2",
        "candidate_sha": contract["candidate_sha"],
        "candidate_tar_sha256": file_sha256(candidate_tar),
        "scenario_sha256": contract["scenario"]["sha256"],
        "seccomp_source_sha256": SECCOMP_SHA256,
        "public_binding_sha256": hashlib.sha256(public_raw).hexdigest(),
        "package_tree_sha256": {name: tree_digest(records[name]) for name in PACKAGE_NAMES},
    }
    (stage / "descriptor.json").write_bytes(canonical(descriptor))
    (stage / "descriptor.json").chmod(0o444)
    state_record = load_json(state / "state.json")
    stage_common(state, stage, {
        "schema_version": "buzz-ci-clean-host-e2e-guest-phase/v2",
        "phase": "run", "challenge": state_record["challenge"],
        "descriptor_sha256": hashlib.sha256(canonical(descriptor)).hexdigest(),
    })
    make_iso(stage, state / "stage.iso", "BUZZCI_STAGE")
    shutil.rmtree(stage)
    make_seed(state, "buzzci-run-" + str(state_record["challenge"])[:16])


def create_verify_stage(
    contract: dict[str, object], state: Path, scenario_raw: bytes,
) -> None:
    clean_transient(state)
    stage = state / "stage"
    stage.mkdir(mode=0o700)
    scenario_path = stage / "scenario.json"
    scenario_path.write_bytes(scenario_raw)
    scenario_path.chmod(0o400)
    state_record = load_json(state / "state.json")
    assets = state_record["harness_asset_sha256"]
    stage_common(state, stage, {
        "schema_version": "buzz-ci-clean-host-e2e-guest-phase/v2",
        "phase": "verify", "challenge": state_record["challenge"],
        "candidate_sha": contract["candidate_sha"],
        "scenario_sha256": contract["scenario"]["sha256"],
        "trusted_verifier_sha256": assets["receipt_verifier.py"],
        "expected_stages_sha256": assets["expected-stages.json"],
    })
    make_iso(stage, state / "stage.iso", "BUZZCI_STAGE")
    shutil.rmtree(stage)
    make_seed(state, "buzzci-verify-" + str(state_record["challenge"])[:16])


def validate_final_frame(frame: dict[str, object], contract: dict[str, object], challenge: str) -> tuple[bytes, bytes, dict[str, object]]:
    expected = {"schema_version", "phase", "challenge", "outcome", "receipt_base64", "verifier_base64", "dormant_proof"}
    if set(frame) != expected or frame["phase"] != "run" or frame["challenge"] != challenge or frame["outcome"] != "pass":
        raise HarnessError("final evidence frame differs")
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
) -> dict[str, object]:
    results = safe_directory(results_arg, create=True)
    success = False
    try:
        challenge = str(load_json(state / "state.json")["challenge"])
        if any((state / name).exists() for name in ("candidate.qcow2", "verifier.qcow2", "transfer.raw")):
            raise HarnessError("prior VM run residue exists")
        qemu_img_create(state, "candidate.qcow2", "trusted.qcow2")
        create_transfer(state)
        create_run_stage(contract, state, records, scenario_raw, seccomp_raw)
        boot(
            state, RUN_TIMEOUT, overlay="candidate.qcow2",
            evidence_expected=False, transfer="read-write",
        )
        (state / "candidate.qcow2").unlink()
        if (state / "candidate.qcow2").exists():
            raise HarnessError("candidate VM overlay remains before evidence transfer")
        if (state / "evidence.bin").exists():
            raise HarnessError("candidate VM reached verifier evidence storage")
        validate_transfer(state)
        qemu_img_create(state, "verifier.qcow2", "trusted.qcow2")
        create_verify_stage(contract, state, scenario_raw)
        frame = boot(
            state, 180, overlay="verifier.qcow2",
            evidence_expected=True, transfer="read-only",
        )
        if frame is None:
            raise HarnessError("verification guest returned no evidence")
        validate_transfer(state)
        receipt_raw, verifier_raw, proof = validate_final_frame(frame, contract, challenge)
        receipt_path = results / "acceptance-receipt.json"
        verifier_path = results / "verifier.json"
        state_record = load_json(state / "state.json")
        receipt_digest = hashlib.sha256(receipt_raw).hexdigest()
        verifier_digest = hashlib.sha256(verifier_raw).hexdigest()
        evidence_manifest = {
            "schema_version": "buzz-ci-clean-host-e2e-evidence/v2",
            "candidate_sha": contract["candidate_sha"],
            "image_sha256": state_record["image_sha256"],
            "tool_sha256": state_record["tool_sha256"],
            "harness_asset_sha256": state_record["harness_asset_sha256"],
            "package_tree_sha256": {name: tree_digest(records[name]) for name in PACKAGE_NAMES},
            "scenario_sha256": contract["scenario"]["sha256"],
            "seccomp_source_sha256": SECCOMP_SHA256,
            "transfer_bytes": TRANSFER_SIZE,
            "transfer_sha256": file_sha256(state / "transfer.raw"),
            "receipt_sha256": receipt_digest,
            "verifier_sha256": verifier_digest,
            "dormant_proof": proof,
        }
        evidence_path = results / "evidence-manifest.json"
        receipt_path.write_bytes(receipt_raw)
        verifier_path.write_bytes(verifier_raw)
        evidence_path.write_bytes(canonical(evidence_manifest))
        receipt_path.chmod(0o400)
        verifier_path.chmod(0o400)
        evidence_path.chmod(0o400)
        success = True
        return {
            "status": "pass", "candidate_sha": contract["candidate_sha"],
            "receipt_sha256": receipt_digest, "verifier_sha256": verifier_digest,
            "evidence_manifest_sha256": hashlib.sha256(canonical(evidence_manifest)).hexdigest(),
            "dormant_proof": proof, "vm_state_absent": True,
        }
    finally:
        destroy_state(state)
        if not success:
            shutil.rmtree(results, ignore_errors=True)


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
    arguments = parser.parse_args()
    try:
        if arguments.action == "capabilities":
            result = capabilities()
        elif arguments.action == "prepare":
            result = prepare(arguments)
        else:
            contract, state, records, scenario_raw, seccomp_raw = validate_contract(arguments.contract)
            result = {"status": "ready", "candidate_sha": contract["candidate_sha"], "boundary": "bubblewrap+qemu-kvm"}
            if arguments.action == "run":
                result = run_vm(contract, state, records, scenario_raw, seccomp_raw, arguments.results)
        sys.stdout.buffer.write(canonical(result))
        return 0
    except (OSError, ValueError, HarnessError, subprocess.SubprocessError) as error:
        sys.stderr.buffer.write(canonical({"status": "error", "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
