#!/usr/bin/env python3
"""Trusted guest-side key ceremony and activation acceptance executor."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import importlib.util
import io
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
import tarfile
import tempfile
import time

PHASE_SCHEMA = "buzz-ci-clean-host-e2e-guest-phase/v2"
FRAME_SCHEMA = "buzz-ci-clean-host-e2e-frame/v2"
BINDING_SCHEMA = "buzz-ci-clean-host-e2e-public-binding/v2"
STAGE_SCHEMA = "buzz-ci-clean-host-e2e-stage/v2"
STATE_ROOT = Path("/var/lib/buzzci-e2e")
EVIDENCE_DEVICE = Path("/dev/virtio-ports/buzzci.evidence")
TRANSFER_DEVICE = Path("/dev/vdb")
KEY_NAMES = ("ci-event", "nip98", "manifest", "acceptance-actor")
PACKAGE_NAMES = ("runner", "controld", "keyholder", "execd", "activation")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON = 1024 * 1024
MAX_COMMAND = 4 * 1024 * 1024
MAX_TREE_FILES = 1024
MAX_TREE_BYTES = 64 * 1024 * 1024
TRANSFER_SIZE = 8 * 1024 * 1024
TRANSFER_MAGIC = b"BUZZCI-EVIDENCE\0"
SECCOMP_SHA256 = "2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4"
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
SOCKETS = (
    "/run/buzzci/acceptance-control.sock", "/run/buzzci/controld-acceptance.sock",
    "/run/buzzci/runner-control.sock", "/run/buzzci/execd.sock",
    "/run/buzzci/executor.sock", "/run/buzzci/keyholder.sock",
)


class GuestError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() + b"\n"


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


def command(argv: list[str], *, stdin: bytes | None = None, timeout: int = 30, allow_failure: bool = False) -> subprocess.CompletedProcess[bytes]:
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
        )
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if stdout.tell() > MAX_COMMAND or stderr.tell() > MAX_COMMAND:
                    raise GuestError(f"guest command output exceeded bound: {Path(argv[0]).name}")
                if time.monotonic() >= deadline:
                    raise GuestError(f"guest command timed out: {Path(argv[0]).name}")
                time.sleep(0.01)
            stdout.seek(0)
            stderr.seek(0)
            result = subprocess.CompletedProcess(argv, process.returncode, stdout.read(MAX_COMMAND + 1), stderr.read(MAX_COMMAND + 1))
        finally:
            reap_process_group(process)
    if len(result.stdout) > MAX_COMMAND or len(result.stderr) > MAX_COMMAND:
        raise GuestError(f"guest command output exceeded bound: {Path(argv[0]).name}")
    if result.returncode != 0 and not allow_failure:
        raise GuestError(f"guest command failed: {Path(argv[0]).name}")
    return result


def require_guest() -> None:
    if os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise GuestError("guest entry requires root under systemd")
    for name in (
        "openssl", "pgrep", "python3", "systemctl", "systemd-creds",
        "systemd-sysusers", "systemd-tmpfiles", "update-ca-certificates", "swapoff",
    ):
        if shutil.which(name) is None:
            raise GuestError(f"guest prerequisite is absent: {name}")


def disable_swap() -> None:
    command(["swapoff", "-a"])
    swaps = SWAPS_PATH.read_text().splitlines()
    if len(swaps) != 1 or not swaps[0].startswith("Filename"):
        raise GuestError("guest swap remains enabled")


def emit(value: dict[str, object]) -> None:
    value = {"schema_version": FRAME_SCHEMA, **value}
    payload = canonical(value)
    frame = struct.pack(">I", len(payload)) + payload + hashlib.sha256(payload).digest()
    fd = os.open(EVIDENCE_DEVICE, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        view = memoryview(frame)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
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
            "schema_version": 1,
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
                "binding_receipt_path": "/var/lib/buzzci/activation-controller/controld-acceptance-v1.json",
                "credential_selector": "acceptance-actor.key",
            },
        },
    }
    binding_path = STATE_ROOT / "public-binding.json"
    binding_path.write_bytes(canonical(binding))
    binding_path.chmod(0o444)
    return {
        "phase": "ceremony", "challenge": phase["challenge"], "outcome": "pass",
        "public_binding": binding, "raw_key_absence": True,
    }


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


def cross_bind(stage: Path, descriptor: dict[str, object]) -> tuple[Path, dict[str, object], dict[str, object]]:
    candidate_tar = stage / "candidate.tar"
    candidate_raw = read_file(candidate_tar, MAX_TREE_BYTES)
    if hashlib.sha256(candidate_raw).hexdigest() != descriptor.get("candidate_tar_sha256"):
        raise GuestError("candidate archive digest differs inside guest")
    inputs = stage / "inputs"
    for name in PACKAGE_NAMES:
        if tree_digest(inputs / name) != descriptor["package_tree_sha256"].get(name):
            raise GuestError(f"package digest differs inside guest: {name}")
    scenario_raw = read_file(inputs / "scenario.json")
    if hashlib.sha256(scenario_raw).hexdigest() != descriptor.get("scenario_sha256"):
        raise GuestError("scenario digest differs inside guest")
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
    candidate_sha = descriptor.get("candidate_sha")
    if not isinstance(candidate_sha, str) or HEX40.fullmatch(candidate_sha) is None:
        raise GuestError("candidate binding differs")
    manifests = {name: package_manifest(inputs / name, name) for name in PACKAGE_NAMES}
    for name, manifest in manifests.items():
        if manifest.get("source_commit") != candidate_sha:
            raise GuestError(f"package source commit differs: {name}")
    activation = manifests["activation"]
    execd = manifests["execd"]
    activation_digest = activation.get("package_digest")
    activation_id = activation.get("activation_id")
    binding = execd.get("activation_binding")
    if (
        not isinstance(binding, dict)
        or binding.get("source_commit") != candidate_sha
        or binding.get("package_digest") != activation_digest
        or binding.get("activation_id") != activation_id
    ):
        raise GuestError("execd package differs from activation package")
    scenario = json.loads(scenario_raw, object_pairs_hook=reject_duplicates)
    fixture = scenario.get("fixture") if isinstance(scenario, dict) else None
    if (
        not isinstance(fixture, dict)
        or fixture.get("integrated_candidate_sha") != candidate_sha
        or fixture.get("activation_package_digest") != activation_digest
        or fixture.get("activation_id") != activation_id
    ):
        raise GuestError("scenario differs from candidate or activation package")
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
    if activation.get("acceptance_template", {}).get("actor") != public.get("acceptance_actor"):
        raise GuestError("activation actor differs from ceremony public key")
    controld_entry = next((item for item in activation.get("entries", []) if item.get("role") == "controld_config"), None)
    if not isinstance(controld_entry, dict):
        raise GuestError("activation controld config entry is absent")
    controld_active = json.loads(
        read_package_member(inputs / "activation", controld_entry.get("active_source")),
        object_pairs_hook=reject_duplicates,
    )
    public_spec = public.get("keyholder_public_spec")
    if (
        not isinstance(public_spec, dict)
        or controld_active.get("relay_url") != public.get("relay_url")
        or controld_active.get("relay_http_origin") != public.get("relay_http_origin")
        or controld_active.get("keyholder_selectors") != public_spec.get("selectors")
        or (controld_active.get("keyholder_uid"), controld_active.get("keyholder_gid"))
        != (public_spec.get("peer", {}).get("uid"), public_spec.get("peer", {}).get("gid"))
    ):
        raise GuestError("activation controld provider differs from ceremony binding")
    return candidate, scenario, public


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


def install_components(candidate: Path, inputs: Path) -> None:
    for name in ("runner", "controld"):
        command(["python3", str(candidate / f"deploy/native-ci/{name}/install.py"), "install", "--package", str(inputs / name)])
    command(["python3", str(candidate / "deploy/native-ci/keyholder/install.py"), "install", "--package", str(inputs / "keyholder")])
    command(["python3", str(candidate / "deploy/native-ci/execd/install.py"), "install", "--package", str(inputs / "execd")])
    command(["systemctl", "daemon-reload"])


def expected_unit_fragments(inputs: Path, package_names: tuple[str, ...]) -> dict[str, dict[str, str]]:
    expected: dict[str, dict[str, str]] = {}
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
            if not isinstance(target, str) or not target.startswith(("/etc/systemd/system/", "/usr/lib/systemd/system/")):
                continue
            unit = Path(target).name
            if not unit.endswith((".service", ".socket", ".target")):
                raise GuestError("package systemd unit inventory differs")
            source = package_member(package, entry.get("source"))
            digest = entry.get("sha256")
            if not isinstance(digest, str) or HEX64.fullmatch(digest) is None or hashlib.sha256(read_file(source)).hexdigest() != digest:
                raise GuestError(f"package systemd unit digest differs: {unit}")
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


def unit_state() -> dict[str, dict[str, str]]:
    properties = ("LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID", "InvocationID", "FragmentPath")
    result: dict[str, dict[str, str]] = {}
    for unit in UNITS:
        process = command(["systemctl", "show", unit, "--property=" + ",".join(properties)], allow_failure=True)
        values: dict[str, str] = {}
        for line in process.stdout.decode().splitlines():
            key, separator, value = line.partition("=")
            if separator and key in properties:
                values[key] = value
        if set(values) != set(properties) or process.returncode != 0 and values.get("LoadState") != "not-found":
            raise GuestError(f"systemd unit readback failed: {unit}")
        result[unit] = values
    return result


def relay_mapping_present() -> bool:
    hosts = Path("/etc/hosts")
    lines = hosts.read_text().splitlines()
    mappings = [line.split() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    for fields in mappings:
        if "relay.test.invalid" in fields[1:] and fields[0] != "127.0.0.1":
            raise GuestError("relay hostname has a conflicting base-image mapping")
    return any(fields and fields[0] == "127.0.0.1" and "relay.test.invalid" in fields[1:] for fields in mappings)


def start_relay(public: dict[str, object]) -> None:
    hosts = Path("/etc/hosts")
    if not relay_mapping_present():
        with hosts.open("a") as handle:
            handle.write("127.0.0.1 relay.test.invalid\n")
    ca_target = Path("/usr/local/share/ca-certificates/buzzci-disposable-e2e.crt")
    shutil.copyfile(STATE_ROOT / "ca.crt", ca_target)
    ca_target.chmod(0o644)
    command(["update-ca-certificates"])
    config = STATE_ROOT / "relay-public.json"
    config.write_bytes(canonical({
        "origin": public["relay_http_origin"],
        "nip98_public_key": public["keyholder_public_spec"]["selectors"]["nip98"]["public_key"],
    }))
    config.chmod(0o444)
    relay_root = Path("/var/lib/buzzci-e2e-relay")
    relay_root.mkdir(mode=0o700, parents=True, exist_ok=False)
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
        "--object-root=/var/lib/buzzci-e2e-relay/objects\n"
    )
    unit.chmod(0o444)
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "start", "buzzci-e2e-relay.service"])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        probe = command(["openssl", "s_client", "-connect", "relay.test.invalid:3443", "-servername", "relay.test.invalid", "-CAfile", str(STATE_ROOT / "ca.crt"), "-brief"], stdin=b"", timeout=2, allow_failure=True)
        if probe.returncode == 0:
            return
        time.sleep(0.1)
    raise GuestError("loopback relay did not become ready")


def cleanup(candidate: Path, activation_package: Path, attempted_stage: bool, hosts_added: bool) -> list[str]:
    errors: list[str] = []
    if attempted_stage:
        try:
            installed = Path("/usr/libexec/buzz-ci-activation-controller")
            controller = installed if installed.is_file() else candidate / "deploy/native-ci/activation/controller.py"
            if command([str(controller), "rollback", "--package", str(activation_package)], timeout=60, allow_failure=True).returncode != 0:
                errors.append("controller rollback failed")
        except BaseException:
            errors.append("controller rollback could not run")
    for unit in UNITS:
        try:
            command(["systemctl", "stop", unit], timeout=10, allow_failure=True)
        except BaseException:
            errors.append(f"unit stop could not run: {unit}")
    try:
        command(["systemctl", "stop", "buzzci-e2e-relay.service"], timeout=10, allow_failure=True)
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
    ca_target = Path("/usr/local/share/ca-certificates/buzzci-disposable-e2e.crt")
    try:
        ca_target.unlink()
        command(["update-ca-certificates", "--fresh"], timeout=30)
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
    relay = command(["systemctl", "show", "buzzci-e2e-relay.service", "--property=LoadState,ActiveState,MainPID"], allow_failure=True)
    relay_values = dict(line.partition("=")[::2] for line in relay.stdout.decode().splitlines() if "=" in line)
    if relay.returncode == 0 or relay_values != {"LoadState": "not-found", "ActiveState": "inactive", "MainPID": "0"}:
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
    descriptor = load_json(stage / "descriptor.json")
    if not isinstance(descriptor, dict) or descriptor.get("schema_version") != STAGE_SCHEMA:
        raise GuestError("stage descriptor schema differs")
    if hashlib.sha256(canonical(descriptor)).hexdigest() != phase.get("descriptor_sha256"):
        raise GuestError("stage descriptor digest differs")
    candidate, _scenario, public = cross_bind(stage, descriptor)
    inputs = stage / "inputs"
    activation_package = inputs / "activation"
    attempted_stage = False
    configs: dict[str, dict[str, object]] | None = None
    units: dict[str, dict[str, str]] | None = None
    receipt_raw: bytes | None = None
    verifier_raw: bytes | None = None
    primary: BaseException | None = None
    hosts_added = False
    try:
        hosts_added = not relay_mapping_present()
        start_relay(public)
        preinstall_units = unit_state()
        if any(state["LoadState"] != "not-found" for state in preinstall_units.values()):
            raise GuestError("clean host already contains a package-owned unit")
        component_units = expected_unit_fragments(inputs, ("runner", "controld", "keyholder", "execd"))
        activation_units = expected_unit_fragments(inputs, ("activation",))
        expected_units = dict(component_units)
        for unit, binding in activation_units.items():
            if unit in expected_units and expected_units[unit] != binding:
                raise GuestError(f"activation unit conflicts with component package: {unit}")
            expected_units[unit] = binding
        if set(expected_units) != set(UNITS):
            raise GuestError("package systemd unit set differs")
        create_principals(activation_package)
        provision_seccomp(inputs / "seccomp.json")
        install_components(candidate, inputs)
        configs = tree_state(Path("/etc/buzzci"))
        units = prove_installed_units(component_units)
        controller = candidate / "deploy/native-ci/activation/controller.py"
        command(["python3", str(controller), "check", "--package", str(activation_package)], timeout=60)
        attempted_stage = True
        command(["python3", str(controller), "stage", "--package", str(activation_package), "--scenario", str(inputs / "scenario.json")], timeout=120)
        prove_installed_units(expected_units)
        command(["/usr/libexec/buzz-ci-activation-controller", "activate", "--package", str(activation_package)], timeout=120)
        receipt_raw = command(["/usr/libexec/buzz-ci-capacity-one-canary"], stdin=read_file(inputs / "scenario.json"), timeout=600).stdout
        receipt_path = STATE_ROOT / "acceptance-receipt.json"
        receipt_path.write_bytes(receipt_raw)
        receipt_path.chmod(0o400)
        verifier_raw = command(["/usr/libexec/buzz-ci-verify-acceptance-receipt", str(inputs / "scenario.json"), str(receipt_path)], timeout=60).stdout
        parse_verdict(verifier_raw)
    except BaseException as error:
        primary = error
    cleanup_errors = cleanup(candidate, activation_package, attempted_stage, hosts_added)
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
    if primary is not None or cleanup_errors or receipt_raw is None or verifier_raw is None or proof is None:
        message = str(primary) if primary is not None else "acceptance evidence incomplete"
        if cleanup_errors:
            message += "; " + "; ".join(cleanup_errors)
        raise GuestError(message)
    pending = {
        "schema_version": "buzz-ci-clean-host-e2e-pending-evidence/v2",
        "challenge": phase["challenge"],
        "candidate_sha": descriptor["candidate_sha"],
        "scenario_sha256": descriptor["scenario_sha256"],
        "receipt_base64": base64.b64encode(receipt_raw).decode(),
        "dormant_proof": proof,
    }
    write_transfer(pending)
    return pending


def verify_pending(phase: dict[str, object], stage: Path) -> dict[str, object]:
    pending = read_transfer()
    if (
        not isinstance(pending, dict)
        or set(pending) != {
            "schema_version", "challenge", "candidate_sha", "scenario_sha256",
            "receipt_base64", "dormant_proof",
        }
        or pending.get("schema_version") != "buzz-ci-clean-host-e2e-pending-evidence/v2"
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
    receipt_path.unlink()
    trusted_binary.unlink()
    stages_path.unlink()
    return {
        "phase": "run", "challenge": phase["challenge"], "outcome": "pass",
        "receipt_base64": base64.b64encode(canonical(receipt)).decode(),
        "verifier_base64": base64.b64encode(canonical({"outcome": "pass", "status": "verified"})).decode(),
        "dormant_proof": pending["dormant_proof"],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        return 2
    try:
        phase = load_json(Path(argv[0]))
        if not isinstance(phase, dict) or phase.get("schema_version") != PHASE_SCHEMA:
            raise GuestError("guest phase schema differs")
        if not isinstance(phase.get("challenge"), str) or HEX64.fullmatch(phase["challenge"]) is None:
            raise GuestError("guest challenge differs")
        require_guest()
        disable_swap()
        if phase.get("phase") == "ceremony":
            if set(phase) != {"schema_version", "phase", "challenge", "controld_uid", "controld_gid"}:
                raise GuestError("ceremony phase fields differ")
            if not EVIDENCE_DEVICE.exists() or not stat.S_ISCHR(EVIDENCE_DEVICE.stat().st_mode):
                raise GuestError("ceremony evidence transport is absent")
            if TRANSFER_DEVICE.exists():
                raise GuestError("ceremony must not have an evidence-transfer device")
            result = ceremony(phase)
            emit(result)
        elif phase.get("phase") == "run":
            if set(phase) != {"schema_version", "phase", "challenge", "descriptor_sha256"}:
                raise GuestError("candidate phase fields differ")
            if EVIDENCE_DEVICE.exists():
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
            }:
                raise GuestError("verification phase fields differ")
            if not EVIDENCE_DEVICE.exists() or not stat.S_ISCHR(EVIDENCE_DEVICE.stat().st_mode):
                raise GuestError("verification evidence transport is absent")
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
