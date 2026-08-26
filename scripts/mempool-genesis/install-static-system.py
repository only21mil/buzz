#!/usr/bin/env python3
"""Install or roll back the reviewed, credential-free agent service package."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

SCHEMA = "buzz-agent-install-package-v2"
MANIFEST_NAME = "install-package.manifest.json"
RECEIPT_SCHEMA = "buzz-agent-static-install-receipt-v2"
REVIEW_TOOL = "/home/victor/.agents/skills/codex-review/scripts/tier2_evidence.py"
BACKUP_ROOT = Path("/var/lib/buzz-agent-install-backups")
PACKAGE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{7,95}$")
BACKUP_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{7,95}-[0-9]{8}T[0-9]{6}\.[0-9]{6}Z$")

TARGETS = {
    "/usr/local/libexec/buzz/verify-installed-agent": ("system/verify-installed-agent", 0o755),
    "/usr/local/libexec/buzz/buzz-agent-key-handoff": ("bin/buzz-agent-key-handoff", 0o755),
    "/usr/local/libexec/buzz/export-managed-agent-key": ("bin/export-managed-agent-key", 0o755),
    "/usr/local/sbin/buzz-install-agent-key": ("bin/buzz-install-agent-key", 0o755),
    "/usr/local/sbin/install-enrollment-map": ("system/install-enrollment-map", 0o755),
    "/etc/sudoers.d/buzz-agent-key-handoff": ("system/buzz-agent-key-handoff.sudoers", 0o440),
    "/etc/systemd/system/buzz-agent@.service": ("system/buzz-agent@.service", 0o644),
}

DESKTOP_TARGETS = {
    "/home/victor/work/buzz-client/Buzz_0.5.8-mempool-genesis_amd64.AppImage": (
        "desktop/Buzz_0.5.8_amd64.AppImage",
        "desktop_app",
        0o755,
        0o755,
    ),
    "/home/victor/projects/buzz/scripts/launch_buzz_desktop.sh": (
        "desktop/launch-buzz-desktop",
        "desktop_launcher",
        0o755,
        0o700,
    ),
}

MANIFEST_KEYS = {
    "schema",
    "package_id",
    "entries",
    "desktop_launcher_sha256",
    "desktop_previous_launcher_sha256",
    "package_fingerprint",
}
ENTRY_KEYS = {
    "owner",
    "role",
    "source",
    "target",
    "source_mode",
    "install_mode",
    "status",
    "sha256",
}


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_json_bytes(path: Path, max_bytes: int = 64 * 1024) -> tuple[dict[str, object], bytes]:
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError("JSON file is too large")
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value, raw


def load_json(path: Path) -> dict[str, object]:
    return load_json_bytes(path)[0]


def require_regular(path: Path, uid: int | None, mode: int) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"unsafe regular file: {path}")
    if uid is not None and metadata.st_uid != uid:
        raise ValueError(f"wrong file owner: {path}")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"wrong file mode: {path}")
    return metadata


def require_directory(path: Path, uid: int, mode: int) -> Path:
    lexical = Path(os.path.abspath(path))
    resolved = Path(os.path.realpath(path))
    if resolved != lexical:
        components = list(reversed(resolved.parents)) + [resolved]
        for component in components:
            component_metadata = component.lstat()
            if (
                not stat.S_ISDIR(component_metadata.st_mode)
                or component_metadata.st_uid != 0
                or component_metadata.st_mode & 0o022
            ):
                raise ValueError(f"unsafe resolved directory component: {component}")
    metadata = resolved.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or metadata.st_gid != uid:
        raise ValueError(f"unsafe directory: {path}")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"wrong directory mode: {path}")
    return resolved


def resolved_target_path(path: Path, uid: int) -> Path:
    parent = path.parent
    parent_metadata = parent.stat()
    resolved_parent = require_directory(parent, uid, stat.S_IMODE(parent_metadata.st_mode))
    return resolved_parent / path.name


def hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def read_verified_source(path: Path, expected_hash: str, expected_mode: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 1000
            or metadata.st_gid != 1000
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != expected_mode
        ):
            raise ValueError(f"unsafe package source: {path}")
        chunks: list[bytes] = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        payload = b"".join(chunks)
        if hashlib.sha256(payload).hexdigest() != expected_hash:
            raise ValueError(f"package source hash drift: {path}")
        return payload
    finally:
        os.close(fd)


def sync_directory(path: Path) -> None:
    metadata = path.stat()
    resolved = require_directory(path, 0, stat.S_IMODE(metadata.st_mode))
    fd = os.open(resolved, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_copy_bytes(
    payload: bytes,
    expected_hash: str,
    target: Path,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    parent = target.parent
    resolved_parent = resolved_target_path(target, uid).parent
    if resolved_parent.lstat().st_mode & 0o022:
        raise ValueError(f"target directory has unsafe mode: {parent}")
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.stage.", dir=resolved_parent))
    temporary_name = staging / target.name
    resolved_target = resolved_parent / target.name
    temporary_fd = -1
    try:
        os.chown(staging, uid, gid)
        require_directory(staging, uid, 0o700)
        temporary_fd = os.open(
            temporary_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        os.fchmod(temporary_fd, mode)
        os.fchown(temporary_fd, uid, gid)
        view = memoryview(payload)
        while view:
            written = os.write(temporary_fd, view)
            view = view[written:]
        os.fsync(temporary_fd)
        if hash_fd(temporary_fd) != expected_hash:
            raise ValueError(f"staged target verification failed: {target}")
        os.close(temporary_fd)
        temporary_fd = -1
        os.replace(temporary_name, resolved_target)
        sync_directory(resolved_parent)
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        try:
            staging.rmdir()
        except FileNotFoundError:
            pass


def atomic_copy_fd(source_fd: int, target: Path, mode: int, uid: int, gid: int) -> None:
    chunks: list[bytes] = []
    os.lseek(source_fd, 0, os.SEEK_SET)
    while chunk := os.read(source_fd, 1024 * 1024):
        chunks.append(chunk)
    payload = b"".join(chunks)
    atomic_copy_bytes(payload, hashlib.sha256(payload).hexdigest(), target, mode, uid, gid)


def copy_path_to_backup(source: Path, target: Path) -> None:
    resolved_source = resolved_target_path(source, 0)
    fd = os.open(resolved_source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe installed target: {source}")
        atomic_copy_fd(fd, target, 0o600, 0, 0)
    finally:
        os.close(fd)


def package_fingerprint(entries: list[dict[str, object]]) -> str:
    ordered = sorted(entries, key=lambda entry: str(entry["target"]).encode())
    payload = "".join(
        f'{entry["status"]}\t{entry["sha256"]}\t{entry["target"]}\n'
        for entry in ordered
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def exact_manifest(
    package: Path, raw: bytes | None = None
) -> tuple[dict[str, object], list[dict[str, object]]]:
    manifest_path = package / MANIFEST_NAME
    require_regular(manifest_path, 1000, 0o600)
    if raw is None:
        manifest = load_json(manifest_path)
    else:
        manifest = json.loads(raw, object_pairs_hook=reject_duplicates)
        if not isinstance(manifest, dict):
            raise ValueError("JSON root must be an object")
    if set(manifest) != MANIFEST_KEYS or manifest["schema"] != SCHEMA:
        raise ValueError("invalid install package manifest")
    package_id = manifest["package_id"]
    entries = manifest["entries"]
    if not isinstance(package_id, str) or not PACKAGE_ID.fullmatch(package_id):
        raise ValueError("invalid package id")
    if not isinstance(entries, list) or len(entries) != len(TARGETS) + len(DESKTOP_TARGETS):
        raise ValueError("invalid manifest entry count")
    expected: dict[str, tuple[str, str, str, int, int]] = {
        target: (source, "static", "static", mode, mode)
        for target, (source, mode) in TARGETS.items()
    }
    expected.update(
        {
            target: (source, "desktop", role, source_mode, install_mode)
            for target, (source, role, source_mode, install_mode) in DESKTOP_TARGETS.items()
        }
    )
    by_target: dict[str, dict[str, object]] = {}
    for raw in entries:
        if not isinstance(raw, dict) or set(raw) != ENTRY_KEYS:
            raise ValueError("invalid manifest entry")
        target = raw["target"]
        if not isinstance(target, str) or target in by_target or target not in expected:
            raise ValueError("invalid or duplicate manifest target")
        source, owner, role, source_mode, install_mode = expected[target]
        if (
            raw["source"] != source
            or raw["owner"] != owner
            or raw["role"] != role
            or raw["source_mode"] != f"{source_mode:04o}"
            or raw["install_mode"] != f"{install_mode:04o}"
            or raw["status"] != "A"
        ):
            raise ValueError("manifest target contract mismatch")
        digest = raw["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid manifest digest")
        by_target[target] = raw
    if set(by_target) != set(expected):
        raise ValueError("manifest target set mismatch")
    ordered = [by_target[target] for target in sorted(expected, key=lambda value: value.encode())]
    launcher = next(entry for entry in ordered if entry["role"] == "desktop_launcher")
    for name in (
        "desktop_launcher_sha256",
        "desktop_previous_launcher_sha256",
        "package_fingerprint",
    ):
        value = manifest[name]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"invalid manifest fingerprint: {name}")
    if manifest["desktop_launcher_sha256"] != launcher["sha256"]:
        raise ValueError("desktop launcher hash mismatch")
    if manifest["package_fingerprint"] != package_fingerprint(ordered):
        raise ValueError("package fingerprint mismatch")
    return manifest, ordered


def require_services_stopped() -> None:
    for slug in ("mempool", "genesis"):
        unit = f"buzz-agent@{slug}.service"
        active = subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False)
        enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", unit], check=False)
        if active.returncode == 0 or enabled.returncode == 0:
            raise ValueError(f"service must be disabled and inactive: {unit}")


def check_closure(state: Path) -> dict[str, str]:
    require_regular(state, 1000, 0o600)
    command = ["python3", REVIEW_TOOL, "check-closure", "--state", str(state)]
    if os.geteuid() == 0:
        command = ["sudo", "-n", "-u", "victor", *command]
    completed = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
    )
    raw = completed.stdout
    if not isinstance(raw, bytes) or len(raw) > 64 * 1024 or raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
        raise ValueError("check-closure did not return one bounded JSON line")
    result = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(result, dict):
        raise ValueError("check-closure output is not a JSON object")
    if (
        result.get("ok") is not True
        or result.get("subcommand") != "check-closure"
        or result.get("terminal") is not True
        or result.get("accepted") is not True
        or result.get("consumable") is not True
    ):
        raise ValueError("check-closure output is not a consumable acceptance")
    attestation: dict[str, str] = {}
    for key in ("state_digest", "bundle_digest", "artifact_fingerprint"):
        value = result.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"check-closure output has invalid {key}")
        attestation[key] = value
    bundle_path = result.get("bundle_path")
    if not isinstance(bundle_path, str) or not os.path.isabs(bundle_path):
        raise ValueError("check-closure output has invalid bundle_path")
    attestation["bundle_path"] = bundle_path
    return attestation


def accepted_bundle(
    state_path: Path, attestation: dict[str, str]
) -> tuple[dict[str, object], str]:
    state, state_raw = load_json_bytes(state_path, 256 * 1024)
    if hashlib.sha256(state_raw).hexdigest() != attestation.get("state_digest"):
        raise ValueError("closure state changed after check-closure")
    if state.get("schema") != "tier2-closure-state-v2":
        raise ValueError("unsupported closure state schema")
    lineage = state.get("lineage")
    if not isinstance(lineage, dict) or lineage.get("terminal") is not True or lineage.get("accepted") is not True:
        raise ValueError("closure state is not terminal and accepted")
    revision = state.get("current_revision")
    revisions = state.get("revisions")
    if not isinstance(revision, int) or revision not in (1, 2) or not isinstance(revisions, dict):
        raise ValueError("invalid closure revision")
    frozen = revisions.get(str(revision))
    if not isinstance(frozen, dict):
        raise ValueError("accepted closure revision is absent")
    bundle_path_text = frozen.get("bundle_path")
    bundle_digest = frozen.get("bundle_digest")
    artifact_fingerprint = frozen.get("artifact_fingerprint")
    if (
        not isinstance(bundle_path_text, str)
        or not os.path.isabs(bundle_path_text)
        or not isinstance(bundle_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", bundle_digest)
        or not isinstance(artifact_fingerprint, str)
        or not re.fullmatch(r"[0-9a-f]{64}", artifact_fingerprint)
    ):
        raise ValueError("invalid accepted closure binding")
    bundle_path = Path(bundle_path_text)
    if (
        bundle_path_text != attestation.get("bundle_path")
        or bundle_digest != attestation.get("bundle_digest")
        or artifact_fingerprint != attestation.get("artifact_fingerprint")
    ):
        raise ValueError("closure binding differs from check-closure attestation")
    require_regular(bundle_path, 1000, 0o600)
    bundle, raw = load_json_bytes(bundle_path)
    if hashlib.sha256(raw).hexdigest() != bundle_digest:
        raise ValueError("accepted evidence bundle digest mismatch")
    if (
        bundle.get("schema") != "tier2-evidence-v2"
        or bundle.get("revision") != revision
        or bundle.get("artifact_fingerprint") != artifact_fingerprint
        or bundle.get("candidate") != {"mode": "files"}
    ):
        raise ValueError("closure does not bind a files-mode evidence v2 bundle")
    return bundle, artifact_fingerprint


def bind_accepted_manifest(
    package: Path,
    manifest: dict[str, object],
    entries: list[dict[str, object]],
    attestation: dict[str, str],
    state_path: Path,
) -> None:
    bundle, accepted_fingerprint = accepted_bundle(state_path, attestation)
    sources = {
        str(package / str(entry["source"])): str(entry["sha256"])
        for entry in entries
    }
    expected_paths = sorted(sources, key=lambda path: path.encode())
    changed_paths = bundle.get("changed_paths")
    if not isinstance(changed_paths, list) or len(changed_paths) != len(expected_paths):
        raise ValueError("closure does not list exactly the installed package sources")
    canonical: list[str] = []
    observed_paths: list[str] = []
    for entry in changed_paths:
        if not isinstance(entry, dict) or set(entry) != {"status", "path", "sha256"}:
            raise ValueError("invalid closure package entry")
        status = entry["status"]
        path = entry["path"]
        digest = entry["sha256"]
        if (
            status != "A"
            or not isinstance(path, str)
            or not os.path.isabs(path)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError("closure package entry is not an installable file")
        observed_paths.append(path)
        if sources.get(path) != digest:
            raise ValueError("package source hash does not match accepted closure")
        canonical.append(f"{status}\t{digest}\t{path}\n")
    if observed_paths != expected_paths:
        raise ValueError("closure package source set or ordering mismatch")
    if hashlib.sha256("".join(canonical).encode()).hexdigest() != accepted_fingerprint:
        raise ValueError("closure artifact fingerprint mismatch")

    fingerprints = bundle.get("fingerprints")
    if not isinstance(fingerprints, dict):
        raise ValueError("accepted bundle lacks install package fingerprints")
    expected_fingerprints = {
        "package_fingerprint": manifest["package_fingerprint"],
        "desktop_launcher_sha256": manifest["desktop_launcher_sha256"],
        "desktop_previous_launcher_sha256": manifest[
            "desktop_previous_launcher_sha256"
        ],
    }
    for name, expected in expected_fingerprints.items():
        if fingerprints.get(name) != expected:
            raise ValueError(f"accepted closure fingerprint mismatch: {name}")


def accepted_manifest_bytes(
    package: Path, state_path: Path, attestation: dict[str, str]
) -> bytes:
    bundle, _artifact_fingerprint = accepted_bundle(state_path, attestation)
    fingerprints = bundle.get("fingerprints")
    expected = (
        fingerprints.get("manifest_sha256")
        if isinstance(fingerprints, dict)
        else None
    )
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("accepted bundle lacks fingerprint: manifest_sha256")
    manifest_path = package / MANIFEST_NAME
    require_regular(manifest_path, 1000, 0o600)
    raw = manifest_path.read_bytes()
    if len(raw) > 64 * 1024:
        raise ValueError("JSON file is too large")
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("accepted closure fingerprint mismatch: manifest_sha256")
    return raw


def verified_package(
    package: Path, state_path: Path
) -> tuple[dict[str, object], list[dict[str, object]], dict[str, bytes]]:
    require_directory(package, 1000, 0o700)
    attestation = check_closure(state_path)
    manifest_raw = accepted_manifest_bytes(package, state_path, attestation)
    manifest, entries = exact_manifest(package, manifest_raw)
    verified_sources: dict[str, bytes] = {}
    for entry in entries:
        verified_sources[str(entry["target"])] = read_verified_source(
            package / str(entry["source"]),
            str(entry["sha256"]),
            int(str(entry["source_mode"]), 8),
        )
    bind_accepted_manifest(package, manifest, entries, attestation, state_path)
    return manifest, entries, verified_sources


def verify_package(
    package: Path, state_path: Path
) -> tuple[dict[str, object], list[dict[str, object]]]:
    manifest, entries, _verified_sources = verified_package(package, state_path)
    return manifest, entries


def accepted_fingerprint(state_path: Path, name: str, attestation: dict[str, str]) -> str:
    bundle, _artifact_fingerprint = accepted_bundle(state_path, attestation)
    fingerprints = bundle.get("fingerprints")
    value = fingerprints.get(name) if isinstance(fingerprints, dict) else None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"accepted bundle lacks fingerprint: {name}")
    return value


def prepare_directories() -> bool:
    expected = {
        Path("/etc/buzz-agents"): 0o755,
        Path("/etc/buzz-agents/prompts"): 0o755,
        Path("/usr/local/libexec/buzz"): 0o755,
        Path("/usr/local/sbin"): 0o755,
        Path("/etc/sudoers.d"): 0o750,
        Path("/etc/systemd/system"): 0o755,
    }
    resolved = {path: require_directory(path, 0, mode) for path, mode in expected.items()}
    credential_dir = resolved[Path("/etc/buzz-agents")] / "credentials"
    if credential_dir.exists() or credential_dir.is_symlink():
        require_directory(credential_dir, 0, 0o700)
        return False
    else:
        try:
            credential_dir.mkdir(mode=0o700)
            os.chown(credential_dir, 0, 0)
            sync_directory(credential_dir.parent)
        except Exception:
            try:
                credential_dir.rmdir()
                sync_directory(credential_dir.parent)
            except OSError:
                pass
            raise
        return True


def target_metadata(path: Path) -> dict[str, object]:
    resolved = resolved_target_path(path, 0)
    metadata = resolved.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
    ):
        raise ValueError(f"unsafe installed target: {path}")
    fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        digest = hash_fd(fd)
    finally:
        os.close(fd)
    return {
        "exists": True,
        "sha256": digest,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def restore_changed(changed: list[str], previous: dict[str, dict[str, object]], backup: Path) -> None:
    for target_text in reversed(changed):
        target = Path(target_text)
        record = previous[target_text]
        if record["exists"]:
            source = backup / "files" / hashlib.sha256(target_text.encode()).hexdigest()
            resolved_source = resolved_target_path(source, 0)
            fd = os.open(resolved_source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                atomic_copy_fd(fd, target, int(str(record["mode"]), 8), int(record["uid"]), int(record["gid"]))
            finally:
                os.close(fd)
        elif target.exists() or target.is_symlink():
            resolved_target = resolved_target_path(target, 0)
            metadata = resolved_target.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != 0
                or metadata.st_gid != 0
            ):
                raise ValueError(f"unsafe rollback target: {target}")
            resolved_target.unlink()
            sync_directory(resolved_target.parent)


def timestamped_backup_id(package_id: str, now: datetime | None = None) -> str:
    instant = now or datetime.now(timezone.utc)
    return f"{package_id}-{instant.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}"


def write_receipt(path: Path, receipt: dict[str, object]) -> None:
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    resolved_path = resolved_target_path(path, 0)
    temporary_fd, temporary_name = tempfile.mkstemp(prefix=".receipt.", dir=resolved_path.parent)
    try:
        os.fchmod(temporary_fd, 0o600)
        os.fchown(temporary_fd, 0, 0)
        view = memoryview(payload)
        while view:
            written = os.write(temporary_fd, view)
            view = view[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.replace(temporary_name, resolved_path)
        sync_directory(resolved_path.parent)
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def remove_created_credential_directory(created: bool) -> None:
    if not created:
        return
    credential_dir = Path("/etc/buzz-agents/credentials")
    resolved_credential_dir = resolved_target_path(credential_dir, 0)
    resolved_credential_dir.rmdir()
    sync_directory(resolved_credential_dir.parent)


def install(package: Path, state: Path) -> None:
    if os.geteuid() != 0 or os.uname().nodename != "framework-desktop":
        raise ValueError("installer must run as root on framework-desktop")
    manifest, all_entries, all_verified_sources = verified_package(package, state)
    require_services_stopped()
    package_id = str(manifest["package_id"])
    entries = [entry for entry in all_entries if entry["owner"] == "static"]
    backup_id = timestamped_backup_id(package_id)
    verified_sources = {
        str(entry["target"]): all_verified_sources[str(entry["target"])]
        for entry in entries
    }
    all_verified_sources.clear()
    try:
        subprocess.run(["visudo", "-cf", str(package / "system/buzz-agent-key-handoff.sudoers")], check=True)
        subprocess.run(["systemd-analyze", "verify", str(package / "system/buzz-agent@.service")], check=True)
        BACKUP_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved_backup_root = require_directory(BACKUP_ROOT, 0, 0o700)
        backup = resolved_backup_root / backup_id
        if backup.exists() or backup.is_symlink():
            raise ValueError("backup/receipt already exists")
        backup.mkdir(mode=0o700)
        (backup / "files").mkdir(mode=0o700)
        require_directory(backup, 0, 0o700)
        require_directory(backup / "files", 0, 0o700)

        try:
            previous: dict[str, dict[str, object]] = {}
            for target_text in TARGETS:
                target = Path(target_text)
                if target.exists() or target.is_symlink():
                    previous[target_text] = target_metadata(target)
                    copy_path_to_backup(
                        target, backup / "files" / hashlib.sha256(target_text.encode()).hexdigest()
                    )
                else:
                    previous[target_text] = {"exists": False}
            receipt: dict[str, object] = {
                "schema": RECEIPT_SCHEMA,
                "backup_id": backup_id,
                "package_id": package_id,
                "install_state": "prepared",
                "previous": previous,
                "installed": {str(entry["target"]): str(entry["sha256"]) for entry in entries},
            }
            receipt_path = backup / "receipt.json"
            write_receipt(receipt_path, receipt)
        except Exception:
            shutil.rmtree(backup)
            sync_directory(resolved_backup_root)
            raise

        changed: list[str] = []
        credential_directory_created = False
        try:
            credential_directory_created = prepare_directories()
            for entry in entries:
                target_text = str(entry["target"])
                changed.append(target_text)
                atomic_copy_bytes(
                    verified_sources[target_text],
                    str(entry["sha256"]),
                    Path(target_text),
                    int(str(entry["install_mode"]), 8),
                    0,
                    0,
                )
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            for entry in entries:
                metadata = target_metadata(Path(str(entry["target"])))
                if (
                    metadata["sha256"] != entry["sha256"]
                    or metadata["mode"] != entry["install_mode"]
                ):
                    raise ValueError("installed target verification failed")
            receipt["install_state"] = "installed"
            write_receipt(receipt_path, receipt)
        except Exception:
            try:
                restore_changed(changed, previous, backup)
                remove_created_credential_directory(credential_directory_created)
                if changed:
                    subprocess.run(["systemctl", "daemon-reload"], check=True)
                receipt["install_state"] = "rolled_back"
                write_receipt(receipt_path, receipt)
            except Exception as rollback_error:
                receipt["install_state"] = "rollback_required"
                try:
                    write_receipt(receipt_path, receipt)
                except Exception:
                    pass
                raise RuntimeError("ROLLBACK_REQUIRED") from rollback_error
            raise
        print(f"INSTALLED {package_id} BACKUP {backup_id}")
    finally:
        verified_sources.clear()


def rollback(backup_id: str) -> None:
    if os.geteuid() != 0 or not BACKUP_ID.fullmatch(backup_id):
        raise ValueError("invalid rollback invocation")
    require_services_stopped()
    backup = require_directory(BACKUP_ROOT / backup_id, 0, 0o700)
    require_directory(backup / "files", 0, 0o700)
    receipt_path = backup / "receipt.json"
    require_regular(receipt_path, 0, 0o600)
    receipt = load_json(receipt_path)
    if set(receipt) != {"schema", "backup_id", "package_id", "install_state", "previous", "installed"}:
        raise ValueError("invalid receipt")
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["backup_id"] != backup_id
        or receipt["install_state"] != "installed"
        or not isinstance(receipt["package_id"], str)
        or not PACKAGE_ID.fullmatch(str(receipt["package_id"]))
    ):
        raise ValueError("wrong receipt identity")
    previous = receipt["previous"]
    installed = receipt["installed"]
    if not isinstance(previous, dict) or not isinstance(installed, dict):
        raise ValueError("invalid receipt maps")
    if set(previous) != set(TARGETS) or set(installed) != set(TARGETS):
        raise ValueError("receipt target mismatch")
    for target_text, expected_hash in installed.items():
        if target_metadata(Path(target_text))["sha256"] != expected_hash:
            raise ValueError("installed target drift blocks rollback")
    receipt["install_state"] = "rollback_started"
    write_receipt(receipt_path, receipt)
    restore_changed(list(TARGETS), previous, backup)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    receipt["install_state"] = "rolled_back"
    write_receipt(receipt_path, receipt)
    print(f"ROLLED_BACK {backup_id}")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--package", required=True)
    install_parser.add_argument("--state", required=True)
    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument("--backup-id", required=True)
    fingerprint_parser = subparsers.add_parser("accepted-fingerprint")
    fingerprint_parser.add_argument("--state", required=True)
    fingerprint_parser.add_argument("--name", required=True)
    entry_parser = subparsers.add_parser("accepted-entry")
    entry_parser.add_argument("--package", required=True)
    entry_parser.add_argument("--state", required=True)
    entry_parser.add_argument(
        "--role", required=True, choices=("desktop_app", "desktop_launcher")
    )
    install_entry_parser = subparsers.add_parser("install-accepted-entry")
    install_entry_parser.add_argument("--package", required=True)
    install_entry_parser.add_argument("--state", required=True)
    install_entry_parser.add_argument(
        "--role", required=True, choices=("desktop_app", "desktop_launcher")
    )
    args = parser.parse_args()
    if args.command == "install":
        package = Path(args.package).resolve(strict=True)
        state = Path(args.state).resolve(strict=True)
        install(package, state)
    elif args.command == "rollback":
        rollback(args.backup_id)
    elif args.command == "accepted-entry":
        package = Path(args.package).resolve(strict=True)
        state = Path(args.state).resolve(strict=True)
        manifest, entries = verify_package(package, state)
        matching = [entry for entry in entries if entry["role"] == args.role]
        if len(matching) != 1:
            raise ValueError("accepted package role is not unique")
        entry = matching[0]
        fields = [
            str(package / str(entry["source"])),
            str(entry["target"]),
            str(entry["source_mode"]),
            str(entry["install_mode"]),
            str(entry["sha256"]),
            str(manifest["desktop_previous_launcher_sha256"]),
        ]
        print("\t".join(fields))
    elif args.command == "install-accepted-entry":
        if os.geteuid() != 1000:
            raise ValueError("desktop entry installer must run as UID 1000")
        package = Path(args.package).resolve(strict=True)
        state = Path(args.state).resolve(strict=True)
        _manifest, entries, verified_sources = verified_package(package, state)
        matching = [entry for entry in entries if entry["role"] == args.role]
        if len(matching) != 1:
            raise ValueError("accepted package role is not unique")
        entry = matching[0]
        atomic_copy_bytes(
            verified_sources[str(entry["target"])],
            str(entry["sha256"]),
            Path(str(entry["target"])),
            int(str(entry["install_mode"]), 8),
            1000,
            1000,
        )
    else:
        state = Path(args.state).resolve(strict=True)
        attestation = check_closure(state)
        print(accepted_fingerprint(state, args.name, attestation))


if __name__ == "__main__":
    main()
