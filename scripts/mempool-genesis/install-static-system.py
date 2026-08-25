#!/usr/bin/env python3
"""Install or roll back the reviewed, credential-free agent service package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

SCHEMA = "buzz-agent-static-package-v1"
RECEIPT_SCHEMA = "buzz-agent-static-install-receipt-v1"
REVIEW_TOOL = "/home/victor/.agents/skills/codex-review/scripts/tier2_evidence.py"
BACKUP_ROOT = Path("/var/lib/buzz-agent-install-backups")
PACKAGE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{7,95}$")

TARGETS = {
    "/usr/local/libexec/buzz/verify-installed-agent": ("system/verify-installed-agent", 0o755),
    "/usr/local/libexec/buzz/buzz-agent-key-handoff": ("bin/buzz-agent-key-handoff", 0o755),
    "/usr/local/libexec/buzz/export-managed-agent-key": ("bin/export-managed-agent-key", 0o755),
    "/usr/local/sbin/buzz-install-agent-key": ("bin/buzz-install-agent-key", 0o755),
    "/usr/local/sbin/install-enrollment-map": ("system/install-enrollment-map", 0o755),
    "/etc/sudoers.d/buzz-agent-key-handoff": ("system/buzz-agent-key-handoff.sudoers", 0o440),
    "/etc/systemd/system/buzz-agent@.service": ("system/buzz-agent@.service", 0o644),
}


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    if len(raw) > 64 * 1024:
        raise ValueError("JSON file is too large")
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def require_regular(path: Path, uid: int | None, mode: int) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"unsafe regular file: {path}")
    if uid is not None and metadata.st_uid != uid:
        raise ValueError(f"wrong file owner: {path}")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"wrong file mode: {path}")
    return metadata


def require_directory(path: Path, uid: int, mode: int) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or metadata.st_gid != uid:
        raise ValueError(f"unsafe directory: {path}")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"wrong directory mode: {path}")


def hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def open_verified_source(path: Path, expected_hash: str, expected_mode: int) -> int:
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
        if hash_fd(fd) != expected_hash:
            raise ValueError(f"package source hash drift: {path}")
        return fd
    except Exception:
        os.close(fd)
        raise


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_copy_fd(source_fd: int, target: Path, mode: int, uid: int, gid: int) -> None:
    parent = target.parent
    require_directory(parent, 0, stat.S_IMODE(parent.lstat().st_mode))
    if parent.lstat().st_mode & 0o022:
        raise ValueError(f"target directory is writable by non-root: {parent}")
    temporary_fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=parent)
    try:
        os.fchmod(temporary_fd, mode)
        os.fchown(temporary_fd, uid, gid)
        os.lseek(source_fd, 0, os.SEEK_SET)
        while chunk := os.read(source_fd, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(temporary_fd, view)
                view = view[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.replace(temporary_name, target)
        sync_directory(parent)
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def copy_path_to_backup(source: Path, target: Path) -> None:
    fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe installed target: {source}")
        atomic_copy_fd(fd, target, 0o600, 0, 0)
    finally:
        os.close(fd)


def exact_manifest(package: Path) -> tuple[str, list[dict[str, object]]]:
    manifest_path = package / "manifest.json"
    require_regular(manifest_path, 1000, 0o600)
    manifest = load_json(manifest_path)
    if set(manifest) != {"schema", "package_id", "entries"} or manifest["schema"] != SCHEMA:
        raise ValueError("invalid static package manifest")
    package_id = manifest["package_id"]
    entries = manifest["entries"]
    if not isinstance(package_id, str) or not PACKAGE_ID.fullmatch(package_id):
        raise ValueError("invalid package id")
    if not isinstance(entries, list) or len(entries) != len(TARGETS):
        raise ValueError("invalid manifest entry count")
    by_target: dict[str, dict[str, object]] = {}
    for raw in entries:
        if not isinstance(raw, dict) or set(raw) != {"source", "target", "mode", "sha256"}:
            raise ValueError("invalid manifest entry")
        target = raw["target"]
        if not isinstance(target, str) or target in by_target or target not in TARGETS:
            raise ValueError("invalid or duplicate manifest target")
        source, mode = TARGETS[target]
        if raw["source"] != source or raw["mode"] != f"{mode:04o}":
            raise ValueError("manifest target contract mismatch")
        digest = raw["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid manifest digest")
        by_target[target] = raw
    if set(by_target) != set(TARGETS):
        raise ValueError("manifest target set mismatch")
    return package_id, [by_target[target] for target in TARGETS]


def require_services_stopped() -> None:
    for slug in ("mempool", "genesis"):
        unit = f"buzz-agent@{slug}.service"
        active = subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False)
        enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", unit], check=False)
        if active.returncode == 0 or enabled.returncode == 0:
            raise ValueError(f"service must be disabled and inactive: {unit}")


def check_closure(state: Path) -> None:
    require_regular(state, 1000, 0o600)
    subprocess.run(
        ["sudo", "-n", "-u", "victor", "python3", REVIEW_TOOL, "check-closure", "--state", str(state)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def prepare_directories() -> None:
    expected = {
        Path("/etc/buzz-agents"): 0o755,
        Path("/etc/buzz-agents/prompts"): 0o755,
        Path("/usr/local/libexec/buzz"): 0o755,
        Path("/usr/local/sbin"): 0o755,
        Path("/etc/sudoers.d"): 0o750,
        Path("/etc/systemd/system"): 0o755,
    }
    for path, mode in expected.items():
        require_directory(path, 0, mode)
    credential_dir = Path("/etc/buzz-agents/credentials")
    if credential_dir.exists() or credential_dir.is_symlink():
        require_directory(credential_dir, 0, 0o700)
    else:
        credential_dir.mkdir(mode=0o700)
        os.chown(credential_dir, 0, 0)
        sync_directory(credential_dir.parent)


def target_metadata(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
    ):
        raise ValueError(f"unsafe installed target: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
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
            fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                atomic_copy_fd(fd, target, int(str(record["mode"]), 8), int(record["uid"]), int(record["gid"]))
            finally:
                os.close(fd)
        elif target.exists() and not target.is_symlink():
            target.unlink()
            sync_directory(target.parent)


def install(package: Path, state: Path) -> None:
    if os.geteuid() != 0 or os.uname().nodename != "framework-desktop":
        raise ValueError("installer must run as root on framework-desktop")
    require_directory(package, 1000, 0o700)
    check_closure(state)
    require_services_stopped()
    package_id, entries = exact_manifest(package)
    backup = BACKUP_ROOT / package_id
    if backup.exists() or backup.is_symlink():
        raise ValueError("backup/receipt already exists")

    opened: dict[str, int] = {}
    try:
        for entry in entries:
            source = package / str(entry["source"])
            opened[str(entry["target"])] = open_verified_source(
                source, str(entry["sha256"]), int(str(entry["mode"]), 8)
            )
        subprocess.run(["visudo", "-cf", str(package / "system/buzz-agent-key-handoff.sudoers")], check=True)
        subprocess.run(["systemd-analyze", "verify", str(package / "system/buzz-agent@.service")], check=True)
        prepare_directories()
        BACKUP_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        require_directory(BACKUP_ROOT, 0, 0o700)
        backup.mkdir(mode=0o700)
        (backup / "files").mkdir(mode=0o700)

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

        changed: list[str] = []
        try:
            for entry in entries:
                target_text = str(entry["target"])
                atomic_copy_fd(opened[target_text], Path(target_text), int(str(entry["mode"]), 8), 0, 0)
                changed.append(target_text)
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            for entry in entries:
                metadata = target_metadata(Path(str(entry["target"])))
                if metadata["sha256"] != entry["sha256"] or metadata["mode"] != entry["mode"]:
                    raise ValueError("installed target verification failed")
        except Exception:
            try:
                restore_changed(changed, previous, backup)
                subprocess.run(["systemctl", "daemon-reload"], check=True)
            except Exception as rollback_error:
                raise RuntimeError("ROLLBACK_REQUIRED") from rollback_error
            raise

        try:
            receipt = {
                "schema": RECEIPT_SCHEMA,
                "package_id": package_id,
                "previous": previous,
                "installed": {str(entry["target"]): str(entry["sha256"]) for entry in entries},
            }
            receipt_path = backup / "receipt.json"
            fd = os.open(
                receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
            )
            try:
                os.write(
                    fd,
                    (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode(),
                )
                os.fsync(fd)
            finally:
                os.close(fd)
            sync_directory(backup)
        except Exception:
            try:
                receipt_path = backup / "receipt.json"
                if receipt_path.exists() and not receipt_path.is_symlink():
                    receipt_path.unlink()
                restore_changed(changed, previous, backup)
                subprocess.run(["systemctl", "daemon-reload"], check=True)
            except Exception as rollback_error:
                raise RuntimeError("ROLLBACK_REQUIRED") from rollback_error
            raise
        print(f"INSTALLED {package_id}")
    finally:
        for fd in opened.values():
            os.close(fd)


def rollback(package_id: str) -> None:
    if os.geteuid() != 0 or not PACKAGE_ID.fullmatch(package_id):
        raise ValueError("invalid rollback invocation")
    require_services_stopped()
    backup = BACKUP_ROOT / package_id
    require_directory(backup, 0, 0o700)
    receipt_path = backup / "receipt.json"
    require_regular(receipt_path, 0, 0o600)
    receipt = load_json(receipt_path)
    if set(receipt) != {"schema", "package_id", "previous", "installed"}:
        raise ValueError("invalid receipt")
    if receipt["schema"] != RECEIPT_SCHEMA or receipt["package_id"] != package_id:
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
    restore_changed(list(TARGETS), previous, backup)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print(f"ROLLED_BACK {package_id}")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--package", required=True)
    install_parser.add_argument("--state", required=True)
    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument("--package-id", required=True)
    args = parser.parse_args()
    if args.command == "install":
        package = Path(args.package).resolve(strict=True)
        state = Path(args.state).resolve(strict=True)
        install(package, state)
    else:
        rollback(args.package_id)


if __name__ == "__main__":
    main()
