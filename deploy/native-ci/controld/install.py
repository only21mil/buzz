#!/usr/bin/env python3
"""Check, plan, install, or roll back a frozen Buzz CI controller package."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import uuid

SCHEMA = "buzz-ci-controld-install-package-v1"
RECEIPT_SCHEMA = "buzz-ci-controld-install-receipt-v1"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
PACKAGE_ID = re.compile(r"^buzz-ci-controld-[0-9a-f]{12}-[0-9a-f]{12}$")
DEFAULT_BACKUP_ROOT = Path("/var/lib/buzzci/install-backups/controld")
MAX_JSON_BYTES = 1024 * 1024

DEFAULT_STATE = {
    "enabled": False,
    "active": False,
    "provisioned": False,
    "capacity": 0,
    "providers_wired": False,
}
DAEMON_CONTRACT = {
    "service_user": "buzzci-controld",
    "config_path": "/etc/buzzci/controld-v1.json",
    "store_root": "/var/lib/buzzci/controld",
    "capacity": 0,
    "network": False,
    "keyholder": False,
}
EXPECTED_TARGETS = {
    "binary": "/usr/libexec/buzz-ci-controld",
    "config": "/etc/buzzci/controld-v1.json",
    "service": "/etc/systemd/system/buzz-ci-controld.service",
    "tmpfiles": "/usr/lib/tmpfiles.d/buzzci-controld.conf",
    "documentation": "/usr/share/doc/buzz-ci-controld/README.md",
}
EXPECTED_DIRECTORIES = {"/etc/buzzci", "/usr/share/doc/buzz-ci-controld"}


@dataclass(frozen=True)
class Entry:
    role: str
    source: str
    target: str
    source_mode: int
    install_mode: int
    uid: int
    gid: int
    sha256: str


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_fd(path: Path, max_bytes: int = 128 * 1024 * 1024) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe regular file: {path}")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"file exceeds byte limit: {path}")
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(fd)


def parse_json_file(path: Path) -> tuple[dict[str, object], bytes, os.stat_result]:
    raw, metadata = read_fd(path, MAX_JSON_BYTES)
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value, raw, metadata


def mode(value: object) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0[4567][0-7]{2}", value):
        raise ValueError("invalid mode")
    return int(value, 8)


def u32(value: object, *, nonzero: bool = False) -> int:
    minimum = 1 if nonzero else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= (1 << 32) - 1:
        raise ValueError("invalid numeric identity")
    return value


def mapped_id(value: int, root: Path, *, group: bool = False) -> int:
    if value != 0 or root == Path("/"):
        return value
    metadata = root.lstat()
    return metadata.st_gid if group else metadata.st_uid


def require_directory(path: Path, uid: int, gid: int, mode_value: int) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode_value
    ):
        raise ValueError(f"unsafe directory metadata: {path}")


def require_package_tree(package: Path, root: Path) -> tuple[int, int]:
    package = Path(os.path.abspath(package))
    if Path(os.path.realpath(package)) != package:
        raise ValueError("package root must not be a symbolic path")
    root_uid = mapped_id(0, root)
    root_gid = mapped_id(0, root, group=True)
    require_directory(package, root_uid, root_gid, 0o700)
    require_directory(package / "assets", root_uid, root_gid, 0o700)
    return root_uid, root_gid


def parse_manifest(package: Path, root: Path) -> tuple[dict[str, object], list[Entry]]:
    root_uid, root_gid = require_package_tree(package, root)
    manifest, _, metadata = parse_json_file(package / "package-manifest.json")
    if metadata.st_uid != root_uid or metadata.st_gid != root_gid or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("package manifest metadata is unsafe")
    expected_keys = {
        "schema", "package_id", "source_commit", "binary_provenance_sha256",
        "default_state", "daemon_contract", "package_uid", "package_gid", "identity", "directories", "entries", "package_digest",
    }
    if set(manifest) != expected_keys or manifest["schema"] != SCHEMA:
        raise ValueError("invalid package manifest fields")
    if not isinstance(manifest["package_id"], str) or not PACKAGE_ID.fullmatch(manifest["package_id"]):
        raise ValueError("invalid package id")
    if not isinstance(manifest["source_commit"], str) or not GIT_OID.fullmatch(manifest["source_commit"]):
        raise ValueError("invalid source commit")
    if (
        manifest["default_state"] != DEFAULT_STATE
        or manifest["daemon_contract"] != DAEMON_CONTRACT
        or manifest["package_uid"] != 0
        or manifest["package_gid"] != 0
    ):
        raise ValueError("package is not closed by default")
    identity = manifest["identity"]
    if (
        not isinstance(identity, dict)
        or set(identity) != {"user", "group", "uid", "gid"}
        or identity["user"] != "buzzci-controld"
        or identity["group"] != "buzzci-controld"
    ):
        raise ValueError("invalid package identity binding")
    u32(identity["uid"], nonzero=True)
    u32(identity["gid"], nonzero=True)
    digest = manifest.pop("package_digest")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or sha256(canonical_json(manifest)) != digest:
        raise ValueError("package digest mismatch")
    manifest["package_digest"] = digest

    provenance, provenance_raw, provenance_meta = parse_json_file(package / "binary-provenance.json")
    if provenance_meta.st_uid != root_uid or provenance_meta.st_gid != root_gid or stat.S_IMODE(provenance_meta.st_mode) != 0o600:
        raise ValueError("binary provenance metadata is unsafe")
    if sha256(provenance_raw) != manifest["binary_provenance_sha256"]:
        raise ValueError("binary provenance digest mismatch")
    if set(provenance) != {"schema", "binary", "source_commit", "profile", "sha256"}:
        raise ValueError("invalid binary provenance fields")
    if (
        provenance["schema"] != "buzz-ci-binary-provenance-v1"
        or provenance["binary"] != "buzz-ci-controld"
        or provenance["profile"] != "release"
        or provenance["source_commit"] != manifest["source_commit"]
        or not isinstance(provenance["sha256"], str)
        or not DIGEST.fullmatch(provenance["sha256"])
    ):
        raise ValueError("binary provenance binding mismatch")

    directories = manifest["directories"]
    if not isinstance(directories, list) or len(directories) != 2:
        raise ValueError("invalid managed directories")
    seen_directories: set[str] = set()
    for directory in directories:
        if not isinstance(directory, dict) or set(directory) != {"target", "mode", "uid", "gid"}:
            raise ValueError("invalid managed directory")
        if directory["target"] not in EXPECTED_DIRECTORIES or mode(directory["mode"]) != 0o755 or u32(directory["uid"]) != 0 or u32(directory["gid"]) != 0:
            raise ValueError("unexpected managed directory")
        seen_directories.add(str(directory["target"]))
    if seen_directories != EXPECTED_DIRECTORIES:
        raise ValueError("managed directory set mismatch")

    raw_entries = manifest["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) != len(EXPECTED_TARGETS):
        raise ValueError("invalid package entry count")
    entries: list[Entry] = []
    seen_roles: set[str] = set()
    seen_sources: set[str] = set()
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict) or set(raw_entry) != {"role", "source", "target", "source_mode", "install_mode", "uid", "gid", "sha256"}:
            raise ValueError("invalid package entry")
        role = raw_entry["role"]
        source = raw_entry["source"]
        target = raw_entry["target"]
        if not isinstance(role, str) or role not in EXPECTED_TARGETS or target != EXPECTED_TARGETS[role]:
            raise ValueError("unexpected package role or target")
        if not isinstance(source, str) or not re.fullmatch(r"assets/[A-Za-z0-9._-]+", source):
            raise ValueError("unsafe package source path")
        if role in seen_roles or source in seen_sources:
            raise ValueError("duplicate package role or source")
        seen_roles.add(role)
        seen_sources.add(source)
        digest_value = raw_entry["sha256"]
        if not isinstance(digest_value, str) or not DIGEST.fullmatch(digest_value):
            raise ValueError("invalid entry digest")
        entry = Entry(role, source, str(target), mode(raw_entry["source_mode"]), mode(raw_entry["install_mode"]), u32(raw_entry["uid"]), u32(raw_entry["gid"]), digest_value)
        if role == "config":
            if entry.install_mode != 0o600 or entry.uid != identity["uid"] or entry.gid != identity["gid"]:
                raise ValueError("controld config must be privately controld-owned")
        elif entry.uid != 0 or entry.gid != 0 or entry.install_mode not in {0o644, 0o755}:
            raise ValueError("static install target must be root-owned")
        payload, source_meta = read_fd(package / source)
        if (
            source_meta.st_uid != root_uid
            or source_meta.st_gid != root_gid
            or stat.S_IMODE(source_meta.st_mode) != entry.source_mode
            or sha256(payload) != entry.sha256
        ):
            raise ValueError(f"package source metadata or digest mismatch: {source}")
        if role == "binary" and entry.sha256 != provenance["sha256"]:
            raise ValueError("controld binary is not bound to provenance")
        entries.append(entry)
    if seen_roles != set(EXPECTED_TARGETS):
        raise ValueError("package roles are incomplete")
    validate_assets(package, entries)
    return manifest, sorted(entries, key=lambda item: item.target.encode())


def validate_assets(package: Path, entries: list[Entry]) -> None:
    payloads = {entry.role: read_fd(package / entry.source)[0] for entry in entries}
    config = json.loads(payloads["config"], object_pairs_hook=reject_duplicates)
    if config != {"capacity": 0, "schema_version": 1, "store_root": "/var/lib/buzzci/controld"}:
        raise ValueError("controld config is not canonical and capacity-zero")
    service = payloads["service"].decode()
    tmpfiles = payloads["tmpfiles"].decode()
    required_service = {
        "ExecStart=/usr/libexec/buzz-ci-controld /etc/buzzci/controld-v1.json",
        "User=buzzci-controld",
        "Group=buzzci-controld",
        "PrivateNetwork=yes",
        "RestrictAddressFamilies=AF_UNIX",
        "ReadOnlyPaths=/etc/buzzci/controld-v1.json",
        "ReadWritePaths=/var/lib/buzzci/controld",
        "Restart=no",
    }
    service_lines = service.splitlines()
    if not all(line in service_lines for line in required_service) or "[Install]" in service_lines:
        raise ValueError("controld service dormant contract mismatch")
    forbidden = ("keyholder", "relay", "runner", "execd", "ListenStream", "Socket")
    if any(token.lower() in (service + tmpfiles).lower() for token in forbidden):
        raise ValueError("controld package crosses a forbidden subsystem boundary")
    expected_tmpfiles = "d /var/lib/buzzci/controld 0700 buzzci-controld buzzci-controld -"
    lines = [line for line in tmpfiles.splitlines() if line and not line.startswith("#")]
    if lines != [expected_tmpfiles]:
        raise ValueError("controld tmpfiles contract mismatch")


def parse_account_file(root: Path, target: str, fields: int) -> list[list[str]]:
    path = rooted(root, target)
    payload, metadata = read_fd(path, 1024 * 1024)
    if (
        metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        raise ValueError(f"account database metadata is unsafe: {target}")
    rows: list[list[str]] = []
    for line in payload.decode().splitlines():
        if not line or line.startswith("#"):
            continue
        row = line.split(":")
        if len(row) != fields:
            raise ValueError(f"malformed account database: {target}")
        rows.append(row)
    return rows


def validate_host_identities(root: Path, manifest: dict[str, object]) -> None:
    identity = manifest["identity"]
    users = parse_account_file(root, "/etc/passwd", 7)
    groups = parse_account_file(root, "/etc/group", 4)
    matching_users = [row for row in users if row[0] == identity["user"]]
    matching_groups = [row for row in groups if row[0] == identity["group"]]
    if len(matching_users) != 1 or len(matching_groups) != 1:
        raise ValueError("host controld identity is missing or duplicated")
    try:
        user_uid = int(matching_users[0][2])
        user_gid = int(matching_users[0][3])
        group_gid = int(matching_groups[0][2])
    except ValueError as error:
        raise ValueError("host controld identity is malformed") from error
    if (user_uid, user_gid, group_gid) != (identity["uid"], identity["gid"], identity["gid"]):
        raise ValueError("host controld identity does not match the package")


def rooted(root: Path, target: str) -> Path:
    if not target.startswith("/") or ".." in Path(target).parts:
        raise ValueError("unsafe target path")
    return root / target.removeprefix("/")


def validate_parent_chain(root: Path, parent: Path) -> None:
    root = Path(os.path.abspath(root))
    if Path(os.path.realpath(root)) != root:
        raise ValueError("install root must not be a symbolic path")
    root_uid = mapped_id(0, root)
    root_gid = mapped_id(0, root, group=True)
    current = root
    require_directory(current, root_uid, root_gid, stat.S_IMODE(current.lstat().st_mode))
    for component in parent.relative_to(root).parts:
        current /= component
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != root_uid or metadata.st_gid != root_gid or metadata.st_mode & 0o022:
            raise ValueError(f"unsafe target directory chain: {current}")


def validate_target_parent(root: Path, parent: Path) -> None:
    if parent.exists():
        validate_parent_chain(root, parent)
        return
    logical = "/" + str(parent.relative_to(root))
    if logical not in EXPECTED_DIRECTORIES or parent.is_symlink():
        raise ValueError(f"target parent is unavailable: {parent}")
    validate_parent_chain(root, parent.parent)


def target_state(root: Path, entry: Entry) -> dict[str, object] | None:
    path = rooted(root, entry.target)
    if not path.exists() and not path.is_symlink():
        return None
    payload, metadata = read_fd(path)
    if stat.S_IMODE(metadata.st_mode) & 0o7000:
        raise ValueError(f"installed target has special mode bits: {path}")
    return {
        "sha256": sha256(payload),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "payload": payload,
    }


def desired_metadata(root: Path, entry: Entry) -> tuple[int, int, int]:
    return mapped_id(entry.uid, root), mapped_id(entry.gid, root, group=True), entry.install_mode


def changes(package: Path, root: Path, entries: list[Entry]) -> list[Entry]:
    changed: list[Entry] = []
    for entry in entries:
        target = rooted(root, entry.target)
        validate_target_parent(root, target.parent)
        state = target_state(root, entry)
        uid, gid, install_mode = desired_metadata(root, entry)
        if state is None or (state["sha256"], state["mode"], state["uid"], state["gid"]) != (entry.sha256, install_mode, uid, gid):
            changed.append(entry)
    return changed


def atomic_write(target: Path, payload: bytes, mode_value: int, uid: int, gid: int) -> None:
    if target.is_symlink():
        raise ValueError(f"target is a symbolic link: {target}")
    parent = target.parent
    fd, name = tempfile.mkstemp(prefix=f".{target.name}.", dir=parent)
    temporary = Path(name)
    try:
        os.fchmod(fd, mode_value)
        os.fchown(fd, uid, gid)
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, target)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def ensure_managed_directories(root: Path, manifest: dict[str, object], created: list[str]) -> None:
    for item in manifest["directories"]:
        target = rooted(root, str(item["target"]))
        if target.exists() or target.is_symlink():
            require_directory(target, mapped_id(0, root), mapped_id(0, root, group=True), 0o755)
            continue
        validate_parent_chain(root, target.parent)
        target.mkdir(mode=0o700)
        created.append(str(item["target"]))
        os.chown(target, mapped_id(0, root), mapped_id(0, root, group=True))
        target.chmod(0o755)
        require_directory(target, mapped_id(0, root), mapped_id(0, root, group=True), 0o755)


def backup_root_path(root: Path, backup_root: Path) -> Path:
    if root == Path("/"):
        return backup_root
    return rooted(root, str(backup_root))


def ensure_private_tree(root: Path, path: Path) -> None:
    root_uid = mapped_id(0, root)
    root_gid = mapped_id(0, root, group=True)
    current = root
    for component in path.relative_to(root).parts:
        current /= component
        if not current.exists():
            current.mkdir(mode=0o700)
            os.chown(current, root_uid, root_gid)
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != root_uid or metadata.st_gid != root_gid or metadata.st_mode & 0o022:
            raise ValueError(f"unsafe backup directory chain: {current}")
    require_directory(path, root_uid, root_gid, 0o700)


def check(package: Path, root: Path) -> dict[str, object]:
    package = Path(os.path.abspath(package))
    manifest, entries = parse_manifest(package, package)
    validate_host_identities(root, manifest)
    planned = changes(package, root, entries)
    return {
        "status": "checked",
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "changed_targets": [entry.target for entry in planned],
        "daemon_contract": DAEMON_CONTRACT,
        **DEFAULT_STATE,
    }


def install(package: Path, root: Path, backup_root: Path, *, dry_run: bool = False) -> dict[str, object]:
    manifest, entries = parse_manifest(package, root)
    validate_host_identities(root, manifest)
    if root == Path("/") and os.geteuid() != 0:
        raise PermissionError("install requires root")
    planned = changes(package, root, entries)
    result: dict[str, object] = {
        "status": "dry_run" if dry_run else ("unchanged" if not planned else "installed"),
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "changed_targets": [entry.target for entry in planned],
        "daemon_contract": DAEMON_CONTRACT,
        **DEFAULT_STATE,
    }
    if dry_run or not planned:
        return result
    backup_base = backup_root_path(root, backup_root)
    ensure_private_tree(root, backup_base)
    backup_id = f"{manifest['package_id']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}-{uuid.uuid4().hex[:8]}"
    transaction = backup_base / backup_id
    transaction.mkdir(mode=0o700)
    os.chown(transaction, mapped_id(0, root), mapped_id(0, root, group=True))
    transaction.chmod(0o700)
    require_directory(transaction, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
    inventory: list[dict[str, object]] = []
    created_directories: list[str] = []
    try:
        ensure_managed_directories(root, manifest, created_directories)
        for index, entry in enumerate(planned):
            prior = target_state(root, entry)
            record: dict[str, object] = {"target": entry.target, "existed": prior is not None}
            if prior is not None:
                record.update({"mode": prior["mode"], "uid": prior["uid"], "gid": prior["gid"], "sha256": prior["sha256"], "backup": f"files/{index}"})
                files = transaction / "files"
                files.mkdir(mode=0o700, exist_ok=True)
                backup_file = files / str(index)
                atomic_write(backup_file, prior["payload"], 0o600, mapped_id(0, root), mapped_id(0, root, group=True))
            inventory.append(record)
            payload, _ = read_fd(package / entry.source)
            uid, gid, install_mode = desired_metadata(root, entry)
            target = rooted(root, entry.target)
            atomic_write(target, payload, install_mode, uid, gid)
            installed = target_state(root, entry)
            if installed is None or (installed["sha256"], installed["mode"], installed["uid"], installed["gid"]) != (entry.sha256, install_mode, uid, gid):
                raise ValueError(f"installed target readback mismatch: {entry.target}")
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "state": "installed",
            "package_id": manifest["package_id"],
            "package_digest": manifest["package_digest"],
            "changed_targets": [entry.target for entry in planned],
            "created_directories": created_directories,
            "inventory": inventory,
        }
        atomic_write(transaction / "receipt.json", canonical_json(receipt), 0o600, mapped_id(0, root), mapped_id(0, root, group=True))
    except BaseException:
        for record in reversed(inventory):
            target = rooted(root, str(record["target"]))
            if record["existed"]:
                payload, _ = read_fd(transaction / str(record["backup"]))
                atomic_write(target, payload, int(record["mode"]), int(record["uid"]), int(record["gid"]))
            elif target.exists():
                target.unlink()
        for directory in reversed(created_directories):
            rooted(root, directory).rmdir()
        raise
    result["backup_id"] = backup_id
    return result


def rollback(package: Path, root: Path, backup_root: Path, backup_id: str, *, dry_run: bool = False) -> dict[str, object]:
    manifest, entries = parse_manifest(package, root)
    if root == Path("/") and os.geteuid() != 0:
        raise PermissionError("rollback requires root")
    if "/" in backup_id or backup_id in {"", ".", ".."}:
        raise ValueError("invalid backup id")
    transaction = backup_root_path(root, backup_root) / backup_id
    require_directory(transaction.parent, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
    require_directory(transaction, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
    receipt, _, metadata = parse_json_file(transaction / "receipt.json")
    if (
        metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("state") != "installed"
    ):
        raise ValueError("backup receipt is not rollbackable")
    if receipt.get("package_id") != manifest["package_id"] or receipt.get("package_digest") != manifest["package_digest"]:
        raise ValueError("backup is bound to another package")
    by_target = {entry.target: entry for entry in entries}
    changed_targets = receipt.get("changed_targets")
    inventory = receipt.get("inventory")
    created_directories = receipt.get("created_directories")
    if (
        not isinstance(changed_targets, list)
        or not changed_targets
        or len(set(changed_targets)) != len(changed_targets)
        or any(target not in by_target for target in changed_targets)
        or not isinstance(inventory, list)
        or len(inventory) != len(changed_targets)
        or not isinstance(created_directories, list)
        or len(set(created_directories)) != len(created_directories)
        or any(directory not in EXPECTED_DIRECTORIES for directory in created_directories)
    ):
        raise ValueError("backup receipt inventory is invalid")
    for index, (target, record) in enumerate(zip(changed_targets, inventory, strict=True)):
        if not isinstance(record, dict) or record.get("target") != target or not isinstance(record.get("existed"), bool):
            raise ValueError("backup receipt entry is invalid")
        expected_record_keys = {"target", "existed"}
        if record["existed"]:
            expected_record_keys |= {"mode", "uid", "gid", "sha256", "backup"}
            if (
                set(record) != expected_record_keys
                or not isinstance(record["backup"], str)
                or record["backup"] != f"files/{index}"
                or isinstance(record["mode"], bool)
                or not isinstance(record["mode"], int)
                or not 0 <= record["mode"] <= 0o777
                or isinstance(record["uid"], bool)
                or not isinstance(record["uid"], int)
                or not 0 <= record["uid"] <= (1 << 32) - 1
                or isinstance(record["gid"], bool)
                or not isinstance(record["gid"], int)
                or not 0 <= record["gid"] <= (1 << 32) - 1
                or not isinstance(record["sha256"], str)
                or not DIGEST.fullmatch(record["sha256"])
            ):
                raise ValueError("backup receipt prior-state binding is invalid")
        elif set(record) != expected_record_keys:
            raise ValueError("backup receipt new-target binding is invalid")

    if any(record["existed"] for record in inventory):
        require_directory(
            transaction / "files",
            mapped_id(0, root),
            mapped_id(0, root, group=True),
            0o700,
        )

    rollback_plan: list[tuple[dict[str, object], Path, bytes | None]] = []
    for target, record in zip(changed_targets, inventory, strict=True):
        entry = by_target[target]
        state = target_state(root, entry)
        uid, gid, install_mode = desired_metadata(root, entry)
        if state is None or (state["sha256"], state["mode"], state["uid"], state["gid"]) != (entry.sha256, install_mode, uid, gid):
            raise ValueError(f"installed target drift blocks rollback: {target}")
        prior_payload: bytes | None = None
        if record["existed"]:
            prior_payload, backup_meta = read_fd(transaction / str(record["backup"]))
            if (
                backup_meta.st_uid != mapped_id(0, root)
                or backup_meta.st_gid != mapped_id(0, root, group=True)
                or stat.S_IMODE(backup_meta.st_mode) != 0o600
            ):
                raise ValueError("backup file mode drift")
            if sha256(prior_payload) != record["sha256"]:
                raise ValueError("backup file digest drift")
        rollback_plan.append((record, rooted(root, target), prior_payload))

    removal_plan: list[Path] = []
    for directory in created_directories:
        path = rooted(root, directory)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            directory_meta = os.fstat(fd)
            if (
                not stat.S_ISDIR(directory_meta.st_mode)
                or directory_meta.st_uid != mapped_id(0, root)
                or directory_meta.st_gid != mapped_id(0, root, group=True)
                or stat.S_IMODE(directory_meta.st_mode) != 0o755
            ):
                raise ValueError(f"rollback directory metadata drift: {directory}")
            present = set(os.listdir(fd))
        finally:
            os.close(fd)
        removable = {
            step_target.name
            for record, step_target, _prior_payload in rollback_plan
            if not record["existed"] and step_target.parent == path
        }
        if present != removable:
            raise ValueError(f"rollback directory removal is blocked: {directory}")
        removal_plan.append(path)

    result = {"status": "rollback_dry_run" if dry_run else "rolled_back", "package_id": manifest["package_id"], "backup_id": backup_id, "restored_targets": receipt["changed_targets"]}
    if dry_run:
        return result
    for record, target, prior_payload in reversed(rollback_plan):
        if prior_payload is not None:
            atomic_write(target, prior_payload, int(record["mode"]), int(record["uid"]), int(record["gid"]))
        else:
            target.unlink()
    for directory in reversed(removal_plan):
        directory.rmdir()
    receipt["state"] = "rolled_back"
    atomic_write(transaction / "receipt.json", canonical_json(receipt), 0o600, mapped_id(0, root), mapped_id(0, root, group=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "dry-run", "install", "rollback"))
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--backup-root", type=Path, default=DEFAULT_BACKUP_ROOT)
    parser.add_argument("--backup-id")
    parser.add_argument("--dry-run", action="store_true", help="validate rollback without changing targets")
    arguments = parser.parse_args()
    try:
        root = Path(os.path.abspath(arguments.root))
        if arguments.action == "check":
            result = check(arguments.package, root)
        elif arguments.action == "dry-run":
            result = install(arguments.package, root, arguments.backup_root, dry_run=True)
        elif arguments.action == "install":
            result = install(arguments.package, root, arguments.backup_root)
        else:
            if not arguments.backup_id:
                raise ValueError("rollback requires --backup-id")
            result = rollback(arguments.package, root, arguments.backup_root, arguments.backup_id, dry_run=arguments.dry_run)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "refused", "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
