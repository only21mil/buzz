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
import stat
import sys
import uuid

SCHEMA = "buzz-ci-controld-install-package-v2"
RECEIPT_SCHEMA = "buzz-ci-controld-install-receipt-v1"
TRANSACTION_SCHEMA = "buzz-ci-controld-install-transaction-v1"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
PACKAGE_ID = re.compile(r"^buzz-ci-controld-[0-9a-f]{12}-[0-9a-f]{12}$")
BACKUP_ID = re.compile(
    r"^buzz-ci-controld-[0-9a-f]{12}-[0-9a-f]{12}-"
    r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{8}$"
)
DEFAULT_BACKUP_ROOT = Path("/var/lib/buzzci/install-backups/controld")
MAX_JSON_BYTES = 1024 * 1024
TRANSACTION_PHASES = {
    "preparing",
    "install_prepared",
    "installing",
    "installed",
    "rolling_back",
    "rolled_back",
}
OPEN_TRANSACTION_PHASES = TRANSACTION_PHASES - {"installed", "rolled_back"}

DEFAULT_STATE = {
    "enabled": False,
    "active": False,
    "provisioned": False,
    "capacity": 0,
    "providers_wired": False,
}
ACCEPTANCE_BINDING = "/var/lib/buzzci/activation-controller/controld-acceptance-v2.json"
CONTROLD_CONFIG = {
    "schema_version": 2,
    "capacity": 0,
    "store_root": "/var/lib/buzzci/controld",
    "acceptance_binding": ACCEPTANCE_BINDING,
}
DAEMON_CONTRACT = {
    "service_user": "buzzci-controld",
    "config_path": "/etc/buzzci/controld-v2.json",
    "acceptance_binding": ACCEPTANCE_BINDING,
    "store_root": "/var/lib/buzzci/controld",
    "default_capacity": 0,
    "maximum_capacity": 1,
    "providers_fail_closed": True,
    "runner_protocol": 2,
    "acceptance_socket": "/run/buzzci/controld-acceptance.sock",
}
EXPECTED_TARGETS = {
    "binary": "/usr/libexec/buzz-ci-controld",
    "config": "/etc/buzzci/controld-v2.json",
    "service": "/etc/systemd/system/buzz-ci-controld.service",
    "acceptance_socket": "/etc/systemd/system/buzz-ci-controld-acceptance.socket",
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
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags | getattr(os, "O_NOATIME", 0))
    except PermissionError:
        fd = os.open(path, flags)
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
        if role == "config" and payload != canonical_json(CONTROLD_CONFIG):
            raise ValueError("controld config is not the canonical acceptance-bound capacity zero config")
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
    if config != CONTROLD_CONFIG or payloads["config"] != canonical_json(CONTROLD_CONFIG):
        raise ValueError("controld config is not canonical, acceptance-bound, and capacity-zero")
    service = payloads["service"].decode()
    tmpfiles = payloads["tmpfiles"].decode()
    required_service = {
        "ExecStart=/usr/libexec/buzz-ci-controld /etc/buzzci/controld-v2.json",
        "User=buzzci-controld",
        "Group=buzzci-controld",
        "PrivateNetwork=no",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "ReadOnlyPaths=/etc/buzzci/controld-v2.json -/var/lib/buzzci/activation-controller/controld-acceptance-v2.json -/run/buzzci/runner-control.sock -/run/buzzci/keyholder.sock",
        "ReadWritePaths=/var/lib/buzzci/controld",
        "Restart=on-failure",
    }
    service_lines = service.splitlines()
    if not all(line in service_lines for line in required_service) or "[Install]" in service_lines:
        raise ValueError("controld service dormant contract mismatch")
    acceptance = payloads["acceptance_socket"].decode()
    required_acceptance = {
        "ListenStream=/run/buzzci/controld-acceptance.sock",
        "FileDescriptorName=buzz-ci-controld-acceptance",
        "SocketUser=root",
        "SocketGroup=buzzci-ctl",
        "SocketMode=0620",
        "DirectoryMode=0711",
        "Accept=no",
        "Service=buzz-ci-controld.service",
    }
    if not required_acceptance.issubset(set(acceptance.splitlines())) or "[Install]" in acceptance:
        raise ValueError("controld acceptance socket contract mismatch")
    if "/run/buzzci/execd.sock" in service + acceptance + tmpfiles:
        raise ValueError("controld must not connect directly to execd")
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
    parent_fd = os.open(
        target.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    temporary = f".{target.name}.{uuid.uuid4().hex}"
    fd = -1
    try:
        try:
            metadata = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        if metadata is not None and stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"target is a symbolic link: {target}")
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(fd, mode_value)
        os.fchown(fd, uid, gid)
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(
            temporary,
            target.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def open_read_directory(path: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        return os.open(path, flags | getattr(os, "O_NOATIME", 0))
    except PermissionError:
        return os.open(path, flags)


def unlink_file(path: Path) -> None:
    parent_fd = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        metadata = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"target is not a regular file: {path}")
        os.unlink(path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


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


def secure_json(path: Path, root: Path) -> dict[str, object]:
    value, _, metadata = parse_json_file(path)
    if (
        metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError(f"transaction metadata is unsafe: {path}")
    return value


def inventory_fields(
    document: dict[str, object],
    manifest: dict[str, object],
    entries: list[Entry],
) -> tuple[list[str], list[str], list[dict[str, object]]]:
    changed_targets = document.get("changed_targets")
    created_directories = document.get("created_directories")
    inventory = document.get("inventory")
    by_target = {entry.target: entry for entry in entries}
    if (
        not isinstance(changed_targets, list)
        or not changed_targets
        or any(not isinstance(target, str) for target in changed_targets)
        or len(set(changed_targets)) != len(changed_targets)
        or any(target not in by_target for target in changed_targets)
        or changed_targets != [entry.target for entry in entries if entry.target in set(changed_targets)]
        or not isinstance(created_directories, list)
        or any(not isinstance(directory, str) for directory in created_directories)
        or len(set(created_directories)) != len(created_directories)
        or any(directory not in EXPECTED_DIRECTORIES for directory in created_directories)
        or created_directories
        != [
            str(item["target"])
            for item in manifest["directories"]
            if item["target"] in set(created_directories)
        ]
        or not isinstance(inventory, list)
        or len(inventory) != len(changed_targets)
    ):
        raise ValueError("transaction inventory is invalid")
    for index, (target, record) in enumerate(zip(changed_targets, inventory, strict=True)):
        if not isinstance(record, dict) or record.get("target") != target or not isinstance(record.get("existed"), bool):
            raise ValueError("transaction inventory entry is invalid")
        expected_keys = {"target", "existed"}
        if record["existed"]:
            expected_keys |= {"mode", "uid", "gid", "sha256", "backup"}
            if (
                set(record) != expected_keys
                or record.get("backup") != f"files/{index}"
                or isinstance(record.get("mode"), bool)
                or not isinstance(record.get("mode"), int)
                or not 0 <= int(record["mode"]) <= 0o777
                or isinstance(record.get("uid"), bool)
                or not isinstance(record.get("uid"), int)
                or not 0 <= int(record["uid"]) <= (1 << 32) - 1
                or isinstance(record.get("gid"), bool)
                or not isinstance(record.get("gid"), int)
                or not 0 <= int(record["gid"]) <= (1 << 32) - 1
                or not isinstance(record.get("sha256"), str)
                or not DIGEST.fullmatch(str(record["sha256"]))
            ):
                raise ValueError("transaction prior-state binding is invalid")
        elif set(record) != expected_keys:
            raise ValueError("transaction absent-state binding is invalid")
    return changed_targets, created_directories, inventory


def validate_transaction_state(
    state: dict[str, object],
    manifest: dict[str, object],
    entries: list[Entry],
    backup_id: str,
) -> None:
    if (
        set(state)
        != {
            "schema",
            "backup_id",
            "phase",
            "package_id",
            "package_digest",
            "changed_targets",
            "created_directories",
            "inventory",
        }
        or state.get("schema") != TRANSACTION_SCHEMA
        or state.get("backup_id") != backup_id
        or state.get("phase") not in TRANSACTION_PHASES
        or state.get("package_id") != manifest["package_id"]
        or state.get("package_digest") != manifest["package_digest"]
    ):
        raise ValueError("transaction state package or phase binding mismatch")
    inventory_fields(state, manifest, entries)


def receipt_from_state(state: dict[str, object], receipt_state: str) -> dict[str, object]:
    return {
        "schema": RECEIPT_SCHEMA,
        "state": receipt_state,
        "package_id": state["package_id"],
        "package_digest": state["package_digest"],
        "changed_targets": state["changed_targets"],
        "created_directories": state["created_directories"],
        "inventory": state["inventory"],
    }


def validate_receipt(
    receipt: dict[str, object],
    manifest: dict[str, object],
    entries: list[Entry],
) -> None:
    if (
        set(receipt)
        != {
            "schema",
            "state",
            "package_id",
            "package_digest",
            "changed_targets",
            "created_directories",
            "inventory",
        }
        or receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("state") not in {"installed", "rolled_back"}
        or receipt.get("package_id") != manifest["package_id"]
        or receipt.get("package_digest") != manifest["package_digest"]
    ):
        raise ValueError("backup receipt package or state binding mismatch")
    inventory_fields(receipt, manifest, entries)


def read_optional_json(path: Path, root: Path) -> dict[str, object] | None:
    try:
        return secure_json(path, root)
    except FileNotFoundError:
        return None


def write_transaction_state(transaction: Path, state: dict[str, object], root: Path) -> None:
    atomic_write(
        transaction / "state.json",
        canonical_json(state),
        0o600,
        mapped_id(0, root),
        mapped_id(0, root, group=True),
    )
    if secure_json(transaction / "state.json", root) != state:
        raise ValueError("transaction state readback mismatch")


def load_transaction(
    transaction: Path,
    root: Path,
    manifest: dict[str, object],
    entries: list[Entry],
    backup_id: str,
    *,
    allow_legacy: bool = False,
) -> tuple[dict[str, object], dict[str, object] | None, bool]:
    require_directory(
        transaction,
        mapped_id(0, root),
        mapped_id(0, root, group=True),
        0o700,
    )
    state = read_optional_json(transaction / "state.json", root)
    receipt = read_optional_json(transaction / "receipt.json", root)
    legacy = state is None
    if state is None:
        if not allow_legacy or receipt is None:
            raise ValueError("transaction state is missing")
        validate_receipt(receipt, manifest, entries)
        state = {
            "schema": TRANSACTION_SCHEMA,
            "backup_id": backup_id,
            "phase": receipt["state"],
            "package_id": receipt["package_id"],
            "package_digest": receipt["package_digest"],
            "changed_targets": receipt["changed_targets"],
            "created_directories": receipt["created_directories"],
            "inventory": receipt["inventory"],
        }
    validate_transaction_state(state, manifest, entries, backup_id)
    if receipt is not None:
        validate_receipt(receipt, manifest, entries)
        expected = receipt_from_state(state, str(receipt["state"]))
        if receipt != expected:
            raise ValueError("transaction receipt/state mismatch")
    phase = str(state["phase"])
    allowed_receipt_states = {
        "preparing": set(),
        "install_prepared": set(),
        "installing": {"installed"},
        "installed": {"installed"},
        "rolling_back": {"installed", "rolled_back"},
        "rolled_back": {"rolled_back"},
    }[phase]
    if receipt is None:
        if phase in {"installed", "rolled_back"}:
            raise ValueError("transaction receipt/state mismatch")
    elif receipt["state"] not in allowed_receipt_states:
        raise ValueError("transaction receipt/state mismatch")
    return state, receipt, legacy


def find_open_transaction(
    backup_base: Path,
    root: Path,
    manifest: dict[str, object],
    entries: list[Entry],
) -> tuple[Path, dict[str, object], dict[str, object] | None] | None:
    open_transactions: list[tuple[Path, dict[str, object], dict[str, object] | None]] = []
    seen_backup_ids: set[str] = set()
    with os.scandir(backup_base) as iterator:
        for item in iterator:
            if not item.is_dir(follow_symlinks=False):
                continue
            backup_id = item.name
            staged = False
            if item.name.startswith(".") and item.name.endswith(".preparing"):
                backup_id = item.name[1:-len(".preparing")]
                staged = True
            if not BACKUP_ID.fullmatch(backup_id):
                continue
            if backup_id in seen_backup_ids:
                continue
            seen_backup_ids.add(backup_id)
            transaction = backup_base / item.name
            state = read_optional_json(transaction / "state.json", root)
            if state is None:
                receipt = read_optional_json(transaction / "receipt.json", root)
                if staged and receipt is None:
                    # The published transaction name does not exist yet, so no
                    # managed target can have been mutated from this staging
                    # directory. A fresh transaction is exact compensation.
                    continue
                if receipt is None:
                    raise ValueError(f"unrecoverable transaction without durable state: {item.name}")
                continue
            if staged:
                loaded_state, receipt, legacy = load_transaction(
                    transaction,
                    root,
                    manifest,
                    entries,
                    backup_id,
                )
                if legacy or loaded_state["phase"] != "preparing" or receipt is not None:
                    raise ValueError("staged transaction is not preparing")
                backup_base_fd = os.open(
                    backup_base,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    os.rename(
                        item.name,
                        backup_id,
                        src_dir_fd=backup_base_fd,
                        dst_dir_fd=backup_base_fd,
                    )
                    os.fsync(backup_base_fd)
                finally:
                    os.close(backup_base_fd)
                transaction = backup_base / backup_id
                open_transactions.append((transaction, loaded_state, receipt))
                continue
            if state.get("phase") not in OPEN_TRANSACTION_PHASES:
                continue
            loaded_state, receipt, legacy = load_transaction(
                transaction,
                root,
                manifest,
                entries,
                backup_id,
            )
            if legacy:
                raise ValueError("open transaction unexpectedly used a legacy receipt")
            open_transactions.append((transaction, loaded_state, receipt))
    if len(open_transactions) > 1:
        raise ValueError("multiple incomplete controld transactions")
    return open_transactions[0] if open_transactions else None


def make_inventory(root: Path, planned: list[Entry]) -> list[dict[str, object]]:
    inventory: list[dict[str, object]] = []
    for index, entry in enumerate(planned):
        prior = target_state(root, entry)
        record: dict[str, object] = {"target": entry.target, "existed": prior is not None}
        if prior is not None:
            record.update(
                {
                    "mode": prior["mode"],
                    "uid": prior["uid"],
                    "gid": prior["gid"],
                    "sha256": prior["sha256"],
                    "backup": f"files/{index}",
                }
            )
        inventory.append(record)
    return inventory


def created_directory_plan(root: Path, manifest: dict[str, object]) -> list[str]:
    created: list[str] = []
    for item in manifest["directories"]:
        logical = str(item["target"])
        target = rooted(root, logical)
        if target.exists() or target.is_symlink():
            require_directory(target, mapped_id(0, root), mapped_id(0, root, group=True), 0o755)
        else:
            validate_parent_chain(root, target.parent)
            created.append(logical)
    return created


def transaction_files_directory(transaction: Path, root: Path, *, create: bool) -> Path:
    files = transaction / "files"
    if not files.exists() and not files.is_symlink():
        if not create:
            raise ValueError("transaction backup directory is missing")
        files.mkdir(mode=0o700)
        os.chown(files, mapped_id(0, root), mapped_id(0, root, group=True))
        files.chmod(0o700)
        fsync_directory(transaction)
    require_directory(files, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
    return files


def prior_tuple(record: dict[str, object]) -> tuple[str, int, int, int] | None:
    if not record["existed"]:
        return None
    return (
        str(record["sha256"]),
        int(record["mode"]),
        int(record["uid"]),
        int(record["gid"]),
    )


def candidate_tuple(root: Path, entry: Entry) -> tuple[str, int, int, int]:
    uid, gid, install_mode = desired_metadata(root, entry)
    return entry.sha256, install_mode, uid, gid


def state_tuple(value: dict[str, object] | None) -> tuple[str, int, int, int] | None:
    if value is None:
        return None
    return str(value["sha256"]), int(value["mode"]), int(value["uid"]), int(value["gid"])


def classify_target(root: Path, entry: Entry, record: dict[str, object]) -> str:
    current = state_tuple(target_state(root, entry))
    if current == candidate_tuple(root, entry):
        return "candidate"
    if current == prior_tuple(record):
        return "prior"
    raise ValueError(f"transaction target drift: {entry.target}")


def verify_unchanged_targets(
    root: Path,
    entries: list[Entry],
    changed_targets: list[str],
) -> None:
    changed = set(changed_targets)
    for entry in entries:
        if entry.target not in changed and state_tuple(target_state(root, entry)) != candidate_tuple(root, entry):
            raise ValueError(f"unchanged managed target drift: {entry.target}")


def backup_payloads(
    transaction: Path,
    root: Path,
    inventory: list[dict[str, object]],
) -> dict[str, bytes | None]:
    priors: dict[str, bytes | None] = {}
    existing = [record for record in inventory if record["existed"]]
    if existing:
        transaction_files_directory(transaction, root, create=False)
    for record in inventory:
        target = str(record["target"])
        if not record["existed"]:
            priors[target] = None
            continue
        payload, metadata = read_fd(transaction / str(record["backup"]))
        if (
            metadata.st_uid != mapped_id(0, root)
            or metadata.st_gid != mapped_id(0, root, group=True)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or sha256(payload) != record["sha256"]
        ):
            raise ValueError("backup file digest drift")
        priors[target] = payload
    return priors


def finish_preparing(
    transaction: Path,
    root: Path,
    state: dict[str, object],
    entries: list[Entry],
) -> dict[str, object]:
    if state["phase"] != "preparing":
        return state
    changed_targets = list(state["changed_targets"])
    inventory = list(state["inventory"])
    by_target = {entry.target: entry for entry in entries}
    verify_unchanged_targets(root, entries, changed_targets)
    if any(record["existed"] for record in inventory):
        transaction_files_directory(transaction, root, create=True)
    for record in inventory:
        entry = by_target[str(record["target"])]
        if classify_target(root, entry, record) != "prior":
            raise ValueError(f"preparing transaction target changed: {entry.target}")
        if not record["existed"]:
            continue
        backup = transaction / str(record["backup"])
        current = target_state(root, entry)
        assert current is not None
        try:
            payload, metadata = read_fd(backup)
        except FileNotFoundError:
            atomic_write(
                backup,
                current["payload"],
                0o600,
                mapped_id(0, root),
                mapped_id(0, root, group=True),
            )
        else:
            if (
                metadata.st_uid != mapped_id(0, root)
                or metadata.st_gid != mapped_id(0, root, group=True)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or sha256(payload) != record["sha256"]
            ):
                raise ValueError("backup file digest drift")
    backup_payloads(transaction, root, inventory)
    state = {**state, "phase": "install_prepared"}
    write_transaction_state(transaction, state, root)
    return state


def ensure_install_directories(
    root: Path,
    manifest: dict[str, object],
    created_directories: list[str],
) -> None:
    created = set(created_directories)
    for item in manifest["directories"]:
        logical = str(item["target"])
        target = rooted(root, logical)
        if target.exists() or target.is_symlink():
            require_directory(target, mapped_id(0, root), mapped_id(0, root, group=True), 0o755)
            continue
        if logical not in created:
            raise ValueError(f"pre-existing managed directory disappeared: {logical}")
        validate_parent_chain(root, target.parent)
        target.mkdir(mode=0o700)
        os.chown(target, mapped_id(0, root), mapped_id(0, root, group=True))
        target.chmod(0o755)
        fsync_directory(target.parent)
        require_directory(target, mapped_id(0, root), mapped_id(0, root, group=True), 0o755)


def created_directory_names(state: dict[str, object]) -> dict[str, set[str]]:
    result = {directory: set() for directory in state["created_directories"]}
    for record in state["inventory"]:
        parent = str(Path(str(record["target"])).parent)
        if parent in result and not record["existed"]:
            result[parent].add(Path(str(record["target"])).name)
    return result


def validate_created_directories(
    root: Path,
    state: dict[str, object],
    *,
    require_complete: bool,
) -> None:
    for logical, expected in created_directory_names(state).items():
        path = rooted(root, logical)
        if not path.exists() and not path.is_symlink():
            if require_complete:
                raise ValueError(f"created managed directory disappeared: {logical}")
            continue
        require_directory(path, mapped_id(0, root), mapped_id(0, root, group=True), 0o755)
        fd = open_read_directory(path)
        try:
            present = set(os.listdir(fd))
        finally:
            os.close(fd)
        if (require_complete and present != expected) or (not require_complete and not present.issubset(expected)):
            raise ValueError(f"managed directory content drift: {logical}")


def remove_created_directories(root: Path, state: dict[str, object]) -> None:
    for logical in reversed(list(state["created_directories"])):
        path = rooted(root, logical)
        if not path.exists() and not path.is_symlink():
            continue
        require_directory(path, mapped_id(0, root), mapped_id(0, root, group=True), 0o755)
        parent_fd = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.rmdir(path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


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
    if dry_run:
        planned = changes(package, root, entries)
        return {
            "status": "dry_run",
            "package_id": manifest["package_id"],
            "package_digest": manifest["package_digest"],
            "changed_targets": [entry.target for entry in planned],
            "daemon_contract": DAEMON_CONTRACT,
            **DEFAULT_STATE,
        }
    backup_base = backup_root_path(root, backup_root)
    ensure_private_tree(root, backup_base)
    active = find_open_transaction(backup_base, root, manifest, entries)
    if active is None:
        planned = changes(package, root, entries)
        if not planned:
            return {
                "status": "unchanged",
                "package_id": manifest["package_id"],
                "package_digest": manifest["package_digest"],
                "changed_targets": [],
                "daemon_contract": DAEMON_CONTRACT,
                **DEFAULT_STATE,
            }
        backup_id = f"{manifest['package_id']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}-{uuid.uuid4().hex[:8]}"
        transaction = backup_base / backup_id
        staging = backup_base / f".{backup_id}.preparing"
        staging.mkdir(mode=0o700)
        os.chown(staging, mapped_id(0, root), mapped_id(0, root, group=True))
        staging.chmod(0o700)
        require_directory(staging, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
        inventory = make_inventory(root, planned)
        state: dict[str, object] = {
            "schema": TRANSACTION_SCHEMA,
            "backup_id": backup_id,
            "phase": "preparing",
            "package_id": manifest["package_id"],
            "package_digest": manifest["package_digest"],
            "changed_targets": [entry.target for entry in planned],
            "created_directories": created_directory_plan(root, manifest),
            "inventory": inventory,
        }
        write_transaction_state(staging, state, root)
        backup_base_fd = os.open(
            backup_base,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.rename(staging.name, backup_id, src_dir_fd=backup_base_fd, dst_dir_fd=backup_base_fd)
            os.fsync(backup_base_fd)
        finally:
            os.close(backup_base_fd)
        receipt = None
    else:
        transaction, state, receipt = active
        backup_id = str(state["backup_id"])
        if state["phase"] == "rolling_back":
            raise ValueError(f"rollback is in progress for transaction: {backup_id}")

    if state["phase"] == "preparing":
        state = finish_preparing(transaction, root, state, entries)
    if state["phase"] == "install_prepared":
        state = {**state, "phase": "installing"}
        write_transaction_state(transaction, state, root)
    if state["phase"] != "installing":
        raise ValueError("incomplete transaction is not install-resumable")

    by_target = {entry.target: entry for entry in entries}
    inventory = list(state["inventory"])
    priors = backup_payloads(transaction, root, inventory)
    verify_unchanged_targets(root, entries, list(state["changed_targets"]))
    ensure_install_directories(root, manifest, list(state["created_directories"]))
    validate_created_directories(root, state, require_complete=False)
    target_classes = {
        str(record["target"]): classify_target(root, by_target[str(record["target"])], record)
        for record in inventory
    }
    if receipt is not None:
        if receipt["state"] != "installed" or any(value != "candidate" for value in target_classes.values()):
            raise ValueError("transaction receipt/state mismatch")
    else:
        for record in inventory:
            target = str(record["target"])
            if target_classes[target] == "candidate":
                continue
            entry = by_target[target]
            payload, _ = read_fd(package / entry.source)
            uid, gid, install_mode = desired_metadata(root, entry)
            atomic_write(rooted(root, target), payload, install_mode, uid, gid)

    for record in inventory:
        target = str(record["target"])
        entry = by_target[target]
        if classify_target(root, entry, record) != "candidate":
            raise ValueError(f"installed target readback mismatch: {target}")
    verify_unchanged_targets(root, entries, list(state["changed_targets"]))
    validate_created_directories(root, state, require_complete=True)
    receipt = receipt_from_state(state, "installed")
    atomic_write(
        transaction / "receipt.json",
        canonical_json(receipt),
        0o600,
        mapped_id(0, root),
        mapped_id(0, root, group=True),
    )
    if secure_json(transaction / "receipt.json", root) != receipt:
        raise ValueError("install receipt readback mismatch")
    state = {**state, "phase": "installed"}
    write_transaction_state(transaction, state, root)
    return {
        "status": "installed",
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "changed_targets": state["changed_targets"],
        "daemon_contract": DAEMON_CONTRACT,
        "backup_id": backup_id,
        **DEFAULT_STATE,
    }


def rollback(package: Path, root: Path, backup_root: Path, backup_id: str, *, dry_run: bool = False) -> dict[str, object]:
    manifest, entries = parse_manifest(package, root)
    if root == Path("/") and os.geteuid() != 0:
        raise PermissionError("rollback requires root")
    if not BACKUP_ID.fullmatch(backup_id):
        raise ValueError("invalid backup id")
    transaction = backup_root_path(root, backup_root) / backup_id
    require_directory(transaction.parent, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
    require_directory(transaction, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
    state, receipt, legacy = load_transaction(
        transaction,
        root,
        manifest,
        entries,
        backup_id,
        allow_legacy=True,
    )
    by_target = {entry.target: entry for entry in entries}
    inventory = list(state["inventory"])
    changed_targets = list(state["changed_targets"])
    if state["phase"] == "preparing" and not dry_run:
        state = finish_preparing(transaction, root, state, entries)
        inventory = list(state["inventory"])

    verify_unchanged_targets(root, entries, changed_targets)
    classes: dict[str, str] = {}
    for record in inventory:
        target = str(record["target"])
        try:
            classes[target] = classify_target(root, by_target[target], record)
        except ValueError as error:
            raise ValueError(f"installed target drift blocks rollback: {target}") from error
    if state["phase"] == "installed" and any(value != "candidate" for value in classes.values()):
        raise ValueError("installed target drift blocks rollback")
    if state["phase"] == "rolled_back" and any(value != "prior" for value in classes.values()):
        raise ValueError("rolled-back target drift")
    if state["phase"] == "rolled_back":
        validate_created_directories(root, state, require_complete=False)
        for directory in state["created_directories"]:
            if rooted(root, str(directory)).exists() or rooted(root, str(directory)).is_symlink():
                raise ValueError(f"rolled-back directory remains: {directory}")
        if not dry_run and legacy:
            write_transaction_state(transaction, state, root)
        return {
            "status": "rollback_dry_run" if dry_run else "rolled_back",
            "package_id": manifest["package_id"],
            "backup_id": backup_id,
            "restored_targets": changed_targets,
        }

    if state["phase"] == "installed":
        validate_created_directories(root, state, require_complete=True)
    else:
        validate_created_directories(root, state, require_complete=False)

    priors: dict[str, bytes | None]
    if state["phase"] == "preparing" and dry_run:
        priors = {str(record["target"]): None for record in inventory}
    else:
        priors = backup_payloads(transaction, root, inventory)
    result = {
        "status": "rollback_dry_run" if dry_run else "rolled_back",
        "package_id": manifest["package_id"],
        "backup_id": backup_id,
        "restored_targets": changed_targets,
    }
    if dry_run:
        return result

    if legacy:
        write_transaction_state(transaction, state, root)
    if state["phase"] != "rolling_back":
        state = {**state, "phase": "rolling_back"}
        write_transaction_state(transaction, state, root)
    for record in reversed(inventory):
        target = str(record["target"])
        entry = by_target[target]
        classification = classify_target(root, entry, record)
        if classification == "prior":
            continue
        prior_payload = priors[target]
        path = rooted(root, target)
        if prior_payload is None:
            unlink_file(path)
        else:
            atomic_write(
                path,
                prior_payload,
                int(record["mode"]),
                int(record["uid"]),
                int(record["gid"]),
            )
    for record in inventory:
        target = str(record["target"])
        if classify_target(root, by_target[target], record) != "prior":
            raise ValueError(f"rollback readback mismatch: {target}")
    verify_unchanged_targets(root, entries, changed_targets)
    validate_created_directories(root, state, require_complete=False)
    remove_created_directories(root, state)
    receipt = receipt_from_state(state, "rolled_back")
    atomic_write(
        transaction / "receipt.json",
        canonical_json(receipt),
        0o600,
        mapped_id(0, root),
        mapped_id(0, root, group=True),
    )
    if secure_json(transaction / "receipt.json", root) != receipt:
        raise ValueError("rollback receipt readback mismatch")
    state = {**state, "phase": "rolled_back"}
    write_transaction_state(transaction, state, root)
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
