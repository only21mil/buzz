#!/usr/bin/env python3
"""Check, plan, install, or roll back a frozen Buzz CI runner package."""

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

SCHEMA = "buzz-ci-runner-install-package-v2"
RECEIPT_SCHEMA = "buzz-ci-runner-install-receipt-v2"
LEGACY_RECEIPT_SCHEMA = "buzz-ci-runner-install-receipt-v1"
TRANSACTION_SCHEMA = "buzz-ci-runner-install-transaction-v1"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
PACKAGE_ID = re.compile(r"^buzz-ci-runner-[0-9a-f]{12}-[0-9a-f]{12}$")
DEFAULT_BACKUP_ROOT = Path("/var/lib/buzzci/install-backups/runner")
MAX_JSON_BYTES = 1024 * 1024
TRANSACTION_PHASES = {
    "install_prepared",
    "install_publishing",
    "installed",
    "rollback_prepared",
    "rollback_restoring",
    "rolled_back",
}

DEFAULT_STATE = {
    "enabled": False,
    "active": False,
    "provisioned": False,
    "capacity": 0,
    "host_block": False,
}
PEER_POLICY = {
    "runner_control_socket": {
        "path": "/run/buzzci/runner-control.sock",
        "descriptor_name": "buzz-ci-runner-control",
        "user": "buzzci-runner",
        "group": "buzzci-controld",
        "mode": "0620",
        "directory_mode": "0711",
    },
    "broker_socket": {
        "path": "/run/buzzci/execd.sock",
        "expected_uid": 0,
        "owner": "root",
        "group": "buzzci-execd",
        "mode": "0620",
        "supplementary_members": ["buzzci-runner", "buzzci-ctl"],
        "managed_by_package": False,
    },
}
EXPECTED_TARGETS = {
    "binary": "/usr/libexec/buzz-ci-runner",
    "config": "/etc/buzzci/runner-v2.json",
    "service": "/etc/systemd/system/buzz-ci-runner.service",
    "socket": "/etc/systemd/system/buzz-ci-runner.socket",
    "tmpfiles": "/usr/lib/tmpfiles.d/buzzci-runner.conf",
    "documentation": "/usr/share/doc/buzz-ci-runner/README.md",
}
EXPECTED_DIRECTORIES = {"/etc/buzzci", "/usr/share/doc/buzz-ci-runner"}


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
        "default_state", "peer_policy", "package_uid", "package_gid", "identities",
        "directories", "entries", "package_digest",
    }
    if set(manifest) != expected_keys or manifest["schema"] != SCHEMA:
        raise ValueError("invalid package manifest fields")
    if not isinstance(manifest["package_id"], str) or not PACKAGE_ID.fullmatch(manifest["package_id"]):
        raise ValueError("invalid package id")
    if not isinstance(manifest["source_commit"], str) or not GIT_OID.fullmatch(manifest["source_commit"]):
        raise ValueError("invalid source commit")
    if manifest["default_state"] != DEFAULT_STATE or manifest["package_uid"] != 0 or manifest["package_gid"] != 0:
        raise ValueError("package is not closed by default")
    if manifest["peer_policy"] != PEER_POLICY:
        raise ValueError("package peer policy is invalid")
    identities = manifest["identities"]
    if not isinstance(identities, dict) or set(identities) != {"runner", "controld"}:
        raise ValueError("invalid package identities")
    for role, user, group in (
        ("runner", "buzzci-runner", "buzzci-runner"),
        ("controld", "buzzci-controld", "buzzci-controld"),
    ):
        identity = identities[role]
        if (
            not isinstance(identity, dict)
            or set(identity) != {"user", "group", "uid", "gid"}
            or identity["user"] != user
            or identity["group"] != group
        ):
            raise ValueError("invalid package identity binding")
        u32(identity["uid"], nonzero=True)
        u32(identity["gid"], nonzero=True)
    if (
        identities["runner"]["uid"] == identities["controld"]["uid"]
        or identities["runner"]["gid"] == identities["controld"]["gid"]
    ):
        raise ValueError("runner and controld identities must be distinct")
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
        or provenance["binary"] != "buzz-ci-runner"
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
            runner_identity = identities["runner"]
            if entry.install_mode != 0o600 or entry.uid != runner_identity["uid"] or entry.gid != runner_identity["gid"]:
                raise ValueError("runner config must be privately runner-owned")
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
            raise ValueError("runner binary is not bound to provenance")
        entries.append(entry)
    if seen_roles != set(EXPECTED_TARGETS):
        raise ValueError("package roles are incomplete")
    validate_assets(package, entries, identities)
    return manifest, sorted(entries, key=lambda item: item.target.encode())


def validate_assets(package: Path, entries: list[Entry], identities: dict[str, object]) -> None:
    payloads = {entry.role: read_fd(package / entry.source)[0] for entry in entries}
    config = json.loads(payloads["config"], object_pairs_hook=reject_duplicates)
    if (
        not isinstance(config, dict)
        or set(config) != {"schema_version", "controld_uid", "controld_gid", "mode"}
        or config["schema_version"] != 2
        or config["mode"] != "dormant"
    ):
        raise ValueError("runner config is not canonical and closed")
    if u32(config["controld_uid"], nonzero=True) != identities["controld"]["uid"]:
        raise ValueError("runner config controld UID binding mismatch")
    if u32(config["controld_gid"], nonzero=True) != identities["controld"]["gid"]:
        raise ValueError("runner config controld GID binding mismatch")
    service = payloads["service"].decode()
    socket = payloads["socket"].decode()
    tmpfiles = payloads["tmpfiles"].decode()
    required_service = {
        "ExecStart=/usr/libexec/buzz-ci-runner --config /etc/buzzci/runner-v2.json",
        "SupplementaryGroups=buzzci-execd",
        "UMask=0077",
        "ReadWritePaths=/var/lib/buzzci/runner",
        "RestrictAddressFamilies=AF_UNIX",
    }
    forbidden_service = {
        "User=root",
        "AmbientCapabilities=",
        "CapabilityBoundingSet=",
        "buzz-ci-executor",
    }
    if (
        not all(line in service.splitlines() for line in required_service)
        or any(token in service for token in forbidden_service)
        or "/var/lib/buzzci/runner-output" in service
    ):
        raise ValueError("runner service path contract mismatch")
    required_socket = {
        "ListenStream=/run/buzzci/runner-control.sock",
        "FileDescriptorName=buzz-ci-runner-control",
        "SocketUser=buzzci-runner",
        "SocketMode=0620",
        "SocketGroup=buzzci-controld",
        "DirectoryMode=0711",
        "Service=buzz-ci-runner.service",
    }
    if not all(line in socket.splitlines() for line in required_socket) or "execd.sock" in socket:
        raise ValueError("runner and broker socket contracts overlap")
    for required in (
        "d /var/lib/buzzci/runner 0700 buzzci-runner buzzci-runner -",
    ):
        if required not in tmpfiles.splitlines():
            raise ValueError("runner tmpfiles contract mismatch")
    if "/var/lib/buzzci/runner-output" in tmpfiles:
        raise ValueError("runner tmpfiles must not own the controld output root")


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
    identities = manifest["identities"]
    users = parse_account_file(root, "/etc/passwd", 7)
    groups = parse_account_file(root, "/etc/group", 4)
    for role in ("runner", "controld"):
        identity = identities[role]
        matching_users = [row for row in users if row[0] == identity["user"]]
        matching_groups = [row for row in groups if row[0] == identity["group"]]
        if len(matching_users) != 1 or len(matching_groups) != 1:
            raise ValueError(f"host {role} identity is missing or duplicated")
        try:
            user_uid = int(matching_users[0][2])
            user_gid = int(matching_users[0][3])
            group_gid = int(matching_groups[0][2])
        except ValueError as error:
            raise ValueError(f"host {role} identity is malformed") from error
        if (user_uid, user_gid, group_gid) != (identity["uid"], identity["gid"], identity["gid"]):
            raise ValueError(f"host {role} identity does not match the package")


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


def directory_fd(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)


def fsync_directory(path: Path) -> None:
    fd = directory_fd(path)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(target: Path, payload: bytes, mode_value: int, uid: int, gid: int) -> None:
    parent_fd = directory_fd(target.parent)
    temporary_name = f".{target.name}.{uuid.uuid4().hex}.tmp"
    fd = -1
    try:
        try:
            target_meta = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            target_meta = None
        if target_meta is not None and stat.S_ISLNK(target_meta.st_mode):
            raise ValueError(f"target is a symbolic link: {target}")
        fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode_value,
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
            temporary_name,
            target.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def unlink_target(target: Path) -> None:
    parent_fd = directory_fd(target.parent)
    try:
        metadata = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"target is not a regular file: {target}")
        os.unlink(target.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def ensure_managed_directories(root: Path, manifest: dict[str, object], created: list[str]) -> None:
    created_set = set(created)
    for item in manifest["directories"]:
        logical = str(item["target"])
        target = rooted(root, logical)
        if target.exists() or target.is_symlink():
            metadata = target.lstat()
            allowed_modes = {0o755, 0o700} if logical in created_set else {0o755}
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != mapped_id(0, root)
                or metadata.st_gid != mapped_id(0, root, group=True)
                or stat.S_IMODE(metadata.st_mode) not in allowed_modes
            ):
                raise ValueError(f"unsafe directory metadata: {target}")
            if stat.S_IMODE(metadata.st_mode) == 0o700:
                fd = directory_fd(target)
                try:
                    os.fchmod(fd, 0o755)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                fsync_directory(target.parent)
                _phase_boundary("install_directory_created", logical)
            continue
        if logical not in created_set:
            raise ValueError(f"managed directory disappeared after transaction preparation: {logical}")
        validate_parent_chain(root, target.parent)
        parent_fd = directory_fd(target.parent)
        target_fd = -1
        try:
            os.mkdir(target.name, mode=0o700, dir_fd=parent_fd)
            target_fd = os.open(
                target.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            os.fchown(target_fd, mapped_id(0, root), mapped_id(0, root, group=True))
            os.fchmod(target_fd, 0o755)
            os.fsync(target_fd)
            os.fsync(parent_fd)
        finally:
            if target_fd >= 0:
                os.close(target_fd)
            os.close(parent_fd)
        require_directory(target, mapped_id(0, root), mapped_id(0, root, group=True), 0o755)
        _phase_boundary("install_directory_created", logical)


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
            parent = current.parent
            current.mkdir(mode=0o700)
            os.chown(current, root_uid, root_gid)
            fsync_directory(parent)
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != root_uid or metadata.st_gid != root_gid or metadata.st_mode & 0o022:
            raise ValueError(f"unsafe backup directory chain: {current}")
    require_directory(path, root_uid, root_gid, 0o700)


def _phase_boundary(phase: str, target: str | None = None) -> None:
    """Test hook called only after a durable phase or target boundary."""


def transaction_contract(state: dict[str, object]) -> dict[str, object]:
    return {
        key: state[key]
        for key in (
            "schema",
            "transaction_id",
            "package_id",
            "package_digest",
            "source_commit",
            "changed_targets",
            "created_directories",
            "inventory",
            "candidate",
        )
    }


def transaction_digest(state: dict[str, object]) -> str:
    return sha256(canonical_json(transaction_contract(state)))


def write_transaction_state(root: Path, transaction: Path, state: dict[str, object], phase: str) -> dict[str, object]:
    if phase not in TRANSACTION_PHASES:
        raise ValueError("invalid transaction phase")
    updated = dict(state)
    updated["phase"] = phase
    updated["transaction_digest"] = transaction_digest(updated)
    atomic_write(
        transaction / "transaction.json",
        canonical_json(updated),
        0o600,
        mapped_id(0, root),
        mapped_id(0, root, group=True),
    )
    return updated


def receipt_for(state: dict[str, object], terminal_state: str) -> dict[str, object]:
    if terminal_state not in {"installed", "rolled_back"}:
        raise ValueError("invalid receipt state")
    return {
        "schema": RECEIPT_SCHEMA,
        "state": terminal_state,
        "transaction_id": state["transaction_id"],
        "transaction_digest": state["transaction_digest"],
        "package_id": state["package_id"],
        "package_digest": state["package_digest"],
        "source_commit": state["source_commit"],
        "changed_targets": state["changed_targets"],
        "created_directories": state["created_directories"],
        "inventory": state["inventory"],
    }


def legacy_receipt_for(state: dict[str, object], terminal_state: str) -> dict[str, object]:
    if terminal_state not in {"installed", "rolled_back"}:
        raise ValueError("invalid legacy receipt state")
    return {
        "schema": LEGACY_RECEIPT_SCHEMA,
        "state": terminal_state,
        "package_id": state["package_id"],
        "package_digest": state["package_digest"],
        "changed_targets": state["changed_targets"],
        "created_directories": state["created_directories"],
        "inventory": state["inventory"],
    }


def write_receipt(root: Path, transaction: Path, state: dict[str, object], terminal_state: str) -> dict[str, object]:
    receipt = receipt_for(state, terminal_state)
    atomic_write(
        transaction / "receipt.json",
        canonical_json(receipt),
        0o600,
        mapped_id(0, root),
        mapped_id(0, root, group=True),
    )
    return receipt


def validate_inventory(
    root: Path,
    transaction: Path,
    state: dict[str, object],
    entries: list[Entry],
) -> dict[str, bytes | None]:
    by_target = {entry.target: entry for entry in entries}
    changed_targets = state.get("changed_targets")
    inventory = state.get("inventory")
    candidate = state.get("candidate")
    created_directories = state.get("created_directories")
    if (
        not isinstance(changed_targets, list)
        or not changed_targets
        or len(set(changed_targets)) != len(changed_targets)
        or any(not isinstance(target, str) or target not in by_target for target in changed_targets)
        or not isinstance(inventory, list)
        or len(inventory) != len(changed_targets)
        or not isinstance(candidate, list)
        or len(candidate) != len(changed_targets)
        or not isinstance(created_directories, list)
        or len(set(created_directories)) != len(created_directories)
        or any(directory not in EXPECTED_DIRECTORIES for directory in created_directories)
    ):
        raise ValueError("transaction inventory is invalid")

    prior_payloads: dict[str, bytes | None] = {}
    if any(isinstance(record, dict) and record.get("existed") is True for record in inventory):
        require_directory(
            transaction / "files",
            mapped_id(0, root),
            mapped_id(0, root, group=True),
            0o700,
        )
    for index, (target, record, desired) in enumerate(
        zip(changed_targets, inventory, candidate, strict=True)
    ):
        entry = by_target[target]
        if not isinstance(record, dict) or record.get("target") != target or not isinstance(record.get("existed"), bool):
            raise ValueError("transaction inventory entry is invalid")
        expected_record_keys = {"target", "existed"}
        prior_payload: bytes | None = None
        if record["existed"]:
            expected_record_keys |= {"mode", "uid", "gid", "sha256", "backup"}
            if (
                set(record) != expected_record_keys
                or record.get("backup") != f"files/{index}"
                or isinstance(record.get("mode"), bool)
                or not isinstance(record.get("mode"), int)
                or not 0 <= record["mode"] <= 0o777
                or isinstance(record.get("uid"), bool)
                or not isinstance(record.get("uid"), int)
                or not 0 <= record["uid"] <= (1 << 32) - 1
                or isinstance(record.get("gid"), bool)
                or not isinstance(record.get("gid"), int)
                or not 0 <= record["gid"] <= (1 << 32) - 1
                or not isinstance(record.get("sha256"), str)
                or not DIGEST.fullmatch(record["sha256"])
            ):
                raise ValueError("transaction prior-state binding is invalid")
            prior_payload, backup_meta = read_fd(transaction / str(record["backup"]))
            if (
                backup_meta.st_uid != mapped_id(0, root)
                or backup_meta.st_gid != mapped_id(0, root, group=True)
                or stat.S_IMODE(backup_meta.st_mode) != 0o600
            ):
                raise ValueError("backup file mode drift")
            if sha256(prior_payload) != record["sha256"]:
                raise ValueError("backup file digest drift")
        elif set(record) != expected_record_keys:
            raise ValueError("transaction absent-state binding is invalid")
        prior_payloads[target] = prior_payload

        uid, gid, install_mode = desired_metadata(root, entry)
        if (
            not isinstance(desired, dict)
            or set(desired) != {"target", "sha256", "mode", "uid", "gid"}
            or desired != {
                "target": target,
                "sha256": entry.sha256,
                "mode": install_mode,
                "uid": uid,
                "gid": gid,
            }
        ):
            raise ValueError("transaction candidate binding is invalid")
    return prior_payloads


def validate_unchanged_targets(root: Path, state: dict[str, object], entries: list[Entry]) -> None:
    changed = set(state["changed_targets"])
    for entry in entries:
        if entry.target in changed:
            continue
        observed = target_state(root, entry)
        uid, gid, install_mode = desired_metadata(root, entry)
        if observed is None or (
            observed["sha256"], observed["mode"], observed["uid"], observed["gid"]
        ) != (entry.sha256, install_mode, uid, gid):
            raise ValueError(f"unchanged package target drift: {entry.target}")


def read_transaction(
    package: Path,
    root: Path,
    transaction: Path,
    manifest: dict[str, object],
    entries: list[Entry],
) -> tuple[dict[str, object], dict[str, bytes | None], dict[str, object] | None]:
    require_directory(transaction, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
    state, _, metadata = parse_json_file(transaction / "transaction.json")
    required_keys = {
        "schema",
        "transaction_id",
        "package_id",
        "package_digest",
        "source_commit",
        "phase",
        "changed_targets",
        "created_directories",
        "inventory",
        "candidate",
        "transaction_digest",
    }
    if (
        metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or set(state) != required_keys
        or state.get("schema") != TRANSACTION_SCHEMA
        or state.get("transaction_id") != transaction.name
        or state.get("package_id") != manifest["package_id"]
        or state.get("package_digest") != manifest["package_digest"]
        or state.get("source_commit") != manifest["source_commit"]
        or state.get("phase") not in TRANSACTION_PHASES
        or not isinstance(state.get("transaction_digest"), str)
        or not DIGEST.fullmatch(state["transaction_digest"])
        or transaction_digest(state) != state["transaction_digest"]
    ):
        raise ValueError("transaction state is invalid or bound to another candidate")
    prior_payloads = validate_inventory(root, transaction, state, entries)
    validate_unchanged_targets(root, state, entries)

    receipt_path = transaction / "receipt.json"
    receipt: dict[str, object] | None = None
    if receipt_path.exists() or receipt_path.is_symlink():
        receipt, _, receipt_meta = parse_json_file(receipt_path)
        receipt_state_value = receipt.get("state")
        expected: dict[str, object] | None = None
        if receipt.get("schema") == RECEIPT_SCHEMA and receipt_state_value in {"installed", "rolled_back"}:
            expected = receipt_for(state, str(receipt_state_value))
        elif (
            receipt.get("schema") == LEGACY_RECEIPT_SCHEMA
            and state.get("phase") in {"installed", "rollback_restoring"}
            and receipt_state_value == "installed"
        ):
            expected = legacy_receipt_for(state, "installed")
        if (
            receipt_meta.st_uid != mapped_id(0, root)
            or receipt_meta.st_gid != mapped_id(0, root, group=True)
            or stat.S_IMODE(receipt_meta.st_mode) != 0o600
            or expected is None
            or receipt != expected
        ):
            raise ValueError("receipt/state mismatch")
    phase = str(state["phase"])
    receipt_state = receipt.get("state") if receipt is not None else None
    allowed_receipts = {
        "install_prepared": {None},
        "install_publishing": {None, "installed"},
        "installed": {"installed"},
        "rollback_prepared": {"installed"},
        "rollback_restoring": {"installed", "rolled_back"},
        "rolled_back": {"rolled_back"},
    }
    if receipt_state not in allowed_receipts[phase]:
        raise ValueError("receipt/state mismatch")
    return state, prior_payloads, receipt


def target_classification(
    root: Path,
    entry: Entry,
    record: dict[str, object],
    desired: dict[str, object],
) -> str:
    observed = target_state(root, entry)
    if observed is not None and (
        observed["sha256"],
        observed["mode"],
        observed["uid"],
        observed["gid"],
    ) == (desired["sha256"], desired["mode"], desired["uid"], desired["gid"]):
        return "candidate"
    if record["existed"]:
        if observed is not None and (
            observed["sha256"],
            observed["mode"],
            observed["uid"],
            observed["gid"],
        ) == (record["sha256"], record["mode"], record["uid"], record["gid"]):
            return "prior"
    elif observed is None:
        return "prior"
    return "drift"


def target_classifications(
    root: Path,
    state: dict[str, object],
    entries: list[Entry],
) -> dict[str, str]:
    by_target = {entry.target: entry for entry in entries}
    result: dict[str, str] = {}
    for target, record, desired in zip(
        state["changed_targets"], state["inventory"], state["candidate"], strict=True
    ):
        result[str(target)] = target_classification(root, by_target[str(target)], record, desired)
    return result


def require_classifications(classifications: dict[str, str], allowed: set[str], operation: str) -> None:
    refused = {target: value for target, value in classifications.items() if value not in allowed}
    if refused:
        target, value = next(iter(refused.items()))
        raise ValueError(f"{operation} target drift: {target} is {value}")


def remove_created_directory(root: Path, logical: str) -> None:
    path = rooted(root, logical)
    parent_fd = directory_fd(path.parent)
    try:
        os.rmdir(path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def validate_rollback_directories(
    root: Path,
    state: dict[str, object],
    classifications: dict[str, str],
) -> None:
    inventory = {str(record["target"]): record for record in state["inventory"]}
    for logical in state["created_directories"]:
        path = rooted(root, str(logical))
        expected_present = {
            Path(target).name
            for target, classification in classifications.items()
            if classification == "candidate"
            and not inventory[target]["existed"]
            and rooted(root, target).parent == path
        }
        if not path.exists() and not path.is_symlink():
            if expected_present:
                raise ValueError(f"rollback directory disappeared with candidate targets: {logical}")
            continue
        try:
            require_directory(path, mapped_id(0, root), mapped_id(0, root, group=True), 0o755)
        except ValueError as error:
            raise ValueError(f"rollback directory metadata drift: {logical}") from error
        fd = directory_fd(path)
        try:
            present = set(os.listdir(fd))
        finally:
            os.close(fd)
        if present != expected_present:
            raise ValueError(f"rollback directory removal is blocked: {logical}")


def read_legacy_receipt(
    root: Path,
    transaction: Path,
    manifest: dict[str, object],
    entries: list[Entry],
) -> tuple[dict[str, object], dict[str, bytes | None], dict[str, object]]:
    require_directory(transaction, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
    receipt, _, metadata = parse_json_file(transaction / "receipt.json")
    expected_keys = {
        "schema",
        "state",
        "package_id",
        "package_digest",
        "changed_targets",
        "created_directories",
        "inventory",
    }
    if (
        metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or set(receipt) != expected_keys
        or receipt.get("schema") != LEGACY_RECEIPT_SCHEMA
        or receipt.get("state") not in {"installed", "rolled_back"}
        or receipt.get("package_id") != manifest["package_id"]
        or receipt.get("package_digest") != manifest["package_digest"]
        or not transaction.name.startswith(f"{manifest['package_id']}-")
    ):
        raise ValueError("legacy backup receipt is invalid or bound to another candidate")

    changed_targets = receipt.get("changed_targets")
    created_directories = receipt.get("created_directories")
    by_target = {entry.target: entry for entry in entries}
    if (
        not isinstance(changed_targets, list)
        or not changed_targets
        or any(not isinstance(target, str) or target not in by_target for target in changed_targets)
        or changed_targets != sorted(changed_targets, key=str.encode)
        or not isinstance(created_directories, list)
        or any(
            not isinstance(directory, str) or directory not in EXPECTED_DIRECTORIES
            for directory in created_directories
        )
        or len(set(created_directories)) != len(created_directories)
        or created_directories
        != [
            str(item["target"])
            for item in manifest["directories"]
            if item["target"] in set(created_directories)
        ]
    ):
        raise ValueError("legacy backup receipt inventory is ambiguous")

    candidate: list[dict[str, object]] = []
    for target in changed_targets:
        entry = by_target[target]
        uid, gid, install_mode = desired_metadata(root, entry)
        candidate.append(
            {
                "target": target,
                "sha256": entry.sha256,
                "mode": install_mode,
                "uid": uid,
                "gid": gid,
            }
        )
    state = {
        "schema": TRANSACTION_SCHEMA,
        "transaction_id": transaction.name,
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "source_commit": manifest["source_commit"],
        "phase": str(receipt["state"]),
        "changed_targets": changed_targets,
        "created_directories": created_directories,
        "inventory": receipt["inventory"],
        "candidate": candidate,
    }
    state["transaction_digest"] = transaction_digest(state)
    if receipt != legacy_receipt_for(state, str(receipt["state"])):
        raise ValueError("legacy backup receipt binding is invalid")
    prior_payloads = validate_inventory(root, transaction, state, entries)
    validate_unchanged_targets(root, state, entries)
    for record, desired in zip(state["inventory"], candidate, strict=True):
        if record["existed"] and (
            record["sha256"], record["mode"], record["uid"], record["gid"]
        ) == (desired["sha256"], desired["mode"], desired["uid"], desired["gid"]):
            raise ValueError("legacy backup prior state is indistinguishable from the candidate")

    classifications = target_classifications(root, state, entries)
    if receipt["state"] == "installed":
        require_classifications(classifications, {"candidate", "prior"}, "legacy installed backup")
        validate_rollback_directories(root, state, classifications)
        if set(classifications.values()) != {"candidate"}:
            state["phase"] = "rollback_restoring"
            state["transaction_digest"] = transaction_digest(state)
    else:
        require_classifications(classifications, {"prior"}, "legacy rolled-back backup")
        validate_rollback_directories(root, state, classifications)
        if any(
            rooted(root, str(logical)).exists() or rooted(root, str(logical)).is_symlink()
            for logical in state["created_directories"]
        ):
            raise ValueError("legacy rolled-back directory evidence is ambiguous")
    return state, prior_payloads, receipt


def result_for_install(manifest: dict[str, object], state: dict[str, object]) -> dict[str, object]:
    return {
        "status": "installed",
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "backup_id": state["transaction_id"],
        "changed_targets": state["changed_targets"],
        "peer_policy": manifest["peer_policy"],
        **DEFAULT_STATE,
    }


def result_for_rollback(manifest: dict[str, object], state: dict[str, object], *, dry_run: bool) -> dict[str, object]:
    return {
        "status": "rollback_dry_run" if dry_run else "rolled_back",
        "package_id": manifest["package_id"],
        "backup_id": state["transaction_id"],
        "restored_targets": state["changed_targets"],
    }


def matching_transactions(
    package: Path,
    root: Path,
    backup_base: Path,
    manifest: dict[str, object],
    entries: list[Entry],
) -> list[tuple[Path, dict[str, object], dict[str, bytes | None], dict[str, object] | None]]:
    prefix = f"{manifest['package_id']}-"
    matches = []
    for transaction in sorted(backup_base.iterdir(), key=lambda item: item.name.encode()):
        if not transaction.name.startswith(prefix):
            continue
        state_path = transaction / "transaction.json"
        if not state_path.exists() and not state_path.is_symlink():
            continue
        state, prior_payloads, receipt = read_transaction(package, root, transaction, manifest, entries)
        matches.append((transaction, state, prior_payloads, receipt))
    return matches


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
        "peer_policy": manifest["peer_policy"],
        **DEFAULT_STATE,
    }


def install(package: Path, root: Path, backup_root: Path, *, dry_run: bool = False) -> dict[str, object]:
    manifest, entries = parse_manifest(package, root)
    validate_host_identities(root, manifest)
    if root == Path("/") and os.geteuid() != 0:
        raise PermissionError("install requires root")
    backup_base = backup_root_path(root, backup_root)
    if dry_run:
        planned = changes(package, root, entries)
        return {
            "status": "dry_run",
            "package_id": manifest["package_id"],
            "package_digest": manifest["package_digest"],
            "changed_targets": [entry.target for entry in planned],
            "peer_policy": manifest["peer_policy"],
            **DEFAULT_STATE,
        }

    ensure_private_tree(root, backup_base)
    transactions = matching_transactions(package, root, backup_base, manifest, entries)
    active = [item for item in transactions if item[1]["phase"] != "rolled_back"]
    if len(active) > 1:
        raise ValueError("multiple non-terminal transactions are bound to this package")

    if active:
        transaction, state, _prior_payloads, receipt = active[0]
        phase = str(state["phase"])
        classifications = target_classifications(root, state, entries)
        if phase in {"rollback_prepared", "rollback_restoring"}:
            raise ValueError(
                f"rollback transaction is incomplete; retry rollback with backup id {state['transaction_id']}"
            )
        if phase == "installed":
            require_classifications(classifications, {"candidate"}, "installed transaction")
            return result_for_install(manifest, state)
        if phase == "install_prepared":
            require_classifications(classifications, {"prior"}, "prepared install")
            if receipt is not None:
                raise ValueError("receipt/state mismatch")
            state = write_transaction_state(root, transaction, state, "install_publishing")
            _phase_boundary("install_publishing")
        elif phase == "install_publishing":
            if receipt is not None:
                require_classifications(classifications, {"candidate"}, "completed install")
                state = write_transaction_state(root, transaction, state, "installed")
                _phase_boundary("installed")
                return result_for_install(manifest, state)
            require_classifications(classifications, {"prior", "candidate"}, "resumed install")
        else:
            raise ValueError("transaction phase cannot be resumed by install")
    else:
        planned = changes(package, root, entries)
        if not planned:
            return {
                "status": "unchanged",
                "package_id": manifest["package_id"],
                "package_digest": manifest["package_digest"],
                "changed_targets": [],
                "peer_policy": manifest["peer_policy"],
                **DEFAULT_STATE,
            }
        backup_id = f"{manifest['package_id']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}-{uuid.uuid4().hex[:8]}"
        transaction = backup_base / backup_id
        transaction.mkdir(mode=0o700)
        os.chown(transaction, mapped_id(0, root), mapped_id(0, root, group=True))
        transaction.chmod(0o700)
        fsync_directory(backup_base)
        require_directory(transaction, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)

        created_directories: list[str] = []
        for item in manifest["directories"]:
            logical = str(item["target"])
            directory = rooted(root, logical)
            if directory.exists() or directory.is_symlink():
                require_directory(directory, mapped_id(0, root), mapped_id(0, root, group=True), 0o755)
            else:
                validate_parent_chain(root, directory.parent)
                created_directories.append(logical)

        inventory: list[dict[str, object]] = []
        candidate: list[dict[str, object]] = []
        files_created = False
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
                files = transaction / "files"
                if not files_created:
                    files.mkdir(mode=0o700)
                    os.chown(files, mapped_id(0, root), mapped_id(0, root, group=True))
                    files.chmod(0o700)
                    fsync_directory(transaction)
                    files_created = True
                atomic_write(
                    files / str(index),
                    prior["payload"],
                    0o600,
                    mapped_id(0, root),
                    mapped_id(0, root, group=True),
                )
            inventory.append(record)
            uid, gid, install_mode = desired_metadata(root, entry)
            candidate.append(
                {
                    "target": entry.target,
                    "sha256": entry.sha256,
                    "mode": install_mode,
                    "uid": uid,
                    "gid": gid,
                }
            )
        state = {
            "schema": TRANSACTION_SCHEMA,
            "transaction_id": backup_id,
            "package_id": manifest["package_id"],
            "package_digest": manifest["package_digest"],
            "source_commit": manifest["source_commit"],
            "changed_targets": [entry.target for entry in planned],
            "created_directories": created_directories,
            "inventory": inventory,
            "candidate": candidate,
        }
        state = write_transaction_state(root, transaction, state, "install_prepared")
        _phase_boundary("install_prepared")
        validate_unchanged_targets(root, state, entries)
        classifications = target_classifications(root, state, entries)
        require_classifications(classifications, {"prior"}, "prepared install")
        state = write_transaction_state(root, transaction, state, "install_publishing")
        _phase_boundary("install_publishing")

    ensure_managed_directories(root, manifest, list(state["created_directories"]))
    by_target = {entry.target: entry for entry in entries}
    classifications = target_classifications(root, state, entries)
    require_classifications(classifications, {"prior", "candidate"}, "install")
    for target, desired in zip(state["changed_targets"], state["candidate"], strict=True):
        entry = by_target[str(target)]
        if classifications[str(target)] == "prior":
            payload, source_meta = read_fd(package / entry.source)
            if stat.S_IMODE(source_meta.st_mode) != entry.source_mode or sha256(payload) != entry.sha256:
                raise ValueError(f"package source drift during install: {entry.source}")
            atomic_write(
                rooted(root, entry.target),
                payload,
                int(desired["mode"]),
                int(desired["uid"]),
                int(desired["gid"]),
            )
            observed = target_state(root, entry)
            if observed is None or (
                observed["sha256"], observed["mode"], observed["uid"], observed["gid"]
            ) != (desired["sha256"], desired["mode"], desired["uid"], desired["gid"]):
                raise ValueError(f"installed target readback mismatch: {entry.target}")
            _phase_boundary("install_target_published", entry.target)
    classifications = target_classifications(root, state, entries)
    require_classifications(classifications, {"candidate"}, "install completion")
    write_receipt(root, transaction, state, "installed")
    _phase_boundary("installed_receipt_written")
    state = write_transaction_state(root, transaction, state, "installed")
    _phase_boundary("installed")
    return result_for_install(manifest, state)


def rollback(package: Path, root: Path, backup_root: Path, backup_id: str, *, dry_run: bool = False) -> dict[str, object]:
    manifest, entries = parse_manifest(package, root)
    if root == Path("/") and os.geteuid() != 0:
        raise PermissionError("rollback requires root")
    if "/" in backup_id or backup_id in {"", ".", ".."}:
        raise ValueError("invalid backup id")
    transaction = backup_root_path(root, backup_root) / backup_id
    require_directory(transaction.parent, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
    state_path = transaction / "transaction.json"
    if not state_path.exists() and not state_path.is_symlink():
        state, prior_payloads, receipt = read_legacy_receipt(root, transaction, manifest, entries)
        if state["phase"] == "rolled_back" or dry_run:
            return result_for_rollback(manifest, state, dry_run=dry_run)
        state = write_transaction_state(root, transaction, state, str(state["phase"]))
        _phase_boundary("legacy_transaction_persisted")
        receipt = write_receipt(root, transaction, state, "installed")
        _phase_boundary("legacy_receipt_migrated")
    else:
        state, prior_payloads, receipt = read_transaction(package, root, transaction, manifest, entries)
        if (
            not dry_run
            and state["phase"] in {"installed", "rollback_restoring"}
            and receipt is not None
            and receipt.get("schema") == LEGACY_RECEIPT_SCHEMA
        ):
            receipt = write_receipt(root, transaction, state, "installed")
            _phase_boundary("legacy_receipt_migrated")
    phase = str(state["phase"])
    if phase in {"install_prepared", "install_publishing"}:
        raise ValueError("install transaction is incomplete; retry install before rollback")
    if phase == "rolled_back":
        classifications = target_classifications(root, state, entries)
        require_classifications(classifications, {"prior"}, "rolled-back transaction")
        validate_rollback_directories(root, state, classifications)
        return result_for_rollback(manifest, state, dry_run=dry_run)

    classifications = target_classifications(root, state, entries)
    if phase == "rollback_restoring" and receipt is not None and receipt.get("state") == "rolled_back":
        if set(classifications.values()) != {"prior"} or any(
            rooted(root, str(logical)).exists() or rooted(root, str(logical)).is_symlink()
            for logical in state["created_directories"]
        ):
            raise ValueError("receipt/state mismatch")
        state = write_transaction_state(root, transaction, state, "rolled_back")
        _phase_boundary("rolled_back")
        return result_for_rollback(manifest, state, dry_run=dry_run)
    if phase == "installed":
        require_classifications(classifications, {"candidate"}, "installed target drift blocks rollback")
        validate_rollback_directories(root, state, classifications)
        if dry_run:
            return result_for_rollback(manifest, state, dry_run=True)
        if receipt is None or receipt.get("state") != "installed":
            raise ValueError("receipt/state mismatch")
        state = write_transaction_state(root, transaction, state, "rollback_prepared")
        _phase_boundary("rollback_prepared")
        phase = "rollback_prepared"
    elif dry_run:
        require_classifications(classifications, {"prior", "candidate"}, "rollback recovery preflight")
        validate_rollback_directories(root, state, classifications)
        return result_for_rollback(manifest, state, dry_run=True)

    if phase == "rollback_prepared":
        classifications = target_classifications(root, state, entries)
        require_classifications(classifications, {"candidate"}, "prepared rollback")
        validate_rollback_directories(root, state, classifications)
        state = write_transaction_state(root, transaction, state, "rollback_restoring")
        _phase_boundary("rollback_restoring")
    elif phase != "rollback_restoring":
        raise ValueError("transaction phase cannot be resumed by rollback")

    classifications = target_classifications(root, state, entries)
    require_classifications(classifications, {"prior", "candidate"}, "resumed rollback")
    validate_rollback_directories(root, state, classifications)
    by_target = {entry.target: entry for entry in entries}
    records = {
        str(record["target"]): record
        for record in state["inventory"]
    }
    for target in reversed(state["changed_targets"]):
        logical = str(target)
        if classifications[logical] == "prior":
            continue
        record = records[logical]
        path = rooted(root, logical)
        prior_payload = prior_payloads[logical]
        if record["existed"]:
            if prior_payload is None:
                raise ValueError("transaction prior payload is missing")
            atomic_write(path, prior_payload, int(record["mode"]), int(record["uid"]), int(record["gid"]))
        else:
            unlink_target(path)
        observed = target_classification(
            root,
            by_target[logical],
            record,
            next(item for item in state["candidate"] if item["target"] == logical),
        )
        if observed != "prior":
            raise ValueError(f"rolled-back target readback mismatch: {logical}")
        classifications[logical] = "prior"
        _phase_boundary("rollback_target_restored", logical)

    validate_rollback_directories(root, state, classifications)
    for logical in reversed(state["created_directories"]):
        path = rooted(root, str(logical))
        if path.exists() or path.is_symlink():
            remove_created_directory(root, str(logical))
            _phase_boundary("rollback_directory_removed", str(logical))
    classifications = target_classifications(root, state, entries)
    require_classifications(classifications, {"prior"}, "rollback completion")
    validate_rollback_directories(root, state, classifications)
    write_receipt(root, transaction, state, "rolled_back")
    _phase_boundary("rolled_back_receipt_written")
    state = write_transaction_state(root, transaction, state, "rolled_back")
    _phase_boundary("rolled_back")
    return result_for_rollback(manifest, state, dry_run=False)


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
