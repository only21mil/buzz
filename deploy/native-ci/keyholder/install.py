#!/usr/bin/env python3
"""Verify or install an acceptance keyholder package without reading credential bytes."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

KEYHOLDER_DIR = Path(__file__).resolve().parent
if str(KEYHOLDER_DIR) not in sys.path:
    sys.path.insert(0, str(KEYHOLDER_DIR))

import freeze_package
import render_keyholder_config

SCHEMA = freeze_package.SCHEMA
MAX_JSON_BYTES = 1024 * 1024
PACKAGE_ID = re.compile(r"^buzz-ci-keyholder-acceptance-[0-9a-f]{12}-[0-9a-f]{12}$")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_TARGETS = {
    "config": "/etc/buzzci/keyholder-v1.json",
    "service": "/etc/systemd/system/buzz-ci-keyholder.service",
    "socket": "/etc/systemd/system/buzz-ci-keyholder.socket",
    "tmpfiles": "/usr/lib/tmpfiles.d/buzzci-keyholder.conf",
    "acceptance_credential_dropin": "/etc/systemd/system/buzz-ci-keyholder.service.d/20-acceptance-actor.conf",
    "documentation": "/usr/share/doc/buzz-ci-keyholder/README.md",
}


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
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def rooted(root: Path, target: str) -> Path:
    if not target.startswith("/") or ".." in Path(target).parts:
        raise ValueError("unsafe target path")
    return root / target.removeprefix("/")


def mapped_id(value: int, root: Path, *, group: bool = False) -> int:
    if value != 0 or root == Path("/"):
        return value
    metadata = root.lstat()
    return metadata.st_gid if group else metadata.st_uid


def read_regular(path: Path, max_bytes: int = 128 * 1024 * 1024) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe regular file: {path}")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"file exceeds byte limit: {path}")
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def parse_json(path: Path) -> tuple[dict[str, object], bytes, os.stat_result]:
    raw, metadata = read_regular(path, MAX_JSON_BYTES)
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value, raw, metadata


def _mode(value: object) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0[4567][0-7]{2}", value):
        raise ValueError("invalid mode")
    return int(value, 8)


def _u32(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 0xFFFF_FFFF:
        raise ValueError("invalid service identity")
    return value


def _require_directory(path: Path, uid: int, gid: int, mode: int) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or metadata.st_gid != gid or stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"unsafe directory metadata: {path}")


def _safe_root(root: Path) -> Path:
    root = Path(os.path.abspath(root))
    if Path(os.path.realpath(root)) != root:
        raise ValueError("install root must not be a symbolic path")
    metadata = root.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or metadata.st_mode & 0o022
    ):
        raise ValueError("install root metadata is unsafe")
    return root


def _validate_directory_chain(root: Path, target: Path) -> None:
    current = root
    for component in target.relative_to(root).parts:
        current /= component
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != mapped_id(0, root)
            or metadata.st_gid != mapped_id(0, root, group=True)
            or metadata.st_mode & 0o022
        ):
            raise ValueError("target directory chain is unsafe")


def parse_package(package: Path, root: Path) -> tuple[dict[str, object], list[Entry]]:
    package = Path(os.path.abspath(package))
    if Path(os.path.realpath(package)) != package:
        raise ValueError("package path must not contain symbolic links")
    package_uid = mapped_id(0, root)
    package_gid = mapped_id(0, root, group=True)
    _require_directory(package, package_uid, package_gid, 0o700)
    _require_directory(package / "assets", package_uid, package_gid, 0o700)
    manifest, _, metadata = parse_json(package / "package-manifest.json")
    if (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (package_uid, package_gid, 0o600):
        raise ValueError("package manifest metadata is unsafe")
    expected_keys = {"schema", "package_id", "source_commit", "package_uid", "package_gid", "identities", "runtime_contract", "credential_contract", "directories", "entries", "package_digest"}
    if set(manifest) != expected_keys or manifest["schema"] != SCHEMA:
        raise ValueError("invalid package manifest fields")
    if not isinstance(manifest["package_id"], str) or not PACKAGE_ID.fullmatch(manifest["package_id"]):
        raise ValueError("invalid package id")
    if not isinstance(manifest["source_commit"], str) or not GIT_OID.fullmatch(manifest["source_commit"]):
        raise ValueError("invalid source commit")
    if manifest["package_uid"] != 0 or manifest["package_gid"] != 0 or manifest["runtime_contract"] != freeze_package.RUNTIME_CONTRACT or manifest["credential_contract"] != freeze_package.CREDENTIAL_CONTRACT:
        raise ValueError("package runtime contract differs")
    identities = manifest["identities"]
    identity_keys = {"keyholder_uid", "keyholder_gid", "controld_uid", "controld_gid"}
    if not isinstance(identities, dict) or set(identities) != identity_keys:
        raise ValueError("invalid package identities")
    for value in identities.values():
        _u32(value)
    directories = manifest["directories"]
    expected_directories = [{"target": target, "mode": "0755", "uid": 0, "gid": 0} for target in freeze_package.DIRECTORIES]
    if directories != expected_directories:
        raise ValueError("invalid package directories")
    claimed_digest = manifest.pop("package_digest")
    if not isinstance(claimed_digest, str) or not DIGEST.fullmatch(claimed_digest) or sha256(canonical_json(manifest)) != claimed_digest:
        raise ValueError("package digest mismatch")
    manifest["package_digest"] = claimed_digest
    raw_entries = manifest["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) != len(EXPECTED_TARGETS):
        raise ValueError("invalid package inventory")
    entries: list[Entry] = []
    for item in raw_entries:
        if not isinstance(item, dict) or set(item) != {"role", "source", "target", "source_mode", "install_mode", "uid", "gid", "sha256"}:
            raise ValueError("invalid package entry")
        role = item["role"]
        if not isinstance(role, str) or EXPECTED_TARGETS.get(role) != item["target"]:
            raise ValueError("unexpected package target")
        source = item["source"]
        if not isinstance(source, str) or not re.fullmatch(r"assets/[A-Za-z0-9._-]+", source):
            raise ValueError("invalid package source")
        source_mode = _mode(item["source_mode"])
        install_mode = _mode(item["install_mode"])
        expected_owner = (identities["keyholder_uid"], identities["keyholder_gid"]) if role == "config" else (0, 0)
        if source_mode != 0o400 or install_mode != (0o600 if role == "config" else 0o644) or (item["uid"], item["gid"]) != expected_owner:
            raise ValueError("package entry metadata differs")
        if not isinstance(item["sha256"], str) or not DIGEST.fullmatch(item["sha256"]):
            raise ValueError("invalid package entry digest")
        payload, source_metadata = read_regular(package / source)
        if (source_metadata.st_uid, source_metadata.st_gid, stat.S_IMODE(source_metadata.st_mode)) != (package_uid, package_gid, source_mode) or sha256(payload) != item["sha256"]:
            raise ValueError("package asset differs")
        entries.append(Entry(role, source, str(item["target"]), source_mode, install_mode, int(item["uid"]), int(item["gid"]), str(item["sha256"])))
    if {entry.role for entry in entries} != set(EXPECTED_TARGETS) or len({entry.source for entry in entries}) != len(entries):
        raise ValueError("package inventory is ambiguous")
    config_entry = next(entry for entry in entries if entry.role == "config")
    config, config_raw, _ = parse_json(package / config_entry.source)
    render_keyholder_config.validate_config(config)
    if canonical_json(config) != config_raw or (config["peer"]["uid"], config["peer"]["gid"]) != (identities["controld_uid"], identities["controld_gid"]):
        raise ValueError("packaged config identity or canonical bytes differ")
    payloads = {entry.role: read_regular(package / entry.source)[0] for entry in entries if entry.role != "config"}
    freeze_package._validate_units(payloads)
    return manifest, entries


def _account_rows(root: Path, target: str, fields: int) -> list[list[str]]:
    path = rooted(root, target)
    payload, metadata = read_regular(path, 1024 * 1024)
    if (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (mapped_id(0, root), mapped_id(0, root, group=True), 0o644):
        raise ValueError("account database metadata is unsafe")
    rows = [line.split(":") for line in payload.decode().splitlines() if line and not line.startswith("#")]
    if any(len(row) != fields for row in rows):
        raise ValueError("account database is malformed")
    return rows


def validate_host(root: Path, manifest: dict[str, object]) -> None:
    root = _safe_root(root)
    identities = manifest["identities"]
    users = _account_rows(root, "/etc/passwd", 7)
    groups = _account_rows(root, "/etc/group", 4)
    keyholder_users = [row for row in users if row[0] == "buzzci-keyholder"]
    controld_users = [row for row in users if row[0] == "buzzci-controld"]
    keyholder_groups = [row for row in groups if row[0] == "buzzci-keyholder"]
    controld_groups = [row for row in groups if row[0] == "buzzci-controld"]
    if not all(len(rows) == 1 for rows in (keyholder_users, controld_users, keyholder_groups, controld_groups)):
        raise ValueError("host keyholder principals are missing or duplicated")
    try:
        actual = (
            int(keyholder_users[0][2]), int(keyholder_users[0][3]), int(keyholder_groups[0][2]),
            int(controld_users[0][2]), int(controld_users[0][3]), int(controld_groups[0][2]),
        )
    except ValueError as error:
        raise ValueError("host keyholder principals are malformed") from error
    expected = (
        identities["keyholder_uid"], identities["keyholder_gid"], identities["keyholder_gid"],
        identities["controld_uid"], identities["controld_gid"], identities["controld_gid"],
    )
    if actual != expected:
        raise ValueError("host keyholder principals differ from package")


def validate_encrypted_credential(root: Path) -> None:
    root = _safe_root(root)
    path = rooted(root, str(freeze_package.CREDENTIAL_CONTRACT["encrypted_source"]))
    try:
        _validate_directory_chain(root, path.parent)
        _require_directory(path.parent, mapped_id(0, root), mapped_id(0, root, group=True), 0o700)
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValueError("acceptance encrypted credential is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or not 1 <= metadata.st_size <= 64 * 1024
    ):
        raise ValueError("acceptance encrypted credential metadata is invalid")


def _ensure_directories(root: Path, manifest: dict[str, object]) -> None:
    root = _safe_root(root)
    for item in manifest["directories"]:
        target = rooted(root, str(item["target"]))
        current = root
        for component in target.relative_to(root).parts:
            current /= component
            if not current.exists():
                current.mkdir(mode=0o755)
                os.chown(current, mapped_id(0, root), mapped_id(0, root, group=True))
            metadata = current.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != mapped_id(0, root)
                or metadata.st_gid != mapped_id(0, root, group=True)
                or metadata.st_mode & 0o022
            ):
                raise ValueError("target directory chain is unsafe")
        target.chmod(0o755)


def _target_matches(root: Path, entry: Entry) -> bool:
    target = rooted(root, entry.target)
    if not target.exists() or target.is_symlink():
        return False
    payload, metadata = read_regular(target)
    return (
        sha256(payload) == entry.sha256
        and stat.S_IMODE(metadata.st_mode) == entry.install_mode
        and metadata.st_uid == mapped_id(entry.uid, root)
        and metadata.st_gid == mapped_id(entry.gid, root, group=True)
    )


def check(package: Path, root: Path) -> dict[str, object]:
    root = _safe_root(root)
    manifest, entries = parse_package(package, package)
    validate_host(root, manifest)
    validate_encrypted_credential(root)
    changed = [entry.target for entry in entries if not _target_matches(root, entry)]
    return {
        "status": "checked",
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "changed_targets": changed,
        "credential_bytes_read": False,
        "enabled": False,
        "active": False,
    }


def _atomic_write(path: Path, payload: bytes, mode: int, uid: int, gid: int) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def install(package: Path, root: Path, *, dry_run: bool = False) -> dict[str, object]:
    root = _safe_root(root)
    manifest, entries = parse_package(package, package)
    validate_host(root, manifest)
    validate_encrypted_credential(root)
    if root == Path("/") and os.geteuid() != 0:
        raise PermissionError("installation requires root")
    changed = [entry for entry in entries if not _target_matches(root, entry)]
    result = {
        "status": "dry_run" if dry_run else ("unchanged" if not changed else "installed"),
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "changed_targets": [entry.target for entry in changed],
        "credential_bytes_read": False,
        "enabled": False,
        "active": False,
    }
    if dry_run or not changed:
        return result
    _ensure_directories(root, manifest)
    for entry in changed:
        payload, _ = read_regular(package / entry.source)
        target = rooted(root, entry.target)
        _atomic_write(target, payload, entry.install_mode, mapped_id(entry.uid, root), mapped_id(entry.gid, root, group=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify-package")
    verify_parser.add_argument("--package", type=Path, required=True)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--package", type=Path, required=True)
    check_parser.add_argument("--root", type=Path, default=Path("/"))
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--package", type=Path, required=True)
    install_parser.add_argument("--root", type=Path, default=Path("/"))
    install_parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    if arguments.command == "verify-package":
        manifest, _ = parse_package(arguments.package, arguments.package)
        result = {"status": "verified", "package_id": manifest["package_id"], "package_digest": manifest["package_digest"]}
    elif arguments.command == "check":
        result = check(arguments.package, arguments.root)
    else:
        result = install(arguments.package, arguments.root, dry_run=arguments.dry_run)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
