#!/usr/bin/env python3
"""Verify, install, or roll back a frozen Buzz CI keyholder package."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

KEYHOLDER_DIR = Path(__file__).resolve().parent
if str(KEYHOLDER_DIR) not in sys.path:
    sys.path.insert(0, str(KEYHOLDER_DIR))

import freeze_package
import render_keyholder_config

SCHEMA = freeze_package.SCHEMA
RECEIPT_SCHEMA = "buzz-ci-keyholder-install-receipt-v1"
ROLLBACK_SCHEMA = "buzz-ci-keyholder-rollback-receipt-v1"
ROLLBACK_STATE_SCHEMA = "buzz-ci-keyholder-rollback-state-v1"
RECEIPT_DIRECTORY = "/var/lib/buzzci/keyholder-package"
MAX_JSON_BYTES = 1024 * 1024
PACKAGE_ID = re.compile(r"^buzz-ci-keyholder-acceptance-[0-9a-f]{12}-[0-9a-f]{12}$")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_TARGETS = {
    "binary": "/usr/libexec/buzz-ci-keyholder",
    "config": "/etc/buzzci/keyholder-v2.json",
    "service": "/etc/systemd/system/buzz-ci-keyholder.service",
    "socket": "/etc/systemd/system/buzz-ci-keyholder.socket",
    "tmpfiles": "/usr/lib/tmpfiles.d/buzzci-keyholder.conf",
    "acceptance_credential_dropin": "/etc/systemd/system/buzz-ci-keyholder.service.d/20-acceptance-actor.conf",
    "documentation": "/usr/share/doc/buzz-ci-keyholder/README.md",
}
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC_RENAMEAT2 = getattr(_LIBC, "renameat2", None)


class ConcurrentMutation(ValueError):
    """A descriptor-relative compare-and-swap found a different live file."""


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
    size: int
    payload: bytes


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


def rooted(root: Path, target: str) -> Path:
    if not target.startswith("/") or ".." in Path(target).parts:
        raise ValueError("unsafe target path")
    return root / target.removeprefix("/")


def mapped_id(value: int, root: Path, *, group: bool = False) -> int:
    if value != 0 or root == Path("/"):
        return value
    metadata = root.lstat()
    return metadata.st_gid if group else metadata.st_uid


def _safe_root(root: Path) -> Path:
    root = Path(os.path.abspath(root))
    metadata = root.lstat()
    if (
        Path(os.path.realpath(root)) != root
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or metadata.st_mode & 0o022
    ):
        raise ValueError("install root metadata is unsafe")
    return root


def _read_descriptor(descriptor: int, limit: int) -> tuple[bytes, os.stat_result]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("unsafe regular file")
    chunks: list[bytes] = []
    size = 0
    while chunk := os.read(descriptor, 1024 * 1024):
        size += len(chunk)
        if size > limit:
            raise ValueError("file exceeds byte limit")
        chunks.append(chunk)
    return b"".join(chunks), metadata


def _read_at(directory_fd: int, name: str, limit: int = 128 * 1024 * 1024) -> tuple[bytes, os.stat_result]:
    if "/" in name or name in {"", ".", ".."}:
        raise ValueError("unsafe descriptor-relative name")
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        return _read_descriptor(descriptor, limit)
    finally:
        os.close(descriptor)


def read_regular(path: Path, max_bytes: int = 128 * 1024 * 1024) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return _read_descriptor(descriptor, max_bytes)
    finally:
        os.close(descriptor)


def _json(raw: bytes) -> dict[str, object]:
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def parse_json(path: Path) -> tuple[dict[str, object], bytes, os.stat_result]:
    raw, metadata = read_regular(path, MAX_JSON_BYTES)
    return _json(raw), raw, metadata


def _mode(value: object) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0[4567][0-7]{2}", value):
        raise ValueError("invalid mode")
    return int(value, 8)


def _u32(value: object, *, nonzero: bool = True) -> int:
    minimum = 1 if nonzero else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 0xFFFF_FFFF:
        raise ValueError("invalid numeric identity")
    return value


def _require_directory(path: Path, uid: int, gid: int, mode: int) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        os.close(descriptor)
        raise ValueError(f"unsafe directory metadata: {path}")
    return descriptor


def parse_package(package: Path, root: Path | None = None) -> tuple[dict[str, object], list[Entry]]:
    package = Path(os.path.abspath(package))
    if Path(os.path.realpath(package)) != package:
        raise ValueError("package path must not contain symbolic links")
    package_metadata = package.lstat()
    package_fd = _require_directory(package, package_metadata.st_uid, package_metadata.st_gid, 0o700)
    assets_fd: int | None = None
    try:
        assets_fd = os.open("assets", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=package_fd)
        assets_metadata = os.fstat(assets_fd)
        if (
            assets_metadata.st_uid != package_metadata.st_uid
            or assets_metadata.st_gid != package_metadata.st_gid
            or stat.S_IMODE(assets_metadata.st_mode) != 0o700
        ):
            raise ValueError("package assets metadata is unsafe")
        manifest_raw, manifest_metadata = _read_at(package_fd, "package-manifest.json", MAX_JSON_BYTES)
        manifest = _json(manifest_raw)
        if (
            manifest_metadata.st_uid != package_metadata.st_uid
            or manifest_metadata.st_gid != package_metadata.st_gid
            or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
            or canonical_json(manifest) != manifest_raw
        ):
            raise ValueError("package manifest metadata or encoding is unsafe")
        expected_keys = {
            "schema", "package_id", "source_commit", "binary_provenance_sha256",
            "public_binding_sha256", "acceptance_public_spec_sha256",
            "package_uid", "package_gid", "identities", "runtime_contract",
            "credential_contract", "directories", "entries", "package_digest",
        }
        if set(manifest) != expected_keys or manifest.get("schema") != SCHEMA:
            raise ValueError("invalid package manifest fields")
        if not isinstance(manifest.get("package_id"), str) or not PACKAGE_ID.fullmatch(str(manifest["package_id"])):
            raise ValueError("invalid package id")
        if not isinstance(manifest.get("source_commit"), str) or not GIT_OID.fullmatch(str(manifest["source_commit"])):
            raise ValueError("invalid source commit")
        if not isinstance(manifest.get("binary_provenance_sha256"), str) or not DIGEST.fullmatch(str(manifest["binary_provenance_sha256"])):
            raise ValueError("invalid provenance digest")
        public_binding_sha256 = manifest.get("public_binding_sha256")
        if public_binding_sha256 is not None and (
            not isinstance(public_binding_sha256, str)
            or not DIGEST.fullmatch(public_binding_sha256)
        ):
            raise ValueError("invalid public binding digest")
        if (
            not isinstance(manifest.get("acceptance_public_spec_sha256"), str)
            or not DIGEST.fullmatch(str(manifest["acceptance_public_spec_sha256"]))
        ):
            raise ValueError("invalid projected public spec digest")
        if (
            manifest.get("package_uid") != 0
            or manifest.get("package_gid") != 0
            or manifest.get("runtime_contract") != freeze_package.RUNTIME_CONTRACT
            or manifest.get("credential_contract") != freeze_package.CREDENTIAL_CONTRACT
        ):
            raise ValueError("package runtime contract differs")
        identities = manifest.get("identities")
        identity_keys = {"keyholder_uid", "keyholder_gid", "controld_uid", "controld_gid"}
        if not isinstance(identities, dict) or set(identities) != identity_keys:
            raise ValueError("invalid package identities")
        for value in identities.values():
            _u32(value)
        expected_directories = [
            {"target": target, "mode": "0755", "uid": 0, "gid": 0}
            for target in freeze_package.DIRECTORIES
        ]
        if manifest.get("directories") != expected_directories:
            raise ValueError("invalid package directories")
        claimed_digest = manifest.pop("package_digest")
        if (
            not isinstance(claimed_digest, str)
            or not DIGEST.fullmatch(claimed_digest)
            or sha256(canonical_json(manifest)) != claimed_digest
        ):
            raise ValueError("package digest mismatch")
        manifest["package_digest"] = claimed_digest

        provenance_raw, provenance_metadata = _read_at(package_fd, "binary-provenance.json", MAX_JSON_BYTES)
        provenance = _json(provenance_raw)
        if (
            provenance_metadata.st_uid != package_metadata.st_uid
            or provenance_metadata.st_gid != package_metadata.st_gid
            or stat.S_IMODE(provenance_metadata.st_mode) != 0o600
            or canonical_json(provenance) != provenance_raw
            or sha256(provenance_raw) != manifest["binary_provenance_sha256"]
            or set(provenance) != {"schema", "binary", "source_commit", "profile", "sha256"}
            or provenance.get("schema") != freeze_package.PROVENANCE_SCHEMA
            or provenance.get("binary") != "buzz-ci-keyholder"
            or provenance.get("profile") != "release"
            or provenance.get("source_commit") != manifest["source_commit"]
            or not isinstance(provenance.get("sha256"), str)
            or not DIGEST.fullmatch(str(provenance["sha256"]))
        ):
            raise ValueError("binary provenance binding differs")

        raw_entries = manifest.get("entries")
        if not isinstance(raw_entries, list) or len(raw_entries) != len(EXPECTED_TARGETS):
            raise ValueError("invalid package inventory")
        entries: list[Entry] = []
        for item in raw_entries:
            if not isinstance(item, dict) or set(item) != {
                "role", "source", "target", "source_mode", "install_mode", "uid", "gid", "sha256", "size",
            }:
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
            expected_source_mode = 0o500 if role == "binary" else 0o400
            expected_install_mode = 0o755 if role == "binary" else (0o600 if role == "config" else 0o644)
            if (
                source_mode != expected_source_mode
                or install_mode != expected_install_mode
                or (item["uid"], item["gid"]) != expected_owner
                or isinstance(item["size"], bool)
                or not isinstance(item["size"], int)
                or not 0 < item["size"] <= 128 * 1024 * 1024
                or not isinstance(item["sha256"], str)
                or not DIGEST.fullmatch(item["sha256"])
            ):
                raise ValueError("package entry metadata differs")
            payload, source_metadata = _read_at(assets_fd, source.removeprefix("assets/"))
            if (
                source_metadata.st_uid != package_metadata.st_uid
                or source_metadata.st_gid != package_metadata.st_gid
                or stat.S_IMODE(source_metadata.st_mode) != source_mode
                or len(payload) != item["size"]
                or sha256(payload) != item["sha256"]
            ):
                raise ValueError("package asset differs")
            entries.append(Entry(role, source, str(item["target"]), source_mode, install_mode, int(item["uid"]), int(item["gid"]), str(item["sha256"]), int(item["size"]), payload))
        if {entry.role for entry in entries} != set(EXPECTED_TARGETS) or len({entry.source for entry in entries}) != len(entries):
            raise ValueError("package inventory is ambiguous")
        binary = next(entry for entry in entries if entry.role == "binary")
        if binary.sha256 != provenance["sha256"]:
            raise ValueError("keyholder binary is not bound to provenance")
        config_entry = next(entry for entry in entries if entry.role == "config")
        config_raw, _ = _read_at(assets_fd, config_entry.source.removeprefix("assets/"), MAX_JSON_BYTES)
        config = _json(config_raw)
        render_keyholder_config.validate_config(config)
        if canonical_json(config) != config_raw or (config["peer"]["uid"], config["peer"]["gid"]) != (identities["controld_uid"], identities["controld_gid"]):
            raise ValueError("packaged config identity or canonical bytes differ")
        projected = dict(config)
        projected["peer"] = dict(config["peer"])
        del projected["peer"]["allowed_operations"]
        render_keyholder_config.validate_spec(projected)
        if sha256(canonical_json(projected)) != manifest["acceptance_public_spec_sha256"]:
            raise ValueError("packaged config projected public spec binding differs")
        try:
            public_binding_raw, public_binding_metadata = _read_at(
                package_fd, "public-binding.json", MAX_JSON_BYTES,
            )
        except FileNotFoundError:
            if public_binding_sha256 is not None:
                raise ValueError("claimed public binding artifact is absent") from None
        else:
            if public_binding_sha256 is None:
                raise ValueError("legacy package contains an unclaimed public binding artifact")
            if (
                public_binding_metadata.st_uid != package_metadata.st_uid
                or public_binding_metadata.st_gid != package_metadata.st_gid
                or stat.S_IMODE(public_binding_metadata.st_mode) != 0o600
                or sha256(public_binding_raw) != public_binding_sha256
            ):
                raise ValueError("public binding artifact metadata or digest differs")
            bound_config, bound_projected = freeze_package.project_public_binding_bytes(
                public_binding_raw,
            )
            if (
                bound_config != config_raw
                or sha256(bound_projected) != manifest["acceptance_public_spec_sha256"]
            ):
                raise ValueError("public binding artifact projection differs")
        payloads = {
            entry.role: _read_at(assets_fd, entry.source.removeprefix("assets/"))[0]
            for entry in entries if entry.role not in {"binary", "config"}
        }
        freeze_package._validate_units(payloads)
        return manifest, entries
    finally:
        if assets_fd is not None:
            os.close(assets_fd)
        os.close(package_fd)


def _account_rows(root: Path, target: str, fields: int) -> list[list[str]]:
    payload, metadata = read_regular(rooted(root, target), MAX_JSON_BYTES)
    if (
        metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        raise ValueError("account database metadata is unsafe")
    rows = [line.split(":") for line in payload.decode().splitlines() if line and not line.startswith("#")]
    if any(len(row) != fields for row in rows):
        raise ValueError("account database is malformed")
    return rows


def validate_host(root: Path, manifest: dict[str, object]) -> None:
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
    target = str(freeze_package.CREDENTIAL_CONTRACT["encrypted_source"])
    parts = Path(target.removeprefix("/")).parts
    root_fd = _open_root(root)
    descriptors: list[int] = []
    current = os.dup(root_fd)
    try:
        try:
            for index, component in enumerate(parts):
                final = index == len(parts) - 1
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                if not final:
                    flags |= os.O_DIRECTORY
                child = os.open(component, flags, dir_fd=current)
                metadata = os.fstat(child)
                if final:
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or metadata.st_uid != mapped_id(0, root)
                        or metadata.st_gid != mapped_id(0, root, group=True)
                        or stat.S_IMODE(metadata.st_mode) != 0o400
                        or not 1 <= metadata.st_size <= 64 * 1024
                    ):
                        os.close(child)
                        raise ValueError("acceptance encrypted credential metadata is invalid")
                elif (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != mapped_id(0, root)
                    or metadata.st_gid != mapped_id(0, root, group=True)
                    or metadata.st_mode & 0o022
                    or (index == len(parts) - 2 and stat.S_IMODE(metadata.st_mode) != 0o700)
                ):
                    os.close(child)
                    raise ValueError("acceptance encrypted credential path is unsafe")
                descriptors.append(child)
                os.close(current)
                current = os.dup(child)
        except FileNotFoundError as error:
            raise ValueError("acceptance encrypted credential is unavailable") from error
        except OSError as error:
            raise ValueError("acceptance encrypted credential path is unsafe") from error

        observed = os.dup(root_fd)
        try:
            for index, (component, expected) in enumerate(zip(parts, descriptors, strict=True)):
                expected_metadata = os.fstat(expected)
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                if index != len(parts) - 1:
                    flags |= os.O_DIRECTORY
                child = os.open(component, flags, dir_fd=observed)
                actual_metadata = os.fstat(child)
                os.close(observed)
                observed = child
                if (actual_metadata.st_dev, actual_metadata.st_ino) != (
                    expected_metadata.st_dev,
                    expected_metadata.st_ino,
                ):
                    raise ValueError("acceptance encrypted credential path changed during validation")
        except OSError as error:
            raise ValueError("acceptance encrypted credential path changed during validation") from error
        finally:
            os.close(observed)
    finally:
        os.close(current)
        for descriptor in descriptors:
            os.close(descriptor)
        os.close(root_fd)


def _open_root(root: Path) -> int:
    return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)


def _open_chain(root_fd: int, target: str, root: Path, *, create: bool, created: list[str] | None = None, final_mode: int | None = 0o755) -> int:
    parts = Path(target.removeprefix("/")).parts
    descriptor = os.dup(root_fd)
    current = ""
    try:
        for index, component in enumerate(parts):
            current += f"/{component}"
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                mode = final_mode if index == len(parts) - 1 and final_mode is not None else 0o755
                made = False
                try:
                    os.mkdir(component, mode, dir_fd=descriptor)
                    made = True
                except FileExistsError:
                    pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                if made:
                    os.fchown(child, mapped_id(0, root), mapped_id(0, root, group=True))
                    os.fchmod(child, mode)
                    os.fsync(child)
                    os.fsync(descriptor)
                    if created is not None:
                        created.append(current)
            metadata = os.fstat(child)
            wanted_mode = final_mode if index == len(parts) - 1 else None
            if (
                metadata.st_uid != mapped_id(0, root)
                or metadata.st_gid != mapped_id(0, root, group=True)
                or metadata.st_mode & 0o022
                or (wanted_mode is not None and stat.S_IMODE(metadata.st_mode) != wanted_mode)
            ):
                os.close(child)
                raise ValueError(f"unsafe directory metadata: {current}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_parent(root_fd: int, target: str, root: Path, *, create: bool = False, created: list[str] | None = None) -> tuple[int, str]:
    path = Path(target)
    return _open_chain(root_fd, str(path.parent), root, create=create, created=created, final_mode=None), path.name


def _state(root_fd: int, root: Path, entry: Entry) -> dict[str, object] | None:
    parent_fd, name = _open_parent(root_fd, entry.target, root)
    try:
        try:
            payload, metadata = _read_at(parent_fd, name)
        except FileNotFoundError:
            return None
        return {
            "sha256": sha256(payload), "size": len(payload),
            "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid, "gid": metadata.st_gid,
        }
    finally:
        os.close(parent_fd)


def _desired(root: Path, entry: Entry) -> dict[str, object]:
    return {
        "sha256": entry.sha256, "size": entry.size, "mode": entry.install_mode,
        "uid": mapped_id(entry.uid, root), "gid": mapped_id(entry.gid, root, group=True),
    }


@dataclass(frozen=True)
class _PriorTarget:
    payload: bytes
    mode: int
    uid: int
    gid: int
    dev: int | None = None
    ino: int | None = None

    def state(self) -> dict[str, object]:
        return {
            "sha256": sha256(self.payload),
            "size": len(self.payload),
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
        }


@dataclass
class _TargetPlan:
    entry: Entry
    directory_fd: int
    components: tuple[str, ...]
    name: str
    current: _PriorTarget | None


@dataclass(frozen=True)
class _Mutation:
    plan: _TargetPlan
    before: _PriorTarget | None
    after: _PriorTarget | None


def _prior_target_at(directory_fd: int, name: str) -> _PriorTarget | None:
    try:
        payload, metadata = _read_at(directory_fd, name)
    except FileNotFoundError:
        return None
    return _PriorTarget(
        payload,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_dev,
        metadata.st_ino,
    )


def _same_snapshot(actual: _PriorTarget | None, expected: _PriorTarget | None) -> bool:
    if actual is None or expected is None:
        return actual is expected
    return (
        actual.state() == expected.state()
        and expected.dev is not None
        and expected.ino is not None
        and (actual.dev, actual.ino) == (expected.dev, expected.ino)
    )


def _renameat2(old_directory_fd: int, old_name: str, new_directory_fd: int, new_name: str, flags: int) -> None:
    if _LIBC_RENAMEAT2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for race-safe keyholder publication")
    while True:
        result = _LIBC_RENAMEAT2(
            old_directory_fd,
            os.fsencode(old_name),
            new_directory_fd,
            os.fsencode(new_name),
            flags,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number != errno.EINTR:
            raise OSError(error_number, os.strerror(error_number), old_name, new_name)


def _lock_directory(directory_fd: int) -> None:
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise ValueError("keyholder installation is already locked") from error


def _lock_target_directories(plans: list[_TargetPlan]) -> None:
    locked: set[tuple[int, int]] = set()
    for plan in sorted(plans, key=lambda value: value.entry.target):
        metadata = os.fstat(plan.directory_fd)
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in locked:
            continue
        _lock_directory(plan.directory_fd)
        locked.add(identity)


def _directory_binding_matches(root_fd: int, components: tuple[str, ...], expected_fd: int) -> bool:
    current = os.dup(root_fd)
    try:
        for component in components:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = child
        actual = os.fstat(current)
        expected = os.fstat(expected_fd)
        return (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)
    except OSError:
        return False
    finally:
        os.close(current)


def _stage_file(parent_fd: int, name: str, payload: bytes, mode: int, uid: int, gid: int) -> tuple[str, int, _PriorTarget]:
    temporary = f".{name}.{uuid.uuid4().hex}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode, dir_fd=parent_fd)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise OSError("short write while publishing keyholder package")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if metadata.st_uid != uid or metadata.st_gid != gid or stat.S_IMODE(metadata.st_mode) != mode or metadata.st_size != len(payload):
            raise OSError("temporary target metadata differs")
        return temporary, descriptor, _PriorTarget(payload, mode, uid, gid, metadata.st_dev, metadata.st_ino)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise


def _unlink_task_temporaries(parent_fd: int, *names: str) -> None:
    for temporary in names:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
    os.fsync(parent_fd)


def _restore_displaced_without_overwriting_latest(parent_fd: int, name: str, temporary: str) -> None:
    try:
        _renameat2(parent_fd, temporary, parent_fd, name, RENAME_NOREPLACE)
    except FileExistsError:
        _unlink_task_temporaries(parent_fd, temporary)
    except FileNotFoundError:
        os.fsync(parent_fd)
    else:
        os.fsync(parent_fd)


def _recover_failed_exchange(
    parent_fd: int,
    name: str,
    temporary: str,
    staged: _PriorTarget,
) -> None:
    probe = f".{name}.{uuid.uuid4().hex}"
    probe_present = False
    try:
        try:
            _renameat2(parent_fd, name, parent_fd, probe, RENAME_NOREPLACE)
        except FileNotFoundError:
            _unlink_task_temporaries(parent_fd, temporary)
            return
        probe_present = True
        os.fsync(parent_fd)
        try:
            probe_snapshot = _prior_target_at(parent_fd, probe)
        except BaseException:
            probe_snapshot = None
        probe_is_staged = _same_snapshot(probe_snapshot, staged)
        source = temporary if probe_is_staged else probe
        try:
            _renameat2(parent_fd, source, parent_fd, name, RENAME_NOREPLACE)
        except (FileExistsError, FileNotFoundError):
            pass
        else:
            if source == probe:
                probe_present = False
    finally:
        cleanup = (temporary, probe) if probe_present else (temporary,)
        _unlink_task_temporaries(parent_fd, *cleanup)


def _cas_publish(
    parent_fd: int,
    name: str,
    expected: _PriorTarget | None,
    replacement: _PriorTarget | None,
) -> _PriorTarget | None:
    if replacement is None:
        if expected is None:
            return None
        temporary = f".{name}.{uuid.uuid4().hex}"
        _renameat2(parent_fd, name, parent_fd, temporary, RENAME_NOREPLACE)
        os.fsync(parent_fd)
        try:
            displaced = _prior_target_at(parent_fd, temporary)
        except BaseException:
            _restore_displaced_without_overwriting_latest(parent_fd, name, temporary)
            raise ConcurrentMutation(f"target changed before compare-and-swap: {name}")
        if not _same_snapshot(displaced, expected):
            if displaced is not None:
                _restore_displaced_without_overwriting_latest(parent_fd, name, temporary)
            raise ConcurrentMutation(f"target changed before compare-and-swap: {name}")
        os.unlink(temporary, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return None

    temporary, descriptor, staged = _stage_file(
        parent_fd,
        name,
        replacement.payload,
        replacement.mode,
        replacement.uid,
        replacement.gid,
    )
    temporary_present = True
    temporary_owned = True
    try:
        if expected is None:
            try:
                _renameat2(parent_fd, temporary, parent_fd, name, RENAME_NOREPLACE)
            except FileExistsError as error:
                raise ConcurrentMutation(f"target appeared before compare-and-swap: {name}") from error
            temporary_present = False
        else:
            _renameat2(parent_fd, temporary, parent_fd, name, RENAME_EXCHANGE)
            temporary_owned = False
            try:
                displaced = _prior_target_at(parent_fd, temporary)
            except BaseException:
                _recover_failed_exchange(parent_fd, name, temporary, staged)
                temporary_present = False
                raise ConcurrentMutation(f"target changed before compare-and-swap: {name}")
            if not _same_snapshot(displaced, expected):
                _recover_failed_exchange(parent_fd, name, temporary, staged)
                temporary_present = False
                raise ConcurrentMutation(f"target changed before compare-and-swap: {name}")
        os.fsync(parent_fd)
        try:
            installed = _prior_target_at(parent_fd, name)
        except BaseException:
            if expected is not None:
                _recover_failed_exchange(parent_fd, name, temporary, staged)
                temporary_present = False
            raise
        if not _same_snapshot(installed, staged):
            if expected is None:
                current = _prior_target_at(parent_fd, name)
                if _same_snapshot(current, staged):
                    _renameat2(parent_fd, name, parent_fd, temporary, RENAME_NOREPLACE)
                    temporary_present = True
                    os.fsync(parent_fd)
            else:
                _recover_failed_exchange(parent_fd, name, temporary, staged)
                temporary_present = False
            raise OSError("atomic compare-and-swap readback differs")
        if expected is not None:
            os.unlink(temporary, dir_fd=parent_fd)
            temporary_present = False
            os.fsync(parent_fd)
        return installed
    finally:
        os.close(descriptor)
        if temporary_present and temporary_owned:
            current_temporary = _prior_target_at(parent_fd, temporary)
            if _same_snapshot(current_temporary, staged):
                os.unlink(temporary, dir_fd=parent_fd)
                os.fsync(parent_fd)


def _write_once(directory_fd: int, name: str, payload: bytes, mode: int, uid: int, gid: int) -> _PriorTarget:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)
    written = _prior_target_at(directory_fd, name)
    if written is None or written.payload != payload or written.state() != {
        "sha256": sha256(payload),
        "size": len(payload),
        "mode": mode,
        "uid": uid,
        "gid": gid,
    }:
        raise OSError(f"create-once readback differs: {name}")
    return written


def _receipt_directory(root_fd: int, root: Path, *, create: bool, created: list[str] | None = None) -> int:
    modes = (("/var", 0o755), ("/var/lib", 0o755), ("/var/lib/buzzci", 0o711), (RECEIPT_DIRECTORY, 0o700))
    descriptor = -1
    for target, mode in modes:
        if descriptor >= 0:
            os.close(descriptor)
        descriptor = _open_chain(root_fd, target, root, create=create, created=created, final_mode=mode)
    return descriptor


def _read_receipt(directory_fd: int, name: str, *, absent_ok: bool) -> tuple[dict[str, object], bytes] | None:
    try:
        raw, metadata = _read_at(directory_fd, name, MAX_JSON_BYTES)
    except FileNotFoundError:
        if absent_ok:
            return None
        raise ValueError(f"{name} is absent")
    value = _json(raw)
    directory_metadata = os.fstat(directory_fd)
    if (
        canonical_json(value) != raw
        or metadata.st_uid != directory_metadata.st_uid
        or metadata.st_gid != directory_metadata.st_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError(f"{name} metadata or encoding differs")
    return value, raw


def _validate_install_receipt(receipt: dict[str, object], manifest: dict[str, object], entries: list[Entry]) -> None:
    if (
        set(receipt) != {"schema", "package_id", "package_digest", "source_commit", "binary_provenance_sha256", "managed", "changes", "created_directories"}
        or receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("package_id") != manifest["package_id"]
        or receipt.get("package_digest") != manifest["package_digest"]
        or receipt.get("source_commit") != manifest["source_commit"]
        or receipt.get("binary_provenance_sha256") != manifest["binary_provenance_sha256"]
    ):
        raise ValueError("keyholder install receipt package binding differs")
    expected_managed = [
        {"target": entry.target, "sha256": entry.sha256, "size": entry.size, "mode": entry.install_mode, "uid": entry.uid, "gid": entry.gid}
        for entry in entries
    ]
    if receipt.get("managed") != expected_managed:
        raise ValueError("keyholder install receipt inventory differs")
    changes = receipt.get("changes")
    created = receipt.get("created_directories")
    if not isinstance(changes, list) or not isinstance(created, list) or len(set(created)) != len(created):
        raise ValueError("keyholder install receipt plan differs")
    by_target = {entry.target: entry for entry in entries}
    for index, record in enumerate(changes):
        if not isinstance(record, dict) or record.get("target") not in by_target or not isinstance(record.get("existed"), bool):
            raise ValueError("keyholder install receipt change differs")
        keys = {"target", "existed"}
        if record["existed"]:
            keys |= {"sha256", "size", "mode", "uid", "gid", "backup"}
            if record.get("backup") != f"prior-{index}" or not isinstance(record.get("sha256"), str) or not DIGEST.fullmatch(str(record["sha256"])):
                raise ValueError("keyholder install receipt prior binding differs")
            for field in ("size", "mode", "uid", "gid"):
                if isinstance(record.get(field), bool) or not isinstance(record.get(field), int) or int(record[field]) < 0:
                    raise ValueError("keyholder install receipt prior metadata differs")
        if set(record) != keys:
            raise ValueError("keyholder install receipt change fields differ")


def _prepare_receipt(
    root: Path,
    directory_fd: int,
    manifest: dict[str, object],
    plans: list[_TargetPlan],
    created: list[str],
) -> tuple[dict[str, object], dict[str, _PriorTarget]]:
    changes: list[dict[str, object]] = []
    written: dict[str, _PriorTarget] = {}
    for plan in plans:
        entry = plan.entry
        state = None if plan.current is None else plan.current.state()
        if state == _desired(root, entry):
            continue
        record: dict[str, object] = {"target": entry.target, "existed": state is not None}
        if state is not None:
            record.update(state)
            record["backup"] = f"prior-{len(changes)}"
        changes.append(record)
    receipt = {
        "schema": RECEIPT_SCHEMA, "package_id": manifest["package_id"], "package_digest": manifest["package_digest"],
        "source_commit": manifest["source_commit"], "binary_provenance_sha256": manifest["binary_provenance_sha256"],
        "managed": [{"target": plan.entry.target, "sha256": plan.entry.sha256, "size": plan.entry.size, "mode": plan.entry.install_mode, "uid": plan.entry.uid, "gid": plan.entry.gid} for plan in plans],
        "changes": changes, "created_directories": created,
    }
    by_target = {plan.entry.target: plan for plan in plans}
    try:
        for record in changes:
            if not record["existed"]:
                continue
            name = str(record["backup"])
            prior = by_target[str(record["target"])].current
            assert prior is not None
            written[name] = _write_once(directory_fd, name, prior.payload, 0o600, mapped_id(0, root), mapped_id(0, root, group=True))
        written["receipt-v1.json"] = _write_once(
            directory_fd,
            "receipt-v1.json",
            canonical_json(receipt),
            0o600,
            mapped_id(0, root),
            mapped_id(0, root, group=True),
        )
        pair = _read_receipt(directory_fd, "receipt-v1.json", absent_ok=False)
        assert pair is not None
        if pair[0] != receipt:
            raise ValueError("keyholder install receipt readback differs")
        return receipt, written
    except BaseException:
        for name, expected in reversed(tuple(written.items())):
            try:
                _cas_publish(directory_fd, name, expected, None)
            except (FileNotFoundError, ConcurrentMutation):
                pass
        os.fsync(directory_fd)
        raise


def _prior_state(record: dict[str, object]) -> dict[str, object] | None:
    if not record["existed"]:
        return None
    return {field: record[field] for field in ("sha256", "size", "mode", "uid", "gid")}


def _open_target_plans(root_fd: int, root: Path, entries: list[Entry]) -> list[_TargetPlan]:
    plans: list[_TargetPlan] = []
    try:
        for entry in entries:
            directory_fd, name = _open_parent(root_fd, entry.target, root)
            components = Path(entry.target).parent.parts[1:]
            plan = _TargetPlan(
                entry,
                directory_fd,
                components,
                name,
                _prior_target_at(directory_fd, name),
            )
            if not _directory_binding_matches(root_fd, components, directory_fd):
                os.close(directory_fd)
                raise ValueError(f"target directory changed during planning: {entry.target}")
            plans.append(plan)
        return plans
    except BaseException:
        for plan in plans:
            os.close(plan.directory_fd)
        raise


def _receipt_priors(
    root: Path,
    directory_fd: int,
    receipt: dict[str, object],
) -> tuple[dict[str, _PriorTarget | None], dict[str, _PriorTarget]]:
    priors: dict[str, _PriorTarget | None] = {}
    artifacts: dict[str, _PriorTarget] = {}
    receipt_snapshot = _prior_target_at(directory_fd, "receipt-v1.json")
    if receipt_snapshot is None or receipt_snapshot.payload != canonical_json(receipt):
        raise ValueError("keyholder install receipt changed during validation")
    artifacts["receipt-v1.json"] = receipt_snapshot
    for record in receipt["changes"]:
        target = str(record["target"])
        if not record["existed"]:
            priors[target] = None
            continue
        payload, metadata = _read_at(directory_fd, str(record["backup"]))
        if (
            metadata.st_uid != mapped_id(0, root)
            or metadata.st_gid != mapped_id(0, root, group=True)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or len(payload) != record["size"]
            or sha256(payload) != record["sha256"]
        ):
            raise ValueError("keyholder install receipt backup differs")
        backup_snapshot = _prior_target_at(directory_fd, str(record["backup"]))
        if backup_snapshot is None or backup_snapshot.payload != payload:
            raise ValueError("keyholder install receipt backup changed during validation")
        artifacts[str(record["backup"])] = backup_snapshot
        priors[target] = _PriorTarget(
            payload,
            int(record["mode"]),
            int(record["uid"]),
            int(record["gid"]),
        )
    return priors, artifacts


def _validate_receipt_artifacts(directory_fd: int, artifacts: dict[str, _PriorTarget]) -> None:
    for name, expected in artifacts.items():
        if not _same_snapshot(_prior_target_at(directory_fd, name), expected):
            raise ValueError(f"keyholder receipt artifact changed during publication: {name}")


def _rollback_targets(receipt: dict[str, object]) -> list[str]:
    return [str(record["target"]) for record in reversed(receipt["changes"])]


def _rollback_directories(receipt: dict[str, object]) -> list[str]:
    return sorted(
        (str(directory) for directory in receipt["created_directories"]),
        key=lambda value: (len(Path(value).parts), value),
        reverse=True,
    )


def _validate_rollback_marker(
    marker: dict[str, object],
    manifest: dict[str, object],
    receipt_raw: bytes,
    receipt: dict[str, object],
) -> None:
    if marker != {
        "schema": ROLLBACK_SCHEMA,
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "install_receipt_sha256": sha256(receipt_raw),
        "restored_targets": _rollback_targets(receipt),
    }:
        raise ValueError("keyholder rollback receipt differs")


def _rollback_state_value(
    manifest: dict[str, object],
    receipt_raw: bytes,
    restored_targets: list[str],
    removed_directories: list[str],
) -> dict[str, object]:
    return {
        "schema": ROLLBACK_STATE_SCHEMA,
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "install_receipt_sha256": sha256(receipt_raw),
        "restored_targets": restored_targets,
        "removed_directories": removed_directories,
    }


def _validate_rollback_state(
    state: dict[str, object],
    manifest: dict[str, object],
    receipt_raw: bytes,
    receipt: dict[str, object],
) -> None:
    restored = state.get("restored_targets")
    removed = state.get("removed_directories")
    expected_targets = _rollback_targets(receipt)
    expected_directories = _rollback_directories(receipt)
    if (
        not isinstance(restored, list)
        or not isinstance(removed, list)
        or restored != expected_targets[:len(restored)]
        or removed != expected_directories[:len(removed)]
        or state != _rollback_state_value(manifest, receipt_raw, restored, removed)
    ):
        raise ValueError("keyholder rollback state differs")


def _publish_rollback_state(
    directory_fd: int,
    root: Path,
    previous: _PriorTarget | None,
    value: dict[str, object],
) -> _PriorTarget:
    raw = canonical_json(value)
    if previous is None:
        return _write_once(
            directory_fd,
            "rollback-state-v1.json",
            raw,
            0o600,
            mapped_id(0, root),
            mapped_id(0, root, group=True),
        )
    published = _cas_publish(
        directory_fd,
        "rollback-state-v1.json",
        previous,
        _PriorTarget(raw, 0o600, mapped_id(0, root), mapped_id(0, root, group=True)),
    )
    assert published is not None
    return published


def _validate_terminal_rollback(
    root_fd: int,
    root: Path,
    receipt: dict[str, object],
    entries: list[Entry],
) -> None:
    records = {str(record["target"]): record for record in receipt["changes"]}
    for entry in entries:
        try:
            current = _state(root_fd, root, entry)
        except FileNotFoundError:
            current = None
        record = records.get(entry.target)
        expected = _desired(root, entry) if record is None else _prior_state(record)
        if current != expected:
            raise ValueError(f"terminal rollback target drift: {entry.target}")
    for directory in receipt["created_directories"]:
        try:
            descriptor = _open_chain(root_fd, str(directory), root, create=False)
        except FileNotFoundError:
            continue
        os.close(descriptor)
        raise ValueError(f"terminal rollback directory remains: {directory}")


def _restore_targets(mutations: list[_Mutation]) -> None:
    errors: list[BaseException] = []
    for mutation in reversed(mutations):
        plan = mutation.plan
        try:
            _cas_publish(plan.directory_fd, plan.name, mutation.after, mutation.before)
        except ConcurrentMutation:
            # A later writer has already displaced our candidate. Preserve it.
            continue
        except BaseException as error:
            errors.append(error)
    if errors:
        raise RuntimeError("; ".join(str(error) for error in errors))


def _remove_receipt_artifacts(directory_fd: int, artifacts: dict[str, _PriorTarget]) -> None:
    for name, expected in reversed(tuple(artifacts.items())):
        try:
            _cas_publish(directory_fd, name, expected, None)
        except ConcurrentMutation:
            pass
    os.fsync(directory_fd)
    for name, expected in artifacts.items():
        if _same_snapshot(_prior_target_at(directory_fd, name), expected):
            raise ValueError(f"keyholder receipt artifact remains after rollback: {name}")


def _remove_created_directories(root_fd: int, root: Path, created: list[str]) -> None:
    targets = sorted(set(created), key=lambda target: len(Path(target).parts), reverse=True)
    for target in targets:
        parent_fd, name = _open_parent(root_fd, target, root)
        try:
            os.rmdir(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


def _result(status: str, manifest: dict[str, object], changed: list[str]) -> dict[str, object]:
    return {
        "status": status, "package_id": manifest["package_id"], "package_digest": manifest["package_digest"],
        "source_commit": manifest["source_commit"], "changed_targets": changed, "credential_bytes_read": False,
        "enabled": False, "active": False, "exec_start": EXPECTED_TARGETS["binary"],
    }


def check(package: Path, root: Path) -> dict[str, object]:
    root = _safe_root(root)
    manifest, entries = parse_package(package, root)
    validate_host(root, manifest)
    validate_encrypted_credential(root)
    root_fd = _open_root(root)
    try:
        changed: list[str] = []
        for entry in entries:
            try:
                current = _state(root_fd, root, entry)
            except FileNotFoundError:
                current = None
            if current != _desired(root, entry):
                changed.append(entry.target)
        try:
            receipt_fd = _receipt_directory(root_fd, root, create=False)
        except FileNotFoundError:
            receipt = None
        else:
            try:
                receipt = _read_receipt(receipt_fd, "receipt-v1.json", absent_ok=True)
                if receipt is not None:
                    _validate_install_receipt(receipt[0], manifest, entries)
            finally:
                os.close(receipt_fd)
        result = _result("checked", manifest, changed)
        result["install_receipt"] = "verified" if receipt is not None else "absent"
        return result
    finally:
        os.close(root_fd)


def install(package: Path, root: Path, *, dry_run: bool = False) -> dict[str, object]:
    previous_umask = os.umask(0o077)
    try:
        root = _safe_root(root)
        package = Path(os.path.abspath(package))
        manifest, entries = parse_package(package, root)
        validate_host(root, manifest)
        validate_encrypted_credential(root)
        if root == Path("/") and os.geteuid() != 0:
            raise PermissionError("installation requires root")
        root_fd = _open_root(root)
        created: list[str] = []
        receipt_created: list[str] = []
        plans: list[_TargetPlan] = []
        receipt_fd = -1
        receipt: dict[str, object] | None = None
        priors: dict[str, _PriorTarget | None] = {}
        receipt_artifacts: dict[str, _PriorTarget] = {}
        mutations: list[_Mutation] = []
        new_receipt = False
        transaction_ready = False
        try:
            if dry_run:
                changed = []
                for entry in entries:
                    try:
                        current = _state(root_fd, root, entry)
                    except FileNotFoundError:
                        current = None
                    if current != _desired(root, entry):
                        changed.append(entry.target)
                return _result("dry_run", manifest, changed)
            for directory in manifest["directories"]:
                descriptor = _open_chain(root_fd, str(directory["target"]), root, create=True, created=created)
                os.close(descriptor)
            receipt_fd = _receipt_directory(root_fd, root, create=True, created=receipt_created)
            _lock_directory(receipt_fd)
            receipt_components = Path(RECEIPT_DIRECTORY).parts[1:]
            if not _directory_binding_matches(root_fd, receipt_components, receipt_fd):
                raise ValueError("keyholder receipt directory changed before locking")
            plans = _open_target_plans(root_fd, root, entries)
            _lock_target_directories(plans)
            if _read_receipt(receipt_fd, "rollback-v1.json", absent_ok=True) is not None:
                raise ValueError("keyholder package was already rolled back")
            if _read_receipt(receipt_fd, "rollback-state-v1.json", absent_ok=True) is not None:
                raise ValueError("keyholder package rollback is in progress")
            receipt_pair = _read_receipt(receipt_fd, "receipt-v1.json", absent_ok=True)
            if receipt_pair is None:
                new_receipt = True
                receipt, receipt_artifacts = _prepare_receipt(root, receipt_fd, manifest, plans, created)
            else:
                receipt = receipt_pair[0]
            _validate_install_receipt(receipt, manifest, entries)
            priors, observed_artifacts = _receipt_priors(root, receipt_fd, receipt)
            if receipt_artifacts and any(
                not _same_snapshot(observed_artifacts.get(name), expected)
                for name, expected in receipt_artifacts.items()
            ):
                raise ValueError("new keyholder receipt changed before publication")
            receipt_artifacts = observed_artifacts
            changes = {str(record["target"]): record for record in receipt["changes"]}
            for plan in plans:
                baseline = plan.current
                observed = _prior_target_at(plan.directory_fd, plan.name)
                if new_receipt and not _same_snapshot(observed, baseline):
                    raise ConcurrentMutation(f"target changed after receipt snapshot: {plan.entry.target}")
                plan.current = observed
                current = None if observed is None else observed.state()
                desired = _desired(root, plan.entry)
                record = changes.get(plan.entry.target)
                if current != desired and (record is None or current != _prior_state(record)):
                    raise ValueError(f"installed target drift blocks replay: {plan.entry.target}")
                if not _directory_binding_matches(root_fd, plan.components, plan.directory_fd):
                    raise ValueError(f"target directory changed during installation: {plan.entry.target}")
            _validate_receipt_artifacts(receipt_fd, receipt_artifacts)
            transaction_ready = True
            changed: list[str] = []
            for plan in plans:
                desired = _desired(root, plan.entry)
                if plan.current is not None and plan.current.state() == desired:
                    continue
                _validate_receipt_artifacts(receipt_fd, receipt_artifacts)
                replacement = _PriorTarget(
                    plan.entry.payload,
                    plan.entry.install_mode,
                    mapped_id(plan.entry.uid, root),
                    mapped_id(plan.entry.gid, root, group=True),
                )
                installed = _cas_publish(
                    plan.directory_fd,
                    plan.name,
                    plan.current,
                    replacement,
                )
                mutation = _Mutation(plan, plan.current, installed)
                mutations.append(mutation)
                plan.current = installed
                current = _prior_target_at(plan.directory_fd, plan.name)
                if not _same_snapshot(current, installed) or current is None or current.state() != desired:
                    raise ValueError(f"installed target readback differs: {plan.entry.target}")
                if not _directory_binding_matches(root_fd, plan.components, plan.directory_fd):
                    raise ValueError(f"target directory changed during installation: {plan.entry.target}")
                if not _directory_binding_matches(root_fd, receipt_components, receipt_fd):
                    raise ValueError("keyholder receipt directory changed during installation")
                _validate_receipt_artifacts(receipt_fd, receipt_artifacts)
                changed.append(plan.entry.target)
            pair = _read_receipt(receipt_fd, "receipt-v1.json", absent_ok=False)
            assert pair is not None
            if pair[0] != receipt:
                raise ValueError("keyholder install receipt readback differs")
            for plan in plans:
                current = _prior_target_at(plan.directory_fd, plan.name)
                if current is None or current.state() != _desired(root, plan.entry):
                    raise ValueError("keyholder package exact readback differs")
                if not _directory_binding_matches(root_fd, plan.components, plan.directory_fd):
                    raise ValueError("keyholder publication directory changed during installation")
            if not _directory_binding_matches(root_fd, receipt_components, receipt_fd):
                raise ValueError("keyholder receipt directory changed during installation")
            validate_encrypted_credential(root)
            return _result("installed" if changed or new_receipt else "unchanged", manifest, changed)
        except BaseException as error:
            rollback_errors: list[BaseException] = []
            if transaction_ready:
                try:
                    _restore_targets(mutations)
                except BaseException as rollback_error:
                    rollback_errors.append(rollback_error)
            if new_receipt and receipt_artifacts and receipt_fd >= 0:
                try:
                    _remove_receipt_artifacts(receipt_fd, receipt_artifacts)
                except BaseException as rollback_error:
                    rollback_errors.append(rollback_error)
            if created or receipt_created:
                try:
                    _remove_created_directories(root_fd, root, created + receipt_created)
                except BaseException as rollback_error:
                    rollback_errors.append(rollback_error)
            if rollback_errors:
                detail = "; ".join(str(rollback_error) for rollback_error in rollback_errors)
                raise RuntimeError(f"keyholder installation rollback failed: {detail}") from error
            raise
        finally:
            if receipt_fd >= 0:
                os.close(receipt_fd)
            for plan in plans:
                os.close(plan.directory_fd)
            os.close(root_fd)
    finally:
        os.umask(previous_umask)


def rollback(package: Path, root: Path, *, dry_run: bool = False) -> dict[str, object]:
    previous_umask = os.umask(0o077)
    try:
        root = _safe_root(root)
        manifest, entries = parse_package(package, root)
        if root == Path("/") and os.geteuid() != 0:
            raise PermissionError("rollback requires root")
        root_fd = _open_root(root)
        receipt_fd = -1
        plans: list[_TargetPlan] = []
        try:
            receipt_fd = _receipt_directory(root_fd, root, create=False)
            _lock_directory(receipt_fd)
            receipt_components = Path(RECEIPT_DIRECTORY).parts[1:]
            if not _directory_binding_matches(root_fd, receipt_components, receipt_fd):
                raise ValueError("keyholder receipt directory changed before rollback locking")
            receipt_pair = _read_receipt(receipt_fd, "receipt-v1.json", absent_ok=False)
            assert receipt_pair is not None
            receipt, receipt_raw = receipt_pair
            _validate_install_receipt(receipt, manifest, entries)
            priors, receipt_artifacts = _receipt_priors(root, receipt_fd, receipt)
            marker_pair = _read_receipt(receipt_fd, "rollback-v1.json", absent_ok=True)
            if marker_pair is not None:
                _validate_rollback_marker(marker_pair[0], manifest, receipt_raw, receipt)
                _validate_terminal_rollback(root_fd, root, receipt, entries)
                status = "rollback_dry_run" if dry_run else "unchanged"
                return _result(status, manifest, _rollback_targets(receipt))
            state_pair = _read_receipt(receipt_fd, "rollback-state-v1.json", absent_ok=True)
            state_snapshot: _PriorTarget | None = None
            if state_pair is None:
                state = _rollback_state_value(manifest, receipt_raw, [], [])
            else:
                state = state_pair[0]
                _validate_rollback_state(state, manifest, receipt_raw, receipt)
                state_snapshot = _prior_target_at(receipt_fd, "rollback-state-v1.json")
                if state_snapshot is None or state_snapshot.payload != state_pair[1]:
                    raise ValueError("keyholder rollback state changed during validation")
                receipt_artifacts["rollback-state-v1.json"] = state_snapshot

            created_directories = set(str(value) for value in receipt["created_directories"])
            removed_directories = set(str(value) for value in state["removed_directories"])
            checkpointed_targets = set(str(value) for value in state["restored_targets"])
            for entry in entries:
                try:
                    directory_fd, name = _open_parent(root_fd, entry.target, root)
                except FileNotFoundError:
                    parent = str(Path(entry.target).parent)
                    under_created = any(
                        parent == directory or parent.startswith(f"{directory}/")
                        for directory in created_directories
                    )
                    if entry.target not in checkpointed_targets or not under_created:
                        raise ValueError(f"rollback target parent is unexpectedly absent: {entry.target}")
                    continue
                components = Path(entry.target).parent.parts[1:]
                plans.append(_TargetPlan(entry, directory_fd, components, name, _prior_target_at(directory_fd, name)))
            _lock_target_directories(plans)
            by_target = {plan.entry.target: plan for plan in plans}
            records = {str(record["target"]): record for record in receipt["changes"]}
            restored_targets = list(str(value) for value in state["restored_targets"])
            for target in restored_targets:
                plan = by_target.get(target)
                if plan is None:
                    continue
                current = None if plan.current is None else plan.current.state()
                if current != _prior_state(records[target]):
                    raise ValueError(f"checkpointed rollback target drift: {target}")
            for target in _rollback_targets(receipt)[len(restored_targets):]:
                plan = by_target.get(target)
                if plan is None:
                    raise ValueError(f"pending rollback target parent is absent: {target}")
                current = None if plan.current is None else plan.current.state()
                if current not in (_desired(root, plan.entry), _prior_state(records[target])):
                    raise ValueError(f"installed target drift blocks rollback: {target}")
            if dry_run:
                return _result("rollback_dry_run", manifest, _rollback_targets(receipt))
            if state_snapshot is None:
                state_snapshot = _publish_rollback_state(receipt_fd, root, None, state)
                receipt_artifacts["rollback-state-v1.json"] = state_snapshot

            for target in _rollback_targets(receipt)[len(restored_targets):]:
                plan = by_target[target]
                record = records[target]
                prior = priors[target]
                prior_state = _prior_state(record)
                current_state = None if plan.current is None else plan.current.state()
                if current_state != prior_state:
                    _validate_receipt_artifacts(receipt_fd, receipt_artifacts)
                    plan.current = _cas_publish(plan.directory_fd, plan.name, plan.current, prior)
                    if not _directory_binding_matches(root_fd, plan.components, plan.directory_fd):
                        raise ValueError(f"target directory changed during rollback: {target}")
                restored_targets.append(target)
                state = _rollback_state_value(
                    manifest,
                    receipt_raw,
                    restored_targets.copy(),
                    list(str(value) for value in state["removed_directories"]),
                )
                state_snapshot = _publish_rollback_state(receipt_fd, root, state_snapshot, state)
                receipt_artifacts["rollback-state-v1.json"] = state_snapshot
                _validate_receipt_artifacts(receipt_fd, receipt_artifacts)

            removed = list(str(value) for value in state["removed_directories"])
            directory_order = _rollback_directories(receipt)
            for directory in directory_order[len(removed):]:
                try:
                    directory_fd = _open_chain(root_fd, directory, root, create=False)
                except FileNotFoundError:
                    directory_fd = -1
                if directory_fd >= 0:
                    try:
                        present = set(os.listdir(directory_fd))
                    finally:
                        os.close(directory_fd)
                    if present:
                        raise ValueError(f"rollback directory content drift: {directory}")
                    parent_fd, name = _open_parent(root_fd, directory, root)
                    try:
                        os.rmdir(name, dir_fd=parent_fd)
                        os.fsync(parent_fd)
                    finally:
                        os.close(parent_fd)
                removed.append(directory)
                state = _rollback_state_value(manifest, receipt_raw, restored_targets.copy(), removed.copy())
                state_snapshot = _publish_rollback_state(receipt_fd, root, state_snapshot, state)
                receipt_artifacts["rollback-state-v1.json"] = state_snapshot
                _validate_receipt_artifacts(receipt_fd, receipt_artifacts)

            _validate_terminal_rollback(root_fd, root, receipt, entries)
            _validate_receipt_artifacts(receipt_fd, receipt_artifacts)
            if not _directory_binding_matches(root_fd, receipt_components, receipt_fd):
                raise ValueError("keyholder receipt directory changed during rollback")
            rollback_receipt = {
                "schema": ROLLBACK_SCHEMA,
                "package_id": manifest["package_id"],
                "package_digest": manifest["package_digest"],
                "install_receipt_sha256": sha256(receipt_raw),
                "restored_targets": _rollback_targets(receipt),
            }
            try:
                marker_snapshot = _write_once(
                    receipt_fd,
                    "rollback-v1.json",
                    canonical_json(rollback_receipt),
                    0o600,
                    mapped_id(0, root),
                    mapped_id(0, root, group=True),
                )
            except FileExistsError:
                marker_pair = _read_receipt(receipt_fd, "rollback-v1.json", absent_ok=False)
                assert marker_pair is not None
                _validate_rollback_marker(marker_pair[0], manifest, receipt_raw, receipt)
                return _result("unchanged", manifest, _rollback_targets(receipt))
            _validate_receipt_artifacts(
                receipt_fd,
                receipt_artifacts | {"rollback-v1.json": marker_snapshot},
            )
            return _result("rolled_back", manifest, _rollback_targets(receipt))
        finally:
            if receipt_fd >= 0:
                os.close(receipt_fd)
            for plan in plans:
                os.close(plan.directory_fd)
            os.close(root_fd)
    finally:
        os.umask(previous_umask)


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
    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument("--package", type=Path, required=True)
    rollback_parser.add_argument("--root", type=Path, default=Path("/"))
    rollback_parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    if arguments.command == "verify-package":
        manifest, _ = parse_package(arguments.package)
        result = {"status": "verified", "package_id": manifest["package_id"], "package_digest": manifest["package_digest"]}
    elif arguments.command == "check":
        result = check(arguments.package, arguments.root)
    elif arguments.command == "rollback":
        result = rollback(arguments.package, arguments.root, dry_run=arguments.dry_run)
    else:
        result = install(arguments.package, arguments.root, dry_run=arguments.dry_run)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
