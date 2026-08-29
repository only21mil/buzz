#!/usr/bin/env python3
"""Verify or atomically install a frozen Buzz CI execd binary package."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

EXECD_DIR = Path(__file__).resolve().parent
if str(EXECD_DIR) not in sys.path:
    sys.path.insert(0, str(EXECD_DIR))

import freeze_package

MAX_JSON_BYTES = 1024 * 1024
PACKAGE_ID = re.compile(r"^buzz-ci-execd-[0-9a-f]{12}-[0-9a-f]{12}$")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Entry:
    source: str
    target: str
    source_mode: int
    install_mode: int
    uid: int
    gid: int
    sha256: str
    payload: bytes


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
    path = Path(target)
    if not target.startswith("/") or ".." in path.parts:
        raise ValueError("unsafe target path")
    return root / target.removeprefix("/")


def mapped_id(value: int, root: Path, *, group: bool = False) -> int:
    if value != 0 or root == Path("/"):
        return value
    metadata = root.lstat()
    return metadata.st_gid if group else metadata.st_uid


def read_regular(path: Path, maximum: int = 128 * 1024 * 1024) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe regular file: {path}")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > maximum:
                raise ValueError(f"file exceeds byte limit: {path}")
            chunks.append(chunk)
        if size == 0:
            raise ValueError(f"empty regular file: {path}")
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def parse_json(path: Path) -> tuple[dict[str, object], bytes, os.stat_result]:
    raw, metadata = read_regular(path, MAX_JSON_BYTES)
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value, raw, metadata


def _require_directory(path: Path, uid: int, gid: int, mode: int) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
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


def _mode(value: object) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0[4567][0-7]{2}", value):
        raise ValueError("invalid mode")
    return int(value, 8)


def parse_package(package: Path) -> tuple[dict[str, object], Entry]:
    package = Path(os.path.abspath(package))
    if Path(os.path.realpath(package)) != package:
        raise ValueError("package path must not contain symbolic links")
    package_uid = package.lstat().st_uid
    package_gid = package.lstat().st_gid
    _require_directory(package, package_uid, package_gid, 0o700)
    _require_directory(package / "assets", package_uid, package_gid, 0o700)
    manifest, raw_manifest, metadata = parse_json(package / "package-manifest.json")
    if (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (
        package_uid,
        package_gid,
        0o600,
    ):
        raise ValueError("package manifest metadata is unsafe")
    expected = {
        "schema",
        "package_id",
        "source_commit",
        "binary_provenance_sha256",
        "default_state",
        "runtime_contract",
        "activation_owned_targets",
        "activation_binding",
        "seccomp_contract",
        "install_receipt",
        "package_uid",
        "package_gid",
        "directories",
        "entries",
        "package_digest",
    }
    if set(manifest) != expected or manifest["schema"] != freeze_package.SCHEMA:
        raise ValueError("package manifest fields differ")
    if (
        not isinstance(manifest["package_id"], str)
        or not PACKAGE_ID.fullmatch(manifest["package_id"])
        or not isinstance(manifest["source_commit"], str)
        or not GIT_OID.fullmatch(manifest["source_commit"])
        or manifest["default_state"] != freeze_package.DEFAULT_STATE
        or manifest["runtime_contract"] != freeze_package.RUNTIME_CONTRACT
        or manifest["activation_owned_targets"] != freeze_package.ACTIVATION_OWNED_TARGETS
        or manifest["seccomp_contract"] != freeze_package.SECCOMP_CONTRACT
        or manifest["install_receipt"] != freeze_package.INSTALL_RECEIPT
        or manifest["package_uid"] != 0
        or manifest["package_gid"] != 0
        or manifest["directories"] != freeze_package.DIRECTORIES
    ):
        raise ValueError("package runtime or ownership contract differs")
    binding = manifest["activation_binding"]
    if (
        not isinstance(binding, dict)
        or set(binding)
        != {
            "activation_id",
            "package_digest",
            "manifest_sha256",
            "source_commit",
            "execd_binary_sha256",
            "execd_provenance_sha256",
            "preactivation_input_sha256",
            "owned_entries_sha256",
            "owned_target_sha256",
            "receipt_path",
            "receipt_schema",
        }
        or binding["source_commit"] != manifest["source_commit"]
        or binding["receipt_path"] != "/var/lib/buzzci/activation-controller/receipt-v1.json"
        or binding["receipt_schema"] != "buzz-ci-capacity-one-activation-receipt-v1"
        or any(
            not isinstance(binding[field], str) or not DIGEST.fullmatch(binding[field])
            for field in (
                "package_digest",
                "manifest_sha256",
                "execd_binary_sha256",
                "execd_provenance_sha256",
                "preactivation_input_sha256",
                "owned_entries_sha256",
            )
        )
        or not isinstance(binding["owned_target_sha256"], list)
        or [item.get("target") for item in binding["owned_target_sha256"] if isinstance(item, dict)]
        != freeze_package.ACTIVATION_OWNED_TARGETS
        or any(
            not isinstance(item, dict)
            or set(item) != {"target", "sha256"}
            or not isinstance(item["sha256"], str)
            or not DIGEST.fullmatch(item["sha256"])
            for item in binding["owned_target_sha256"]
        )
        or binding["activation_id"]
        != f"buzz-ci-capacity-one-{str(binding['source_commit'])[:12]}-{str(binding['package_digest'])[:12]}"
    ):
        raise ValueError("activation package binding differs")
    claimed = manifest.pop("package_digest")
    if (
        not isinstance(claimed, str)
        or not DIGEST.fullmatch(claimed)
        or sha256(canonical_json(manifest)) != claimed
    ):
        raise ValueError("package digest differs")
    manifest["package_digest"] = claimed
    if canonical_json(manifest) != raw_manifest:
        raise ValueError("package manifest is not canonical")

    provenance, provenance_raw, provenance_metadata = parse_json(
        package / "binary-provenance.json"
    )
    if (
        set(provenance) != {"schema", "binary", "source_commit", "profile", "sha256"}
        or provenance["schema"] != freeze_package.PROVENANCE_SCHEMA
        or provenance["binary"] != "buzz-ci-execd"
        or provenance["source_commit"] != manifest["source_commit"]
        or provenance["profile"] != "release"
        or not isinstance(provenance["sha256"], str)
        or not DIGEST.fullmatch(provenance["sha256"])
        or sha256(provenance_raw) != manifest["binary_provenance_sha256"]
        or canonical_json(provenance) != provenance_raw
        or (provenance_metadata.st_uid, provenance_metadata.st_gid, stat.S_IMODE(provenance_metadata.st_mode))
        != (package_uid, package_gid, 0o600)
    ):
        raise ValueError("binary provenance differs")
    entries = manifest["entries"]
    if not isinstance(entries, list) or len(entries) != 1:
        raise ValueError("package inventory differs")
    item = entries[0]
    if not isinstance(item, dict) or set(item) != {
        "role",
        "source",
        "target",
        "source_mode",
        "install_mode",
        "uid",
        "gid",
        "sha256",
    }:
        raise ValueError("package entry shape differs")
    if (
        item["role"] != "binary"
        or item["source"] != "assets/buzz-ci-execd"
        or item["target"] != freeze_package.RUNTIME_CONTRACT["binary"]
        or item["uid"] != 0
        or item["gid"] != 0
        or _mode(item["source_mode"]) != 0o500
        or _mode(item["install_mode"]) != 0o755
        or not isinstance(item["sha256"], str)
        or not DIGEST.fullmatch(item["sha256"])
        or item["sha256"] != provenance["sha256"]
        or item["sha256"] != binding["execd_binary_sha256"]
        or sha256(provenance_raw) != binding["execd_provenance_sha256"]
    ):
        raise ValueError("package entry differs")
    payload, source_metadata = read_regular(package / str(item["source"]))
    if (
        (source_metadata.st_uid, source_metadata.st_gid, stat.S_IMODE(source_metadata.st_mode))
        != (package_uid, package_gid, 0o500)
        or sha256(payload) != item["sha256"]
    ):
        raise ValueError("package binary differs")
    return manifest, Entry(
        source=str(item["source"]),
        target=str(item["target"]),
        source_mode=0o500,
        install_mode=0o755,
        uid=0,
        gid=0,
        sha256=str(item["sha256"]),
        payload=payload,
    )


def _verify_external_seccomp(root: Path) -> None:
    contract = freeze_package.SECCOMP_CONTRACT
    payload, metadata = read_regular(rooted(root, str(contract["source_path"])), 16 * 1024 * 1024)
    if (
        metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or sha256(payload) != contract["source_sha256"]
    ):
        raise ValueError("external seccomp source provenance differs")


def _receipt_parent(
    root: Path,
    target: str,
    exact_modes: dict[str, int],
) -> bool:
    current = root
    for component in Path(target).parent.relative_to("/").parts:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return False
        rooted_name = "/" + current.relative_to(root).as_posix()
        expected_mode = exact_modes.get(rooted_name)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != mapped_id(0, root)
            or metadata.st_gid != mapped_id(0, root, group=True)
            or (expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode)
            or (expected_mode is None and metadata.st_mode & 0o022)
        ):
            raise ValueError("receipt directory chain is unsafe")
    return True


def _activation_receipt_state(root: Path, manifest: dict[str, object]) -> str:
    binding = manifest["activation_binding"]
    receipt_path = rooted(root, str(binding["receipt_path"]))
    parent_ready = _receipt_parent(
        root,
        str(binding["receipt_path"]),
        {"/var/lib/buzzci": 0o711, "/var/lib/buzzci/activation-controller": 0o711},
    )
    try:
        receipt_path.lstat()
        receipt_exists = True
    except FileNotFoundError:
        receipt_exists = False
    if not parent_ready or not receipt_exists:
        if any(os.path.lexists(rooted(root, target)) for target in freeze_package.ACTIVATION_OWNED_TARGETS):
            raise ValueError("activation-owned targets exist without a central receipt")
        return "pending"
    receipt, receipt_raw, metadata = parse_json(receipt_path)
    expected_keys = {
        "schema",
        "activation_id",
        "package_digest",
        "source_commit",
        "state",
        "created_at",
        "updated_at",
        "principals_retained_on_rollback",
        "targets",
        "acceptance_generated",
        "acceptance_ledger_prior",
        "fixed_package",
        "systemd_before",
        "qualification",
        "capacity_one",
        "qualification_zero",
        "last_error",
    }
    if (
        set(receipt) != expected_keys
        or canonical_json(receipt) != receipt_raw
        or metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or receipt.get("schema") != binding["receipt_schema"]
        or receipt.get("activation_id") != binding["activation_id"]
        or receipt.get("package_digest") != binding["package_digest"]
        or receipt.get("source_commit") != binding["source_commit"]
        or receipt.get("principals_retained_on_rollback") is not True
    ):
        raise ValueError("central activation receipt binding differs")
    targets = receipt.get("targets")
    fixed_package = receipt.get("fixed_package")
    if not isinstance(targets, list) or not isinstance(fixed_package, dict):
        raise ValueError("central activation receipt targets are absent")
    expected = {item["target"]: item["sha256"] for item in binding["owned_target_sha256"]}
    observed = {
        item.get("target"): item.get("staged_sha256")
        for item in targets
        if isinstance(item, dict) and item.get("target") in expected
    }
    if observed != expected or fixed_package.get("manifest_sha256") != binding["manifest_sha256"]:
        raise ValueError("central activation receipt managed bindings differ")
    return "verified"


def _receipt_bytes(manifest: dict[str, object]) -> bytes:
    binding = manifest["activation_binding"]
    return canonical_json(
        {
            "schema": freeze_package.INSTALL_RECEIPT["schema"],
            "package_id": manifest["package_id"],
            "package_digest": manifest["package_digest"],
            "source_commit": manifest["source_commit"],
            "binary_sha256": binding["execd_binary_sha256"],
            "activation_id": binding["activation_id"],
            "activation_package_digest": binding["package_digest"],
            "activation_manifest_sha256": binding["manifest_sha256"],
            "activation_owned_entries_sha256": binding["owned_entries_sha256"],
            "seccomp_source_sha256": freeze_package.SECCOMP_CONTRACT["source_sha256"],
            "enabled": False,
            "active": False,
            "capacity": 0,
        }
    )


def _verify_install_receipt(root: Path, manifest: dict[str, object], *, absent_ok: bool) -> bool:
    path = rooted(root, str(freeze_package.INSTALL_RECEIPT["path"]))
    parent_ready = _receipt_parent(
        root,
        str(freeze_package.INSTALL_RECEIPT["path"]),
        {
            "/var/lib/buzzci": 0o711,
            "/var/lib/buzzci/execd-v2": 0o711,
            "/var/lib/buzzci/execd-v2/package": 0o700,
        },
    )
    try:
        path.lstat()
        exists = True
    except FileNotFoundError:
        exists = False
    if not parent_ready or not exists:
        if absent_ok:
            return False
        raise ValueError("execd package install receipt is absent")
    payload, metadata = read_regular(path, MAX_JSON_BYTES)
    if (
        payload != _receipt_bytes(manifest)
        or metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("execd package install receipt differs")
    return True


def _target_matches(root: Path, entry: Entry) -> bool:
    target = rooted(root, entry.target)
    try:
        payload, metadata = read_regular(target)
    except (FileNotFoundError, ValueError, OSError):
        return False
    return (
        sha256(payload) == entry.sha256
        and stat.S_IMODE(metadata.st_mode) == entry.install_mode
        and metadata.st_uid == mapped_id(entry.uid, root)
        and metadata.st_gid == mapped_id(entry.gid, root, group=True)
    )


@dataclass(frozen=True)
class _PriorTarget:
    payload: bytes
    mode: int
    uid: int
    gid: int


@dataclass
class _Publication:
    directory_fd: int
    name: str
    rollback_name: str | None
    prior: _PriorTarget | None


def _open_root(root: Path) -> int:
    descriptor = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or metadata.st_mode & 0o022
    ):
        os.close(descriptor)
        raise ValueError("install root metadata is unsafe")
    return descriptor


def _open_directory_chain(
    root_fd: int,
    plan: tuple[tuple[str, int | None], ...],
    uid: int,
    gid: int,
) -> int:
    current = os.dup(root_fd)
    try:
        for component, exact_mode in plan:
            created = False
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, exact_mode or 0o755, dir_fd=current)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current,
                )
            try:
                if created:
                    os.fchown(child, uid, gid)
                    os.fchmod(child, exact_mode or 0o755)
                    os.fsync(child)
                    os.fsync(current)
                metadata = os.fstat(child)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != uid
                    or metadata.st_gid != gid
                    or (exact_mode is not None and stat.S_IMODE(metadata.st_mode) != exact_mode)
                    or (exact_mode is None and metadata.st_mode & 0o022)
                ):
                    raise ValueError("target directory chain is unsafe")
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _directory_binding_matches(
    root_fd: int,
    components: tuple[str, ...],
    expected_fd: int,
) -> bool:
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
        observed = os.fstat(current)
        expected = os.fstat(expected_fd)
        return (observed.st_dev, observed.st_ino) == (expected.st_dev, expected.st_ino)
    except OSError:
        return False
    finally:
        os.close(current)


def _read_regular_at(
    directory_fd: int,
    name: str,
    maximum: int = 128 * 1024 * 1024,
) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe regular file: {name}")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > maximum:
                raise ValueError(f"file exceeds byte limit: {name}")
            chunks.append(chunk)
        if size == 0:
            raise ValueError(f"empty regular file: {name}")
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def _binary_matches_at(directory_fd: int, entry: Entry, uid: int, gid: int) -> bool:
    try:
        payload, metadata = _read_regular_at(directory_fd, Path(entry.target).name)
    except (FileNotFoundError, ValueError, OSError):
        return False
    return (
        sha256(payload) == entry.sha256
        and stat.S_IMODE(metadata.st_mode) == entry.install_mode
        and metadata.st_uid == uid
        and metadata.st_gid == gid
    )


def _temporary_name(directory_fd: int, stem: str) -> str:
    for _ in range(128):
        name = f".{stem}.{secrets.token_hex(12)}"
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return name
    raise FileExistsError("could not allocate a private publication name")


def _write_temporary_at(
    directory_fd: int,
    stem: str,
    payload: bytes,
    mode: int,
    uid: int,
    gid: int,
) -> str:
    name = _temporary_name(directory_fd, stem)
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise OSError("short write while publishing execd package")
            view = view[written:]
        os.fsync(descriptor)
        return name
    except BaseException:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)


def _prior_target_at(directory_fd: int, name: str) -> _PriorTarget | None:
    try:
        payload, metadata = _read_regular_at(directory_fd, name)
    except FileNotFoundError:
        return None
    return _PriorTarget(
        payload=payload,
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def _assert_prior_restored(publication: _Publication) -> None:
    if publication.prior is None:
        try:
            os.stat(publication.name, dir_fd=publication.directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError("new execd binary remains after rollback")
    payload, metadata = _read_regular_at(publication.directory_fd, publication.name)
    if (
        payload != publication.prior.payload
        or stat.S_IMODE(metadata.st_mode) != publication.prior.mode
        or metadata.st_uid != publication.prior.uid
        or metadata.st_gid != publication.prior.gid
    ):
        raise ValueError("prior execd binary restore differs")


def _restore_publication(publication: _Publication) -> None:
    if publication.prior is None:
        try:
            os.unlink(publication.name, dir_fd=publication.directory_fd)
        except FileNotFoundError:
            pass
    else:
        restored = False
        if publication.rollback_name is not None:
            try:
                os.replace(
                    publication.rollback_name,
                    publication.name,
                    src_dir_fd=publication.directory_fd,
                    dst_dir_fd=publication.directory_fd,
                )
                restored = True
            except FileNotFoundError:
                pass
        if not restored:
            temporary = _write_temporary_at(
                publication.directory_fd,
                publication.name,
                publication.prior.payload,
                publication.prior.mode,
                publication.prior.uid,
                publication.prior.gid,
            )
            os.replace(
                temporary,
                publication.name,
                src_dir_fd=publication.directory_fd,
                dst_dir_fd=publication.directory_fd,
            )
    os.fsync(publication.directory_fd)
    _assert_prior_restored(publication)


def _publish_binary(directory_fd: int, entry: Entry, uid: int, gid: int) -> _Publication:
    name = Path(entry.target).name
    prior = _prior_target_at(directory_fd, name)
    temporary = _write_temporary_at(
        directory_fd,
        name,
        entry.payload,
        entry.install_mode,
        uid,
        gid,
    )
    rollback_name: str | None = None
    prior_moved = False
    published = False
    publication = _Publication(directory_fd, name, None, prior)
    try:
        if prior is not None:
            rollback_name = _temporary_name(directory_fd, f"{name}.rollback")
            os.replace(
                name,
                rollback_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            prior_moved = True
            publication.rollback_name = rollback_name
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        published = True
        temporary = ""
        os.fsync(directory_fd)
        if not _binary_matches_at(directory_fd, entry, uid, gid):
            raise ValueError("installed execd binary readback differs")
        return publication
    except BaseException:
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        if published or prior_moved:
            _restore_publication(publication)
        raise


def _discard_rollback(publication: _Publication) -> None:
    if publication.rollback_name is None:
        return
    os.unlink(publication.rollback_name, dir_fd=publication.directory_fd)
    os.fsync(publication.directory_fd)


def _verify_receipt_at(
    directory_fd: int,
    manifest: dict[str, object],
    uid: int,
    gid: int,
) -> None:
    payload, metadata = _read_regular_at(directory_fd, "receipt-v1.json", MAX_JSON_BYTES)
    if (
        payload != _receipt_bytes(manifest)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("execd package install receipt differs")


def _publish_receipt(
    directory_fd: int,
    manifest: dict[str, object],
    uid: int,
    gid: int,
) -> bool:
    temporary = _write_temporary_at(
        directory_fd,
        "receipt-v1.json",
        _receipt_bytes(manifest),
        0o600,
        uid,
        gid,
    )
    created = False
    try:
        try:
            os.link(
                temporary,
                "receipt-v1.json",
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            created = True
        except FileExistsError:
            pass
        os.unlink(temporary, dir_fd=directory_fd)
        temporary = ""
        os.fsync(directory_fd)
        return created
    except BaseException:
        if created:
            try:
                os.unlink("receipt-v1.json", dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        raise


def _remove_created_receipt(directory_fd: int) -> None:
    try:
        os.unlink("receipt-v1.json", dir_fd=directory_fd)
    except FileNotFoundError:
        pass
    os.fsync(directory_fd)
    try:
        os.stat("receipt-v1.json", dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError("execd package receipt remains after rollback")


def inspect(package: Path, root: Path) -> dict[str, object]:
    root = _safe_root(root)
    manifest, entry = parse_package(package)
    _verify_external_seccomp(root)
    activation_receipt = _activation_receipt_state(root, manifest)
    receipt = _verify_install_receipt(root, manifest, absent_ok=True)
    changed = [] if _target_matches(root, entry) else [entry.target]
    return {
        "status": "checked",
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "changed_targets": changed,
        "enabled": False,
        "active": False,
        "capacity": 0,
        "activation_receipt": activation_receipt,
        "install_receipt": "verified" if receipt else "absent",
    }


def install(package: Path, root: Path, *, dry_run: bool = False) -> dict[str, object]:
    root = _safe_root(root)
    manifest, entry = parse_package(package)
    _verify_external_seccomp(root)
    activation_receipt = _activation_receipt_state(root, manifest)
    if root == Path("/") and os.geteuid() != 0:
        raise PermissionError("installation requires root")
    changed = not _target_matches(root, entry)
    receipt_present = _verify_install_receipt(root, manifest, absent_ok=True)
    result = {
        "status": "dry_run" if dry_run else ("installed" if changed or not receipt_present else "unchanged"),
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "changed_targets": ([entry.target] if changed else [])
        + ([] if receipt_present else [str(freeze_package.INSTALL_RECEIPT["path"])]),
        "enabled": False,
        "active": False,
        "capacity": 0,
        "activation_receipt": activation_receipt,
        "install_receipt": "pending" if changed else "verified",
    }
    if dry_run:
        return result
    uid = mapped_id(0, root)
    gid = mapped_id(0, root, group=True)
    root_fd = _open_root(root)
    binary_directory = -1
    receipt_directory = -1
    publication: _Publication | None = None
    receipt_created = False
    try:
        binary_directory = _open_directory_chain(
            root_fd,
            (("usr", None), ("libexec", 0o755)),
            uid,
            gid,
        )
        receipt_directory = _open_directory_chain(
            root_fd,
            (
                ("var", 0o755),
                ("lib", 0o755),
                ("buzzci", 0o711),
                ("execd-v2", 0o711),
                ("package", 0o700),
            ),
            uid,
            gid,
        )
        changed = not _binary_matches_at(binary_directory, entry, uid, gid)
        try:
            _verify_receipt_at(receipt_directory, manifest, uid, gid)
            receipt_present = True
        except FileNotFoundError:
            receipt_present = False
        result["status"] = "installed" if changed or not receipt_present else "unchanged"
        result["changed_targets"] = ([entry.target] if changed else []) + (
            [] if receipt_present else [str(freeze_package.INSTALL_RECEIPT["path"])]
        )
        result["install_receipt"] = "pending" if changed or not receipt_present else "verified"

        if changed:
            publication = _publish_binary(binary_directory, entry, uid, gid)
        if not _binary_matches_at(binary_directory, entry, uid, gid):
            raise ValueError("installed execd binary readback differs")
        if not _directory_binding_matches(root_fd, ("usr", "libexec"), binary_directory):
            raise ValueError("execd binary directory changed during installation")
        if not receipt_present:
            receipt_created = _publish_receipt(receipt_directory, manifest, uid, gid)
        _verify_receipt_at(receipt_directory, manifest, uid, gid)
        if not _binary_matches_at(binary_directory, entry, uid, gid):
            raise ValueError("installed execd binary readback differs")
        if (
            not _directory_binding_matches(root_fd, ("usr", "libexec"), binary_directory)
            or not _directory_binding_matches(
                root_fd,
                ("var", "lib", "buzzci", "execd-v2", "package"),
                receipt_directory,
            )
        ):
            raise ValueError("execd publication directory changed during installation")
        if publication is not None:
            _discard_rollback(publication)
        result["install_receipt"] = "verified"
        return result
    except BaseException as install_error:
        rollback_errors: list[BaseException] = []
        if receipt_created and receipt_directory >= 0:
            try:
                _remove_created_receipt(receipt_directory)
            except BaseException as error:
                rollback_errors.append(error)
        if publication is not None:
            try:
                _restore_publication(publication)
            except BaseException as error:
                rollback_errors.append(error)
        if rollback_errors:
            detail = "; ".join(str(error) for error in rollback_errors)
            raise RuntimeError(f"execd installation rollback failed: {detail}") from install_error
        raise
    finally:
        if receipt_directory >= 0:
            os.close(receipt_directory)
        if binary_directory >= 0:
            os.close(binary_directory)
        os.close(root_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify-package")
    verify.add_argument("--package", type=Path, required=True)
    check = subparsers.add_parser("check")
    check.add_argument("--package", type=Path, required=True)
    check.add_argument("--root", type=Path, default=Path("/"))
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--package", type=Path, required=True)
    install_parser.add_argument("--root", type=Path, default=Path("/"))
    install_parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    if arguments.command == "verify-package":
        manifest, _ = parse_package(arguments.package)
        result = {
            "status": "verified",
            "package_id": manifest["package_id"],
            "package_digest": manifest["package_digest"],
        }
    elif arguments.command == "check":
        result = inspect(arguments.package, arguments.root)
    else:
        result = install(arguments.package, arguments.root, dry_run=arguments.dry_run)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
