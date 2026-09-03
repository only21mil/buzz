#!/usr/bin/env python3
"""Verify or atomically install a frozen Buzz CI execd binary package."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import fcntl
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
RECEIPT_NAME = "receipt-v1.json"
PREIMAGE_NAME = "preimage-v1.bin"
ROLLBACK_RECEIPT_NAME = "rollback-v1.json"
ROLLBACK_TERMINAL_STAGE_NAME = "rollback-terminal-v1.json"
INSTALL_TRANSACTION_NAME = "install-transaction-v1.json"
INSTALL_LOCK_NAME = "install.lock"
CANDIDATE_STAGE_NAME = ".buzz-ci-execd.install-v1"
CANDIDATE_IDENTITY_NAME = "candidate-identity-v1.json"
ROLLBACK_STAGE_NAME = ".buzz-ci-execd.rollback-v1"
COMPENSATION_STAGE_NAME = ".buzz-ci-execd.compensate-v1"
ROLLBACK_STAGE_IDENTITY_NAME = "rollback-stage-identity-v1.json"
INSTALL_TRANSACTION_SCHEMA = "buzz-ci-execd-package-install-transaction-v1"
CANDIDATE_IDENTITY_SCHEMA = "buzz-ci-execd-package-candidate-identity-v1"
ROLLBACK_STAGE_IDENTITY_SCHEMA = "buzz-ci-execd-package-rollback-stage-identity-v1"
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2


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


class _RollbackHoldError(ValueError):
    pass


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


ROLLBACK_CLEANUP_PATH = "/var/lib/buzzci/activation-controller/rollback-cleanup-v1.json"
ROLLBACK_CLEANUP_SCHEMA = "buzz-ci-activation-rollback-cleanup-v1"
ACTIVATION_RECEIPT_KEYS = frozenset({
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
    "persistent_authorization",
    "persistent_activation",
    "qualification_zero",
    "last_error",
})
ROLLBACK_CLEANUP_KEYS = frozenset({
    "schema",
    "activation_id",
    "package_digest",
    "source_commit",
    "manifest_sha256",
    "package_assets",
    "manifest",
})


def _activation_binding_of(value: dict[str, object]) -> tuple[object, object, object]:
    return value.get("activation_id"), value.get("package_digest"), value.get("source_commit")


def _rollback_cleanup_marker(root: Path) -> dict[str, object] | None:
    """Read the controller's terminal rollback-cleanup marker, or None when absent."""
    path = rooted(root, ROLLBACK_CLEANUP_PATH)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    value, raw, metadata = parse_json(path)
    if (
        metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or canonical_json(value) != raw
        or set(value) != ROLLBACK_CLEANUP_KEYS
        or value.get("schema") != ROLLBACK_CLEANUP_SCHEMA
    ):
        raise ValueError("activation rollback cleanup marker differs")
    manifest = value.get("manifest")
    assets = value.get("package_assets")
    if (
        not isinstance(manifest, dict)
        or not isinstance(value.get("manifest_sha256"), str)
        or value["manifest_sha256"] != sha256(canonical_json(manifest))
        or _activation_binding_of(manifest) != _activation_binding_of(value)
        or not isinstance(assets, list)
        or any(not isinstance(item, str) for item in assets)
        or assets != sorted(assets)
    ):
        raise ValueError("activation rollback cleanup marker binding differs")
    return value


def _activation_receipt_state(root: Path, manifest: dict[str, object]) -> str:
    """Classify the central activation receipt relative to this execd package.

    Returns ``pending`` when no central receipt exists, ``verified`` when the
    receipt is bound to this package's activation, and ``rolled_back`` when the
    receipt belongs to another activation whose rollback reached its terminal
    state and the controller's rollback-cleanup marker proves that rollback.
    Any receipt bound to another activation in a live state fails closed.
    """
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
    if (
        set(receipt) != ACTIVATION_RECEIPT_KEYS
        or canonical_json(receipt) != receipt_raw
        or metadata.st_uid != mapped_id(0, root)
        or metadata.st_gid != mapped_id(0, root, group=True)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or receipt.get("schema") != binding["receipt_schema"]
        or receipt.get("principals_retained_on_rollback") is not True
    ):
        raise ValueError("central activation receipt binding differs")
    expected_binding = (binding["activation_id"], binding["package_digest"], binding["source_commit"])
    fixed_package = receipt.get("fixed_package")
    if _activation_binding_of(receipt) != expected_binding:
        if receipt.get("state") != "rolled_back":
            raise ValueError("central activation receipt binding differs")
        marker = _rollback_cleanup_marker(root)
        if marker is None:
            raise ValueError("rolled-back central activation receipt lacks its rollback cleanup marker")
        if (
            _activation_binding_of(marker) != _activation_binding_of(receipt)
            or not isinstance(fixed_package, dict)
            or fixed_package.get("manifest_sha256") != marker["manifest_sha256"]
        ):
            raise ValueError("rolled-back central activation receipt differs from its rollback cleanup marker")
        return "rolled_back"
    targets = receipt.get("targets")
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


def _prior_record(prior: _PriorTarget | None, uid: int, gid: int) -> dict[str, object]:
    if prior is None:
        return {"state": "absent", "binary": None, "preimage": None}
    digest = sha256(prior.payload)
    return {
        "state": "present",
        "binary": {
            "sha256": digest,
            "mode": prior.mode,
            "uid": prior.uid,
            "gid": prior.gid,
        },
        "preimage": {
            "name": PREIMAGE_NAME,
            "sha256": digest,
            "mode": 0o600,
            "uid": uid,
            "gid": gid,
        },
    }


def _receipt_value(
    manifest: dict[str, object],
    prior: _PriorTarget | None,
    uid: int,
    gid: int,
) -> dict[str, object]:
    binding = manifest["activation_binding"]
    return {
        "schema": freeze_package.INSTALL_RECEIPT["schema"],
        "state": "installed",
        "package_id": manifest["package_id"],
        "package_digest": manifest["package_digest"],
        "source_commit": manifest["source_commit"],
        "binary_sha256": binding["execd_binary_sha256"],
        "binary_target": freeze_package.RUNTIME_CONTRACT["binary"],
        "binary_mode": _mode(freeze_package.RUNTIME_CONTRACT["mode"]),
        "binary_uid": uid,
        "binary_gid": gid,
        "activation_id": binding["activation_id"],
        "activation_package_digest": binding["package_digest"],
        "activation_manifest_sha256": binding["manifest_sha256"],
        "activation_owned_entries_sha256": binding["owned_entries_sha256"],
        "seccomp_source_sha256": freeze_package.SECCOMP_CONTRACT["source_sha256"],
        "enabled": False,
        "active": False,
        "capacity": 0,
        "prior": _prior_record(prior, uid, gid),
    }


def _receipt_bytes(
    manifest: dict[str, object],
    prior: _PriorTarget | None,
    uid: int,
    gid: int,
) -> bytes:
    return canonical_json(_receipt_value(manifest, prior, uid, gid))


def _receipt_prior(
    value: dict[str, object],
    manifest: dict[str, object],
    uid: int,
    gid: int,
) -> _PriorTarget | None:
    expected = _receipt_value(manifest, None, uid, gid)
    expected.pop("prior")
    observed = dict(value)
    prior = observed.pop("prior", None)
    if observed != expected or not isinstance(prior, dict):
        raise ValueError("execd package install receipt differs")
    if prior == {"state": "absent", "binary": None, "preimage": None}:
        return None
    if set(prior) != {"state", "binary", "preimage"} or prior.get("state") != "present":
        raise ValueError("execd package prior receipt differs")
    binary = prior.get("binary")
    preimage = prior.get("preimage")
    if (
        not isinstance(binary, dict)
        or set(binary) != {"sha256", "mode", "uid", "gid"}
        or not isinstance(preimage, dict)
        or set(preimage) != {"name", "sha256", "mode", "uid", "gid"}
        or not isinstance(binary.get("sha256"), str)
        or not DIGEST.fullmatch(str(binary["sha256"]))
        or preimage != {
            "name": PREIMAGE_NAME,
            "sha256": binary["sha256"],
            "mode": 0o600,
            "uid": uid,
            "gid": gid,
        }
        or isinstance(binary.get("mode"), bool)
        or not isinstance(binary.get("mode"), int)
        or not 0 <= int(binary["mode"]) <= 0o7777
        or isinstance(binary.get("uid"), bool)
        or not isinstance(binary.get("uid"), int)
        or int(binary["uid"]) < 0
        or isinstance(binary.get("gid"), bool)
        or not isinstance(binary.get("gid"), int)
        or int(binary["gid"]) < 0
    ):
        raise ValueError("execd package prior receipt differs")
    return _PriorTarget(b"", int(binary["mode"]), int(binary["uid"]), int(binary["gid"]))


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
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("execd package install receipt is invalid") from error
    uid = mapped_id(0, root)
    gid = mapped_id(0, root, group=True)
    if (
        not isinstance(value, dict)
        or canonical_json(value) != payload
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("execd package install receipt differs")
    _receipt_prior(value, manifest, uid, gid)
    return True


def _verify_installed_candidate_identity(
    root: Path,
    manifest: dict[str, object],
    entry: Entry,
) -> None:
    uid = mapped_id(0, root)
    gid = mapped_id(0, root, group=True)
    root_fd = _open_root(root)
    binary_directory = -1
    receipt_directory = -1
    try:
        binary_directory = _open_directory_chain(
            root_fd,
            (("usr", None), ("libexec", 0o755)),
            uid,
            gid,
            create=False,
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
            create=False,
        )
        identity = _read_candidate_identity_at(
            receipt_directory, manifest, entry, uid, gid
        )
        if not _identity_matches_at(
            binary_directory, Path(entry.target).name, identity
        ):
            raise ValueError("installed execd candidate ownership differs")
    finally:
        if receipt_directory >= 0:
            os.close(receipt_directory)
        if binary_directory >= 0:
            os.close(binary_directory)
        os.close(root_fd)


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
    device: int | None = None
    inode: int | None = None


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
    *,
    create: bool = True,
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
                if not create:
                    raise
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
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )


def _absent_at(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _durable_phase(_phase: str) -> None:
    """Test seam reached only after the named state is durable."""


def _acquire_install_lock_at(directory_fd: int, uid: int, gid: int) -> int:
    created = False
    try:
        descriptor = os.open(
            INSTALL_LOCK_NAME,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        created = True
    except FileExistsError:
        descriptor = os.open(
            INSTALL_LOCK_NAME,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    try:
        if created:
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(directory_fd)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("execd package install lock metadata is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        bound = os.stat(
            INSTALL_LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False
        )
        current = os.fstat(descriptor)
        if (bound.st_dev, bound.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("execd package install lock binding changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _baseline_identity(prior: _PriorTarget | None) -> dict[str, object]:
    if prior is None:
        return {"state": "absent"}
    if prior.device is None or prior.inode is None:
        raise ValueError("execd baseline identity is unavailable")
    return {
        "state": "present",
        "device": prior.device,
        "inode": prior.inode,
        "sha256": sha256(prior.payload),
        "mode": prior.mode,
        "uid": prior.uid,
        "gid": prior.gid,
    }


def _file_identity_value(
    schema: str,
    package_id: object,
    package_digest: object,
    source_commit: object,
    target: str,
    payload: bytes,
    metadata: os.stat_result,
) -> dict[str, object]:
    return {
        "schema": schema,
        "package_id": package_id,
        "package_digest": package_digest,
        "source_commit": source_commit,
        "target": target,
        "sha256": sha256(payload),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def _read_identity_at(
    directory_fd: int,
    name: str,
    schema: str,
    manifest: dict[str, object],
    target: str,
    expected_sha256: str,
    expected_mode: int,
    expected_uid: int,
    expected_gid: int,
    identity_uid: int | None = None,
    identity_gid: int | None = None,
) -> dict[str, object]:
    payload, metadata = _read_regular_at(directory_fd, name, MAX_JSON_BYTES)
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"execd package identity is invalid: {name}") from error
    expected_keys = {
        "schema", "package_id", "package_digest", "source_commit", "target",
        "sha256", "mode", "uid", "gid", "device", "inode",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("schema") != schema
        or value.get("package_id") != manifest["package_id"]
        or value.get("package_digest") != manifest["package_digest"]
        or value.get("source_commit") != manifest["source_commit"]
        or value.get("target") != target
        or value.get("sha256") != expected_sha256
        or value.get("mode") != expected_mode
        or value.get("uid") != expected_uid
        or value.get("gid") != expected_gid
        or isinstance(value.get("device"), bool)
        or not isinstance(value.get("device"), int)
        or int(value["device"]) < 0
        or isinstance(value.get("inode"), bool)
        or not isinstance(value.get("inode"), int)
        or int(value["inode"]) <= 0
        or canonical_json(value) != payload
        or metadata.st_uid != (expected_uid if identity_uid is None else identity_uid)
        or metadata.st_gid != (expected_gid if identity_gid is None else identity_gid)
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError(f"execd package identity differs: {name}")
    return value


def _identity_matches_at(
    directory_fd: int,
    name: str,
    identity: dict[str, object],
) -> bool:
    try:
        payload, metadata = _read_regular_at(directory_fd, name)
    except (FileNotFoundError, ValueError, OSError):
        return False
    return (
        metadata.st_dev == identity["device"]
        and metadata.st_ino == identity["inode"]
        and sha256(payload) == identity["sha256"]
        and stat.S_IMODE(metadata.st_mode) == identity["mode"]
        and metadata.st_uid == identity["uid"]
        and metadata.st_gid == identity["gid"]
    )


def _install_transaction_value(
    manifest: dict[str, object],
    entry: Entry,
    prior: _PriorTarget | None,
    uid: int,
    gid: int,
    phase: str,
) -> dict[str, object]:
    if phase not in {"intent", "prepared", "published", "receipted"}:
        raise ValueError("invalid execd install transaction phase")
    return {
        "schema": INSTALL_TRANSACTION_SCHEMA,
        "phase": phase,
        "install_receipt": _receipt_value(manifest, prior, uid, gid),
        "baseline_identity": _baseline_identity(prior),
        "candidate": {
            "target": entry.target,
            "sha256": entry.sha256,
            "mode": entry.install_mode,
            "uid": uid,
            "gid": gid,
            "stage_name": CANDIDATE_STAGE_NAME,
            "identity_name": CANDIDATE_IDENTITY_NAME,
        },
    }


def _read_install_transaction_at(
    directory_fd: int,
    manifest: dict[str, object],
    entry: Entry,
    uid: int,
    gid: int,
) -> tuple[str, _PriorTarget | None, dict[str, object], dict[str, object]]:
    payload, metadata = _read_regular_at(
        directory_fd, INSTALL_TRANSACTION_NAME, MAX_JSON_BYTES
    )
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("execd package install transaction is invalid") from error
    if (
        not isinstance(value, dict)
        or set(value)
        != {"schema", "phase", "install_receipt", "baseline_identity", "candidate"}
        or value.get("schema") != INSTALL_TRANSACTION_SCHEMA
        or value.get("phase") not in {"intent", "prepared", "published", "receipted"}
        or not isinstance(value.get("install_receipt"), dict)
        or not isinstance(value.get("baseline_identity"), dict)
        or value.get("candidate")
        != {
            "target": entry.target,
            "sha256": entry.sha256,
            "mode": entry.install_mode,
            "uid": uid,
            "gid": gid,
            "stage_name": CANDIDATE_STAGE_NAME,
            "identity_name": CANDIDATE_IDENTITY_NAME,
        }
        or canonical_json(value) != payload
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("execd package install transaction differs")
    receipt = value["install_receipt"]
    prior = _receipt_prior(receipt, manifest, uid, gid)
    identity = value["baseline_identity"]
    if prior is None:
        if identity != {"state": "absent"}:
            raise ValueError("execd package absent baseline identity differs")
    else:
        record = receipt["prior"]["binary"]
        if (
            set(identity) != {"state", "device", "inode", "sha256", "mode", "uid", "gid"}
            or identity.get("state") != "present"
            or identity.get("sha256") != record["sha256"]
            or identity.get("mode") != record["mode"]
            or identity.get("uid") != record["uid"]
            or identity.get("gid") != record["gid"]
            or isinstance(identity.get("device"), bool)
            or not isinstance(identity.get("device"), int)
            or int(identity["device"]) < 0
            or isinstance(identity.get("inode"), bool)
            or not isinstance(identity.get("inode"), int)
            or int(identity["inode"]) <= 0
        ):
            raise ValueError("execd package baseline identity differs")
    return str(value["phase"]), prior, identity, receipt


def _baseline_matches_identity_at(
    directory_fd: int,
    name: str,
    identity: dict[str, object],
) -> bool:
    if identity == {"state": "absent"}:
        return _absent_at(directory_fd, name)
    try:
        payload, metadata = _read_regular_at(directory_fd, name)
    except (FileNotFoundError, ValueError, OSError):
        return False
    return (
        metadata.st_dev == identity["device"]
        and metadata.st_ino == identity["inode"]
        and sha256(payload) == identity["sha256"]
        and stat.S_IMODE(metadata.st_mode) == identity["mode"]
        and metadata.st_uid == identity["uid"]
        and metadata.st_gid == identity["gid"]
    )


def _load_transaction_prior_at(
    receipt_directory: int,
    binary_directory: int,
    name: str,
    prior: _PriorTarget | None,
    identity: dict[str, object],
    receipt: dict[str, object],
    uid: int,
    gid: int,
    *,
    create_preimage: bool,
) -> _PriorTarget | None:
    if prior is None:
        if not _absent_at(receipt_directory, PREIMAGE_NAME):
            raise ValueError("absent execd baseline has an unexpected preimage")
        return None
    try:
        payload, metadata = _read_regular_at(receipt_directory, PREIMAGE_NAME)
    except FileNotFoundError:
        if not create_preimage or not _baseline_matches_identity_at(
            binary_directory, name, identity
        ):
            raise ValueError("execd package durable preimage is absent") from None
        current = _prior_target_at(binary_directory, name)
        if current is None:
            raise ValueError("execd package baseline disappeared before custody")
        if not _publish_create_once(
            receipt_directory, PREIMAGE_NAME, current.payload, 0o600, uid, gid
        ):
            raise ValueError("execd package preimage appeared during installation")
        _durable_phase("preimage_captured")
        payload, metadata = _read_regular_at(receipt_directory, PREIMAGE_NAME)
    record = receipt["prior"]["binary"]
    if (
        sha256(payload) != record["sha256"]
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise ValueError("execd package preimage differs")
    return _PriorTarget(
        payload,
        int(record["mode"]),
        int(record["uid"]),
        int(record["gid"]),
        int(identity["device"]),
        int(identity["inode"]),
    )


def _write_install_transaction_at(
    directory_fd: int,
    value: dict[str, object],
    uid: int,
    gid: int,
) -> None:
    _atomic_replace_at(
        directory_fd,
        INSTALL_TRANSACTION_NAME,
        canonical_json(value),
        0o600,
        uid,
        gid,
    )
    _durable_phase(str(value["phase"]))


def _set_install_transaction_phase_at(
    directory_fd: int,
    value: dict[str, object],
    phase: str,
    uid: int,
    gid: int,
) -> dict[str, object]:
    updated = dict(value)
    updated["phase"] = phase
    _write_install_transaction_at(directory_fd, updated, uid, gid)
    return updated


def _ensure_candidate_stage_at(
    binary_directory: int,
    entry: Entry,
    uid: int,
    gid: int,
) -> None:
    try:
        payload, metadata = _read_regular_at(binary_directory, CANDIDATE_STAGE_NAME)
    except FileNotFoundError:
        if not _publish_create_once(
            binary_directory,
            CANDIDATE_STAGE_NAME,
            entry.payload,
            entry.install_mode,
            uid,
            gid,
            temporary_stem=Path(entry.target).name,
        ):
            raise ValueError("execd candidate stage appeared during installation")
        _durable_phase("candidate_staged")
        payload, metadata = _read_regular_at(binary_directory, CANDIDATE_STAGE_NAME)
    if (
        sha256(payload) != entry.sha256
        or stat.S_IMODE(metadata.st_mode) != entry.install_mode
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise ValueError("execd candidate stage differs")


def _read_candidate_identity_at(
    receipt_directory: int,
    manifest: dict[str, object],
    entry: Entry,
    uid: int,
    gid: int,
) -> dict[str, object]:
    return _read_identity_at(
        receipt_directory,
        CANDIDATE_IDENTITY_NAME,
        CANDIDATE_IDENTITY_SCHEMA,
        manifest,
        entry.target,
        entry.sha256,
        entry.install_mode,
        uid,
        gid,
    )


def _ensure_candidate_identity_at(
    receipt_directory: int,
    binary_directory: int,
    manifest: dict[str, object],
    entry: Entry,
    uid: int,
    gid: int,
) -> dict[str, object]:
    _ensure_candidate_stage_at(binary_directory, entry, uid, gid)
    try:
        identity = _read_candidate_identity_at(
            receipt_directory, manifest, entry, uid, gid
        )
    except FileNotFoundError:
        payload, metadata = _read_regular_at(
            binary_directory, CANDIDATE_STAGE_NAME
        )
        identity = _file_identity_value(
            CANDIDATE_IDENTITY_SCHEMA,
            manifest["package_id"],
            manifest["package_digest"],
            manifest["source_commit"],
            entry.target,
            payload,
            metadata,
        )
        if not _publish_create_once(
            receipt_directory,
            CANDIDATE_IDENTITY_NAME,
            canonical_json(identity),
            0o600,
            uid,
            gid,
        ):
            raise ValueError("execd candidate identity appeared during installation")
        _durable_phase("candidate_identity")
        identity = _read_candidate_identity_at(
            receipt_directory, manifest, entry, uid, gid
        )
    if not _identity_matches_at(
        binary_directory, CANDIDATE_STAGE_NAME, identity
    ):
        raise ValueError("execd candidate stage ownership differs")
    return identity


def _renameat2_at(directory_fd: int, source: str, target: str, flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError("renameat2 is unavailable for execd publication")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(target),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def _publish_candidate_cas_at(
    binary_directory: int,
    entry: Entry,
    baseline_identity: dict[str, object],
    candidate_identity: dict[str, object],
    uid: int,
    gid: int,
) -> None:
    name = Path(entry.target).name
    if _identity_matches_at(binary_directory, name, candidate_identity):
        if _absent_at(binary_directory, CANDIDATE_STAGE_NAME):
            return
        if baseline_identity != {"state": "absent"} and _baseline_matches_identity_at(
            binary_directory, CANDIDATE_STAGE_NAME, baseline_identity
        ):
            _remove_if_present_at(binary_directory, CANDIDATE_STAGE_NAME)
            return
        if baseline_identity != {"state": "absent"}:
            _renameat2_at(
                binary_directory,
                CANDIDATE_STAGE_NAME,
                name,
                RENAME_EXCHANGE,
            )
            os.fsync(binary_directory)
            raise ValueError("execd baseline changed at publication")
        raise ValueError("absent-baseline execd candidate retains a stage")
    if not _identity_matches_at(
        binary_directory, CANDIDATE_STAGE_NAME, candidate_identity
    ):
        raise ValueError("execd candidate stage ownership differs")
    if not _baseline_matches_identity_at(binary_directory, name, baseline_identity):
        raise ValueError("execd baseline changed before publication")
    if baseline_identity == {"state": "absent"}:
        try:
            _renameat2_at(
                binary_directory,
                CANDIDATE_STAGE_NAME,
                name,
                RENAME_NOREPLACE,
            )
        except FileExistsError as error:
            raise ValueError("execd baseline changed before publication") from error
    else:
        _renameat2_at(
            binary_directory,
            CANDIDATE_STAGE_NAME,
            name,
            RENAME_EXCHANGE,
        )
    os.fsync(binary_directory)
    _durable_phase("candidate_exchanged")
    if baseline_identity != {"state": "absent"}:
        if not _baseline_matches_identity_at(
            binary_directory, CANDIDATE_STAGE_NAME, baseline_identity
        ):
            _renameat2_at(
                binary_directory,
                CANDIDATE_STAGE_NAME,
                name,
                RENAME_EXCHANGE,
            )
            os.fsync(binary_directory)
            if _binary_matches_at(binary_directory, entry, uid, gid):
                raise ValueError("execd replacement restore differs")
            raise ValueError("execd baseline changed at publication")
        _remove_if_present_at(binary_directory, CANDIDATE_STAGE_NAME)
    _durable_phase("candidate_published")
    if not _identity_matches_at(binary_directory, name, candidate_identity):
        raise ValueError("installed execd candidate ownership differs")


def _remove_if_present_at(directory_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        return
    os.fsync(directory_fd)


def _remove_install_transaction_at(directory_fd: int) -> None:
    _remove_if_present_at(directory_fd, INSTALL_TRANSACTION_NAME)


def _compensate_installed_candidate_cas_at(
    binary_directory: int,
    name: str,
    prior: _PriorTarget | None,
    candidate_identity: dict[str, object],
) -> None:
    if not _absent_at(binary_directory, COMPENSATION_STAGE_NAME):
        if not _identity_matches_at(
            binary_directory, COMPENSATION_STAGE_NAME, candidate_identity
        ):
            raise ValueError("execd compensation stage ownership differs")
        if not _target_matches_prior_at(binary_directory, name, prior):
            raise ValueError("execd install compensation is in recoverable hold")
        _remove_if_present_at(binary_directory, COMPENSATION_STAGE_NAME)
        return

    if prior is None:
        if not _identity_matches_at(binary_directory, name, candidate_identity):
            raise ValueError("execd candidate changed before install compensation")
        try:
            _renameat2_at(
                binary_directory,
                name,
                COMPENSATION_STAGE_NAME,
                RENAME_NOREPLACE,
            )
        except FileExistsError as error:
            raise ValueError(
                "execd compensation stage appeared during mutation"
            ) from error
        os.fsync(binary_directory)
        _durable_phase("install_compensation_exchanged")
        if not _identity_matches_at(
            binary_directory, COMPENSATION_STAGE_NAME, candidate_identity
        ):
            _renameat2_at(
                binary_directory,
                COMPENSATION_STAGE_NAME,
                name,
                RENAME_NOREPLACE,
            )
            os.fsync(binary_directory)
            raise ValueError("execd candidate changed at install compensation")
        if not _absent_at(binary_directory, name):
            raise ValueError("execd install compensation is in recoverable hold")
    else:
        if not _absent_at(binary_directory, COMPENSATION_STAGE_NAME):
            raise ValueError("execd compensation stage is occupied")
        if not _publish_create_once(
            binary_directory,
            COMPENSATION_STAGE_NAME,
            prior.payload,
            prior.mode,
            prior.uid,
            prior.gid,
            temporary_stem=name,
        ):
            raise ValueError("execd compensation stage appeared during publication")
        prior_payload, prior_metadata = _read_regular_at(
            binary_directory, COMPENSATION_STAGE_NAME
        )
        prior_identity = _file_identity_value(
            "execd-install-compensation-stage-v1",
            "",
            "",
            "",
            name,
            prior_payload,
            prior_metadata,
        )
        if not _identity_matches_at(binary_directory, name, candidate_identity):
            _remove_if_present_at(binary_directory, COMPENSATION_STAGE_NAME)
            raise ValueError("execd candidate changed before install compensation")
        _renameat2_at(
            binary_directory,
            COMPENSATION_STAGE_NAME,
            name,
            RENAME_EXCHANGE,
        )
        os.fsync(binary_directory)
        _durable_phase("install_compensation_exchanged")
        if not _identity_matches_at(
            binary_directory, COMPENSATION_STAGE_NAME, candidate_identity
        ):
            _renameat2_at(
                binary_directory,
                COMPENSATION_STAGE_NAME,
                name,
                RENAME_EXCHANGE,
            )
            os.fsync(binary_directory)
            if _identity_matches_at(
                binary_directory, COMPENSATION_STAGE_NAME, prior_identity
            ):
                _remove_if_present_at(binary_directory, COMPENSATION_STAGE_NAME)
            raise ValueError("execd candidate changed at install compensation")
        if not _identity_matches_at(binary_directory, name, prior_identity):
            raise ValueError("execd install compensation is in recoverable hold")
    _remove_if_present_at(binary_directory, COMPENSATION_STAGE_NAME)
    if not _target_matches_prior_at(binary_directory, name, prior):
        raise ValueError("prior execd binary rollback readback differs")


def _compensate_install_transaction_at(
    receipt_directory: int,
    binary_directory: int,
    manifest: dict[str, object],
    entry: Entry,
    prior: _PriorTarget | None,
    identity: dict[str, object],
    uid: int,
    gid: int,
) -> None:
    name = Path(entry.target).name
    try:
        candidate_identity = _read_candidate_identity_at(
            receipt_directory, manifest, entry, uid, gid
        )
    except FileNotFoundError:
        candidate_identity = None
    if candidate_identity is not None and _identity_matches_at(
        binary_directory, name, candidate_identity
    ):
        _compensate_installed_candidate_cas_at(
            binary_directory, name, prior, candidate_identity
        )
    elif candidate_identity is not None and not _absent_at(
        binary_directory, COMPENSATION_STAGE_NAME
    ):
        _compensate_installed_candidate_cas_at(
            binary_directory, name, prior, candidate_identity
        )
    elif not _baseline_matches_identity_at(binary_directory, name, identity):
        # A concurrent replacement owns the live name. Preserve it and release
        # only this transaction's private custody.
        pass
    if not _absent_at(receipt_directory, RECEIPT_NAME):
        payload, metadata = _read_regular_at(
            receipt_directory, RECEIPT_NAME, MAX_JSON_BYTES
        )
        if (
            payload != _receipt_bytes(manifest, prior, uid, gid)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("execd package receipt differs during compensation")
        _remove_created_receipt(receipt_directory)
    if not _absent_at(binary_directory, CANDIDATE_STAGE_NAME):
        if candidate_identity is not None:
            stage_owned = _identity_matches_at(
                binary_directory, CANDIDATE_STAGE_NAME, candidate_identity
            )
        else:
            try:
                stage_payload, stage_metadata = _read_regular_at(
                    binary_directory, CANDIDATE_STAGE_NAME
                )
            except (ValueError, OSError) as error:
                raise ValueError("execd candidate stage differs") from error
            stage_owned = (
                sha256(stage_payload) == entry.sha256
                and stat.S_IMODE(stage_metadata.st_mode) == entry.install_mode
                and stage_metadata.st_uid == uid
                and stage_metadata.st_gid == gid
            )
        if not stage_owned:
            raise ValueError("execd candidate stage ownership differs")
        _remove_if_present_at(binary_directory, CANDIDATE_STAGE_NAME)
    if candidate_identity is not None:
        _remove_if_present_at(receipt_directory, CANDIDATE_IDENTITY_NAME)
    if prior is not None:
        _remove_if_present_at(receipt_directory, PREIMAGE_NAME)
    _remove_install_transaction_at(receipt_directory)


def _verify_receipt_at(
    directory_fd: int,
    manifest: dict[str, object],
    uid: int,
    gid: int,
) -> _PriorTarget | None:
    payload, metadata = _read_regular_at(directory_fd, RECEIPT_NAME, MAX_JSON_BYTES)
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("execd package install receipt is invalid") from error
    if (
        not isinstance(value, dict)
        or canonical_json(value) != payload
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("execd package install receipt differs")
    prior = _receipt_prior(value, manifest, uid, gid)
    if prior is None:
        if not _absent_at(directory_fd, PREIMAGE_NAME):
            raise ValueError("execd package has an unexpected preimage")
        return None
    preimage, preimage_metadata = _read_regular_at(directory_fd, PREIMAGE_NAME)
    if (
        sha256(preimage) != value["prior"]["preimage"]["sha256"]
        or preimage_metadata.st_uid != uid
        or preimage_metadata.st_gid != gid
        or stat.S_IMODE(preimage_metadata.st_mode) != 0o600
    ):
        raise ValueError("execd package preimage differs")
    return _PriorTarget(preimage, prior.mode, prior.uid, prior.gid)


def _publish_create_once(
    directory_fd: int,
    name: str,
    payload: bytes,
    mode: int,
    uid: int,
    gid: int,
    *,
    temporary_stem: str | None = None,
) -> bool:
    temporary = _write_temporary_at(
        directory_fd, temporary_stem or name, payload, mode, uid, gid
    )
    created = False
    try:
        try:
            os.link(
                temporary,
                name,
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
                os.unlink(name, dir_fd=directory_fd)
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


def _publish_receipt(
    directory_fd: int,
    manifest: dict[str, object],
    prior: _PriorTarget | None,
    uid: int,
    gid: int,
) -> bool:
    return _publish_create_once(
        directory_fd,
        RECEIPT_NAME,
        _receipt_bytes(manifest, prior, uid, gid),
        0o600,
        uid,
        gid,
    )


def _remove_created_receipt(directory_fd: int) -> None:
    try:
        os.unlink(RECEIPT_NAME, dir_fd=directory_fd)
    except FileNotFoundError:
        pass
    os.fsync(directory_fd)
    try:
        os.stat(RECEIPT_NAME, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError("execd package receipt remains after rollback")


def inspect(package: Path, root: Path) -> dict[str, object]:
    root = _safe_root(root)
    manifest, entry = parse_package(package)
    _verify_external_seccomp(root)
    activation_receipt = _activation_receipt_state(root, manifest)
    receipt = _verify_install_receipt(root, manifest, absent_ok=True)
    if receipt:
        _verify_installed_candidate_identity(root, manifest, entry)
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


def _complete_install_transaction_at(
    receipt_directory: int,
    binary_directory: int,
    manifest: dict[str, object],
    entry: Entry,
    phase: str,
    prior: _PriorTarget | None,
    identity: dict[str, object],
    uid: int,
    gid: int,
) -> None:
    name = Path(entry.target).name
    if phase == "receipted":
        candidate_identity = _read_candidate_identity_at(
            receipt_directory, manifest, entry, uid, gid
        )
        _verify_receipt_at(receipt_directory, manifest, uid, gid)
        if not _identity_matches_at(binary_directory, name, candidate_identity):
            raise ValueError("receipted execd candidate ownership differs")
        if not _absent_at(binary_directory, CANDIDATE_STAGE_NAME):
            raise ValueError("receipted execd candidate retains a stage")
        _remove_install_transaction_at(receipt_directory)
        _durable_phase("install_complete")
        return
    value = _install_transaction_value(manifest, entry, prior, uid, gid, phase)
    if phase == "intent":
        candidate_identity = _ensure_candidate_identity_at(
            receipt_directory, binary_directory, manifest, entry, uid, gid
        )
    else:
        candidate_identity = _read_candidate_identity_at(
            receipt_directory, manifest, entry, uid, gid
        )

    if phase == "intent":
        if _baseline_matches_identity_at(binary_directory, name, identity):
            value = _set_install_transaction_phase_at(
                receipt_directory, value, "prepared", uid, gid
            )
            phase = "prepared"
        else:
            raise ValueError("execd baseline changed before publication")

    if phase == "prepared":
        _publish_candidate_cas_at(
            binary_directory,
            entry,
            identity,
            candidate_identity,
            uid,
            gid,
        )
        value = _set_install_transaction_phase_at(
            receipt_directory, value, "published", uid, gid
        )
        phase = "published"

    if phase != "published" or not _identity_matches_at(
        binary_directory, name, candidate_identity
    ):
        raise ValueError("installed execd candidate ownership differs")
    if not _binary_matches_at(binary_directory, entry, uid, gid):
        raise ValueError("installed execd binary readback differs")
    receipt_created = _publish_receipt(
        receipt_directory, manifest, prior, uid, gid
    )
    if receipt_created:
        _durable_phase("receipt_published")
    else:
        _verify_receipt_at(receipt_directory, manifest, uid, gid)
    _verify_receipt_at(receipt_directory, manifest, uid, gid)
    value = _set_install_transaction_phase_at(
        receipt_directory, value, "receipted", uid, gid
    )
    _verify_receipt_at(receipt_directory, manifest, uid, gid)
    if not _identity_matches_at(binary_directory, name, candidate_identity):
        raise ValueError("installed execd candidate ownership differs")
    if not _binary_matches_at(binary_directory, entry, uid, gid):
        raise ValueError("installed execd binary readback differs")
    if not _absent_at(binary_directory, CANDIDATE_STAGE_NAME):
        raise ValueError("installed execd candidate retains a stage")
    _remove_install_transaction_at(receipt_directory)
    _durable_phase("install_complete")


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
    lock_fd = -1
    transaction_active = False
    compensation_prior: _PriorTarget | None = None
    compensation_identity: dict[str, object] | None = None
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
        lock_fd = _acquire_install_lock_at(receipt_directory, uid, gid)
        if not _absent_at(receipt_directory, ROLLBACK_RECEIPT_NAME):
            raise ValueError("execd package rollback receipt blocks install replay")

        try:
            phase, prior_stub, identity, transaction_receipt = (
                _read_install_transaction_at(
                    receipt_directory, manifest, entry, uid, gid
                )
            )
            transaction_active = True
        except FileNotFoundError:
            phase = ""
            prior_stub = None
            identity = {}
            transaction_receipt = {}

        if not transaction_active:
            try:
                receipt_prior = _verify_receipt_at(
                    receipt_directory, manifest, uid, gid
                )
            except FileNotFoundError:
                receipt_prior = None
                receipt_present = False
            else:
                receipt_present = True
            if receipt_present:
                candidate_identity = _read_candidate_identity_at(
                    receipt_directory, manifest, entry, uid, gid
                )
                if not _identity_matches_at(
                    binary_directory,
                    Path(entry.target).name,
                    candidate_identity,
                ):
                    raise ValueError(
                        "installed execd candidate ownership differs"
                    )
                result["status"] = "unchanged"
                result["changed_targets"] = []
                result["install_receipt"] = "verified"
                return result
            if not _absent_at(receipt_directory, PREIMAGE_NAME):
                raise ValueError("unreceipted execd package preimage blocks installation")
            if not _absent_at(receipt_directory, CANDIDATE_IDENTITY_NAME):
                raise ValueError(
                    "unreceipted execd candidate identity blocks installation"
                )
            if not _absent_at(binary_directory, CANDIDATE_STAGE_NAME):
                raise ValueError("unreceipted execd candidate stage blocks installation")
            prior = _prior_target_at(binary_directory, Path(entry.target).name)
            transaction = _install_transaction_value(
                manifest, entry, prior, uid, gid, "intent"
            )
            if not _publish_create_once(
                receipt_directory,
                INSTALL_TRANSACTION_NAME,
                canonical_json(transaction),
                0o600,
                uid,
                gid,
            ):
                raise ValueError("execd install transaction appeared during publication")
            _durable_phase("intent")
            phase = "intent"
            prior_stub = prior
            identity = transaction["baseline_identity"]
            transaction_receipt = transaction["install_receipt"]
            transaction_active = True

        if phase == "receipted":
            prior = _verify_receipt_at(receipt_directory, manifest, uid, gid)
        else:
            if (
                phase == "intent"
                and prior_stub is not None
                and _absent_at(receipt_directory, PREIMAGE_NAME)
                and not _baseline_matches_identity_at(
                    binary_directory, Path(entry.target).name, identity
                )
            ):
                _remove_if_present_at(binary_directory, CANDIDATE_STAGE_NAME)
                _remove_install_transaction_at(receipt_directory)
                transaction_active = False
                raise ValueError("execd baseline changed before preimage custody")
            prior = _load_transaction_prior_at(
                receipt_directory,
                binary_directory,
                Path(entry.target).name,
                prior_stub,
                identity,
                transaction_receipt,
                uid,
                gid,
                create_preimage=phase == "intent",
            )
        compensation_prior = prior
        compensation_identity = identity
        _complete_install_transaction_at(
            receipt_directory,
            binary_directory,
            manifest,
            entry,
            phase,
            prior,
            identity,
            uid,
            gid,
        )
        if (
            not _directory_binding_matches(root_fd, ("usr", "libexec"), binary_directory)
            or not _directory_binding_matches(
                root_fd,
                ("var", "lib", "buzzci", "execd-v2", "package"),
                receipt_directory,
            )
        ):
            raise ValueError("execd publication directory changed during installation")
        transaction_active = False
        result["status"] = "installed"
        result["changed_targets"] = [entry.target, str(freeze_package.INSTALL_RECEIPT["path"])]
        result["install_receipt"] = "verified"
        return result
    except BaseException as install_error:
        if (
            transaction_active
            and compensation_identity is not None
            and receipt_directory >= 0
            and binary_directory >= 0
        ):
            try:
                _compensate_install_transaction_at(
                    receipt_directory,
                    binary_directory,
                    manifest,
                    entry,
                    compensation_prior,
                    compensation_identity,
                    uid,
                    gid,
                )
            except BaseException as compensation_error:
                raise RuntimeError(
                    f"execd installation compensation failed: {compensation_error}"
                ) from install_error
        raise
    finally:
        if lock_fd >= 0:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        if receipt_directory >= 0:
            os.close(receipt_directory)
        if binary_directory >= 0:
            os.close(binary_directory)
        os.close(root_fd)


def _rollback_live_target_value(
    prior: _PriorTarget | None,
    state: str,
    rollback_identity: dict[str, object] | None = None,
) -> dict[str, object]:
    if prior is None:
        if rollback_identity is not None:
            raise ValueError("absent execd baseline has a live identity")
        return {"state": "absent"}
    elif rollback_identity is None:
        if state != "rolling_back":
            raise ValueError("execd rollback receipt lacks a live identity")
        return {"state": "pending"}
    return {
        "state": "present",
        "device": rollback_identity["device"],
        "inode": rollback_identity["inode"],
        "sha256": rollback_identity["sha256"],
        "mode": rollback_identity["mode"],
        "uid": rollback_identity["uid"],
        "gid": rollback_identity["gid"],
    }


def _rollback_receipt_bytes(
    manifest: dict[str, object],
    prior: _PriorTarget | None,
    uid: int,
    gid: int,
    state: str,
    rollback_identity: dict[str, object] | None = None,
) -> bytes:
    if state not in {"rolling_back", "holding", "rolled_back"}:
        raise ValueError("invalid execd rollback receipt state")
    live_target = _rollback_live_target_value(
        prior, state, rollback_identity
    )
    return canonical_json({
        "schema": "buzz-ci-execd-package-rollback-receipt-v1",
        "state": state,
        "install_receipt": _receipt_value(manifest, prior, uid, gid),
        "live_target": live_target,
    })


def _atomic_replace_at(
    directory_fd: int,
    name: str,
    payload: bytes,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    temporary = _write_temporary_at(directory_fd, name, payload, mode, uid, gid)
    try:
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary = ""
        os.fsync(directory_fd)
    finally:
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass


def _rollback_terminal_race(_phase: str) -> None:
    """Test seam around the nonblocking terminal publication sequence."""


def _publish_rollback_terminal_at(
    receipt_directory: int,
    binary_directory: int,
    manifest: dict[str, object],
    entry: Entry,
    prior: _PriorTarget | None,
    rollback_identity: dict[str, object] | None,
    uid: int,
    gid: int,
) -> None:
    expected = _rollback_receipt_bytes(
        manifest,
        prior,
        uid,
        gid,
        "rolled_back",
        rollback_identity,
    )
    _publish_create_once(
        receipt_directory,
        ROLLBACK_TERMINAL_STAGE_NAME,
        expected,
        0o600,
        uid,
        gid,
    )
    payload, metadata = _read_regular_at(
        receipt_directory,
        ROLLBACK_TERMINAL_STAGE_NAME,
        MAX_JSON_BYTES,
    )
    if (
        payload != expected
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise ValueError("execd rollback terminal stage differs")
    _rollback_terminal_race("temp_fsynced")
    _durable_phase("rollback_terminal_prepared")
    _rollback_terminal_race("before_publish")
    if not _rollback_live_matches_intended_at(
        binary_directory, entry, prior, rollback_identity
    ):
        raise _RollbackHoldError(
            "execd rollback is in recoverable hold: live target changed"
        )
    os.replace(
        ROLLBACK_TERMINAL_STAGE_NAME,
        ROLLBACK_RECEIPT_NAME,
        src_dir_fd=receipt_directory,
        dst_dir_fd=receipt_directory,
    )
    _rollback_terminal_race("after_publish")
    if not _rollback_live_matches_intended_at(
        binary_directory, entry, prior, rollback_identity
    ):
        raise _RollbackHoldError(
            "execd rollback is in recoverable hold: live target changed"
        )
    os.fsync(receipt_directory)
    _durable_phase("rollback_terminal_committed")
    _rollback_terminal_race("after_commit")
    if not _rollback_live_matches_intended_at(
        binary_directory, entry, prior, rollback_identity
    ):
        raise _RollbackHoldError(
            "execd rollback is in recoverable hold: live target changed"
        )


def _read_rollback_receipt_at(
    directory_fd: int,
    manifest: dict[str, object],
    uid: int,
    gid: int,
) -> tuple[
    str,
    _PriorTarget | None,
    dict[str, object],
    dict[str, object],
]:
    payload, metadata = _read_regular_at(
        directory_fd, ROLLBACK_RECEIPT_NAME, MAX_JSON_BYTES
    )
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("execd package rollback receipt is invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "state", "install_receipt", "live_target"}
        or value.get("schema") != "buzz-ci-execd-package-rollback-receipt-v1"
        or value.get("state") not in {"rolling_back", "holding", "rolled_back"}
        or not isinstance(value.get("install_receipt"), dict)
        or canonical_json(value) != payload
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("execd package rollback receipt differs")
    install_receipt = value["install_receipt"]
    prior = _receipt_prior(install_receipt, manifest, uid, gid)
    live_target = value.get("live_target")
    if prior is None:
        live_valid = live_target == {"state": "absent"}
    elif live_target == {"state": "pending"}:
        live_valid = value["state"] == "rolling_back"
    else:
        prior_record = install_receipt["prior"]["binary"]
        live_valid = (
            isinstance(live_target, dict)
            and set(live_target)
            == {"state", "device", "inode", "sha256", "mode", "uid", "gid"}
            and live_target.get("state") == "present"
            and not isinstance(live_target.get("device"), bool)
            and isinstance(live_target.get("device"), int)
            and int(live_target["device"]) >= 0
            and not isinstance(live_target.get("inode"), bool)
            and isinstance(live_target.get("inode"), int)
            and int(live_target["inode"]) > 0
            and live_target.get("sha256") == prior_record["sha256"]
            and live_target.get("mode") == prior_record["mode"]
            and live_target.get("uid") == prior_record["uid"]
            and live_target.get("gid") == prior_record["gid"]
        )
    if not live_valid:
        raise ValueError("execd package rollback live binding differs")
    assert isinstance(live_target, dict)
    return str(value["state"]), prior, install_receipt, live_target


def _resume_prior_at(
    receipt_directory: int,
    binary_directory: int,
    entry: Entry,
    prior: _PriorTarget | None,
    install_receipt: dict[str, object],
    uid: int,
    gid: int,
) -> _PriorTarget | None:
    if prior is None:
        if not _absent_at(receipt_directory, PREIMAGE_NAME):
            raise ValueError("absent execd baseline has an unexpected preimage")
        return None
    record = install_receipt["prior"]["binary"]
    try:
        payload, metadata = _read_regular_at(receipt_directory, PREIMAGE_NAME)
        from_preimage = True
    except FileNotFoundError:
        payload, metadata = _read_regular_at(binary_directory, Path(entry.target).name)
        from_preimage = False
    if (
        sha256(payload) != record["sha256"]
        or (
            from_preimage
            and (
                stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != uid
                or metadata.st_gid != gid
            )
        )
        or (
            not from_preimage
            and (
                stat.S_IMODE(metadata.st_mode) != int(record["mode"])
                or metadata.st_uid != int(record["uid"])
                or metadata.st_gid != int(record["gid"])
            )
        )
    ):
        raise ValueError("rolling-back execd preimage differs")
    return _PriorTarget(
        payload,
        int(record["mode"]),
        int(record["uid"]),
        int(record["gid"]),
    )


def _target_matches_prior_at(
    directory_fd: int,
    name: str,
    prior: _PriorTarget | None,
) -> bool:
    if prior is None:
        return _absent_at(directory_fd, name)
    try:
        payload, metadata = _read_regular_at(directory_fd, name)
    except (FileNotFoundError, ValueError, OSError):
        return False
    return (
        sha256(payload) == sha256(prior.payload)
        and stat.S_IMODE(metadata.st_mode) == prior.mode
        and metadata.st_uid == prior.uid
        and metadata.st_gid == prior.gid
    )


def _read_rollback_stage_identity_at(
    receipt_directory: int,
    manifest: dict[str, object],
    entry: Entry,
    prior: _PriorTarget,
    uid: int,
    gid: int,
) -> dict[str, object]:
    return _read_identity_at(
        receipt_directory,
        ROLLBACK_STAGE_IDENTITY_NAME,
        ROLLBACK_STAGE_IDENTITY_SCHEMA,
        manifest,
        entry.target,
        sha256(prior.payload),
        prior.mode,
        prior.uid,
        prior.gid,
        identity_uid=uid,
        identity_gid=gid,
    )


def _ensure_rollback_stage_identity_at(
    receipt_directory: int,
    binary_directory: int,
    manifest: dict[str, object],
    entry: Entry,
    prior: _PriorTarget | None,
    uid: int,
    gid: int,
) -> dict[str, object] | None:
    if prior is None:
        if not _absent_at(receipt_directory, ROLLBACK_STAGE_IDENTITY_NAME):
            raise ValueError("absent execd baseline has a rollback stage identity")
        return None
    try:
        identity = _read_rollback_stage_identity_at(
            receipt_directory, manifest, entry, prior, uid, gid
        )
    except FileNotFoundError:
        if not _absent_at(binary_directory, ROLLBACK_STAGE_NAME):
            raise ValueError("unbound execd rollback stage blocks rollback")
        if not _publish_create_once(
            binary_directory,
            ROLLBACK_STAGE_NAME,
            prior.payload,
            prior.mode,
            prior.uid,
            prior.gid,
            temporary_stem=Path(entry.target).name,
        ):
            raise ValueError("execd rollback stage appeared during publication")
        payload, metadata = _read_regular_at(binary_directory, ROLLBACK_STAGE_NAME)
        identity = _file_identity_value(
            ROLLBACK_STAGE_IDENTITY_SCHEMA,
            manifest["package_id"],
            manifest["package_digest"],
            manifest["source_commit"],
            entry.target,
            payload,
            metadata,
        )
        if not _publish_create_once(
            receipt_directory,
            ROLLBACK_STAGE_IDENTITY_NAME,
            canonical_json(identity),
            0o600,
            uid,
            gid,
        ):
            raise ValueError("execd rollback stage identity appeared during publication")
        _durable_phase("rollback_stage_identity")
        identity = _read_rollback_stage_identity_at(
            receipt_directory, manifest, entry, prior, uid, gid
        )
    if not (
        _identity_matches_at(binary_directory, ROLLBACK_STAGE_NAME, identity)
        or _identity_matches_at(
            binary_directory, Path(entry.target).name, identity
        )
    ):
        raise ValueError("execd rollback stage ownership differs")
    return identity


def _rollback_candidate_cas_at(
    binary_directory: int,
    entry: Entry,
    prior: _PriorTarget | None,
    candidate_identity: dict[str, object],
    rollback_identity: dict[str, object] | None,
) -> None:
    name = Path(entry.target).name
    candidate_live = _identity_matches_at(
        binary_directory, name, candidate_identity
    )
    candidate_stage = _identity_matches_at(
        binary_directory, ROLLBACK_STAGE_NAME, candidate_identity
    )
    if prior is None:
        if _absent_at(binary_directory, name) and candidate_stage:
            return
        if not candidate_live:
            raise ValueError("installed execd candidate ownership changed before rollback")
        if not _absent_at(binary_directory, ROLLBACK_STAGE_NAME):
            raise ValueError("execd rollback stage is occupied")
        try:
            _renameat2_at(
                binary_directory,
                name,
                ROLLBACK_STAGE_NAME,
                RENAME_NOREPLACE,
            )
        except FileExistsError as error:
            raise ValueError("execd rollback stage appeared during mutation") from error
        os.fsync(binary_directory)
        _durable_phase("rollback_exchanged")
        if not _identity_matches_at(
            binary_directory, ROLLBACK_STAGE_NAME, candidate_identity
        ):
            _renameat2_at(
                binary_directory,
                ROLLBACK_STAGE_NAME,
                name,
                RENAME_NOREPLACE,
            )
            os.fsync(binary_directory)
            raise ValueError("execd candidate changed at rollback mutation")
        return

    assert rollback_identity is not None
    prior_live = _identity_matches_at(binary_directory, name, rollback_identity)
    prior_stage = _identity_matches_at(
        binary_directory, ROLLBACK_STAGE_NAME, rollback_identity
    )
    if prior_live:
        if candidate_stage:
            return
        if not _absent_at(binary_directory, ROLLBACK_STAGE_NAME):
            _renameat2_at(
                binary_directory,
                ROLLBACK_STAGE_NAME,
                name,
                RENAME_EXCHANGE,
            )
            os.fsync(binary_directory)
            raise ValueError("execd candidate changed at rollback mutation")
        raise ValueError("rolling-back execd candidate custody is absent")
    if not candidate_live or not prior_stage:
        raise ValueError("installed execd candidate ownership changed before rollback")
    _renameat2_at(
        binary_directory,
        ROLLBACK_STAGE_NAME,
        name,
        RENAME_EXCHANGE,
    )
    os.fsync(binary_directory)
    _durable_phase("rollback_exchanged")
    if not _identity_matches_at(
        binary_directory, ROLLBACK_STAGE_NAME, candidate_identity
    ):
        _renameat2_at(
            binary_directory,
            ROLLBACK_STAGE_NAME,
            name,
            RENAME_EXCHANGE,
        )
        os.fsync(binary_directory)
        raise ValueError("execd candidate changed at rollback mutation")


def _compensate_rollback_publication_at(
    binary_directory: int,
    entry: Entry,
    prior: _PriorTarget | None,
    candidate_identity: dict[str, object],
    rollback_identity: dict[str, object] | None,
) -> None:
    name = Path(entry.target).name
    if _identity_matches_at(binary_directory, name, candidate_identity):
        return
    if not _identity_matches_at(
        binary_directory, ROLLBACK_STAGE_NAME, candidate_identity
    ):
        return
    if prior is None:
        if not _absent_at(binary_directory, name):
            return
        _renameat2_at(
            binary_directory,
            ROLLBACK_STAGE_NAME,
            name,
            RENAME_NOREPLACE,
        )
    else:
        assert rollback_identity is not None
        if not _identity_matches_at(binary_directory, name, rollback_identity):
            return
        _renameat2_at(
            binary_directory,
            ROLLBACK_STAGE_NAME,
            name,
            RENAME_EXCHANGE,
        )
    os.fsync(binary_directory)
    if not _identity_matches_at(binary_directory, name, candidate_identity):
        raise ValueError("execd rollback candidate compensation differs")


def _finalize_rollback_stages_at(
    receipt_directory: int,
    binary_directory: int,
    candidate_identity: dict[str, object],
) -> None:
    if not _absent_at(binary_directory, ROLLBACK_STAGE_NAME):
        if not _identity_matches_at(
            binary_directory, ROLLBACK_STAGE_NAME, candidate_identity
        ):
            raise ValueError("terminal execd rollback stage ownership differs")
        _remove_if_present_at(binary_directory, ROLLBACK_STAGE_NAME)
    _remove_if_present_at(receipt_directory, ROLLBACK_STAGE_IDENTITY_NAME)


def _remove_rollback_managed_at(directory_fd: int, prior: _PriorTarget | None) -> None:
    try:
        os.unlink(RECEIPT_NAME, dir_fd=directory_fd)
    except FileNotFoundError:
        pass
    if prior is not None:
        try:
            os.unlink(PREIMAGE_NAME, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
    os.fsync(directory_fd)


def _rollback_live_matches_intended_at(
    binary_directory: int,
    entry: Entry,
    prior: _PriorTarget | None,
    rollback_identity: dict[str, object] | None,
) -> bool:
    name = Path(entry.target).name
    if prior is None:
        return _absent_at(binary_directory, name)
    assert rollback_identity is not None
    return _identity_matches_at(binary_directory, name, rollback_identity)


def _rollback_live_matches_binding_at(
    binary_directory: int,
    entry: Entry,
    live_target: dict[str, object],
) -> bool:
    if live_target == {"state": "absent"}:
        return _absent_at(binary_directory, Path(entry.target).name)
    if live_target.get("state") != "present":
        return False
    return _identity_matches_at(
        binary_directory, Path(entry.target).name, live_target
    )


def _restore_active_rollback_custody_at(
    receipt_directory: int,
    manifest: dict[str, object],
    prior: _PriorTarget | None,
    uid: int,
    gid: int,
) -> None:
    if prior is not None:
        expected_preimage = prior.payload
        try:
            payload, metadata = _read_regular_at(receipt_directory, PREIMAGE_NAME)
        except FileNotFoundError:
            if not _publish_create_once(
                receipt_directory,
                PREIMAGE_NAME,
                expected_preimage,
                0o600,
                uid,
                gid,
            ):
                raise ValueError("execd rollback preimage appeared during hold")
        else:
            if (
                payload != expected_preimage
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != uid
                or metadata.st_gid != gid
            ):
                raise ValueError("execd rollback preimage differs during hold")
    elif not _absent_at(receipt_directory, PREIMAGE_NAME):
        raise ValueError("absent execd baseline has an unexpected preimage")

    expected_receipt = _receipt_bytes(manifest, prior, uid, gid)
    try:
        payload, metadata = _read_regular_at(
            receipt_directory, RECEIPT_NAME, MAX_JSON_BYTES
        )
    except FileNotFoundError:
        if not _publish_create_once(
            receipt_directory,
            RECEIPT_NAME,
            expected_receipt,
            0o600,
            uid,
            gid,
        ):
            raise ValueError("execd install receipt appeared during rollback hold")
    else:
        if (
            payload != expected_receipt
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != uid
            or metadata.st_gid != gid
        ):
            raise ValueError("execd install receipt differs during rollback hold")
    _verify_receipt_at(receipt_directory, manifest, uid, gid)


def _enter_rollback_hold_at(
    receipt_directory: int,
    manifest: dict[str, object],
    prior: _PriorTarget | None,
    rollback_identity: dict[str, object] | None,
    uid: int,
    gid: int,
) -> None:
    _restore_active_rollback_custody_at(
        receipt_directory, manifest, prior, uid, gid
    )
    _atomic_replace_at(
        receipt_directory,
        ROLLBACK_RECEIPT_NAME,
        _rollback_receipt_bytes(
            manifest,
            prior,
            uid,
            gid,
            "holding",
            rollback_identity,
        ),
        0o600,
        uid,
        gid,
    )
    state, _, _, _ = _read_rollback_receipt_at(
        receipt_directory, manifest, uid, gid
    )
    if state != "holding":
        raise ValueError("execd rollback hold readback differs")


def _compensate_rollback(
    receipt_directory: int,
    binary_directory: int,
    manifest: dict[str, object],
    entry: Entry,
    prior: _PriorTarget | None,
    candidate_identity: dict[str, object],
    rollback_identity: dict[str, object] | None,
    uid: int,
    gid: int,
) -> None:
    if not _absent_at(receipt_directory, ROLLBACK_TERMINAL_STAGE_NAME):
        payload, metadata = _read_regular_at(
            receipt_directory,
            ROLLBACK_TERMINAL_STAGE_NAME,
            MAX_JSON_BYTES,
        )
        if (
            payload
            != _rollback_receipt_bytes(
                manifest,
                prior,
                uid,
                gid,
                "rolled_back",
                rollback_identity,
            )
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != uid
            or metadata.st_gid != gid
        ):
            raise ValueError("execd rollback terminal stage differs")
        _remove_if_present_at(
            receipt_directory, ROLLBACK_TERMINAL_STAGE_NAME
        )
    _compensate_rollback_publication_at(
        binary_directory,
        entry,
        prior,
        candidate_identity,
        rollback_identity,
    )
    if prior is not None:
        _atomic_replace_at(
            receipt_directory,
            PREIMAGE_NAME,
            prior.payload,
            0o600,
            uid,
            gid,
        )
    elif not _absent_at(receipt_directory, PREIMAGE_NAME):
        os.unlink(PREIMAGE_NAME, dir_fd=receipt_directory)
    _atomic_replace_at(
        receipt_directory,
        RECEIPT_NAME,
        _receipt_bytes(manifest, prior, uid, gid),
        0o600,
        uid,
        gid,
    )
    try:
        os.unlink(ROLLBACK_RECEIPT_NAME, dir_fd=receipt_directory)
    except FileNotFoundError:
        pass
    if not _absent_at(binary_directory, ROLLBACK_STAGE_NAME):
        if rollback_identity is None or not _identity_matches_at(
            binary_directory, ROLLBACK_STAGE_NAME, rollback_identity
        ):
            raise ValueError("execd rollback compensation stage differs")
        _remove_if_present_at(binary_directory, ROLLBACK_STAGE_NAME)
    _remove_if_present_at(receipt_directory, ROLLBACK_STAGE_IDENTITY_NAME)
    os.fsync(receipt_directory)
    _verify_receipt_at(receipt_directory, manifest, uid, gid)


def rollback(package: Path, root: Path) -> dict[str, object]:
    root = _safe_root(root)
    manifest, entry = parse_package(package)
    if root == Path("/") and os.geteuid() != 0:
        raise PermissionError("rollback requires root")
    uid = mapped_id(0, root)
    gid = mapped_id(0, root, group=True)
    root_fd = _open_root(root)
    binary_directory = -1
    receipt_directory = -1
    lock_fd = -1
    try:
        binary_directory = _open_directory_chain(
            root_fd,
            (("usr", None), ("libexec", 0o755)),
            uid,
            gid,
            create=False,
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
            create=False,
        )
        lock_fd = _acquire_install_lock_at(receipt_directory, uid, gid)
        if (
            not _directory_binding_matches(root_fd, ("usr", "libexec"), binary_directory)
            or not _directory_binding_matches(
                root_fd,
                ("var", "lib", "buzzci", "execd-v2", "package"),
                receipt_directory,
            )
        ):
            raise ValueError("execd rollback directory binding differs")
        try:
            install_phase, install_prior_stub, install_identity, install_receipt = (
                _read_install_transaction_at(
                    receipt_directory, manifest, entry, uid, gid
                )
            )
        except FileNotFoundError:
            pass
        else:
            if install_phase == "receipted":
                install_prior = _verify_receipt_at(
                    receipt_directory, manifest, uid, gid
                )
            else:
                if (
                    install_phase == "intent"
                    and install_prior_stub is not None
                    and _absent_at(receipt_directory, PREIMAGE_NAME)
                    and not _baseline_matches_identity_at(
                        binary_directory,
                        Path(entry.target).name,
                        install_identity,
                    )
                ):
                    _remove_if_present_at(
                        binary_directory, CANDIDATE_STAGE_NAME
                    )
                    _remove_install_transaction_at(receipt_directory)
                    raise ValueError(
                        "execd baseline changed before preimage custody"
                    )
                install_prior = _load_transaction_prior_at(
                    receipt_directory,
                    binary_directory,
                    Path(entry.target).name,
                    install_prior_stub,
                    install_identity,
                    install_receipt,
                    uid,
                    gid,
                    create_preimage=install_phase == "intent",
                )
            try:
                _complete_install_transaction_at(
                    receipt_directory,
                    binary_directory,
                    manifest,
                    entry,
                    install_phase,
                    install_prior,
                    install_identity,
                    uid,
                    gid,
                )
            except BaseException as install_recovery_error:
                try:
                    _compensate_install_transaction_at(
                        receipt_directory,
                        binary_directory,
                        manifest,
                        entry,
                        install_prior,
                        install_identity,
                        uid,
                        gid,
                    )
                except BaseException as compensation_error:
                    raise RuntimeError(
                        "execd interrupted-install compensation failed: "
                        f"{compensation_error}"
                    ) from install_recovery_error
                raise
        candidate_identity = _read_candidate_identity_at(
            receipt_directory, manifest, entry, uid, gid
        )
        try:
            (
                marker_state,
                marker_prior,
                marker_receipt,
                marker_live_target,
            ) = _read_rollback_receipt_at(receipt_directory, manifest, uid, gid)
        except FileNotFoundError:
            marker_state = "absent"
            marker_prior = None
            marker_receipt = None
            marker_live_target = None
        if marker_state == "rolled_back":
            assert marker_receipt is not None
            assert marker_live_target is not None
            prior_record = marker_receipt["prior"]
            active_custody = not _absent_at(receipt_directory, RECEIPT_NAME)
            if active_custody:
                active_prior = _verify_receipt_at(
                    receipt_directory, manifest, uid, gid
                )
                if (active_prior is None) != (marker_prior is None) or (
                    active_prior is not None
                    and marker_prior is not None
                    and (
                        active_prior.mode != marker_prior.mode
                        or active_prior.uid != marker_prior.uid
                        or active_prior.gid != marker_prior.gid
                    )
                ):
                    raise ValueError("rolled-back execd active custody differs")
            else:
                active_prior = None
                if not _absent_at(receipt_directory, PREIMAGE_NAME):
                    raise ValueError("rolled-back execd package retains a preimage")
            if not _rollback_live_matches_binding_at(
                binary_directory, entry, marker_live_target
            ):
                candidate_retained = _identity_matches_at(
                    binary_directory,
                    ROLLBACK_STAGE_NAME,
                    candidate_identity,
                )
                if active_custody and candidate_retained:
                    rollback_identity = (
                        None
                        if marker_prior is None
                        else marker_live_target
                    )
                    _enter_rollback_hold_at(
                        receipt_directory,
                        manifest,
                        active_prior,
                        rollback_identity,
                        uid,
                        gid,
                    )
                    _durable_phase("rollback_holding")
                    raise ValueError(
                        "execd rollback is in recoverable hold: "
                        "terminal live target changed"
                    )
                raise ValueError("rolled-back execd live binding differs")
            if active_custody:
                _remove_rollback_managed_at(receipt_directory, active_prior)
            _finalize_rollback_stages_at(
                receipt_directory, binary_directory, candidate_identity
            )
            return {
                "status": "unchanged",
                "state": "rolled_back",
                "package_id": manifest["package_id"],
                "package_digest": manifest["package_digest"],
                "restored_target": entry.target,
                "prior_state": prior_record["state"],
            }
        if marker_state in {"rolling_back", "holding"}:
            assert marker_receipt is not None
            assert marker_live_target is not None
            prior = _resume_prior_at(
                receipt_directory,
                binary_directory,
                entry,
                marker_prior,
                marker_receipt,
                uid,
                gid,
            )
            candidate_current = _identity_matches_at(
                binary_directory,
                Path(entry.target).name,
                candidate_identity,
            )
            candidate_retained = _identity_matches_at(
                binary_directory,
                ROLLBACK_STAGE_NAME,
                candidate_identity,
            )
            prior_current = _target_matches_prior_at(
                binary_directory, Path(entry.target).name, prior
            )
            if not candidate_current and not prior_current and not candidate_retained:
                raise ValueError("rolling-back execd binary differs from candidate and baseline")
            try:
                active_prior = _verify_receipt_at(
                    receipt_directory, manifest, uid, gid
                )
                if active_prior != prior:
                    raise ValueError("rolling-back execd active custody differs")
            except FileNotFoundError:
                if marker_state == "holding" or (
                    not prior_current and not candidate_retained
                ):
                    raise ValueError(
                        "rolling-back execd candidate lacks active custody"
                    ) from None
        else:
            prior = _verify_receipt_at(receipt_directory, manifest, uid, gid)
            if not _identity_matches_at(
                binary_directory,
                Path(entry.target).name,
                candidate_identity,
            ):
                raise ValueError(
                    "installed execd binary drift blocks rollback: "
                    "candidate ownership changed"
                )
            if not _absent_at(receipt_directory, ROLLBACK_RECEIPT_NAME):
                raise ValueError("execd rollback receipt appeared during validation")
            rolling = _rollback_receipt_bytes(
                manifest, prior, uid, gid, "rolling_back"
            )
            if not _publish_create_once(
                receipt_directory,
                ROLLBACK_RECEIPT_NAME,
                rolling,
                0o600,
                uid,
                gid,
            ):
                raise ValueError("execd rollback receipt appeared during publication")
            _durable_phase("rollback_intent")
        candidate_retained = _identity_matches_at(
            binary_directory,
            ROLLBACK_STAGE_NAME,
            candidate_identity,
        )
        if marker_state in {"rolling_back", "holding"} and candidate_retained:
            if prior is None:
                rollback_identity = None
                if not _absent_at(
                    receipt_directory, ROLLBACK_STAGE_IDENTITY_NAME
                ):
                    raise ValueError(
                        "absent execd baseline has a rollback stage identity"
                    )
            else:
                rollback_identity = _read_rollback_stage_identity_at(
                    receipt_directory, manifest, entry, prior, uid, gid
                )
        else:
            rollback_identity = _ensure_rollback_stage_identity_at(
                receipt_directory,
                binary_directory,
                manifest,
                entry,
                prior,
                uid,
                gid,
            )
        if marker_state == "holding" and marker_live_target != (
            _rollback_live_target_value(prior, "holding", rollback_identity)
        ):
            raise ValueError("execd rollback hold live binding differs")
        try:
            if candidate_retained and not _rollback_live_matches_intended_at(
                binary_directory, entry, prior, rollback_identity
            ):
                raise _RollbackHoldError(
                    "execd rollback is in recoverable hold: live target changed"
                )
            _rollback_candidate_cas_at(
                binary_directory,
                entry,
                prior,
                candidate_identity,
                rollback_identity,
            )
            _durable_phase("rollback_restored")
            if not _directory_binding_matches(root_fd, ("usr", "libexec"), binary_directory):
                raise ValueError("execd binary directory changed during rollback")
            _publish_rollback_terminal_at(
                receipt_directory,
                binary_directory,
                manifest,
                entry,
                prior,
                rollback_identity,
                uid,
                gid,
            )
            state, _, _, live_target = _read_rollback_receipt_at(
                receipt_directory, manifest, uid, gid
            )
            if (
                state != "rolled_back"
                or live_target
                != _rollback_live_target_value(
                    prior, "rolled_back", rollback_identity
                )
                or not _rollback_live_matches_intended_at(
                    binary_directory, entry, prior, rollback_identity
                )
            ):
                raise ValueError("execd rollback terminal readback differs")
            _remove_rollback_managed_at(receipt_directory, prior)
            _durable_phase("rollback_released")
            if not _rollback_live_matches_intended_at(
                binary_directory, entry, prior, rollback_identity
            ):
                raise _RollbackHoldError(
                    "execd rollback is in recoverable hold: live target changed"
                )
            _durable_phase("rollback_complete")
            _finalize_rollback_stages_at(
                receipt_directory, binary_directory, candidate_identity
            )
        except _RollbackHoldError as rollback_error:
            _enter_rollback_hold_at(
                receipt_directory,
                manifest,
                prior,
                rollback_identity,
                uid,
                gid,
            )
            _durable_phase("rollback_holding")
            raise ValueError(str(rollback_error)) from rollback_error
        except BaseException as rollback_error:
            try:
                _compensate_rollback(
                    receipt_directory,
                    binary_directory,
                    manifest,
                    entry,
                    prior,
                    candidate_identity,
                    rollback_identity,
                    uid,
                    gid,
                )
            except BaseException as compensation_error:
                raise RuntimeError(
                    f"execd rollback compensation failed: {compensation_error}"
                ) from rollback_error
            raise
        return {
            "status": "rolled_back",
            "state": "rolled_back",
            "package_id": manifest["package_id"],
            "package_digest": manifest["package_digest"],
            "restored_target": entry.target,
            "prior_state": "absent" if prior is None else "present",
        }
    finally:
        if lock_fd >= 0:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
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
    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument("--package", type=Path, required=True)
    rollback_parser.add_argument("--root", type=Path, default=Path("/"))
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
    elif arguments.command == "install":
        result = install(arguments.package, arguments.root, dry_run=arguments.dry_run)
    else:
        result = rollback(arguments.package, arguments.root)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
