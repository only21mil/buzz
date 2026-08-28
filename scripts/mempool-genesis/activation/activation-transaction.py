#!/usr/bin/env python3
"""Fail-closed Mempool/Genesis activation and rollback state machine."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any

STATE_SCHEMA = "buzz-mempool-genesis-activation-transaction-v1"
PHASE_SCHEMA = "buzz-mempool-genesis-phase-gate-v1"
SEALED_RECEIPT_SCHEMA = "buzz-agent-capability-parity-sealed-receipt-v1"
PARITY_RECEIPT_SCHEMA = "buzz-agent-capability-parity-receipt-v2"
CHANNEL_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SLUGS = ("mempool", "genesis")


class TransactionError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TransactionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, *, owner_only: bool = True) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (owner_only and stat.S_IMODE(metadata.st_mode) & 0o077)
    ):
        raise TransactionError(f"unsafe private JSON: {path}")
    value = json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise TransactionError(f"private JSON is not an object: {path}")
    return value


def safe_directory(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise TransactionError(f"unsafe transaction directory: {path}")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_private(path: Path, payload: bytes, *, replace: bool = False) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.new")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short private write")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if not replace and (path.exists() or path.is_symlink()):
        temporary.unlink()
        raise TransactionError(f"refusing to replace transaction artifact: {path}")
    os.replace(temporary, path)
    fsync_directory(path.parent)


def write_state(state_dir: Path, value: dict[str, Any]) -> None:
    write_private(state_dir / "state.json", canonical_json(value), replace=True)


def read_state(state_dir: Path) -> dict[str, Any]:
    safe_directory(state_dir)
    value = load_json(state_dir / "state.json")
    if value.get("schema") != STATE_SCHEMA:
        raise TransactionError("activation transaction schema mismatch")
    return value


def copy_exact(source: Path, destination: Path) -> None:
    metadata = source.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise TransactionError(f"unsafe credential file: {source}")
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    destination_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        while chunk := os.read(source_fd, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("short credential backup write")
                view = view[written:]
        os.fchmod(destination_fd, stat.S_IMODE(metadata.st_mode))
        if os.geteuid() == 0:
            os.fchown(destination_fd, metadata.st_uid, metadata.st_gid)
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)
    fsync_directory(destination.parent)


def descriptor(path: Path, path_class: str) -> dict[str, object]:
    if not path.exists() and not path.is_symlink():
        return {"path_class": path_class, "present": False}
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise TransactionError(f"unsafe credential state: {path_class}")
    digest = hashlib.sha256()
    descriptor_fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    size = 0
    try:
        while chunk := os.read(descriptor_fd, 1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    finally:
        os.close(descriptor_fd)
    return {
        "path_class": path_class,
        "present": True,
        "length": size,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "nlink": metadata.st_nlink,
        "sha256_prefix": digest.hexdigest()[:12],
    }


def same_bytes(left: Path, right: Path) -> bool:
    if not left.is_file() or left.is_symlink() or not right.is_file() or right.is_symlink():
        return False
    if left.stat().st_size != right.stat().st_size:
        return False
    left_fd = os.open(left, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    right_fd = os.open(right, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        while True:
            a = os.read(left_fd, 1024 * 1024)
            b = os.read(right_fd, 1024 * 1024)
            if a != b:
                return False
            if not a:
                return True
    finally:
        os.close(right_fd)
        os.close(left_fd)


def load_parity_module(script: Path):
    spec = importlib.util.spec_from_file_location("mgact_activation_parity", script)
    if spec is None or spec.loader is None:
        raise TransactionError("cannot load parity verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manifest_bound_runtime_tool(
    manifest: dict[str, Any], path: Path, root: Path
) -> None:
    records = manifest.get("runtime_targets")
    if not isinstance(records, list):
        raise TransactionError("manifest runtime target inventory is absent")
    target = "/usr/local/libexec/buzz/verify-agent-capability-parity"
    matches = [item for item in records if isinstance(item, dict) and item.get("target") == target]
    if len(matches) != 1:
        raise TransactionError("manifest parity runtime target is not unique")
    record = matches[0]
    expected_path = rooted(root, target)
    if path != expected_path:
        raise TransactionError("parity runtime tool path is not manifest-bound")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise TransactionError("parity runtime tool is unsafe")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if (
        record.get("sha256") != digest
        or record.get("mode") != f"{stat.S_IMODE(metadata.st_mode):04o}"
        or record.get("uid") != metadata.st_uid
        or record.get("gid") != metadata.st_gid
    ):
        raise TransactionError("parity runtime tool metadata or digest is not manifest-bound")


def rooted(root: Path, absolute: str) -> Path:
    if not absolute.startswith("/"):
        raise TransactionError("credential path is not absolute")
    return root / absolute.lstrip("/")


def sealed_authority_digest(envelope: object) -> str:
    expected_fields = {
        "schema", "receipt", "signature", "signer", "verifier", "verified",
        "sealed_sha256",
    }
    if not isinstance(envelope, dict) or set(envelope) != expected_fields:
        raise TransactionError("sealed parity receipt envelope schema mismatch")
    if (
        envelope.get("schema") != SEALED_RECEIPT_SCHEMA
        or envelope.get("verified") is not True
        or not isinstance(envelope.get("sealed_sha256"), str)
        or not HEX64.fullmatch(envelope["sealed_sha256"])
    ):
        raise TransactionError("sealed parity receipt envelope is invalid")
    receipt = envelope.get("receipt")
    if not isinstance(receipt, dict) or receipt.get("schema") != PARITY_RECEIPT_SCHEMA:
        raise TransactionError("sealed parity receipt payload schema mismatch")
    authority_digest = receipt.get("authority_receipt_sha256")
    if not isinstance(authority_digest, str) or not HEX64.fullmatch(authority_digest):
        raise TransactionError("sealed parity live authority digest is invalid")
    return authority_digest


def prepare(
    manifest_path: Path,
    receipt_path: Path,
    policy_path: Path,
    parity_tool: Path,
    state_dir: Path,
    root: Path,
) -> dict[str, Any]:
    if root == Path("/"):
        if os.geteuid() != 0:
            raise TransactionError("real-root activation transaction requires root")
        if state_dir != Path("/var/lib/buzz-agent-activation/current"):
            raise TransactionError("real-root activation transaction path is fixed")
    manifest = load_json(manifest_path)
    receipt = load_json(receipt_path)
    policy = load_json(policy_path, owner_only=False)
    manifest_bound_runtime_tool(manifest, parity_tool, root)
    parity = load_parity_module(parity_tool)
    try:
        envelope = parity.verify_sealed_receipt(
            receipt,
            parity.validate_policy(policy),
            manifest,
            rooted(root, parity.ROOT_VERIFIER_TARGET),
            root,
        )
        binding = parity.activation_binding(manifest)
    except parity.ParityError as error:
        raise TransactionError(f"sealed parity gate failed: {error}") from error
    authority_receipt_sha256 = sealed_authority_digest(envelope)
    identities = manifest.get("identities")
    if not isinstance(identities, dict) or set(identities) != set(SLUGS):
        raise TransactionError("manifest identity inventory mismatch")
    if state_dir.exists() or state_dir.is_symlink():
        raise TransactionError("activation transaction already exists")
    safe_directory(state_dir, create=True)
    backups = state_dir / "backups"
    safe_directory(backups, create=True)
    credentials: dict[str, object] = {}
    for slug in SLUGS:
        identity = identities[slug]
        if not isinstance(identity, dict) or identity.get("public_key") != manifest.get("inputs", {}).get(slug):
            raise TransactionError(f"{slug} manifest identity binding mismatch")
        path_text = identity.get("credential_path")
        if not isinstance(path_text, str):
            raise TransactionError(f"{slug} credential path is invalid")
        path = rooted(root, path_text)
        before = descriptor(path, f"{slug}:buzz-private-key")
        before_backup = None
        if before["present"]:
            before_backup = f"backups/{slug}.before"
            copy_exact(path, state_dir / before_backup)
        credentials[slug] = {
            "path": path_text,
            "before": before,
            "before_backup": before_backup,
            "after": None,
            "after_backup": None,
            "restored": False,
        }
    write_private(state_dir / "bundle-manifest.json", canonical_json(manifest))
    write_private(state_dir / "capability-parity-receipt.json", canonical_json(envelope))
    claim = os.urandom(32)
    write_private(state_dir / "rollback.claim", claim)
    state = {
        "schema": STATE_SCHEMA,
        "state": "prepared",
        "binding": binding,
        "sealed_receipt_sha256": envelope["sealed_sha256"],
        "claim_sha256": sha256_bytes(claim),
        "claim_used": False,
        "credentials": credentials,
        "memberships": [],
        "phase_receipts": {},
        "channel_contract": {
            key: manifest["capability_parity"][key]
            for key in (
                "reference_channels_sha256",
                "eligible_channels_sha256",
                "authority_exclusions_sha256",
            )
        } | {"authority_receipt_sha256": authority_receipt_sha256},
    }
    write_state(state_dir, state)
    return state


def begin_phase(state_dir: Path, slug: str) -> dict[str, Any]:
    state = read_state(state_dir)
    expected = "prepared" if slug == "mempool" else "mempool_complete"
    if state["state"] != expected:
        raise TransactionError(f"{slug} phase blocked by state {state['state']}")
    state["state"] = f"{slug}_in_progress"
    write_state(state_dir, state)
    return state


def record_credential(state_dir: Path, slug: str, root: Path) -> dict[str, Any]:
    state = read_state(state_dir)
    if state["state"] != f"{slug}_in_progress":
        raise TransactionError(f"{slug} credential record is out of phase")
    record = state["credentials"][slug]
    if record["after"] is not None:
        raise TransactionError(f"{slug} credential post-state is already recorded")
    path = rooted(root, record["path"])
    after = descriptor(path, f"{slug}:buzz-private-key")
    if after["present"] is not True:
        raise TransactionError(f"{slug} credential is absent after handoff")
    after_backup = f"backups/{slug}.after"
    copy_exact(path, state_dir / after_backup)
    record["after"] = after
    record["after_backup"] = after_backup
    write_state(state_dir, state)
    return state


def plan_membership(
    state_dir: Path, slug: str, channel_id: str, pubkey: str
) -> dict[str, Any]:
    state = read_state(state_dir)
    if state["state"] != f"{slug}_in_progress":
        raise TransactionError(f"{slug} membership record is out of phase")
    if not CHANNEL_ID.fullmatch(channel_id) or not HEX64.fullmatch(pubkey):
        raise TransactionError("membership identity is invalid")
    manifest = load_json(state_dir / "bundle-manifest.json")
    if manifest.get("inputs", {}).get(slug) != pubkey:
        raise TransactionError("membership public key is not manifest-bound")
    eligible = manifest.get("capability_parity", {}).get("eligible_channels")
    if not isinstance(eligible, list) or channel_id not in {
        item.get("channel_id") for item in eligible if isinstance(item, dict)
    }:
        raise TransactionError("membership channel is excluded or unknown")
    key = (slug, channel_id, pubkey)
    if any((item["slug"], item["channel_id"], item["pubkey"]) == key for item in state["memberships"]):
        raise TransactionError("membership write is already recorded")
    state["memberships"].append(
        {
            "slug": slug,
            "channel_id": channel_id,
            "pubkey": pubkey,
            "before_role": None,
            "after_role": "member",
            "confirmed": False,
            "rolled_back": False,
        }
    )
    write_state(state_dir, state)
    return state


def confirm_membership(
    state_dir: Path, slug: str, channel_id: str, pubkey: str
) -> dict[str, Any]:
    state = read_state(state_dir)
    if state["state"] != f"{slug}_in_progress":
        raise TransactionError(f"{slug} membership confirmation is out of phase")
    matches = [
        item for item in state["memberships"]
        if (item["slug"], item["channel_id"], item["pubkey"]) == (slug, channel_id, pubkey)
    ]
    if len(matches) != 1 or matches[0]["confirmed"]:
        raise TransactionError("membership confirmation record mismatch")
    matches[0]["confirmed"] = True
    write_state(state_dir, state)
    return state


def complete_phase(state_dir: Path, slug: str, gate_path: Path) -> dict[str, Any]:
    state = read_state(state_dir)
    if state["state"] != f"{slug}_in_progress":
        raise TransactionError(f"{slug} completion is out of phase")
    gate = load_json(gate_path)
    expected_fields = {
        "schema", "status", "slug", "binding", "gates",
        "reference_channels_sha256", "eligible_channels_sha256",
        "authority_exclusions_sha256", "authority_receipt_sha256",
    }
    if set(gate) != expected_fields or gate.get("schema") != PHASE_SCHEMA:
        raise TransactionError("phase gate receipt schema mismatch")
    if gate.get("status") != "PASS" or gate.get("slug") != slug or gate.get("binding") != state["binding"]:
        raise TransactionError("phase gate receipt binding mismatch")
    if gate.get("gates") != {
        "config": True,
        "credential": True,
        "membership": True,
        "parity": True,
    }:
        raise TransactionError("phase gate receipt is incomplete")
    manifest = load_json(state_dir / "bundle-manifest.json")
    parity_contract = manifest.get("capability_parity", {})
    envelope = load_json(state_dir / "capability-parity-receipt.json")
    authority_receipt_sha256 = sealed_authority_digest(envelope)
    expected_contract = {
        "reference_channels_sha256": parity_contract.get("reference_channels_sha256"),
        "eligible_channels_sha256": parity_contract.get("eligible_channels_sha256"),
        "authority_exclusions_sha256": parity_contract.get("authority_exclusions_sha256"),
        "authority_receipt_sha256": authority_receipt_sha256,
    }
    if any(gate.get(key) != value for key, value in expected_contract.items()):
        raise TransactionError("phase channel authority contract is not manifest-bound")
    if state.get("channel_contract") != expected_contract:
        raise TransactionError("activation transaction channel authority contract drifted")
    credential = state["credentials"][slug]
    if credential["after"] is None:
        raise TransactionError(f"{slug} credential post-state is not recorded")
    state["phase_receipts"][slug] = sha256_bytes(canonical_json(gate))
    state["state"] = "mempool_complete" if slug == "mempool" else "complete"
    write_state(state_dir, state)
    return state


def credential_drift_blockers(state_dir: Path, state: dict[str, Any], root: Path) -> list[str]:
    blockers: list[str] = []
    for slug in SLUGS:
        record = state["credentials"][slug]
        path = rooted(root, record["path"])
        after_backup = record["after_backup"]
        before_backup = record["before_backup"]
        expected_backup = state_dir / (after_backup or before_backup) if (after_backup or before_backup) else None
        if expected_backup is None:
            if path.exists() or path.is_symlink():
                blockers.append(f"{slug} credential appeared after an absent snapshot")
        elif not same_bytes(path, expected_backup):
            blockers.append(f"{slug} credential drift blocks rollback")
        elif descriptor(path, f"{slug}:buzz-private-key") != (record["after"] or record["before"]):
            blockers.append(f"{slug} credential metadata drift blocks rollback")
    return blockers


def matches_before_snapshot(state_dir: Path, record: dict[str, Any], root: Path) -> bool:
    path = rooted(root, record["path"])
    before = record["before"]
    backup = record["before_backup"]
    if before["present"] is False:
        return not path.exists() and not path.is_symlink()
    return (
        backup is not None
        and same_bytes(path, state_dir / backup)
        and descriptor(path, str(before["path_class"])) == before
    )


def begin_rollback(state_dir: Path, root: Path) -> dict[str, Any]:
    state = read_state(state_dir)
    if state["state"] == "rollback_started":
        return state
    if state["state"] == "rolled_back":
        raise TransactionError("activation transaction is already rolled back")
    blockers = credential_drift_blockers(state_dir, state, root)
    if blockers:
        raise TransactionError("; ".join(blockers))
    claim = state_dir / "rollback.claim"
    used = state_dir / "rollback.claim.used"
    if state.get("claim_used") is not False or not claim.is_file() or used.exists():
        raise TransactionError("rollback claim is unavailable or already used")
    if sha256_bytes(claim.read_bytes()) != state["claim_sha256"]:
        raise TransactionError("rollback claim digest mismatch")
    os.replace(claim, used)
    state["claim_used"] = True
    state["state"] = "rollback_started"
    write_state(state_dir, state)
    return state


def rollback_plan(state_dir: Path) -> list[dict[str, object]]:
    state = read_state(state_dir)
    if state["state"] != "rollback_started":
        raise TransactionError("rollback has not started")
    return [
        {
            "slug": item["slug"],
            "channel_id": item["channel_id"],
            "pubkey": item["pubkey"],
            "confirmed": item["confirmed"],
        }
        for item in reversed(state["memberships"])
        if not item["rolled_back"]
    ]


def mark_membership_rolled_back(
    state_dir: Path, slug: str, channel_id: str, pubkey: str
) -> dict[str, Any]:
    state = read_state(state_dir)
    if state["state"] != "rollback_started":
        raise TransactionError("membership rollback is out of phase")
    matches = [
        item for item in state["memberships"]
        if (item["slug"], item["channel_id"], item["pubkey"]) == (slug, channel_id, pubkey)
    ]
    if len(matches) != 1 or matches[0]["rolled_back"]:
        raise TransactionError("membership rollback record mismatch")
    matches[0]["rolled_back"] = True
    write_state(state_dir, state)
    return state


def restore_credential(state_dir: Path, record: dict[str, Any], root: Path) -> None:
    path = rooted(root, record["path"])
    before_backup = record["before_backup"]
    if before_backup is None:
        if path.exists() and not path.is_symlink():
            path.unlink()
        elif path.is_symlink():
            raise TransactionError("credential symlink drift blocks rollback")
        return
    source = state_dir / before_backup
    temporary = path.with_name(f".{path.name}.{os.getpid()}.rollback")
    copy_exact(source, temporary)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def finish_rollback(state_dir: Path, root: Path) -> dict[str, Any]:
    state = read_state(state_dir)
    if state["state"] != "rollback_started":
        raise TransactionError("rollback completion is out of phase")
    if any(not item["rolled_back"] for item in state["memberships"]):
        raise TransactionError("membership rollback is incomplete")
    for slug in reversed(SLUGS):
        record = state["credentials"][slug]
        if matches_before_snapshot(state_dir, record, root):
            record["restored"] = True
            write_state(state_dir, state)
            continue
        if record["restored"]:
            raise TransactionError(f"{slug} restored credential drift blocks rollback resume")
        expected = record["after"] or record["before"]
        expected_backup = record["after_backup"] or record["before_backup"]
        path = rooted(root, record["path"])
        if (
            expected_backup is None
            or not same_bytes(path, state_dir / expected_backup)
            or descriptor(path, f"{slug}:buzz-private-key") != expected
        ):
            raise TransactionError(f"{slug} credential drift blocks rollback")
        restore_credential(state_dir, record, root)
        if not matches_before_snapshot(state_dir, record, root):
            raise TransactionError(f"{slug} credential restoration verification failed")
        record["restored"] = True
        write_state(state_dir, state)
    for slug in SLUGS:
        record = state["credentials"][slug]
        path = rooted(root, record["path"])
        before_backup = record["before_backup"]
        if before_backup is None:
            if path.exists() or path.is_symlink():
                raise TransactionError(f"{slug} credential absence was not restored")
        elif not same_bytes(path, state_dir / before_backup):
            raise TransactionError(f"{slug} credential bytes were not restored")
    state["state"] = "rolled_back"
    write_state(state_dir, state)
    return state


def main() -> None:
    parser = argparse.ArgumentParser()
    children = parser.add_subparsers(dest="command", required=True)
    prepare_parser = children.add_parser("prepare")
    prepare_parser.add_argument("--bundle-manifest", required=True)
    prepare_parser.add_argument("--sealed-receipt", required=True)
    prepare_parser.add_argument("--policy", required=True)
    prepare_parser.add_argument("--parity-tool", required=True)
    prepare_parser.add_argument("--state-dir", required=True)
    prepare_parser.add_argument("--root", default="/")
    for name in ("begin-phase", "record-credential", "complete-phase"):
        child = children.add_parser(name)
        child.add_argument("--state-dir", required=True)
        child.add_argument("--slug", choices=SLUGS, required=True)
        if name == "record-credential":
            child.add_argument("--root", default="/")
        if name == "complete-phase":
            child.add_argument("--gate-receipt", required=True)
    for name in ("plan-membership", "confirm-membership"):
        membership = children.add_parser(name)
        membership.add_argument("--state-dir", required=True)
        membership.add_argument("--slug", choices=SLUGS, required=True)
        membership.add_argument("--channel-id", required=True)
        membership.add_argument("--pubkey", required=True)
    begin = children.add_parser("begin-rollback")
    begin.add_argument("--state-dir", required=True)
    begin.add_argument("--root", default="/")
    plan = children.add_parser("rollback-plan")
    plan.add_argument("--state-dir", required=True)
    marked = children.add_parser("mark-membership-rolled-back")
    marked.add_argument("--state-dir", required=True)
    marked.add_argument("--slug", choices=SLUGS, required=True)
    marked.add_argument("--channel-id", required=True)
    marked.add_argument("--pubkey", required=True)
    finish = children.add_parser("finish-rollback")
    finish.add_argument("--state-dir", required=True)
    finish.add_argument("--root", default="/")
    args = parser.parse_args()
    state_dir = Path(args.state_dir).resolve() if hasattr(args, "state_dir") else None
    if args.command == "prepare":
        result = prepare(
            Path(args.bundle_manifest).resolve(strict=True),
            Path(args.sealed_receipt).resolve(strict=True),
            Path(args.policy).resolve(strict=True),
            Path(args.parity_tool).resolve(strict=True),
            Path(args.state_dir).resolve(),
            Path(args.root).resolve(strict=True),
        )
    elif args.command == "begin-phase":
        result = begin_phase(state_dir, args.slug)
    elif args.command == "record-credential":
        result = record_credential(state_dir, args.slug, Path(args.root).resolve(strict=True))
    elif args.command == "plan-membership":
        result = plan_membership(state_dir, args.slug, args.channel_id, args.pubkey)
    elif args.command == "confirm-membership":
        result = confirm_membership(state_dir, args.slug, args.channel_id, args.pubkey)
    elif args.command == "complete-phase":
        result = complete_phase(state_dir, args.slug, Path(args.gate_receipt).resolve(strict=True))
    elif args.command == "begin-rollback":
        result = begin_rollback(state_dir, Path(args.root).resolve(strict=True))
    elif args.command == "rollback-plan":
        print(json.dumps(rollback_plan(state_dir), sort_keys=True))
        return
    elif args.command == "mark-membership-rolled-back":
        result = mark_membership_rolled_back(state_dir, args.slug, args.channel_id, args.pubkey)
    else:
        result = finish_rollback(state_dir, Path(args.root).resolve(strict=True))
    print(json.dumps({"status": result["state"]}, sort_keys=True))


if __name__ == "__main__":
    main()
