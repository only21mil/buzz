#!/usr/bin/env python3
"""Issue and consume the one-wave parent Tier 1 MGACT acceptance record."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types
from typing import Callable

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
SOURCE_REPO = Path("/home/victor/work/mempool-genesis-activation-expiry-20260826")
BUNDLE = Path(
    "/home/victor/work/mgact-activation-staging/"
    "candidate-activation-8cf1537b905a8bae5ae3aa7623b95c639a4402ee"
)
MANIFEST = BUNDLE / "bundle-manifest.json"
RECEIPT = Path(
    "/home/victor/work/mgact-activation-staging/"
    "preflight-receipt-activation-8cf1537b905a8bae5ae3aa7623b95c639a4402ee.json"
)
REVIEW_FILES = BUNDLE / "metadata/review-files.json"
ACCEPTANCE = Path(
    "/home/victor/work/mgact-activation-staging/"
    "parent-tier1-acceptance-8cf1537b905a8bae5ae3aa7623b95c639a4402ee.json"
)

SCHEMA = "buzz-mempool-genesis-parent-tier1-acceptance-v1"
INSTALL_RECEIPT_SCHEMA = "buzz-mempool-genesis-install-receipt-v3"
SOURCE_COMMIT = "8cf1537b905a8bae5ae3aa7623b95c639a4402ee"
SOURCE_TREE = "f8f06060d5cbf6c61d2e58ccf0dff0fb4aed7dba"
SOURCE_PARENT = "02f24e7af165a414cb2fb09821ed44b5fe6760bf"
SOURCE_BRANCH = "sats/mempool-genesis-activation-expiry-20260826"
BRIDGE_BRANCH = "sats/mempool-genesis-tier1-bridge-20260826"
MANIFEST_SHA256 = "d9ffa5a329f5f5660b200569a8233869233db0ef7ece1c465bb3e92bad089b49"
RECEIPT_SHA256 = "6456f9c456af63ec2092029fe5ad5e3bf02fdf6668db0c6670f4c54a51724ea0"
REVIEW_FILES_SHA256 = "08ff7860b32c5a4e82e57285e2dcbe72981801ac92b73e7c610b44f5e0f99b4a"
PACKAGE_DIGEST = "744b636de5ab1b4d76222d55df0275a75bc48ea092df478e058ea8ec18851cf7"
RUNTIME_FINGERPRINT = "6e5ebd94ea2b33995573073e48f49c22d73f4ffb8f52c9483994203ccd0f4b07"
RUNTIME_TARGET_AGGREGATE = "af95f89f02d75d0c536ff69dc6dde6d68307d1ad86772b840749003581313428"
GENESIS_CLOSURE_SHA256 = "d4f688e7d5b72b8dcaa94cf39e48802e144e284bc4078ef8831f222f88936b0d"
MEMPOOL_CLOSURE_SHA256 = "8e2ae4c7a35c87d2c3b82d41d43d6b7937dcc42b51e08b721623fbdfbf73e2c1"
GENESIS_PUBKEY = "8308c14c76bbe4623b42a47234129cb71278a182caae1342bdf2c86e24cb6339"
MEMPOOL_PUBKEY = "40a3be8c0c731bc8fc0622a0e92435917fddcbe622189fc260a6aedd67ce2a01"
CONTROLLER = "Sats Codex-2"
CLASSIFICATION_EVENT = "6fcb6ceb1857133242d0c50c66873a453d31975df0f947428ee322d3d829042e"
ACTIVATION_AUTHORITY_EVENT = "071138030a5d3cc0017be0ecfce9538a7cdd304833f2e5a141e3a1a0808e1dba"
FRESHNESS_SECONDS = 5_400
RUNTIME_TARGET_COUNT = 22
OPS_TARGET_COUNT = 1
SHARED_TARGET_COUNT = 16
IDENTITY_TARGET_COUNT = 6
ARTIFACT_UID = 1000
ARTIFACT_GID = 1000
CLOSURE_TARGET = "/etc/buzz-agents/review-closure.json"
CLAIM_DIRECTORY = "/var/lib/buzz-mgact-tier1-claims"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
sys.dont_write_bytecode = True


FROZEN_PREFLIGHT_PATH = "scripts/mempool-genesis/activation/make-tier1-receipt.py"
FROZEN_INSTALLER_PATH = "scripts/mempool-genesis/activation/install-activation-bundle.py"
FROZEN_PREFLIGHT_SHA256 = "d0d78fa2b51230ca827a794a55266812e807cc779d0e25099aedabcdc044c180"
FROZEN_INSTALLER_SHA256 = "5461716792bb3a45c7f241086a9abfc218d8be6c33294ae39ffdd68a59438cb3"


@dataclass(frozen=True)
class StaticInputs:
    manifest: dict[str, object]
    receipt: dict[str, object]
    receipt_generated_at: datetime
    expires_at: datetime
    bridge: dict[str, object]


@dataclass(frozen=True)
class Acceptance:
    value: dict[str, object]
    digest: str
    metadata: os.stat_result


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def require_regular(
    path: Path,
    *,
    mode: int | None = None,
    uid: int | None = None,
    gid: int | None = None,
) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"unsafe regular file metadata: {path}")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"wrong file mode: {path}")
    if uid is not None and metadata.st_uid != uid:
        raise ValueError(f"wrong file owner: {path}")
    if gid is not None and metadata.st_gid != gid:
        raise ValueError(f"wrong file group: {path}")
    return metadata


def load_json(path: Path, *, mode: int | None = None, uid: int | None = None) -> dict[str, object]:
    require_regular(path, mode=mode, uid=uid)
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError(f"JSON file is too large: {path}")
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return value


def git_value(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    return result.stdout.strip()


def git_blob(relative: str) -> bytes:
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("Git blob path escapes the repository")
    return subprocess.run(
        ["/usr/bin/git", "-C", str(REPO_ROOT), "show", f"{SOURCE_COMMIT}:{relative}"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    ).stdout


def execute_frozen_module(name: str, relative: str, payload: bytes) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = f"/immutable/{SOURCE_COMMIT}/{relative}"
    module.__package__ = ""
    sys.modules[name] = module
    exec(compile(payload, module.__file__, "exec"), module.__dict__)
    return module


def load_frozen_installer() -> types.ModuleType:
    preflight_payload = git_blob(FROZEN_PREFLIGHT_PATH)
    if sha256_bytes(preflight_payload) != FROZEN_PREFLIGHT_SHA256:
        raise ValueError("frozen preflight helper hash mismatch")
    execute_frozen_module("mgact_tier1_frozen_preflight", FROZEN_PREFLIGHT_PATH, preflight_payload)
    installer_payload = git_blob(FROZEN_INSTALLER_PATH)
    if sha256_bytes(installer_payload) != FROZEN_INSTALLER_SHA256:
        raise ValueError("frozen installer helper hash mismatch")
    source = installer_payload.decode()
    needle = (
        'PREFLIGHT_SUPPORT = load_module("mgact_preflight_support", '
        'SCRIPT_DIR / "make-tier1-receipt.py")'
    )
    replacement = 'PREFLIGHT_SUPPORT = sys.modules["mgact_tier1_frozen_preflight"]'
    if source.count(needle) != 1:
        raise ValueError("frozen installer preflight binding changed")
    return execute_frozen_module(
        "mgact_tier1_frozen_installer",
        FROZEN_INSTALLER_PATH,
        source.replace(needle, replacement).encode(),
    )


INSTALLER = load_frozen_installer()


def parse_instant(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} is absent")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{field} is malformed") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{field} lacks a timezone")
    return parsed.astimezone(timezone.utc)


def format_instant(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def validate_manifest_bindings(manifest: dict[str, object]) -> None:
    if manifest.get("source_commit") != SOURCE_COMMIT or manifest.get("source_branch") != SOURCE_BRANCH:
        raise ValueError("source commit or branch mismatch")
    if manifest.get("package_digest") != PACKAGE_DIGEST:
        raise ValueError("package digest mismatch")
    if manifest.get("runtime_artifact_fingerprint") != RUNTIME_FINGERPRINT:
        raise ValueError("runtime fingerprint mismatch")
    if manifest.get("inputs") != {"genesis": GENESIS_PUBKEY, "mempool": MEMPOOL_PUBKEY}:
        raise ValueError("identity map mismatch")
    runtime = manifest.get("runtime_targets")
    ops = manifest.get("ops_targets")
    closures = manifest.get("review_files")
    if not isinstance(runtime, list) or len(runtime) != RUNTIME_TARGET_COUNT:
        raise ValueError("runtime target count mismatch")
    if not isinstance(ops, list) or len(ops) != OPS_TARGET_COUNT:
        raise ValueError("ops target count mismatch")
    if not isinstance(closures, dict) or set(closures) != {"genesis", "mempool"}:
        raise ValueError("closure map mismatch")
    if sha256_bytes(canonical_json(runtime)) != RUNTIME_TARGET_AGGREGATE:
        raise ValueError("runtime target aggregate mismatch")
    if sha256_bytes(canonical_json(closures["genesis"])) != GENESIS_CLOSURE_SHA256:
        raise ValueError("Genesis closure mismatch")
    if sha256_bytes(canonical_json(closures["mempool"])) != MEMPOOL_CLOSURE_SHA256:
        raise ValueError("Mempool closure mismatch")
    genesis_paths = {entry["path"] for entry in closures["genesis"]}
    mempool_paths = {entry["path"] for entry in closures["mempool"]}
    if len(genesis_paths & mempool_paths) != SHARED_TARGET_COUNT:
        raise ValueError("shared target count mismatch")
    if len(genesis_paths ^ mempool_paths) != IDENTITY_TARGET_COUNT:
        raise ValueError("identity-specific target count mismatch")
    all_targets = [entry.get("target") for entry in runtime + ops if isinstance(entry, dict)]
    if len(all_targets) != RUNTIME_TARGET_COUNT + OPS_TARGET_COUNT or len(set(all_targets)) != len(all_targets):
        raise ValueError("package target path set mismatch")


def validate_frozen_generator_sources(manifest: dict[str, object]) -> None:
    records = manifest.get("generator_sources")
    if not isinstance(records, list) or not records:
        raise ValueError("generator source inventory is absent")
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "mode", "sha256"}:
            raise ValueError("generator source record is malformed")
        relative = record.get("path")
        digest = record.get("sha256")
        if not isinstance(relative, str) or not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise ValueError("generator source binding is malformed")
        if sha256_bytes(git_blob(relative)) != digest:
            raise ValueError(f"frozen generator source hash mismatch: {relative}")


def validate_receipt(
    receipt: dict[str, object], manifest: dict[str, object], now: datetime
) -> tuple[datetime, datetime]:
    if receipt.get("status") != "READY_FOR_PARENT_TIER1":
        raise ValueError("receipt status mismatch")
    if receipt.get("installable") is not False or receipt.get("next_gate") != "parent-tier1-readback":
        raise ValueError("receipt authority fields mismatch")
    bundle = receipt.get("bundle")
    if not isinstance(bundle, dict):
        raise ValueError("receipt package binding is absent")
    expected_bundle = {
        "path": str(BUNDLE),
        "manifest_sha256": MANIFEST_SHA256,
        "package_digest": PACKAGE_DIGEST,
        "runtime_artifact_fingerprint": RUNTIME_FINGERPRINT,
        "review_files_sha256": REVIEW_FILES_SHA256,
    }
    for key, expected in expected_bundle.items():
        if bundle.get(key) != expected:
            raise ValueError(f"receipt package binding mismatch: {key}")
    guard = receipt.get("live_guard")
    if (
        not isinstance(guard, dict)
        or guard.get("unchanged") is not True
        or guard.get("before") != guard.get("after")
    ):
        raise ValueError("receipt live snapshot mismatch")
    commands = receipt.get("commands")
    if not isinstance(commands, list) or not commands or any(
        not isinstance(command, dict) or command.get("exit") != 0 for command in commands
    ):
        raise ValueError("receipt command gate mismatch")
    generated = parse_instant(receipt.get("generated_at"), "receipt generated_at")
    expires = generated + timedelta(seconds=FRESHNESS_SECONDS)
    now = now.astimezone(timezone.utc)
    if now < generated:
        raise ValueError("receipt timestamp is in the future")
    if now > expires:
        raise ValueError("receipt is stale")
    if manifest.get("installable") is not False:
        raise ValueError("original package installable flag changed")
    return generated, expires


def bridge_binding() -> dict[str, object]:
    branch = git_value(REPO_ROOT, "branch", "--show-current")
    commit = git_value(REPO_ROOT, "rev-parse", "HEAD")
    parent = git_value(REPO_ROOT, "rev-parse", "HEAD^")
    if branch != BRIDGE_BRANCH:
        raise ValueError("bridge branch mismatch")
    if subprocess.run(
        ["/usr/bin/git", "-C", str(REPO_ROOT), "merge-base", "--is-ancestor", SOURCE_COMMIT, commit],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    ).returncode != 0:
        raise ValueError("bridge does not descend from the package source commit")
    script = Path(__file__).resolve(strict=True)
    require_regular(script, mode=0o755)
    relative = str(script.relative_to(REPO_ROOT))
    if git_value(REPO_ROOT, "status", "--porcelain", "--", relative):
        raise ValueError("bridge script differs from its committed bytes")
    return {
        "repo": str(REPO_ROOT),
        "branch": branch,
        "commit": commit,
        "tree": git_value(REPO_ROOT, "rev-parse", "HEAD^{tree}"),
        "parent": parent,
        "script": str(script),
        "script_sha256": sha256_file(script),
    }


def validate_static_inputs(now: datetime | None = None) -> StaticInputs:
    instant = now or datetime.now(timezone.utc)
    if BUNDLE.resolve(strict=True) != BUNDLE or RECEIPT.resolve(strict=True) != RECEIPT:
        raise ValueError("candidate or receipt path is not exact")
    if MANIFEST.resolve(strict=True) != MANIFEST or REVIEW_FILES.resolve(strict=True) != REVIEW_FILES:
        raise ValueError("manifest or review path is not exact")
    bundle_metadata = BUNDLE.lstat()
    if (
        not stat.S_ISDIR(bundle_metadata.st_mode)
        or stat.S_IMODE(bundle_metadata.st_mode) != 0o700
        or bundle_metadata.st_uid != ARTIFACT_UID
        or bundle_metadata.st_gid != ARTIFACT_GID
    ):
        raise ValueError("candidate directory metadata mismatch")
    require_regular(MANIFEST, mode=0o600, uid=ARTIFACT_UID, gid=ARTIFACT_GID)
    require_regular(RECEIPT, mode=0o600, uid=ARTIFACT_UID, gid=ARTIFACT_GID)
    require_regular(REVIEW_FILES, mode=0o600, uid=ARTIFACT_UID, gid=ARTIFACT_GID)
    if sha256_file(MANIFEST) != MANIFEST_SHA256:
        raise ValueError("manifest hash mismatch")
    if sha256_file(RECEIPT) != RECEIPT_SHA256:
        raise ValueError("receipt hash mismatch")
    if sha256_file(REVIEW_FILES) != REVIEW_FILES_SHA256:
        raise ValueError("review-files hash mismatch")
    if git_value(REPO_ROOT, "cat-file", "-t", SOURCE_COMMIT) != "commit":
        raise ValueError("source anchor is not a commit")
    if git_value(REPO_ROOT, "show", "-s", "--format=%T", SOURCE_COMMIT) != SOURCE_TREE:
        raise ValueError("source tree mismatch")
    if git_value(REPO_ROOT, "show", "-s", "--format=%P", SOURCE_COMMIT) != SOURCE_PARENT:
        raise ValueError("source parent mismatch")
    manifest = load_json(MANIFEST, mode=0o600, uid=ARTIFACT_UID)
    validate_manifest_bindings(manifest)
    validate_frozen_generator_sources(manifest)
    for record in manifest["runtime_targets"] + manifest["ops_targets"]:
        source = BUNDLE / record["source"]
        require_regular(
            source,
            mode=int(record["mode"], 8),
            uid=ARTIFACT_UID,
            gid=ARTIFACT_GID,
        )
    receipt = load_json(RECEIPT, mode=0o600)
    generated, expires = validate_receipt(receipt, manifest, instant)
    return StaticInputs(manifest, receipt, generated, expires, bridge_binding())


def acceptance_value(static: StaticInputs, issued_at: datetime) -> dict[str, object]:
    manifest = static.manifest
    return {
        "schema": SCHEMA,
        "status": "ACCEPTED_FOR_ACTIVATION",
        "tier": 1,
        "activation_only": True,
        "tier2_evidence_accepted": False,
        "tier2_state_accepted": False,
        "controller": CONTROLLER,
        "authority": {
            "classification_event": CLASSIFICATION_EVENT,
            "host_activation_event": ACTIVATION_AUTHORITY_EVENT,
        },
        "issued_at": format_instant(issued_at),
        "receipt_generated_at": format_instant(static.receipt_generated_at),
        "expires_at": format_instant(static.expires_at),
        "freshness_seconds": FRESHNESS_SECONDS,
        "record_path": str(ACCEPTANCE),
        "source": {
            "repo": str(SOURCE_REPO),
            "branch": SOURCE_BRANCH,
            "commit": SOURCE_COMMIT,
            "tree": SOURCE_TREE,
            "parent": SOURCE_PARENT,
        },
        "bridge": static.bridge,
        "package": {
            "bundle": str(BUNDLE),
            "manifest": str(MANIFEST),
            "manifest_sha256": MANIFEST_SHA256,
            "receipt": str(RECEIPT),
            "receipt_sha256": RECEIPT_SHA256,
            "review_files": str(REVIEW_FILES),
            "review_files_sha256": REVIEW_FILES_SHA256,
            "package_digest": PACKAGE_DIGEST,
            "runtime_artifact_fingerprint": RUNTIME_FINGERPRINT,
            "runtime_target_aggregate": RUNTIME_TARGET_AGGREGATE,
            "runtime_targets": manifest["runtime_targets"],
            "ops_targets": manifest["ops_targets"],
        },
        "identities": {
            "genesis": {
                "pubkey": GENESIS_PUBKEY,
                "service": "buzz-agent@genesis.service",
                "user": "buzz-genesis",
                "closure_sha256": GENESIS_CLOSURE_SHA256,
                "closure": manifest["review_files"]["genesis"],
            },
            "mempool": {
                "pubkey": MEMPOOL_PUBKEY,
                "service": "buzz-agent@mempool.service",
                "user": "buzz-mempool",
                "closure_sha256": MEMPOOL_CLOSURE_SHA256,
                "closure": manifest["review_files"]["mempool"],
            },
        },
    }


def private_parent(path: Path, uid: int) -> None:
    parent = path.parent
    metadata = parent.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != uid
        or metadata.st_nlink < 1
    ):
        raise ValueError("acceptance parent is not private to the artifact owner")


def issue(now: datetime | None = None) -> Acceptance:
    if os.geteuid() == 0:
        raise ValueError("issue must run as the artifact owner, not root")
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    static = validate_static_inputs(instant)
    owner = INSTALLER.artifact_owner()
    private_parent(ACCEPTANCE, owner.uid)
    value = acceptance_value(static, instant)
    payload = canonical_json(value)
    descriptor = os.open(
        ACCEPTANCE,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = require_regular(ACCEPTANCE, mode=0o600, uid=owner.uid)
    return Acceptance(value, sha256_bytes(payload), metadata)


def validate_acceptance(static: StaticInputs, now: datetime | None = None) -> Acceptance:
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    owner = INSTALLER.artifact_owner()
    if ACCEPTANCE.resolve(strict=True) != ACCEPTANCE:
        raise ValueError("acceptance path is not exact")
    private_parent(ACCEPTANCE, owner.uid)
    metadata = require_regular(ACCEPTANCE, mode=0o600, uid=owner.uid)
    raw = ACCEPTANCE.read_bytes()
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict) or raw != canonical_json(value):
        raise ValueError("acceptance is not canonical JSON")
    issued = parse_instant(value.get("issued_at"), "acceptance issued_at")
    if issued < static.receipt_generated_at or issued > static.expires_at or issued > instant:
        raise ValueError("acceptance issue time is invalid")
    if instant > static.expires_at:
        raise ValueError("acceptance is stale")
    expected = acceptance_value(static, issued)
    if value != expected:
        raise ValueError("acceptance fields mismatch")
    return Acceptance(value, sha256_bytes(raw), metadata)


def rooted(root: Path, path: str) -> Path:
    return root / path.lstrip("/")


def live_snapshot_blockers(
    receipt: dict[str, object],
    root: Path,
    manifest: dict[str, object] | None = None,
) -> list[str]:
    guard = receipt.get("live_guard")
    after = guard.get("after") if isinstance(guard, dict) else None
    if not isinstance(after, dict):
        return ["receipt live snapshot is absent"]
    blockers: list[str] = []
    for absolute, expected in after.items():
        if not isinstance(absolute, str) or not isinstance(expected, dict):
            blockers.append("receipt live snapshot entry is malformed")
            continue
        path = rooted(root, absolute)
        if expected.get("exists") is False:
            if os.path.lexists(path):
                blockers.append(f"stale live snapshot: {absolute}")
            continue
        if expected.get("exists") == "unreadable":
            if not os.path.lexists(path):
                blockers.append(f"stale live snapshot: {absolute}")
                continue
            if manifest is not None:
                records = manifest.get("runtime_targets", []) + manifest.get("ops_targets", [])
                matches = [
                    record
                    for record in records
                    if isinstance(record, dict) and record.get("target") == absolute
                ]
                try:
                    if len(matches) != 1:
                        raise ValueError("target is not uniquely package-bound")
                    record = matches[0]
                    metadata = require_regular(
                        path,
                        mode=int(str(record["mode"]), 8),
                        uid=int(record["uid"]),
                        gid=int(record["gid"]),
                    )
                    if metadata.st_size < 0 or sha256_file(path) != record.get("sha256"):
                        raise ValueError("target hash mismatch")
                except Exception:
                    blockers.append(f"stale live snapshot: {absolute}")
            continue
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            blockers.append(f"stale live snapshot: {absolute}")
            continue
        actual_type = "regular" if stat.S_ISREG(metadata.st_mode) else "directory" if stat.S_ISDIR(metadata.st_mode) else "other"
        checks = {
            "type": actual_type,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "links": metadata.st_nlink,
            "size": metadata.st_size,
        }
        if any(expected.get(key) != value for key, value in checks.items()):
            blockers.append(f"stale live snapshot: {absolute}")
            continue
        digest = expected.get("sha256")
        if isinstance(digest, str) and HEX64.fullmatch(digest):
            if not stat.S_ISREG(metadata.st_mode) or sha256_file(path) != digest:
                blockers.append(f"stale live snapshot: {absolute}")
    return blockers


def closure_payload(static: StaticInputs, acceptance: Acceptance) -> bytes:
    authority = {
        "tier": 1,
        "activation_only": True,
        "controller": CONTROLLER,
        "classification_event": CLASSIFICATION_EVENT,
        "host_activation_event": ACTIVATION_AUTHORITY_EVENT,
        "acceptance_sha256": acceptance.digest,
    }
    return canonical_json(
        {
            "schema": "buzz-agent-review-closure-v2",
            "accepted": True,
            "acceptance_tier": 1,
            "activation_only": True,
            "verdict_source": SCHEMA,
            "lineage_id": f"parent-tier1:{CLASSIFICATION_EVENT}",
            "state_id": acceptance.digest,
            "runtime_artifact_fingerprint": RUNTIME_FINGERPRINT,
            "candidate_fingerprint": RUNTIME_TARGET_AGGREGATE,
            "bundle_digest": PACKAGE_DIGEST,
            "state_digest": acceptance.digest,
            "verdict_digest": sha256_bytes(canonical_json(authority)),
            "verdict": "PASS",
            "authority": authority,
            "files": static.manifest["review_files"],
        }
    )


def package_targets(static: StaticInputs, acceptance: Acceptance) -> tuple[object, ...]:
    records = static.manifest["runtime_targets"] + static.manifest["ops_targets"]
    targets = [INSTALLER.parse_target(BUNDLE, record) for record in records]
    payload = closure_payload(static, acceptance)
    targets.append(
        INSTALLER.Target(
            CLOSURE_TARGET,
            None,
            payload,
            0o644,
            0,
            0,
            sha256_bytes(payload),
            install_last=True,
        )
    )
    return tuple(targets)


def ordered_targets(targets: tuple[object, ...]) -> list[object]:
    ordered = sorted(targets, key=lambda target: (target.install_last, target.target.encode()))
    if ordered[-1].target != CLOSURE_TARGET or any(target.install_last for target in ordered[:-1]):
        raise ValueError("closure-last ordering failed")
    return ordered


def preflight(
    root: Path,
    *,
    now: datetime | None = None,
    enforce_live_snapshot: bool = True,
    enforce_unclaimed: bool = True,
) -> tuple[StaticInputs | None, Acceptance | None, tuple[object, ...], tuple[str, ...]]:
    try:
        static = validate_static_inputs(now)
        acceptance = validate_acceptance(static, now)
        targets = package_targets(static, acceptance)
    except Exception as error:
        return None, None, (), (str(error),)
    blockers = INSTALLER.service_blockers(root)
    if enforce_live_snapshot:
        blockers.extend(live_snapshot_blockers(static.receipt, root, static.manifest))
    if enforce_unclaimed:
        claim = claim_directory(root) / f"{acceptance.digest}.claim"
        if os.path.lexists(claim):
            blockers.append("Tier 1 acceptance was already consumed")
    try:
        INSTALLER.root_metadata(root)
    except Exception as error:
        blockers.append(str(error))
    states = []
    for target in ordered_targets(targets):
        try:
            state = INSTALLER.inspect_target(target, root)
        except Exception as error:
            destination = rooted(root, target.target)
            state = INSTALLER.TargetState(target, destination, destination.parent, "blocked", str(error))
        states.append(state)
        if state.status == "blocked":
            blockers.append(f"{target.target}: {state.reason}")
    return static, acceptance, tuple(states), tuple(blockers)


def render_preflight(
    mode: str,
    static: StaticInputs | None,
    acceptance: Acceptance | None,
    states: tuple[object, ...],
    blockers: tuple[str, ...],
) -> str:
    digest = acceptance.digest if acceptance else "unresolved"
    lines = [f"MGACT Tier1 {mode} package={PACKAGE_DIGEST} acceptance={digest}"]
    lines.extend(f"TARGET {state.target.target} status={state.status} reason={state.reason}" for state in states)
    if blockers:
        lines.append("PREFLIGHT BLOCKERS:")
        lines.extend(f"- {blocker}" for blocker in blockers)
    else:
        lines.append(
            "PREFLIGHT OK "
            f"add={sum(state.status == 'add' for state in states)} "
            f"replace={sum(state.status == 'replace' for state in states)} "
            f"current={sum(state.status == 'current' for state in states)} writes=0"
        )
    return "\n".join(lines) + "\n"


def claim_directory(root: Path) -> Path:
    return rooted(root, CLAIM_DIRECTORY)


def ensure_claim_directory(root: Path) -> Path:
    path = claim_directory(root)
    INSTALLER.ensure_admin_directory(path.parent, root, 0o755)
    INSTALLER.ensure_admin_directory(path, root, 0o700)
    return path


def create_claim(root: Path, acceptance: Acceptance) -> Path:
    directory = ensure_claim_directory(root)
    path = directory / f"{acceptance.digest}.claim"
    uid, gid = INSTALLER.admin_owner(root)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchown(descriptor, uid, gid)
        os.write(
            descriptor,
            canonical_json(
                {
                    "schema": "buzz-mempool-genesis-tier1-single-use-claim-v1",
                    "acceptance_sha256": acceptance.digest,
                    "package_digest": PACKAGE_DIGEST,
                }
            ),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def acceptance_unchanged(acceptance: Acceptance) -> None:
    metadata = require_regular(ACCEPTANCE, mode=0o600, uid=acceptance.metadata.st_uid)
    if metadata.st_dev != acceptance.metadata.st_dev or metadata.st_ino != acceptance.metadata.st_ino:
        raise ValueError("acceptance was replaced during validation")
    if sha256_file(ACCEPTANCE) != acceptance.digest:
        raise ValueError("acceptance mutated during validation")


def installed_records(changed: list[object]) -> dict[str, dict[str, object]]:
    return {
        state.target.target: {
            "sha256": state.target.sha256,
            "mode": f"{state.target.mode:04o}",
            "uid": state.target.uid,
            "gid": state.target.gid,
        }
        for state in changed
    }


def install(
    root: Path,
    *,
    now: datetime | None = None,
    after_claim: Callable[[Path], None] | None = None,
) -> int:
    initial = preflight(root, now=now)
    static, acceptance, states, blockers = initial
    if blockers or static is None or acceptance is None:
        print(render_preflight("install", *initial), end="")
        return 1
    backup_root, lock_handle = INSTALLER.prepare_admin_paths(root)
    try:
        checked = preflight(root, now=now)
        static, acceptance, states, blockers = checked
        if blockers or static is None or acceptance is None:
            print(render_preflight("install-locked", *checked), end="")
            return 1
        claim = create_claim(root, acceptance)
        if after_claim is not None:
            after_claim(claim)
        acceptance_unchanged(acceptance)
        changed = [state for state in states if state.status in {"add", "replace"}]
        instant = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        backup_id = f"{INSTALLER.BUNDLE_ID}-{PACKAGE_DIGEST[:12]}-{instant}"
        backup = backup_root / backup_id
        backup.mkdir(mode=0o700)
        (backup / "files").mkdir(mode=0o700)
        previous: dict[str, dict[str, object]] = {}
        for state in changed:
            destination = state.resolved_parent / state.destination.name
            if state.status == "replace":
                metadata = require_regular(destination)
                name = hashlib.sha256(state.target.target.encode()).hexdigest()
                INSTALLER.backup_file(destination, backup / "files" / name)
                previous[state.target.target] = {
                    "exists": True,
                    "backup_name": name,
                    "sha256": sha256_file(destination),
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                }
            else:
                previous[state.target.target] = {"exists": False}
        install_receipt = {
            "schema": INSTALL_RECEIPT_SCHEMA,
            "backup_id": backup_id,
            "acceptance_sha256": acceptance.digest,
            "claim": str(claim),
            "package_digest": PACKAGE_DIGEST,
            "state": "prepared",
            "changed_targets": [state.target.target for state in changed],
            "previous": previous,
            "installed": installed_records(changed),
        }
        receipt_path = backup / "receipt.json"
        INSTALLER.write_receipt(receipt_path, install_receipt)
        applied = []
        try:
            for state in changed:
                acceptance_unchanged(acceptance)
                INSTALLER.verify_previous_state(state, previous[state.target.target])
                applied.append(state)
                INSTALLER.atomic_copy_source(state.target, state, root)
            final = preflight(
                root,
                now=now,
                enforce_live_snapshot=False,
                enforce_unclaimed=False,
            )
            if final[3] or any(state.status != "current" for state in final[2]):
                raise ValueError("post-install preflight did not reach current state")
            acceptance_unchanged(acceptance)
            install_receipt["state"] = "installed"
            INSTALLER.write_receipt(receipt_path, install_receipt)
        except Exception:
            try:
                INSTALLER.restore_targets(applied, previous, backup, root)
                install_receipt["state"] = "rolled_back"
                INSTALLER.write_receipt(receipt_path, install_receipt)
            except Exception as rollback_error:
                install_receipt["state"] = "rollback_required"
                try:
                    INSTALLER.write_receipt(receipt_path, install_receipt)
                except Exception:
                    pass
                raise RuntimeError(f"ROLLBACK_REQUIRED backup_id={backup_id}") from rollback_error
            raise
        print(f"INSTALLED backup_id={backup_id} changed={len(changed)} claim={claim}")
        return 0
    finally:
        lock_handle.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("issue", "check", "dry-run", "install"))
    args = parser.parse_args()
    if args.command == "issue":
        acceptance = issue()
        print(f"ISSUED path={ACCEPTANCE} sha256={acceptance.digest}")
        raise SystemExit(0)
    root = Path("/")
    if args.command in {"check", "dry-run"}:
        checked = preflight(root)
        print(render_preflight(args.command, *checked), end="")
        raise SystemExit(1 if checked[3] else 0)
    raise SystemExit(install(root))


if __name__ == "__main__":
    main()
