#!/usr/bin/env python3
"""Preflight, install, or roll back one Tier 2 v2-reviewed MGACT package."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from typing import BinaryIO

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
TIER2_VERIFIER_RELATIVE = Path(
    "scripts/mempool-genesis/activation/tier2-evidence-verifier.py"
)
TIER2_ENGINE_PATH = Path("/home/victor/.agents/skills/codex-review/scripts/tier2")
TIER2_VERIFIER_MODE = 0o755
SUDO_PATH = Path("/usr/bin/sudo")
BUNDLE_SCHEMA = "buzz-mempool-genesis-activation-bundle-v3"
PREFLIGHT_RECEIPT_SCHEMA = "buzz-mempool-genesis-preflight-receipt-v3"
INSTALL_RECEIPT_SCHEMA = "buzz-mempool-genesis-install-receipt-v3"
INSTALLED_CLOSURE_SCHEMA = "buzz-agent-review-closure-v2"
BUNDLE_ID = "mempool-genesis-activation-20260825"
CLOSURE_TARGET = "/etc/buzz-agents/review-closure.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BACKUP_ID = re.compile(
    r"^mempool-genesis-activation-20260825-[0-9a-f]{12}-[0-9]{8}T[0-9]{6}\.[0-9]{6}Z$"
)
sys.dont_write_bytecode = True


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PREFLIGHT_SUPPORT = load_module("mgact_preflight_support", SCRIPT_DIR / "make-tier1-receipt.py")


@dataclass(frozen=True)
class ArtifactOwner:
    uid: int
    gid: int
    user: str
    home: str


@dataclass(frozen=True)
class Target:
    target: str
    source: Path | None
    payload: bytes | None
    mode: int
    uid: int
    gid: int
    sha256: str
    install_last: bool = False


@dataclass(frozen=True)
class TargetState:
    target: Target
    destination: Path
    resolved_parent: Path
    status: str
    reason: str


@dataclass(frozen=True)
class Tier2Acceptance:
    lineage_id: str
    state_id: str
    revision: int
    verdict: str
    reviewer_identity: str
    verdict_digest: str
    evidence_digest: str
    candidate_fingerprint: str
    state_digest: str


@dataclass(frozen=True)
class Preflight:
    manifest: dict[str, object] | None
    acceptance: Tier2Acceptance | None
    targets: tuple[TargetState, ...]
    blockers: tuple[str, ...]


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


def hash_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return hash_fd(descriptor)
    finally:
        os.close(descriptor)


def rooted(root: Path, absolute: str) -> Path:
    return root / absolute.lstrip("/")


def require_regular(
    path: Path,
    *,
    mode: int | None = None,
    owner_uid: int | None = None,
    links: int = 1,
) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"not a regular file: {path}")
    if metadata.st_nlink != links:
        raise ValueError(f"wrong hard-link count: {path}")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"wrong mode: {path}")
    if owner_uid is not None and metadata.st_uid != owner_uid:
        raise ValueError(f"wrong owner: {path}")
    return metadata


def parent_executable() -> Path:
    return Path(os.readlink(f"/proc/{os.getppid()}/exe")).resolve(strict=True)


def parent_process_ids() -> tuple[tuple[int, ...], tuple[int, ...]]:
    status = Path(f"/proc/{os.getppid()}/status").read_text()
    values: dict[str, tuple[int, ...]] = {}
    for line in status.splitlines():
        key, separator, raw = line.partition(":")
        if separator and key in {"Uid", "Gid"}:
            fields = tuple(int(value) for value in raw.split())
            if len(fields) != 4:
                raise ValueError(f"malformed sudo parent {key} record")
            values[key] = fields
    if set(values) != {"Uid", "Gid"}:
        raise ValueError("sudo parent identity records are absent")
    return values["Uid"], values["Gid"]


def parse_sudo_id(name: str, value: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]{0,9}", value):
        raise ValueError(f"malformed {name}")
    parsed = int(value)
    if parsed > 2**31 - 1:
        raise ValueError(f"out-of-range {name}")
    return parsed


def artifact_owner() -> ArtifactOwner:
    effective_uid = os.geteuid()
    real_uid = os.getuid()
    real_gid = os.getgid()
    if effective_uid != 0:
        if effective_uid != real_uid:
            raise ValueError("unsupported non-root privilege transition")
        account = pwd.getpwuid(real_uid)
        return ArtifactOwner(real_uid, real_gid, account.pw_name, account.pw_dir)

    names = ("SUDO_UID", "SUDO_GID", "SUDO_USER")
    values = {name: os.environ.get(name) for name in names}
    if all(value is None for value in values.values()):
        account = pwd.getpwuid(0)
        return ArtifactOwner(0, 0, account.pw_name, account.pw_dir)
    if any(value is None for value in values.values()):
        raise ValueError("incomplete sudo invoker identity")

    uid = parse_sudo_id("SUDO_UID", str(values["SUDO_UID"]))
    gid = parse_sudo_id("SUDO_GID", str(values["SUDO_GID"]))
    user = str(values["SUDO_USER"])
    if uid == 0 or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise ValueError("invalid sudo invoker identity")
    try:
        account = pwd.getpwuid(uid)
    except KeyError as error:
        raise ValueError("unknown sudo invoker uid") from error
    if account.pw_name != user or account.pw_gid != gid:
        raise ValueError("sudo invoker identity mismatch")

    executable = parent_executable()
    if executable != SUDO_PATH:
        raise ValueError("SUDO_UID present without an authenticated sudo parent")
    metadata = executable.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or mode & 0o022
        or not (mode & stat.S_ISUID)
        or not (mode & 0o111)
    ):
        raise ValueError("unsafe sudo parent executable")
    parent_uids, parent_gids = parent_process_ids()
    if parent_uids != (uid, 0, 0, 0) or parent_gids != (0, 0, 0, 0):
        raise ValueError("SUDO_UID does not match the authenticated sudo process")
    return ArtifactOwner(uid, gid, user, account.pw_dir)


def load_json(
    path: Path,
    max_bytes: int = 1024 * 1024,
    *,
    mode: int | None = None,
    owner_uid: int | None = None,
) -> dict[str, object]:
    require_regular(path, mode=mode, owner_uid=owner_uid)
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(f"JSON file is too large: {path}")
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return value


def parse_mode(value: object) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0[0-7]{3}", value):
        raise ValueError("invalid target mode")
    return int(value, 8)


def parse_target(bundle: Path, raw: object) -> Target:
    if not isinstance(raw, dict):
        raise ValueError("target record is not an object")
    required = {"target", "source", "mode", "uid", "gid", "sha256"}
    if not required.issubset(raw):
        raise ValueError("target record is incomplete")
    target, source = raw.get("target"), raw.get("source")
    uid, gid, digest = raw.get("uid"), raw.get("gid"), raw.get("sha256")
    if not isinstance(target, str) or not Path(target).is_absolute():
        raise ValueError("target path is not absolute")
    if not isinstance(source, str):
        raise ValueError("source path is not a string")
    relative = Path(source)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("source path escapes package")
    source_path = bundle / relative
    try:
        source_path.resolve(strict=True).relative_to(bundle.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ValueError(f"source path escapes package: {source}") from error
    mode = parse_mode(raw.get("mode"))
    if not isinstance(uid, int) or uid < 0 or not isinstance(gid, int) or gid < 0:
        raise ValueError("invalid target ownership")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ValueError("invalid target digest")
    require_regular(source_path, mode=mode)
    if sha256_file(source_path) != digest:
        raise ValueError(f"package source hash mismatch: {source}")
    return Target(target, source_path, None, mode, uid, gid, digest)


def validate_preflight_receipt(
    receipt_path: Path,
    bundle: Path,
    manifest: dict[str, object],
    evidence_path: Path,
    owner: ArtifactOwner,
) -> dict[str, object]:
    receipt = load_json(receipt_path, mode=0o600, owner_uid=owner.uid)
    if set(receipt) != {
        "schema",
        "generated_at",
        "status",
        "installable",
        "next_gate",
        "bundle",
        "tier2_bundle",
        "execution_bounds",
        "input_contract",
        "commands",
        "live_guard",
    }:
        raise ValueError("preflight receipt fields mismatch")
    if receipt.get("schema") != PREFLIGHT_RECEIPT_SCHEMA:
        raise ValueError("preflight receipt schema mismatch")
    if receipt.get("status") != "READY_FOR_PARENT_TIER1":
        raise ValueError("preflight receipt is not ready for parent Tier 1 readback")
    if receipt.get("installable") is not False or receipt.get("next_gate") != "parent-tier1-readback":
        raise ValueError("preflight receipt makes an invalid authority claim")
    bundle_record = receipt.get("bundle")
    if not isinstance(bundle_record, dict):
        raise ValueError("preflight receipt package record is absent")
    expected = {
        "manifest_sha256": sha256_file(bundle / "bundle-manifest.json"),
        "bundle_id": manifest["bundle_id"],
        "package_digest": manifest["package_digest"],
        "input_status": manifest["input_status"],
        "runtime_artifact_fingerprint": manifest["runtime_artifact_fingerprint"],
        "review_files_sha256": manifest["review_files_record"]["sha256"],
        "tier2_review": manifest["tier2_review"],
        "tier2_engine_sha256": manifest["tier2_engine"]["sha256"],
    }
    if bundle_record.get("path") != str(bundle):
        raise ValueError("preflight receipt package path mismatch")
    for key, value in expected.items():
        if bundle_record.get(key) != value:
            raise ValueError(f"preflight receipt package mismatch: {key}")
    tier2_record = receipt.get("tier2_bundle")
    expected_tier2_record = {
        "path": str(evidence_path),
        "sha256": sha256_file(evidence_path),
        "schema": "tier2-evidence-v2",
        "candidate_root": str(bundle),
    }
    if tier2_record != expected_tier2_record:
        raise ValueError("preflight receipt Tier 2 evidence binding mismatch")
    bounds = receipt.get("execution_bounds")
    expected_bounds = {
        "installed",
        "published",
        "pushed",
        "merged",
        "activated",
        "credentials_used",
        "relay_events_sent",
    }
    if (
        not isinstance(bounds, dict)
        or set(bounds) != expected_bounds
        or any(value is not False for value in bounds.values())
    ):
        raise ValueError("preflight receipt execution bounds are invalid")
    live_guard = receipt.get("live_guard")
    if not isinstance(live_guard, dict) or live_guard.get("unchanged") is not True:
        raise ValueError("preflight receipt live guard did not pass")
    commands = receipt.get("commands")
    expected_commands = PREFLIGHT_SUPPORT.gate_commands(bundle)
    if (
        not isinstance(commands, list)
        or [result.get("command") for result in commands if isinstance(result, dict)]
        != expected_commands
        or any(not isinstance(result, dict) or result.get("exit") != 0 for result in commands)
    ):
        raise ValueError("preflight receipt command gate did not pass")
    return receipt


def verifier_source_record(manifest: dict[str, object]) -> dict[str, object]:
    records = manifest.get("generator_sources")
    if not isinstance(records, list):
        raise ValueError("package generator source inventory is absent")
    relative = str(TIER2_VERIFIER_RELATIVE)
    matches = [record for record in records if isinstance(record, dict) and record.get("path") == relative]
    if len(matches) != 1:
        raise ValueError("package-bound Tier 2 verifier record is absent or duplicated")
    record = matches[0]
    if set(record) != {"path", "mode", "sha256"}:
        raise ValueError("package-bound Tier 2 verifier record is invalid")
    if parse_mode(record.get("mode")) != TIER2_VERIFIER_MODE:
        raise ValueError("package-bound Tier 2 verifier mode mismatch")
    digest = record.get("sha256")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ValueError("package-bound Tier 2 verifier digest is invalid")
    return record


def tier2_engine_record(manifest: dict[str, object]) -> dict[str, str]:
    record = manifest.get("tier2_engine")
    if not isinstance(record, dict) or set(record) != {"path", "mode", "sha256"}:
        raise ValueError("package-bound Tier 2 engine record is invalid")
    path_raw, mode_raw, digest = record.get("path"), record.get("mode"), record.get("sha256")
    if path_raw != str(TIER2_ENGINE_PATH):
        raise ValueError("package-bound Tier 2 engine path is invalid")
    if parse_mode(mode_raw) != 0o700:
        raise ValueError("package-bound Tier 2 engine mode mismatch")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ValueError("package-bound Tier 2 engine digest is invalid")
    return {"path": path_raw, "mode": str(mode_raw), "sha256": digest}


def open_bound_tier2_verifier(
    manifest: dict[str, object], repo_root: Path
) -> int:
    record = verifier_source_record(manifest)
    path = repo_root / TIER2_VERIFIER_RELATIVE
    source = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    sealed = -1
    try:
        metadata = os.fstat(source)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != TIER2_VERIFIER_MODE
        ):
            raise ValueError("unsafe package-bound Tier 2 verifier")
        sealed = os.memfd_create(
            "mgact-tier2-verifier",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        digest = hashlib.sha256()
        while chunk := os.read(source, 1024 * 1024):
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(sealed, view)
                if written <= 0:
                    raise OSError("short write while freezing the Tier 2 verifier")
                view = view[written:]
        if digest.hexdigest() != record["sha256"]:
            raise ValueError("package-bound Tier 2 verifier hash mismatch")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
        fcntl.fcntl(sealed, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(sealed, fcntl.F_GET_SEALS) & seals != seals:
            raise ValueError("package-bound Tier 2 verifier memfd is not fully sealed")
        os.lseek(sealed, 0, os.SEEK_SET)
        return sealed
    except Exception:
        if sealed >= 0:
            os.close(sealed)
        raise
    finally:
        os.close(source)


def drop_to_artifact_owner(owner: ArtifactOwner) -> None:
    if os.geteuid() == owner.uid:
        return
    if os.geteuid() != 0:
        raise RuntimeError("cannot enter artifact-owner identity")
    os.setgroups([])
    os.setgid(owner.gid)
    os.setuid(owner.uid)


def run_tier2_check(
    state_path: Path,
    evidence_path: Path,
    bundle: Path,
    manifest: dict[str, object],
    repo_root: Path,
    owner: ArtifactOwner,
) -> dict[str, object]:
    require_regular(state_path, mode=0o600, owner_uid=owner.uid)
    descriptor = open_bound_tier2_verifier(manifest, repo_root)
    engine = tier2_engine_record(manifest)
    environment = {
        "HOME": owner.home,
        "LC_ALL": "C",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        completed = subprocess.run(
            [
                sys.executable,
                f"/proc/self/fd/{descriptor}",
                "check",
                "--state",
                str(state_path),
                "--evidence",
                str(evidence_path),
                "--candidate-root",
                str(bundle),
                "--engine",
                engine["path"],
                "--engine-sha256",
                engine["sha256"],
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            env=environment,
            pass_fds=(descriptor,),
            preexec_fn=(
                (lambda: drop_to_artifact_owner(owner))
                if os.geteuid() != owner.uid
                else None
            ),
        )
    finally:
        os.close(descriptor)
    lines = [line for line in completed.stdout.splitlines() if line]
    if completed.returncode != 0:
        detail = completed.stderr.strip()
        raise ValueError(f"Tier 2 v2 closure rejected: {detail or completed.returncode}")
    if len(lines) != 1:
        raise ValueError("Tier 2 v2 closure check returned an invalid response count")
    value = json.loads(lines[0], object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("Tier 2 v2 closure check did not return an object")
    return value


def validate_tier2_acceptance(
    bundle: Path,
    manifest: dict[str, object],
    receipt: dict[str, object],
    evidence_path: Path,
    state_path: Path,
    repo_root: Path,
    owner: ArtifactOwner,
) -> Tier2Acceptance:
    for path, label, limit in (
        (evidence_path, "evidence bundle", 64 * 1024),
        (state_path, "state", 1024 * 1024),
    ):
        try:
            require_regular(path, mode=0o600, owner_uid=owner.uid)
            if path.lstat().st_size > limit:
                raise ValueError(f"file exceeds {limit} bytes")
        except Exception as error:
            raise ValueError(f"unsafe Tier 2 v2 {label}: {error}") from error

    evidence_raw = load_json(
        evidence_path,
        max_bytes=64 * 1024,
        mode=0o600,
        owner_uid=owner.uid,
    )
    commands = receipt.get("commands")
    if not isinstance(commands, list):
        raise ValueError("preflight receipt commands are absent")
    expected_evidence = PREFLIGHT_SUPPORT.expected_tier2_bundle(bundle, manifest, commands)
    if evidence_raw != expected_evidence:
        raise ValueError("Tier 2 v2 evidence does not bind the exact package and Tier 1 results")
    evidence_digest = sha256_file(evidence_path)

    check = run_tier2_check(
        state_path,
        evidence_path,
        bundle,
        manifest,
        repo_root,
        owner,
    )
    expected_keys = {
        "ok",
        "subcommand",
        "state_schema",
        "producer_provider",
        "escalated",
        "route",
        "lineage_id",
        "state_id",
        "revision",
        "verdict",
        "reviewer_identity",
        "evidence_digest",
        "state_digest",
        "candidate_fingerprint",
        "verdict_digest",
    }
    if set(check) != expected_keys or check.get("ok") is not True:
        raise ValueError("Tier 2 v2 closure response fields mismatch")
    if check.get("subcommand") != "check" or check.get("state_schema") != "tier2-state-v2":
        raise ValueError("Tier 2 v2 closure response type mismatch")
    if check.get("producer_provider") != "gpt" or check.get("escalated") is not False:
        raise ValueError("Tier 2 v2 closure producer or activation override mismatch")
    if check.get("route") != {
        "provider": "claude",
        "model": "claude-opus-5",
        "effort": "high",
    }:
        raise ValueError("Tier 2 v2 closure review route mismatch")
    if check.get("evidence_digest") != evidence_digest:
        raise ValueError("Tier 2 v2 closure evidence digest mismatch")
    if check.get("state_digest") != sha256_file(state_path):
        raise ValueError("Tier 2 v2 state changed during validation")
    revision = check.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision not in (1, 2):
        raise ValueError("Tier 2 v2 closure revision is invalid")
    if check.get("verdict") not in ("PASS", "PASS WITH RISKS"):
        raise ValueError("Tier 2 v2 closure verdict is not accepted")
    for key in (
        "lineage_id",
        "state_id",
        "reviewer_identity",
        "candidate_fingerprint",
        "verdict_digest",
    ):
        value = check.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Tier 2 v2 closure {key} is absent")
    for key in ("candidate_fingerprint", "verdict_digest", "state_digest"):
        if not HEX64.fullmatch(str(check[key])):
            raise ValueError(f"Tier 2 v2 closure {key} is invalid")

    return Tier2Acceptance(
        lineage_id=str(check["lineage_id"]),
        state_id=str(check["state_id"]),
        revision=revision,
        verdict=str(check["verdict"]),
        reviewer_identity=str(check["reviewer_identity"]),
        verdict_digest=str(check["verdict_digest"]),
        evidence_digest=evidence_digest,
        candidate_fingerprint=str(check["candidate_fingerprint"]),
        state_digest=str(check["state_digest"]),
    )


def build_installed_closure(
    manifest: dict[str, object],
    acceptance: Tier2Acceptance,
) -> bytes:
    files = manifest.get("review_files")
    if not isinstance(files, dict) or set(files) != {"mempool", "genesis"}:
        raise ValueError("review file map is absent")
    for slug in ("mempool", "genesis"):
        values = files.get(slug)
        if not isinstance(values, list) or len(values) != 17:
            raise ValueError(f"{slug} installed closure must contain exactly 17 paths")
    return canonical_json(
        {
            "schema": INSTALLED_CLOSURE_SCHEMA,
            "accepted": True,
            "lineage_id": acceptance.lineage_id,
            "state_id": acceptance.state_id,
            "runtime_artifact_fingerprint": manifest["runtime_artifact_fingerprint"],
            "candidate_fingerprint": acceptance.candidate_fingerprint,
            "bundle_digest": manifest["package_digest"],
            "state_digest": acceptance.state_digest,
            "verdict_digest": acceptance.verdict_digest,
            "verdict": acceptance.verdict,
            "files": files,
        }
    )


def load_bundle(
    bundle: Path,
    receipt_path: Path,
    evidence_path: Path,
    state_path: Path,
    repo_root: Path = REPO_ROOT,
) -> tuple[dict[str, object], Tier2Acceptance, tuple[Target, ...]]:
    owner = artifact_owner()
    if os.geteuid() == 0 and repo_root != REPO_ROOT:
        raise ValueError("real-root validation requires the reviewed activation repository")
    manifest = PREFLIGHT_SUPPORT.validate_bundle(bundle, repo_root)
    if manifest.get("schema") != BUNDLE_SCHEMA or manifest.get("bundle_id") != BUNDLE_ID:
        raise ValueError("package schema or identity mismatch")
    if manifest.get("input_status") != "complete" or manifest.get("ready_for_parent_tier1") is not True:
        raise ValueError("package public-key inputs are incomplete")
    if manifest.get("installable") is not False:
        raise ValueError("producer package must remain non-installable")
    receipt = validate_preflight_receipt(receipt_path, bundle, manifest, evidence_path, owner)
    acceptance = validate_tier2_acceptance(
        bundle,
        manifest,
        receipt,
        evidence_path,
        state_path,
        repo_root,
        owner,
    )
    runtime_raw, ops_raw = manifest.get("runtime_targets"), manifest.get("ops_targets")
    if not isinstance(runtime_raw, list) or len(runtime_raw) != 19:
        raise ValueError("runtime target count must be 19")
    if not isinstance(ops_raw, list) or len(ops_raw) != 1:
        raise ValueError("ops target count must be one")
    runtime_targets = tuple(parse_target(bundle, raw) for raw in runtime_raw)
    ops_targets = tuple(parse_target(bundle, raw) for raw in ops_raw)
    if len({target.target for target in runtime_targets + ops_targets}) != 20:
        raise ValueError("duplicate install target")
    closure_payload = build_installed_closure(manifest, acceptance)
    closure_target = Target(
        CLOSURE_TARGET,
        None,
        closure_payload,
        0o644,
        0,
        0,
        sha256_bytes(closure_payload),
        True,
    )
    return manifest, acceptance, runtime_targets + ops_targets + (closure_target,)


def expected_owner(target: Target, root: Path) -> tuple[int, int]:
    if root == Path("/"):
        return target.uid, target.gid
    if os.environ.get("MGACT_TESTING") != "1":
        raise ValueError("non-root install roots require MGACT_TESTING=1")
    return os.getuid(), os.getgid()


def root_metadata(root: Path) -> os.stat_result:
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("install root is not a directory")
    if root.is_symlink():
        raise ValueError("install root must not be a symlink")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError("install root is group/world-writable")
    return metadata


def trusted_parent_directory(root: Path, link: Path) -> Path | None:
    try:
        resolved_root = root.resolve(strict=True)
        resolved_parent = link.parent.resolve(strict=True)
        resolved = link.resolve(strict=True)
        metadata = resolved.lstat()
    except (OSError, RuntimeError):
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return None
    if resolved == resolved_root or resolved_root not in resolved.parents:
        return None
    if resolved == resolved_parent or resolved_parent not in resolved.parents:
        return None
    return resolved


def walk_parent(root: Path, target: Target) -> tuple[Path | None, str | None]:
    root_metadata(root)
    uid, gid = expected_owner(target, root)
    allowed_owners = {0, uid}
    allowed_groups = {0, gid}
    current = root
    for part in Path(target.target).parts[1:-1]:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return None, "parent absent"
        if stat.S_ISLNK(metadata.st_mode):
            if metadata.st_uid not in allowed_owners or metadata.st_gid not in allowed_groups:
                return None, "parent component owner mismatch"
            trusted = trusted_parent_directory(root, current)
            if trusted is None:
                return None, "symlink in parent path"
            current = trusted
            metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            return None, "parent component not directory"
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            return None, "parent component group/world-writable"
        if metadata.st_uid not in allowed_owners or metadata.st_gid not in allowed_groups:
            return None, "parent component owner mismatch"
    metadata = current.lstat()
    if metadata.st_uid != uid or metadata.st_gid != gid:
        return None, "parent owner mismatch"
    return current, None


def inspect_target(target: Target, root: Path) -> TargetState:
    destination = rooted(root, target.target)
    parent, blocker = walk_parent(root, target)
    if parent is None:
        return TargetState(target, destination, destination.parent, "blocked", str(blocker))
    uid, gid = expected_owner(target, root)
    resolved_destination = parent / destination.name
    try:
        existing = resolved_destination.lstat()
    except FileNotFoundError:
        return TargetState(target, destination, parent, "add", "target absent")
    if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
        return TargetState(target, destination, parent, "blocked", "unsafe existing target")
    if existing.st_uid != uid or existing.st_gid != gid:
        return TargetState(target, destination, parent, "blocked", "target owner mismatch")
    if stat.S_IMODE(existing.st_mode) == target.mode and sha256_file(resolved_destination) == target.sha256:
        return TargetState(target, destination, parent, "current", "hash and metadata match")
    return TargetState(target, destination, parent, "replace", "hash or mode differs")


def host_name() -> str:
    return os.uname().nodename


def systemctl_readback(action: str, unit: str) -> tuple[int, str]:
    completed = subprocess.run(
        ["systemctl", action, unit],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    return completed.returncode, completed.stdout.strip()


def service_blockers(root: Path) -> list[str]:
    if root != Path("/"):
        return []
    blockers: list[str] = []
    if host_name() != "framework-desktop":
        blockers.append("real-root operation requires framework-desktop")
    if os.geteuid() != 0:
        blockers.append("real-root operation requires root")
    for slug in ("mempool", "genesis"):
        unit = f"buzz-agent@{slug}.service"
        try:
            active_code, active_state = systemctl_readback("is-active", unit)
            enabled_code, enabled_state = systemctl_readback("is-enabled", unit)
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            blockers.append(f"service state unreadable: {unit}: {type(error).__name__}")
            continue
        if active_code != 3 or active_state != "inactive":
            blockers.append(f"service must be stopped: {unit} state={active_state or active_code}")
        if enabled_code != 1 or enabled_state != "disabled":
            blockers.append(f"service must be disabled: {unit} state={enabled_state or enabled_code}")
    return blockers


def preflight(
    bundle: Path,
    receipt: Path,
    evidence: Path,
    state: Path,
    root: Path,
    repo_root: Path = REPO_ROOT,
) -> Preflight:
    try:
        manifest, acceptance, targets = load_bundle(
            bundle,
            receipt,
            evidence,
            state,
            repo_root,
        )
    except Exception as error:
        return Preflight(None, None, (), (str(error),))
    try:
        blockers = service_blockers(root)
        root_metadata(root)
    except Exception as error:
        blockers = [str(error)]
    states: list[TargetState] = []
    for target in sorted(targets, key=lambda value: (value.install_last, value.target.encode())):
        try:
            target_state = inspect_target(target, root)
        except Exception as error:
            destination = rooted(root, target.target)
            target_state = TargetState(target, destination, destination.parent, "blocked", str(error))
        states.append(target_state)
        if target_state.status == "blocked":
            blockers.append(f"{target.target}: {target_state.reason}")
    return Preflight(manifest, acceptance, tuple(states), tuple(blockers))


def render_preflight(value: Preflight, mode: str) -> str:
    bundle_id = value.manifest.get("bundle_id") if value.manifest else "unresolved"
    lineage_id = value.acceptance.lineage_id if value.acceptance else "unresolved"
    lines = [f"MGACT {mode} bundle={bundle_id} lineage={lineage_id}"]
    for state in value.targets:
        lines.append(f"TARGET {state.target.target} status={state.status} reason={state.reason}")
    if value.blockers:
        lines.append("PREFLIGHT BLOCKERS:")
        lines.extend(f"- {blocker}" for blocker in value.blockers)
    else:
        adds = sum(state.status == "add" for state in value.targets)
        replacements = sum(state.status == "replace" for state in value.targets)
        current = sum(state.status == "current" for state in value.targets)
        lines.append(f"PREFLIGHT OK add={adds} replace={replacements} current={current} writes=0")
    return "\n".join(lines) + "\n"


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_copy_source(target: Target, state: TargetState, root: Path) -> None:
    uid, gid = expected_owner(target, root)
    source_descriptor = -1
    if target.payload is None:
        if target.source is None:
            raise ValueError("target has no source")
        source_descriptor = os.open(target.source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    temporary_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{state.destination.name}.mgact.", dir=state.resolved_parent
    )
    try:
        digest = hashlib.sha256()
        if target.payload is not None:
            chunks = [target.payload]
        else:
            source_metadata = os.fstat(source_descriptor)
            if not stat.S_ISREG(source_metadata.st_mode) or source_metadata.st_nlink != 1:
                raise ValueError(f"unsafe source during copy: {target.source}")
            chunks = iter(lambda: os.read(source_descriptor, 1024 * 1024), b"")
        for chunk in chunks:
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(temporary_descriptor, view)
                if written <= 0:
                    raise OSError("short write during atomic install")
                view = view[written:]
        os.fchmod(temporary_descriptor, target.mode)
        if root == Path("/"):
            os.fchown(temporary_descriptor, uid, gid)
        os.fsync(temporary_descriptor)
        if digest.hexdigest() != target.sha256:
            raise ValueError(f"source changed during copy: {target.target}")
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        os.replace(temporary_name, state.resolved_parent / state.destination.name)
        sync_directory(state.resolved_parent)
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def backup_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    source_descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    destination_descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        metadata = os.fstat(source_descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe backup source: {source}")
        while chunk := os.read(source_descriptor, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise OSError("short write during backup")
                view = view[written:]
        os.fsync(destination_descriptor)
    finally:
        os.close(source_descriptor)
        os.close(destination_descriptor)


def write_receipt(path: Path, value: dict[str, object]) -> None:
    payload = canonical_json(value)
    temporary_descriptor, temporary_name = tempfile.mkstemp(prefix=".receipt.", dir=path.parent)
    try:
        os.fchmod(temporary_descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(temporary_descriptor, view)
            if written <= 0:
                raise OSError("short write during install receipt update")
            view = view[written:]
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        os.replace(temporary_name, path)
        sync_directory(path.parent)
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def backup_root_for(root: Path) -> Path:
    return rooted(root, "/var/lib/buzz-mgact-backups")


def lock_path_for(root: Path) -> Path:
    return rooted(root, "/run/lock/buzz-mgact-install.lock")


def admin_owner(root: Path) -> tuple[int, int]:
    if root == Path("/"):
        return 0, 0
    if os.environ.get("MGACT_TESTING") != "1":
        raise ValueError("non-root install roots require MGACT_TESTING=1")
    return os.getuid(), os.getgid()


def ensure_admin_directory(path: Path, root: Path, mode: int) -> None:
    uid, gid = admin_owner(root)
    relative = path.relative_to(root)
    current = root
    root_metadata(root)
    for index, part in enumerate(relative.parts):
        current = current / part
        expected_mode = mode if index == len(relative.parts) - 1 else 0o755
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=expected_mode)
            current.chmod(expected_mode)
            metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"unsafe admin directory: {current}")
        if metadata.st_uid != uid or metadata.st_gid != gid:
            raise ValueError(f"admin directory owner mismatch: {current}")
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise ValueError(f"admin directory mode mismatch: {current}")


def prepare_admin_paths(root: Path) -> tuple[Path, BinaryIO]:
    backup_root, lock_path = backup_root_for(root), lock_path_for(root)
    ensure_admin_directory(backup_root.parent, root, 0o755)
    ensure_admin_directory(backup_root, root, 0o700)
    ensure_admin_directory(lock_path.parent, root, 0o755)
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    metadata = os.fstat(descriptor)
    uid, gid = admin_owner(root)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise ValueError("unsafe install lock")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        os.close(descriptor)
        raise
    return backup_root, os.fdopen(descriptor, "r+b", closefd=True)


def atomic_restore(
    source: Path,
    state: TargetState,
    mode: int,
    uid: int,
    gid: int,
    root: Path,
) -> None:
    target = Target(state.target.target, source, None, mode, uid, gid, sha256_file(source))
    atomic_copy_source(target, state, root)


def metadata_matches(metadata: os.stat_result, mode: int, uid: int, gid: int) -> bool:
    return (
        stat.S_IMODE(metadata.st_mode) == mode
        and metadata.st_uid == uid
        and metadata.st_gid == gid
    )


def restore_targets(
    changed: list[TargetState],
    previous: dict[str, dict[str, object]],
    backup: Path,
    root: Path,
) -> None:
    for state in reversed(changed):
        record = previous[state.target.target]
        destination = state.resolved_parent / state.destination.name
        try:
            metadata = require_regular(destination, links=1)
        except FileNotFoundError:
            if record["exists"] is True:
                atomic_restore(
                    backup / "files" / str(record["backup_name"]),
                    state,
                    int(str(record["mode"]), 8),
                    int(record["uid"]),
                    int(record["gid"]),
                    root,
                )
            continue
        current_digest = sha256_file(destination)
        installed_uid, installed_gid = expected_owner(state.target, root)
        installed_matches = current_digest == state.target.sha256 and metadata_matches(
            metadata,
            state.target.mode,
            installed_uid,
            installed_gid,
        )
        if record["exists"] is True:
            previous_mode = int(str(record["mode"]), 8)
            previous_uid = int(record["uid"])
            previous_gid = int(record["gid"])
            previous_matches = current_digest == record["sha256"] and metadata_matches(
                metadata,
                previous_mode,
                previous_uid,
                previous_gid,
            )
            if previous_matches:
                continue
            if not installed_matches:
                raise ValueError(f"installed target drift blocks rollback: {state.target.target}")
            atomic_restore(
                backup / "files" / str(record["backup_name"]),
                state,
                previous_mode,
                previous_uid,
                previous_gid,
                root,
            )
        else:
            if not installed_matches:
                raise ValueError(f"installed target drift blocks rollback: {state.target.target}")
            destination.unlink()
            sync_directory(state.resolved_parent)


def verify_previous_state(state: TargetState, record: dict[str, object]) -> None:
    destination = state.resolved_parent / state.destination.name
    if record["exists"] is False:
        if os.path.lexists(destination):
            raise ValueError(f"target appeared after preflight: {state.target.target}")
        return
    metadata = require_regular(destination, links=1)
    if (
        sha256_file(destination) != record["sha256"]
        or stat.S_IMODE(metadata.st_mode) != int(str(record["mode"]), 8)
        or metadata.st_uid != int(record["uid"])
        or metadata.st_gid != int(record["gid"])
    ):
        raise ValueError(f"target changed after preflight: {state.target.target}")


def install(
    bundle: Path,
    receipt: Path,
    evidence: Path,
    state: Path,
    root: Path,
    repo_root: Path = REPO_ROOT,
) -> int:
    initial = preflight(bundle, receipt, evidence, state, root, repo_root)
    if initial.blockers or initial.manifest is None or initial.acceptance is None:
        print(render_preflight(initial, "install"), end="")
        return 1
    if not any(target.status in {"add", "replace"} for target in initial.targets):
        print("ALREADY_INSTALLED writes=0")
        return 0
    backup_root, lock_handle = prepare_admin_paths(root)
    try:
        checked = preflight(bundle, receipt, evidence, state, root, repo_root)
        if checked.blockers or checked.manifest is None or checked.acceptance is None:
            print(render_preflight(checked, "install-locked"), end="")
            return 1
        changed = [target for target in checked.targets if target.status in {"add", "replace"}]
        if not changed:
            print("ALREADY_INSTALLED writes=0")
            return 0
        instant = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        backup_id = f"{BUNDLE_ID}-{str(checked.manifest['package_digest'])[:12]}-{instant}"
        if not BACKUP_ID.fullmatch(backup_id):
            raise ValueError("generated backup ID is invalid")
        backup = backup_root / backup_id
        backup.mkdir(mode=0o700)
        (backup / "files").mkdir(mode=0o700)
        previous: dict[str, dict[str, object]] = {}
        for target in changed:
            destination = target.resolved_parent / target.destination.name
            if target.status == "replace":
                metadata = require_regular(destination, links=1)
                backup_name = hashlib.sha256(target.target.target.encode()).hexdigest()
                backup_file(destination, backup / "files" / backup_name)
                previous[target.target.target] = {
                    "exists": True,
                    "backup_name": backup_name,
                    "sha256": sha256_file(destination),
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                }
            else:
                previous[target.target.target] = {"exists": False}
        acceptance = checked.acceptance
        install_receipt: dict[str, object] = {
            "schema": INSTALL_RECEIPT_SCHEMA,
            "backup_id": backup_id,
            "bundle_id": checked.manifest["bundle_id"],
            "package_digest": checked.manifest["package_digest"],
            "preflight_receipt_sha256": sha256_file(receipt),
            "tier2_evidence_sha256": acceptance.evidence_digest,
            "tier2_state_sha256": acceptance.state_digest,
            "tier2_verdict_sha256": acceptance.verdict_digest,
            "tier2_candidate_fingerprint": acceptance.candidate_fingerprint,
            "review_lineage_id": acceptance.lineage_id,
            "review_state_id": acceptance.state_id,
            "review_revision": acceptance.revision,
            "review_verdict": acceptance.verdict,
            "state": "prepared",
            "changed_targets": [target.target.target for target in changed],
            "previous": previous,
            "installed": {
                target.target.target: {
                    "sha256": target.target.sha256,
                    "mode": f"{target.target.mode:04o}",
                    "uid": target.target.uid,
                    "gid": target.target.gid,
                }
                for target in changed
            },
        }
        receipt_path = backup / "receipt.json"
        write_receipt(receipt_path, install_receipt)
        applied: list[TargetState] = []
        try:
            for target in changed:
                verify_previous_state(target, previous[target.target.target])
                applied.append(target)
                atomic_copy_source(target.target, target, root)
            final = preflight(bundle, receipt, evidence, state, root, repo_root)
            if final.blockers or any(target.status != "current" for target in final.targets):
                raise ValueError("post-install preflight did not reach current state")
            install_receipt["state"] = "installed"
            write_receipt(receipt_path, install_receipt)
        except Exception:
            try:
                restore_targets(applied, previous, backup, root)
                install_receipt["state"] = "rolled_back"
                write_receipt(receipt_path, install_receipt)
            except Exception as rollback_error:
                install_receipt["state"] = "rollback_required"
                try:
                    write_receipt(receipt_path, install_receipt)
                except Exception:
                    pass
                raise RuntimeError(f"ROLLBACK_REQUIRED backup_id={backup_id}") from rollback_error
            raise
        print(f"INSTALLED backup_id={backup_id} changed={len(changed)}")
        return 0
    finally:
        lock_handle.close()


def rollback(backup_id: str, root: Path) -> int:
    if not BACKUP_ID.fullmatch(backup_id):
        raise ValueError("invalid backup ID")
    blockers = service_blockers(root)
    if blockers:
        raise ValueError("ROLLBACK REFUSED: " + "; ".join(blockers))
    backup_root, lock_handle = prepare_admin_paths(root)
    try:
        backup = backup_root / backup_id
        receipt_path = backup / "receipt.json"
        require_regular(receipt_path, mode=0o600)
        receipt = load_json(receipt_path)
        if (
            receipt.get("schema") != INSTALL_RECEIPT_SCHEMA
            or receipt.get("backup_id") != backup_id
            or receipt.get("state") != "installed"
        ):
            raise ValueError("backup receipt is not rollback-ready")
        changed = receipt.get("changed_targets")
        previous = receipt.get("previous")
        installed = receipt.get("installed")
        if (
            not isinstance(changed, list)
            or not isinstance(previous, dict)
            or not isinstance(installed, dict)
            or set(changed) != set(previous)
            or set(changed) != set(installed)
        ):
            raise ValueError("backup receipt target set mismatch")
        states: list[TargetState] = []
        for target_text in changed:
            if not isinstance(target_text, str) or not Path(target_text).is_absolute():
                raise ValueError("invalid rollback target")
            destination = rooted(root, target_text)
            record = installed[target_text]
            if not isinstance(record, dict):
                raise ValueError("invalid installed record")
            target = Target(
                target_text,
                destination,
                None,
                parse_mode(record.get("mode")),
                int(record.get("uid")),
                int(record.get("gid")),
                str(record.get("sha256")),
            )
            parent, blocker = walk_parent(root, target)
            if parent is None:
                raise ValueError(f"rollback parent blocked: {target_text}: {blocker}")
            current = parent / destination.name
            try:
                metadata = require_regular(current, links=1)
            except (FileNotFoundError, ValueError) as error:
                raise ValueError(
                    f"installed target drift blocks rollback: {target_text}: {error}"
                ) from error
            uid, gid = expected_owner(target, root)
            if sha256_file(current) != target.sha256 or not metadata_matches(
                metadata,
                target.mode,
                uid,
                gid,
            ):
                raise ValueError(f"installed target drift blocks rollback: {target_text}")
            states.append(TargetState(target, destination, parent, "replace", "rollback"))
        receipt["state"] = "rollback_started"
        write_receipt(receipt_path, receipt)
        restore_targets(states, previous, backup, root)
        receipt["state"] = "rolled_back"
        write_receipt(receipt_path, receipt)
        print(f"ROLLED_BACK backup_id={backup_id}")
        return 0
    finally:
        lock_handle.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    children = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "dry-run", "install"):
        child = children.add_parser(name)
        child.add_argument("--bundle", required=True)
        child.add_argument("--receipt", required=True)
        child.add_argument("--tier2-evidence", required=True)
        child.add_argument("--tier2-state", required=True)
        child.add_argument("--root", default="/")
        child.add_argument("--repo-root", default=str(REPO_ROOT))
    child = children.add_parser("rollback")
    child.add_argument("--backup-id", required=True)
    child.add_argument("--root", default="/")
    args = parser.parse_args()
    root = Path(args.root).absolute()
    if args.command == "rollback":
        raise SystemExit(rollback(args.backup_id, root))
    bundle = Path(args.bundle).resolve(strict=True)
    receipt = Path(args.receipt).resolve(strict=True)
    evidence = Path(args.tier2_evidence).resolve(strict=True)
    state = Path(args.tier2_state).resolve(strict=True)
    repo_root = Path(args.repo_root).resolve(strict=True)
    if args.command in {"check", "dry-run"}:
        value = preflight(bundle, receipt, evidence, state, root, repo_root)
        print(render_preflight(value, args.command), end="")
        raise SystemExit(1 if value.blockers else 0)
    raise SystemExit(install(bundle, receipt, evidence, state, root, repo_root))


if __name__ == "__main__":
    main()
