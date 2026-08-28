#!/usr/bin/env python3
"""Run deterministic preflight gates and write a non-authorizing receipt."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
BUNDLE_SCHEMA = "buzz-mempool-genesis-activation-bundle-v3"
BUNDLE_ID = "mempool-genesis-activation-20260825"
INPUT_BINDING_DESKTOP_SAVED = "desktop-saved"
RECEIPT_SCHEMA = "buzz-mempool-genesis-preflight-receipt-v3"
REVIEW_FILES_SCHEMA = "buzz-agent-review-files-v1"
TIER2_EVIDENCE_SCHEMA = "tier2-evidence-v3"
TIER2_ENGINE_PATH = Path("/home/victor/.agents/skills/codex-review/scripts/tier2")
TIER2_ENGINE_MODE = 0o755
TIER2_ENGINE_SHA256 = "10222c7a28c71232d65695562d28f68b158307bbac0e6f0c0e67bd8c57a08ef0"
TIER2_ENGINE_SOURCE_COMMIT = "8614f91296a8258ddba1c37d6ad0fd72b172619f"
TIER2_ENGINE_SOURCE_TREE = "d7ab1633c3bcf1e64b1725e82fd84470ceafe3c6"
TIER2_REVIEW = {
    "producer_provider": "gpt",
    "reviewer_provider": "claude",
    "model": "claude-opus-5",
    "effort": "high",
    "auth_source": "profile",
    "engine_subcommands": ["prepare", "review", "check"],
}
MAX_TIER2_EVIDENCE_BYTES = 64 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
SECP256K1_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ASSIGNER_PUBKEYS = (
    "4a34c131ec5cb5dd9a200bac619bbd103c0793e068fad278d1de59203d05b97d",
    "7806a7beb69ba4fd3b6e9b86d56931a446b62666e9794533f87fb2d1b956684f",
    "73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812",
    "aefa6783cdf2f33f9aa3705b41e5ae3ec214318c64db48f1410fc77db015f2ec",
    "db965b1f484ec4ebd3b0041091e890e2cd28e64732d9be53fd07ba640255af61",
)
RESERVED_PUBKEYS = ASSIGNER_PUBKEYS
PLACEHOLDERS = {
    "mempool": "DESKTOP_SAVE_REQUIRED_MEMPOOL_PUBKEY",
    "genesis": "DESKTOP_SAVE_REQUIRED_GENESIS_PUBKEY",
}
CLOSURE_TARGET = "/etc/buzz-agents/review-closure.json"
SHELLCHECK_PATH = "/home/victor/.npm-global/bin/shellcheck"
RUNTIME_TARGET_COUNT = 25
OPS_TARGET_COUNT = 4
TOTAL_PACKAGE_TARGET_COUNT = 29
REVIEW_PATH_COUNT = 22
SYSTEMD_FRAGMENT = "/etc/systemd/system/buzz-agent@.service"
SYSTEMD_MANAGER_DROPIN = "/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
SYSTEMD_INSTANCE_DROPINS = {
    "mempool": "/etc/systemd/system/buzz-agent@mempool.service.d/ci-migration.conf",
    "genesis": "/etc/systemd/system/buzz-agent@genesis.service.d/capability-parity.conf",
}
SYSTEMD_UNITS = ("buzz-agent@mempool.service", "buzz-agent@genesis.service")


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parity_canonical_json(value: object) -> bytes:
    path = SCRIPT_DIR / "capability-parity.py"
    spec = importlib.util.spec_from_file_location("mgact_preflight_canonical_json", path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load capability parity canonical JSON implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.canonical_json(value)
    except module.ParityError as error:
        raise ValueError(f"value is outside canonical JSON contract: {error}") from error


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def hash_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return hash_fd(descriptor)
    finally:
        os.close(descriptor)


def require_regular(
    path: Path,
    mode: int | None = None,
    *,
    owner_uid: int | None = None,
    links: int = 1,
) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != links:
        raise ValueError(f"unsafe regular file: {path}")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"wrong mode: {path}")
    if owner_uid is not None and metadata.st_uid != owner_uid:
        raise ValueError(f"wrong owner: {path}")
    return metadata


def load_json(
    path: Path,
    max_bytes: int = 1024 * 1024,
    *,
    mode: int | None = None,
    owner_uid: int | None = None,
) -> dict[str, object]:
    require_regular(path, mode, owner_uid=owner_uid)
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


def validate_source_record(bundle: Path, raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise ValueError("target record is not an object")
    required = {"target", "source", "mode", "uid", "gid", "sha256"}
    if not required.issubset(raw):
        raise ValueError("target record is incomplete")
    target, source = raw.get("target"), raw.get("source")
    digest, uid, gid = raw.get("sha256"), raw.get("uid"), raw.get("gid")
    if not isinstance(target, str) or not Path(target).is_absolute():
        raise ValueError("target path is not absolute")
    if not isinstance(source, str) or Path(source).is_absolute() or ".." in Path(source).parts:
        raise ValueError("source path escapes package")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ValueError("invalid target digest")
    if not isinstance(uid, int) or uid < 0 or not isinstance(gid, int) or gid < 0:
        raise ValueError("invalid target ownership")
    mode = parse_mode(raw.get("mode"))
    source_path = bundle / source
    try:
        source_path.resolve(strict=True).relative_to(bundle.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ValueError(f"source path escapes package: {source}") from error
    require_regular(source_path, mode)
    if sha256_file(source_path) != digest:
        raise ValueError(f"package source hash mismatch: {source}")
    return raw


def validate_review_files(
    manifest: dict[str, object], runtime_targets: list[dict[str, object]]
) -> dict[str, list[dict[str, str]]]:
    expected = manifest.get("expected_closure_paths")
    observed = manifest.get("review_files")
    if not isinstance(expected, dict) or set(expected) != {"mempool", "genesis"}:
        raise ValueError("expected closure path map mismatch")
    if not isinstance(observed, dict) or set(observed) != {"mempool", "genesis"}:
        raise ValueError("review file map mismatch")
    by_target = {str(record["target"]): record for record in runtime_targets}
    normalized: dict[str, list[dict[str, str]]] = {}
    for slug in ("mempool", "genesis"):
        paths, records = expected.get(slug), observed.get(slug)
        if (
            not isinstance(paths, list)
            or len(paths) != REVIEW_PATH_COUNT
            or len(set(paths)) != REVIEW_PATH_COUNT
        ):
            raise ValueError(
                f"{slug} expected closure list must contain {REVIEW_PATH_COUNT} unique paths"
            )
        if not isinstance(records, list) or len(records) != REVIEW_PATH_COUNT:
            raise ValueError(f"{slug} review file list must contain {REVIEW_PATH_COUNT} paths")
        values: list[dict[str, str]] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
                raise ValueError(f"invalid {slug} review record")
            path, digest = record.get("path"), record.get("sha256")
            if path != paths[index] or path not in by_target:
                raise ValueError(f"{slug} review order or path mismatch")
            if digest != by_target[path].get("sha256"):
                raise ValueError(f"{slug} review digest mismatch")
            values.append({"path": str(path), "sha256": str(digest)})
        normalized[slug] = values
    return normalized


def validate_generator_sources(manifest: dict[str, object], repo_root: Path) -> None:
    records = manifest.get("generator_sources")
    if not isinstance(records, list) or not records:
        raise ValueError("generator source inventory is absent")
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "mode", "sha256"}:
            raise ValueError("invalid generator source record")
        relative, digest = record.get("path"), record.get("sha256")
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("generator source path escapes repository")
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise ValueError("invalid generator source digest")
        mode = parse_mode(record.get("mode"))
        path = repo_root / relative
        require_regular(path, mode)
        if sha256_file(path) != digest:
            raise ValueError(f"generator source changed after package creation: {relative}")
        tree_line = subprocess.run(
            ["git", "ls-files", "--stage", "--", relative],
            cwd=repo_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
        ).stdout.strip()
        fields = tree_line.split(None, 3)
        if len(fields) != 4 or fields[2] != "0" or fields[3] != relative:
            raise ValueError(f"generator source is absent from source tree: {relative}")
        tree_mode = {"100644": 0o644, "100755": 0o755}.get(fields[0])
        if tree_mode != mode:
            raise ValueError(f"generator source mode is not bound to source tree: {relative}")
        committed = subprocess.run(
            ["git", "show", f":{relative}"],
            cwd=repo_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
        ).stdout
        if sha256_bytes(committed) != digest:
            raise ValueError(f"generator source is not bound to source tree: {relative}")


def git_value(repo_root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
    ).stdout.strip()


def artifact_fingerprint(records: list[dict[str, object]]) -> str:
    payload = "".join(
        f"A\t{record['sha256']}\t{record['mode']}\t{record['target']}\n"
        for record in sorted(records, key=lambda record: str(record["target"]).encode())
    ).encode()
    return sha256_bytes(payload)


def valid_xonly_public_key(value: str) -> bool:
    if not HEX64.fullmatch(value) or len(set(value)) == 1:
        return False
    x_coordinate = int(value, 16)
    if x_coordinate >= SECP256K1_FIELD:
        return False
    curve_value = (pow(x_coordinate, 3, SECP256K1_FIELD) + 7) % SECP256K1_FIELD
    return pow(curve_value, (SECP256K1_FIELD - 1) // 2, SECP256K1_FIELD) == 1


def validate_tier2_review(value: object) -> dict[str, object]:
    if value != TIER2_REVIEW:
        raise ValueError("Tier 2 review route must use the current GPT-to-Claude Opus 5 high route")
    return TIER2_REVIEW


def validate_tier2_engine(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "path",
        "mode",
        "sha256",
        "source_commit",
        "source_tree",
    }:
        raise ValueError("Tier 2 engine record is invalid")
    path_raw, mode_raw, digest = value.get("path"), value.get("mode"), value.get("sha256")
    if path_raw != str(TIER2_ENGINE_PATH):
        raise ValueError("Tier 2 engine path is invalid")
    path = TIER2_ENGINE_PATH
    if parse_mode(mode_raw) != TIER2_ENGINE_MODE:
        raise ValueError("Tier 2 engine mode mismatch")
    if digest != TIER2_ENGINE_SHA256:
        raise ValueError("Tier 2 engine digest does not match reviewed fleet source")
    if value.get("source_commit") != TIER2_ENGINE_SOURCE_COMMIT:
        raise ValueError("Tier 2 engine source commit mismatch")
    if value.get("source_tree") != TIER2_ENGINE_SOURCE_TREE:
        raise ValueError("Tier 2 engine source tree mismatch")
    require_regular(path, TIER2_ENGINE_MODE)
    if sha256_file(path) != digest:
        raise ValueError("Tier 2 engine changed after package creation")
    return {
        "path": path_raw,
        "mode": str(mode_raw),
        "sha256": digest,
        "source_commit": TIER2_ENGINE_SOURCE_COMMIT,
        "source_tree": TIER2_ENGINE_SOURCE_TREE,
    }


def tier2_command_result(result: dict[str, object]) -> dict[str, object]:
    command = result.get("command")
    exit_code = result.get("exit")
    stdout = result.get("stdout")
    stderr = result.get("stderr")
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(argument, str) or not argument for argument in command)
        or not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
        or not isinstance(stdout, str)
        or not isinstance(stderr, str)
    ):
        raise ValueError("preflight command result cannot be represented as Tier 2 evidence")
    output_parts = []
    if stdout:
        output_parts.append("stdout:\n" + stdout)
    if stderr:
        output_parts.append("stderr:\n" + stderr)
    return {
        "kind": "result",
        "argv": command,
        "exit_code": exit_code,
        "output": "\n".join(output_parts) if output_parts else "<no output>",
    }


def tier2_git_candidate(bundle: Path, manifest: dict[str, object]) -> tuple[Path, list[str]]:
    probe = subprocess.run(
        ["git", "-C", str(bundle), "rev-parse", "--show-toplevel"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if probe.returncode != 0:
        raise ValueError("Tier 2 v3 package candidate must be inside a Git worktree")
    candidate_root = Path(probe.stdout.strip()).resolve(strict=True)
    try:
        bundle_prefix = bundle.resolve(strict=True).relative_to(candidate_root)
    except ValueError as error:
        raise ValueError("package escapes its Tier 2 Git candidate root") from error

    package_paths = manifest.get("tier2_candidate_paths")
    if (
        not isinstance(package_paths, list)
        or not package_paths
        or any(not isinstance(item, str) or not item for item in package_paths)
        or len(set(package_paths)) != len(package_paths)
    ):
        raise ValueError("Tier 2 package candidate path inventory is invalid")
    actual_paths = sorted(
        (
            str(path.relative_to(bundle))
            for path in bundle.rglob("*")
            if path.is_file()
        ),
        key=str.encode,
    )
    if actual_paths != package_paths:
        raise ValueError("Tier 2 package candidate path inventory does not match package files")
    prefix = "" if str(bundle_prefix) == "." else f"{bundle_prefix.as_posix()}/"
    expected_status_paths = [prefix + item for item in package_paths]

    status = subprocess.run(
        ["git", "-C", str(candidate_root), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if status.returncode != 0:
        raise ValueError("cannot inspect Tier 2 v3 package candidate Git status")
    fields = status.stdout.split(b"\0")
    if not fields or fields[-1] != b"":
        raise ValueError("Tier 2 v3 package candidate Git status is malformed")
    observed_paths: list[str] = []
    for raw in fields[:-1]:
        if not raw.startswith(b"?? "):
            raise ValueError("Tier 2 v3 package candidate must contain only untracked package files")
        try:
            observed_paths.append(raw[3:].decode("utf-8"))
        except UnicodeDecodeError as error:
            raise ValueError("Tier 2 v3 package candidate path is not UTF-8") from error
    if sorted(observed_paths, key=str.encode) != expected_status_paths:
        raise ValueError("Tier 2 v3 package candidate Git inventory contains non-package drift")
    return candidate_root, expected_status_paths


def expected_tier2_bundle(
    bundle: Path,
    manifest: dict[str, object],
    commands: list[dict[str, object]],
) -> dict[str, object]:
    validate_tier2_review(manifest.get("tier2_review"))
    if manifest.get("tier2_evidence_schema") != TIER2_EVIDENCE_SCHEMA:
        raise ValueError("Tier 2 evidence schema mismatch")
    candidate_root, candidate_paths = tier2_git_candidate(bundle, manifest)
    value = {
        "schema": TIER2_EVIDENCE_SCHEMA,
        "candidate_root": str(candidate_root),
        "summary": (
            "GPT-produced Mempool and Genesis credential, signing, and production activation "
            "package; the current opposite-provider contract requires one Claude Opus 5 reviewer "
            "at high reasoning."
        ),
        "paths": candidate_paths,
        "invariants": [
            "The review binds the exact package manifest and 22 review-file paths per agent, covering 25 distinct installed paths.",
            "The package and review state remain owner-only and credential-free.",
            "The parent Tier 1 receipt is deterministic evidence only and grants no install authority.",
            "Mempool and Genesis stay stopped and disabled through review and install preflight.",
            "Installation remains absent-only for credentials and preserves rollback and exact hashes.",
            "Prepare must use --producer-provider gpt with stable scope binding; review and check use the same state.",
        ],
        "commands": [tier2_command_result(result) for result in commands],
        "known_limits": [],
    }
    payload = canonical_json(value)
    if len(payload) > MAX_TIER2_EVIDENCE_BYTES:
        raise ValueError("Tier 2 evidence exceeds the current engine's 64 KiB bound")
    return value


def validate_bundle(bundle: Path, repo_root: Path) -> dict[str, object]:
    bundle_metadata = bundle.lstat()
    if not stat.S_ISDIR(bundle_metadata.st_mode) or stat.S_IMODE(bundle_metadata.st_mode) & 0o077:
        raise ValueError("package directory must be owner-only")
    manifest_path = bundle / "bundle-manifest.json"
    require_regular(manifest_path, 0o600)
    manifest = load_json(manifest_path)
    required = {
        "schema",
        "bundle_id",
        "source_commit",
        "source_tree",
        "source_branch",
        "generator_sources",
        "inputs",
        "identities",
        "acp_state_dirs",
        "identity_binding",
        "input_status",
        "ready_for_parent_tier1",
        "installable",
        "runtime_artifact_fingerprint",
        "package_digest",
        "runtime_targets",
        "ops_targets",
        "review_files",
        "expected_closure_paths",
        "review_files_record",
        "tier2_review",
        "tier2_engine",
        "tier2_evidence_schema",
        "tier2_candidate_paths",
        "capability_parity",
    }
    if set(manifest) != required or manifest.get("schema") != BUNDLE_SCHEMA:
        raise ValueError("package manifest schema or fields mismatch")
    if manifest.get("bundle_id") != BUNDLE_ID:
        raise ValueError("package identity mismatch")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != {"mempool", "genesis"}:
        raise ValueError("package input map mismatch")
    if manifest.get("identity_binding") != INPUT_BINDING_DESKTOP_SAVED:
        raise ValueError("package identities are not explicitly bound to Desktop-saved inputs")
    complete = True
    for slug in ("mempool", "genesis"):
        value = inputs.get(slug)
        if value == PLACEHOLDERS[slug]:
            complete = False
        elif not isinstance(value, str) or not HEX64.fullmatch(value):
            raise ValueError(f"{slug} public key is invalid")
        elif len(set(value)) == 1:
            raise ValueError(f"{slug} public key is a repeated-nibble placeholder")
        elif not valid_xonly_public_key(value):
            raise ValueError(f"{slug} public key is not a valid secp256k1 x-only public key")
    if complete:
        if inputs["mempool"] == inputs["genesis"]:
            raise ValueError("Mempool and Genesis public keys are not distinct")
        if inputs["mempool"] in RESERVED_PUBKEYS or inputs["genesis"] in RESERVED_PUBKEYS:
            raise ValueError("agent public keys reuse a reserved responder identity")
    expected_status = "complete" if complete else "desktop-save-required"
    if manifest.get("input_status") != expected_status:
        raise ValueError("package input status mismatch")
    if manifest.get("ready_for_parent_tier1") is not complete:
        raise ValueError("package parent-readback readiness claim is invalid")
    if manifest.get("installable") is not False:
        raise ValueError("producer package must remain non-installable")

    identities = manifest.get("identities")
    state_dirs = manifest.get("acp_state_dirs")
    expected_identities = {
        slug: {
            "public_key": inputs[slug],
            "user": f"buzz-{slug}",
            "home": f"/home/buzz-{slug}",
            "credential_path": f"/etc/buzz-agents/credentials/{slug}.key",
            "environment_path": f"/etc/buzz-agents/{slug}.env",
            "prompt_path": f"/etc/buzz-agents/prompts/{slug}.md",
            "acp_state_dir": f"/home/buzz-{slug}/.local/state/buzz-acp",
            "systemd_unit": f"buzz-agent@{slug}.service",
        }
        for slug in ("mempool", "genesis")
    }
    expected_state_dirs = {
        slug: f"/home/buzz-{slug}/.local/state/buzz-acp"
        for slug in ("mempool", "genesis")
    }
    if identities != expected_identities:
        raise ValueError("identity descriptor map mismatch")
    if state_dirs != expected_state_dirs:
        raise ValueError("ACP state directory map mismatch")

    runtime_raw, ops_raw = manifest.get("runtime_targets"), manifest.get("ops_targets")
    if not isinstance(runtime_raw, list) or len(runtime_raw) != RUNTIME_TARGET_COUNT:
        raise ValueError(f"runtime target count must be {RUNTIME_TARGET_COUNT}")
    if not isinstance(ops_raw, list) or len(ops_raw) != OPS_TARGET_COUNT:
        raise ValueError(f"ops target count must be {OPS_TARGET_COUNT}")
    runtime = [validate_source_record(bundle, record) for record in runtime_raw]
    ops = [validate_source_record(bundle, record) for record in ops_raw]
    targets = [str(record["target"]) for record in runtime + ops]
    if len(set(targets)) != TOTAL_PACKAGE_TARGET_COUNT:
        raise ValueError("package target set contains a duplicate")
    runtime_targets = {str(record["target"]) for record in runtime}
    expected_systemd_targets = {
        SYSTEMD_FRAGMENT,
        SYSTEMD_MANAGER_DROPIN,
        *SYSTEMD_INSTANCE_DROPINS.values(),
    }
    packaged_systemd_targets = {
        target
        for target in runtime_targets
        if target == SYSTEMD_FRAGMENT
        or target == SYSTEMD_MANAGER_DROPIN
        or target.startswith("/etc/systemd/system/buzz-agent@")
    }
    if packaged_systemd_targets != expected_systemd_targets:
        raise ValueError("packaged systemd fragment/drop-in target set mismatch")
    expected_ops = {
        "/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep": {
            "mode": "0700",
            "scope": "Codex-R-matched open and eligible Sats/Victor private membership",
        },
        "/home/victor/.config/systemd/user/buzz-sats-channel-sweep.service": {
            "mode": "0600",
            "scope": "Buzz-owned user service binding for the source-pinned sweep",
        },
        "/home/victor/.agents/tools/buzz-parity-owner-signer": {
            "mode": "0700",
            "scope": "owner Schnorr parity receipt signing from a sanctioned private file",
        },
        "/home/victor/.agents/tools/buzz-parity-owner-verifier": {
            "mode": "0700",
            "scope": "owner Schnorr parity receipt verification from standard input",
        },
    }
    by_target = {str(record["target"]): record for record in ops}
    if set(by_target) != set(expected_ops):
        raise ValueError("ops target paths mismatch")
    for target, expected in expected_ops.items():
        record = by_target[target]
        for key, value in {**expected, "uid": 1000, "gid": 1000}.items():
            if record.get(key) != value:
                raise ValueError(f"ops target mismatch: {target} {key}")
    files = validate_review_files(manifest, runtime)
    for slug in ("mempool", "genesis"):
        covered = {str(record["path"]) for record in files[slug]}
        effective = {
            SYSTEMD_FRAGMENT,
            SYSTEMD_MANAGER_DROPIN,
            SYSTEMD_INSTANCE_DROPINS[slug],
        }
        if not effective <= covered:
            raise ValueError(f"{slug} effective systemd paths escape review closure")
    fingerprint = artifact_fingerprint(runtime)
    if manifest.get("runtime_artifact_fingerprint") != fingerprint:
        raise ValueError("runtime artifact fingerprint mismatch")

    review_record = manifest.get("review_files_record")
    if not isinstance(review_record, dict) or set(review_record) != {"path", "sha256"}:
        raise ValueError("review file record is invalid")
    review_path, review_digest = review_record.get("path"), review_record.get("sha256")
    if review_path != "metadata/review-files.json":
        raise ValueError("review file path mismatch")
    if not isinstance(review_digest, str) or not HEX64.fullmatch(review_digest):
        raise ValueError("review file digest is invalid")
    review_source = bundle / review_path
    require_regular(review_source, 0o600)
    if sha256_file(review_source) != review_digest:
        raise ValueError("review file source hash mismatch")
    review_value = load_json(review_source)
    expected_review_status = "pending-tier2-v3" if complete else "blocked-on-desktop-pubkeys"
    if review_value != {
        "schema": REVIEW_FILES_SCHEMA,
        "status": expected_review_status,
        "runtime_artifact_fingerprint": fingerprint,
        "package_digest": manifest["package_digest"],
        "files": files,
    }:
        raise ValueError("review file payload mismatch")

    validate_tier2_review(manifest.get("tier2_review"))
    validate_tier2_engine(manifest.get("tier2_engine"))
    if manifest.get("tier2_evidence_schema") != TIER2_EVIDENCE_SCHEMA:
        raise ValueError("Tier 2 evidence schema mismatch")
    package_paths = manifest.get("tier2_candidate_paths")
    if (
        not isinstance(package_paths, list)
        or not package_paths
        or any(not isinstance(item, str) or not item for item in package_paths)
        or len(set(package_paths)) != len(package_paths)
    ):
        raise ValueError("Tier 2 package candidate path inventory is invalid")
    policy_document = json.loads(
        (SCRIPT_DIR / "capability-parity-policy.json").read_text(),
        object_pairs_hook=reject_duplicates,
    )
    unit_sources = {
        "template": REPO_ROOT / "scripts/mempool-genesis/buzz-agent@.service",
        "mempool_dropin": SCRIPT_DIR / "templates/systemd/buzz-agent@mempool.service.d/ci-migration.conf",
        "genesis_dropin": SCRIPT_DIR / "templates/systemd/buzz-agent@genesis.service.d/capability-parity.conf",
    }
    expected_no_af_netlink = {
        label: {"path": str(path.relative_to(REPO_ROOT)), "sha256": sha256_file(path)}
        for label, path in unit_sources.items()
    }
    if any(b"AF_NETLINK" in path.read_bytes() for path in unit_sources.values()):
        raise ValueError("staged unit unexpectedly permits AF_NETLINK")
    if manifest.get("capability_parity") != {
        "manifest_schema": "buzz-agent-capability-manifest-v1",
        "receipt_schema": "buzz-agent-capability-parity-receipt-v2",
        "authority_receipt_schema": "buzz-agent-capability-authority-receipt-v1",
        "canonical_json_contract": "buzz-canonical-json-ascii-v1",
        "tool": "/usr/local/libexec/buzz/verify-agent-capability-parity",
        "policy": "/etc/buzz-agents/capability-parity-policy.json",
        "receipt_binding": {
            "status": "pending-live-capture",
            "path": "metadata/capability-parity-receipt.json",
            "sha256": None,
            "required_before_activation": True,
        },
        "authority_receipt_binding": {
            "path": "metadata/live-authority-receipt.json",
            "required": True,
            "max_age_seconds": 300,
        },
        "reference_channels": policy_document["reference_channels"],
        "reference_channels_sha256": sha256_bytes(parity_canonical_json(policy_document["reference_channels"])),
        "eligible_channels": policy_document["eligible_channels"],
        "eligible_channels_sha256": sha256_bytes(parity_canonical_json(policy_document["eligible_channels"])),
        "authority_exclusions": policy_document["authority_exclusions"],
        "authority_exclusions_sha256": sha256_bytes(parity_canonical_json(policy_document["authority_exclusions"])),
        "channel_sweep_target": "/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep",
        "owner_signer_target": "/home/victor/.agents/tools/buzz-parity-owner-signer",
        "owner_verifier_target": "/home/victor/.agents/tools/buzz-parity-owner-verifier",
        "owner_private_input": {
            "transport": "private-file",
            "field": "BUZZ_OWNER_PRIVATE_KEY",
            "mode": "0600",
            "parent_mode": "0700",
        },
        "payload_transport": "anonymous-pipe-stdin",
        "no_af_netlink": expected_no_af_netlink,
    }:
        raise ValueError("capability parity contract mismatch")
    digest_input = {
        "schema": BUNDLE_SCHEMA,
        "bundle_id": BUNDLE_ID,
        "source_commit": manifest["source_commit"],
        "source_tree": manifest["source_tree"],
        "inputs": inputs,
        "identities": identities,
        "acp_state_dirs": state_dirs,
        "identity_binding": manifest["identity_binding"],
        "input_status": expected_status,
        "runtime_targets": sorted(runtime, key=lambda record: str(record["target"]).encode()),
        "ops_targets": ops,
        "review_files": files,
        "expected_closure_paths": manifest["expected_closure_paths"],
        "generator_sources": manifest["generator_sources"],
        "tier2_review": manifest["tier2_review"],
        "tier2_engine": manifest["tier2_engine"],
        "tier2_evidence_schema": manifest["tier2_evidence_schema"],
        "tier2_candidate_paths": manifest["tier2_candidate_paths"],
        "capability_parity": manifest["capability_parity"],
    }
    package_digest = sha256_bytes(canonical_json(digest_input))
    if manifest.get("package_digest") != package_digest:
        raise ValueError("package digest mismatch")

    validate_generator_sources(manifest, repo_root)
    source_commit = manifest.get("source_commit")
    source_tree = manifest.get("source_tree")
    if not isinstance(source_commit, str) or not HEX40.fullmatch(source_commit):
        raise ValueError("package source commit is invalid")
    if not isinstance(source_tree, str) or not HEX40.fullmatch(source_tree):
        raise ValueError("package source tree is invalid")
    if source_commit != git_value(repo_root, "rev-parse", "HEAD"):
        raise ValueError("package source commit is stale")
    if source_tree != git_value(repo_root, "write-tree"):
        raise ValueError("package source tree is stale")
    if manifest.get("source_branch") != git_value(repo_root, "branch", "--show-current"):
        raise ValueError("package source branch is stale")
    return manifest


def snapshot(paths: list[str]) -> dict[str, object]:
    result: dict[str, object] = {}
    for raw in paths:
        path = Path(raw)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            result[raw] = {"exists": False}
            continue
        except PermissionError:
            result[raw] = {"exists": "unreadable"}
            continue
        record: dict[str, object] = {
            "exists": True,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "links": metadata.st_nlink,
            "size": metadata.st_size,
        }
        if stat.S_ISREG(metadata.st_mode):
            record["type"] = "regular"
            try:
                record["sha256"] = sha256_file(path)
            except PermissionError:
                record["sha256"] = "unreadable"
        elif stat.S_ISLNK(metadata.st_mode):
            record["type"] = "symlink"
            record["link_target"] = os.readlink(path)
        else:
            record["type"] = "other"
        result[raw] = record
    return result


def run(command: list[str], cwd: Path, test_root: Path) -> dict[str, object]:
    environment = os.environ.copy()
    environment.update(
        {
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "MGACT_TEST_ROOT": str(test_root),
        }
    )
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
            env=environment,
        )
        return {
            "command": command,
            "exit": completed.returncode,
            "stdout": completed.stdout[-12000:],
            "stderr": completed.stderr[-12000:],
        }
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        return {
            "command": command,
            "exit": 127,
            "stdout": "",
            "stderr": f"{type(error).__name__}: {error}",
        }


def systemd_verify_command(bundle: Path, *, debug: bool = False) -> list[str]:
    stage = (bundle / "install-root").resolve(strict=True)
    if ":" in str(stage):
        raise ValueError("staged systemd root contains a unit-path separator")
    unit_path = ":".join(
        (
            str(stage / "etc/systemd/system"),
            str(stage / "usr/lib/systemd/system"),
            "/usr/lib/systemd/system",
        )
    )
    command = ["/usr/bin/env", f"SYSTEMD_UNIT_PATH={unit_path}"]
    if debug:
        command.append("SYSTEMD_LOG_LEVEL=debug")
    return [*command, "/usr/bin/systemd-analyze", "verify", *SYSTEMD_UNITS]


def effective_unit_paths(output: str, unit: str) -> tuple[str, list[str]]:
    lines = output.splitlines()
    markers = {f"\t→ Unit {unit}:", f"\t-> Unit {unit}:"}
    starts = [index for index, line in enumerate(lines) if line in markers]
    if len(starts) != 1:
        raise ValueError(f"systemd verification did not report exactly one {unit} block")
    block_lines: list[str] = []
    for line in lines[starts[0] + 1 :]:
        if line.startswith("\t→ Unit ") or line.startswith("\t-> Unit "):
            break
        block_lines.append(line)
    fragments = [
        line.strip().removeprefix("Fragment Path: ")
        for line in block_lines
        if line.strip().startswith("Fragment Path: ")
    ]
    dropins = [
        line.strip().removeprefix("DropIn Path: ")
        for line in block_lines
        if line.strip().startswith("DropIn Path: ")
    ]
    if len(fragments) != 1:
        raise ValueError(f"systemd verification reported an invalid {unit} fragment set")
    return fragments[0], dropins


def verify_staged_systemd(bundle: Path) -> dict[str, object]:
    completed = subprocess.run(
        systemd_verify_command(bundle, debug=True),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    if completed.returncode != 0:
        raise ValueError(f"staged systemd verification failed with exit {completed.returncode}")
    output = completed.stdout + completed.stderr
    stage = (bundle / "install-root").resolve(strict=True)
    manifest = load_json(bundle / "bundle-manifest.json", mode=0o600)
    closures = manifest.get("expected_closure_paths")
    if not isinstance(closures, dict):
        raise ValueError("staged systemd closure map is absent")
    observed: dict[str, object] = {}
    for slug in ("mempool", "genesis"):
        unit = f"buzz-agent@{slug}.service"
        fragment, dropins = effective_unit_paths(output, unit)
        effective = [SYSTEMD_FRAGMENT, SYSTEMD_MANAGER_DROPIN, SYSTEMD_INSTANCE_DROPINS[slug]]
        expected_fragment = str(stage / SYSTEMD_FRAGMENT.lstrip("/"))
        expected_dropins = [str(stage / path.lstrip("/")) for path in effective[1:]]
        if fragment != expected_fragment or dropins != expected_dropins:
            raise ValueError(f"{slug} effective systemd paths escape the staged inventory")
        closure = closures.get(slug)
        if not isinstance(closure, list) or not set(effective) <= set(closure):
            raise ValueError(f"{slug} effective systemd paths escape the review closure")
        observed[slug] = {"fragment": effective[0], "dropins": effective[1:]}
    return observed


def gate_commands(bundle: Path) -> list[list[str]]:
    sweep_template = SCRIPT_DIR / "templates/buzz-sats-channel-sweep.sh"
    sweep_candidate = bundle / "ops-root/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep"
    commands = [
        [
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            str(SCRIPT_DIR / "tests"),
            "-p",
            "test_activation.py",
            "-v",
        ],
        [
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            str(SCRIPT_DIR / "tests"),
            "-p",
            "test_capability_parity.py",
            "-v",
        ],
        ["bash", "-n", str(sweep_template)],
        ["bash", "-n", str(sweep_candidate)],
        [
            sys.executable,
            "-B",
            str(SCRIPT_DIR / "make-tier1-receipt.py"),
            "--verify-systemd-stage",
            str(bundle),
        ],
    ]
    commands.append(
        [SHELLCHECK_PATH, "-S", "warning", str(sweep_template), str(sweep_candidate)]
    )
    return commands


def write_atomic(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_metadata = path.parent.lstat()
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_IMODE(parent_metadata.st_mode) & 0o077:
        raise ValueError("output parent must be owner-only")
    if path.exists() or path.is_symlink():
        require_regular(path, mode, owner_uid=os.getuid())
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while writing preflight output")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary_name, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def build_receipt(
    bundle: Path,
    manifest: dict[str, object],
    commands: list[dict[str, object]],
    before: dict[str, object],
    after: dict[str, object],
    tier2_bundle: dict[str, object] | None,
) -> dict[str, object]:
    commands_passed = all(result.get("exit") == 0 for result in commands)
    unchanged = before == after
    complete = manifest.get("input_status") == "complete"
    if commands_passed and unchanged:
        status = "READY_FOR_PARENT_TIER1" if complete else "BLOCKED_ON_DESKTOP_PUBKEYS"
    else:
        status = "FAILED"
    if status == "READY_FOR_PARENT_TIER1":
        if not isinstance(tier2_bundle, dict):
            raise ValueError("complete green preflight requires a generated Tier 2 v3 evidence bundle")
    elif tier2_bundle is not None:
        raise ValueError("blocked or failed preflight must not claim a reviewable Tier 2 bundle")
    return {
        "schema": RECEIPT_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "installable": False,
        "next_gate": "parent-tier1-readback" if complete else "desktop-public-key-save",
        "bundle": {
            "path": str(bundle),
            "manifest_sha256": sha256_file(bundle / "bundle-manifest.json"),
            "bundle_id": manifest["bundle_id"],
            "source_commit": manifest["source_commit"],
            "source_tree": manifest["source_tree"],
            "package_digest": manifest["package_digest"],
            "input_status": manifest["input_status"],
            "runtime_artifact_fingerprint": manifest["runtime_artifact_fingerprint"],
            "review_files_sha256": manifest["review_files_record"]["sha256"],
            "tier2_review": manifest["tier2_review"],
            "tier2_engine_sha256": manifest["tier2_engine"]["sha256"],
            "identities": manifest["identities"],
            "acp_state_dirs": manifest["acp_state_dirs"],
            "capability_parity": manifest["capability_parity"],
        },
        "tier2_bundle": tier2_bundle,
        "execution_bounds": {
            "installed": False,
            "published": False,
            "pushed": False,
            "merged": False,
            "activated": False,
            "credentials_used": False,
            "relay_events_sent": False,
        },
        "input_contract": {
            "schema": "buzz-mempool-genesis-activation-input-v1",
            "required_after_desktop_save": [
                "identity_binding: desktop-saved",
                "mempool_pubkey: 64 lowercase hex",
                "genesis_pubkey: 64 lowercase hex",
                "values must be distinct valid secp256k1 x-only keys and must not reuse any assignment-roster identity",
            ],
            "forbidden": ["private keys", "auth tags", "OAuth credentials", "Desktop keyring files"],
        },
        "commands": commands,
        "live_guard": {"paths": sorted(before), "unchanged": unchanged, "before": before, "after": after},
    }


def generate_receipt(
    bundle: Path,
    output: Path,
    repo_root: Path,
    *,
    tier2_bundle_output: Path | None = None,
    command_results: list[dict[str, object]] | None = None,
    before_snapshot: dict[str, object] | None = None,
    after_snapshot: dict[str, object] | None = None,
) -> dict[str, object]:
    if os.geteuid() == 0:
        raise ValueError("preflight receipt gates must run as a non-root artifact owner")
    manifest = validate_bundle(bundle, repo_root)
    live_paths = sorted(
        {str(record["target"]) for record in list(manifest["runtime_targets"]) + list(manifest["ops_targets"])}
        | {CLOSURE_TARGET}
    )
    before = snapshot(live_paths) if before_snapshot is None else before_snapshot
    test_root = output.parent / ".preflight-unit-tests"
    test_root.mkdir(mode=0o700, exist_ok=True)
    results = (
        [run(command, repo_root, test_root) for command in gate_commands(bundle)]
        if command_results is None
        else command_results
    )
    after = snapshot(live_paths) if after_snapshot is None else after_snapshot
    ready = (
        manifest.get("input_status") == "complete"
        and all(result.get("exit") == 0 for result in results)
        and before == after
    )
    tier2_record = None
    if ready:
        if tier2_bundle_output is None:
            raise ValueError("green complete preflight requires --tier2-bundle-output")
        tier2_value = expected_tier2_bundle(bundle, manifest, results)
        tier2_payload = canonical_json(tier2_value)
        write_atomic(tier2_bundle_output, tier2_payload)
        tier2_record = {
            "path": str(tier2_bundle_output.absolute()),
            "sha256": sha256_bytes(tier2_payload),
            "schema": TIER2_EVIDENCE_SCHEMA,
            "candidate_root": str(tier2_value["candidate_root"]),
        }
    receipt = build_receipt(bundle, manifest, results, before, after, tier2_record)
    write_atomic(output, canonical_json(receipt))
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-systemd-stage")
    parser.add_argument("--bundle")
    parser.add_argument("--output")
    parser.add_argument("--tier2-bundle-output")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    args = parser.parse_args()
    if args.verify_systemd_stage:
        if args.bundle or args.output or args.tier2_bundle_output:
            parser.error("--verify-systemd-stage cannot be combined with receipt arguments")
        observed = verify_staged_systemd(Path(args.verify_systemd_stage).resolve(strict=True))
        print(json.dumps({"status": "OK", "effective_units": observed}, sort_keys=True))
        return
    if not args.bundle or not args.output:
        parser.error("--bundle and --output are required")
    receipt = generate_receipt(
        Path(args.bundle).resolve(strict=True),
        Path(args.output).absolute(),
        Path(args.repo_root).resolve(strict=True),
        tier2_bundle_output=(
            Path(args.tier2_bundle_output).absolute() if args.tier2_bundle_output else None
        ),
    )
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "receipt": str(Path(args.output).absolute()),
                "installable": False,
                "next_gate": receipt["next_gate"],
            },
            sort_keys=True,
        )
    )
    raise SystemExit(0 if receipt["status"] != "FAILED" else 1)


if __name__ == "__main__":
    main()
