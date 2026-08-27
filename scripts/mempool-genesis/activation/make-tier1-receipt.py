#!/usr/bin/env python3
"""Run deterministic preflight gates and write a non-authorizing receipt."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
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
RECEIPT_SCHEMA = "buzz-mempool-genesis-preflight-receipt-v3"
REVIEW_FILES_SCHEMA = "buzz-agent-review-files-v1"
TIER2_EVIDENCE_SCHEMA = "tier2-evidence-v2"
TIER2_ENGINE_PATH = Path("/home/victor/.agents/skills/codex-review/scripts/tier2")
TIER2_ENGINE_MODE = 0o750
TIER2_REVIEW = {
    "producer_provider": "gpt",
    "reviewer_provider": "claude",
    "model": "claude-opus-5",
    "effort": "high",
    "engine_subcommands": ["prepare", "review", "check"],
}
TIER2_CANDIDATE_PATHS = ["bundle-manifest.json", "metadata/review-files.json"]
MAX_TIER2_EVIDENCE_BYTES = 64 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ASSIGNER_PUBKEYS = (
    "4a34c131ec5cb5dd9a200bac619bbd103c0793e068fad278d1de59203d05b97d",
    "7806a7beb69ba4fd3b6e9b86d56931a446b62666e9794533f87fb2d1b956684f",
    "73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812",
    "aefa6783cdf2f33f9aa3705b41e5ae3ec214318c64db48f1410fc77db015f2ec",
    "db965b1f484ec4ebd3b0041091e890e2cd28e64732d9be53fd07ba640255af61",
)
PLACEHOLDERS = {
    "mempool": "DESKTOP_SAVE_REQUIRED_MEMPOOL_PUBKEY",
    "genesis": "DESKTOP_SAVE_REQUIRED_GENESIS_PUBKEY",
}
CLOSURE_TARGET = "/etc/buzz-agents/review-closure.json"
SHELLCHECK_PATH = "/home/victor/.npm-global/bin/shellcheck"
RUNTIME_TARGET_COUNT = 22
TOTAL_PACKAGE_TARGET_COUNT = 23
REVIEW_PATH_COUNT = 19
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


def validate_tier2_review(value: object) -> dict[str, object]:
    if value != TIER2_REVIEW:
        raise ValueError("Tier 2 review route must use the current GPT-to-Claude Opus 5 high route")
    return TIER2_REVIEW


def validate_tier2_engine(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "mode", "sha256"}:
        raise ValueError("Tier 2 engine record is invalid")
    path_raw, mode_raw, digest = value.get("path"), value.get("mode"), value.get("sha256")
    if path_raw != str(TIER2_ENGINE_PATH):
        raise ValueError("Tier 2 engine path is invalid")
    path = TIER2_ENGINE_PATH
    if parse_mode(mode_raw) != TIER2_ENGINE_MODE:
        raise ValueError("Tier 2 engine mode mismatch")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ValueError("Tier 2 engine digest is invalid")
    require_regular(path, TIER2_ENGINE_MODE)
    if sha256_file(path) != digest:
        raise ValueError("Tier 2 engine changed after package creation")
    return {"path": path_raw, "mode": str(mode_raw), "sha256": digest}


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
        "argv": command,
        "exit_code": exit_code,
        "output": "\n".join(output_parts) if output_parts else "<no output>",
    }


def expected_tier2_bundle(
    bundle: Path,
    manifest: dict[str, object],
    commands: list[dict[str, object]],
) -> dict[str, object]:
    validate_tier2_review(manifest.get("tier2_review"))
    if manifest.get("tier2_evidence_schema") != TIER2_EVIDENCE_SCHEMA:
        raise ValueError("Tier 2 evidence schema mismatch")
    if manifest.get("tier2_candidate_paths") != TIER2_CANDIDATE_PATHS:
        raise ValueError("Tier 2 candidate path set mismatch")
    value = {
        "schema": TIER2_EVIDENCE_SCHEMA,
        "candidate_root": str(bundle.resolve(strict=True)),
        "summary": (
            "GPT-produced Mempool and Genesis credential, signing, and production activation "
            "package; the current opposite-provider contract requires one Claude Opus 5 reviewer "
            "at high reasoning."
        ),
        "paths": TIER2_CANDIDATE_PATHS,
        "invariants": [
            "The review binds the exact package manifest and exact 19-path review-file record.",
            "The package and review state remain owner-only and credential-free.",
            "The parent Tier 1 receipt is deterministic evidence only and grants no install authority.",
            "Mempool and Genesis stay stopped and disabled through review and install preflight.",
            "Installation remains absent-only for credentials and preserves rollback and exact hashes.",
            "Prepare must use --producer-provider gpt; review and check use the same state.",
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
        "source_branch",
        "generator_sources",
        "inputs",
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
    }
    if set(manifest) != required or manifest.get("schema") != BUNDLE_SCHEMA:
        raise ValueError("package manifest schema or fields mismatch")
    if manifest.get("bundle_id") != BUNDLE_ID:
        raise ValueError("package identity mismatch")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != {"mempool", "genesis"}:
        raise ValueError("package input map mismatch")
    complete = True
    for slug in ("mempool", "genesis"):
        value = inputs.get(slug)
        if value == PLACEHOLDERS[slug]:
            complete = False
        elif not isinstance(value, str) or not HEX64.fullmatch(value):
            raise ValueError(f"{slug} public key is invalid")
    if complete:
        if inputs["mempool"] == inputs["genesis"]:
            raise ValueError("Mempool and Genesis public keys are not distinct")
        if inputs["mempool"] in ASSIGNER_PUBKEYS or inputs["genesis"] in ASSIGNER_PUBKEYS:
            raise ValueError("agent public keys reuse an assignment-roster identity")
    expected_status = "complete" if complete else "desktop-save-required"
    if manifest.get("input_status") != expected_status:
        raise ValueError("package input status mismatch")
    if manifest.get("ready_for_parent_tier1") is not complete:
        raise ValueError("package parent-readback readiness claim is invalid")
    if manifest.get("installable") is not False:
        raise ValueError("producer package must remain non-installable")

    runtime_raw, ops_raw = manifest.get("runtime_targets"), manifest.get("ops_targets")
    if not isinstance(runtime_raw, list) or len(runtime_raw) != RUNTIME_TARGET_COUNT:
        raise ValueError(f"runtime target count must be {RUNTIME_TARGET_COUNT}")
    if not isinstance(ops_raw, list) or len(ops_raw) != 1:
        raise ValueError("ops target count must be one")
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
        "target": "/home/victor/.agents/tools/buzz-sats-channel-sweep.sh",
        "mode": "0700",
        "uid": 1000,
        "gid": 1000,
        "scope": "Victor-owner-authenticated all-open-channel fixed public-key roster",
    }
    for key, value in expected_ops.items():
        if ops[0].get(key) != value:
            raise ValueError(f"ops target mismatch: {key}")
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
    expected_review_status = "pending-tier2-v2" if complete else "blocked-on-desktop-pubkeys"
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
    if manifest.get("tier2_candidate_paths") != TIER2_CANDIDATE_PATHS:
        raise ValueError("Tier 2 candidate path set mismatch")
    digest_input = {
        "schema": BUNDLE_SCHEMA,
        "bundle_id": BUNDLE_ID,
        "inputs": inputs,
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
    }
    package_digest = sha256_bytes(canonical_json(digest_input))
    if manifest.get("package_digest") != package_digest:
        raise ValueError("package digest mismatch")

    validate_generator_sources(manifest, repo_root)
    if manifest.get("source_commit") != git_value(repo_root, "rev-parse", "HEAD"):
        raise ValueError("package source commit is stale")
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
    sweep_candidate = bundle / "ops-root/home/victor/.agents/tools/buzz-sats-channel-sweep.sh"
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
            raise ValueError("complete green preflight requires a generated Tier 2 v2 evidence bundle")
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
            "package_digest": manifest["package_digest"],
            "input_status": manifest["input_status"],
            "runtime_artifact_fingerprint": manifest["runtime_artifact_fingerprint"],
            "review_files_sha256": manifest["review_files_record"]["sha256"],
            "tier2_review": manifest["tier2_review"],
            "tier2_engine_sha256": manifest["tier2_engine"]["sha256"],
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
                "mempool_pubkey: 64 lowercase hex",
                "genesis_pubkey: 64 lowercase hex",
                "values must be distinct and must not reuse any assignment-roster identity",
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
    test_root = bundle.parent / ".preflight-unit-tests"
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
            "candidate_root": str(bundle.resolve(strict=True)),
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
