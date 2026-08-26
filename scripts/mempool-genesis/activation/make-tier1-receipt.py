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
BUNDLE_SCHEMA = "buzz-mempool-genesis-activation-bundle-v2"
BUNDLE_ID = "mempool-genesis-activation-20260825"
RECEIPT_SCHEMA = "buzz-mempool-genesis-preflight-receipt-v2"
REVIEW_FILES_SCHEMA = "buzz-agent-review-files-v1"
EVIDENCE_INPUTS_SCHEMA = "buzz-mempool-genesis-tier2-evidence-inputs-v1"
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
        if not isinstance(paths, list) or len(paths) != 17 or len(set(paths)) != 17:
            raise ValueError(f"{slug} expected closure list must contain 17 unique paths")
        if not isinstance(records, list) or len(records) != 17:
            raise ValueError(f"{slug} review file list must contain 17 paths")
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


def expected_evidence_inputs(
    bundle: Path,
    manifest: dict[str, object],
    review_digest: str,
) -> dict[str, object]:
    manifest_digest = sha256_file(bundle / "bundle-manifest.json")
    return {
        "schema": EVIDENCE_INPUTS_SCHEMA,
        "candidate": {"mode": "files"},
        "changed_paths": [
            {
                "status": "A",
                "relative_path": "bundle-manifest.json",
                "sha256": manifest_digest,
            },
            {
                "status": "A",
                "relative_path": "metadata/review-files.json",
                "sha256": review_digest,
            },
        ],
        "fingerprints": {
            "package_digest": manifest["package_digest"],
            "review_files_sha256": review_digest,
            "runtime_artifact_fingerprint": manifest["runtime_artifact_fingerprint"],
        },
        "required_review": {
            "reviewer_provider": "gpt",
            "model": "gpt-5.6-sol",
            "effort": "xhigh",
            "normal_tier2": True,
        },
    }


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
        "tier2_evidence_inputs_path",
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
    if not isinstance(runtime_raw, list) or len(runtime_raw) != 19:
        raise ValueError("runtime target count must be 19")
    if not isinstance(ops_raw, list) or len(ops_raw) != 1:
        raise ValueError("ops target count must be one")
    runtime = [validate_source_record(bundle, record) for record in runtime_raw]
    ops = [validate_source_record(bundle, record) for record in ops_raw]
    targets = [str(record["target"]) for record in runtime + ops]
    if len(set(targets)) != 20:
        raise ValueError("package target set contains a duplicate")
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
    expected_review_status = "pending-normal-tier2" if complete else "blocked-on-desktop-pubkeys"
    if review_value != {
        "schema": REVIEW_FILES_SCHEMA,
        "status": expected_review_status,
        "runtime_artifact_fingerprint": fingerprint,
        "package_digest": manifest["package_digest"],
        "files": files,
    }:
        raise ValueError("review file payload mismatch")

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
    }
    package_digest = sha256_bytes(canonical_json(digest_input))
    if manifest.get("package_digest") != package_digest:
        raise ValueError("package digest mismatch")

    evidence_relative = manifest.get("tier2_evidence_inputs_path")
    if evidence_relative != "metadata/tier2-evidence-inputs.json":
        raise ValueError("Tier 2 evidence input path mismatch")
    evidence_source = bundle / str(evidence_relative)
    require_regular(evidence_source, 0o600)
    if load_json(evidence_source) != expected_evidence_inputs(bundle, manifest, review_digest):
        raise ValueError("Tier 2 evidence inputs mismatch")

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
) -> dict[str, object]:
    commands_passed = all(result.get("exit") == 0 for result in commands)
    unchanged = before == after
    complete = manifest.get("input_status") == "complete"
    if commands_passed and unchanged:
        status = "READY_FOR_PARENT_TIER1" if complete else "BLOCKED_ON_DESKTOP_PUBKEYS"
    else:
        status = "FAILED"
    evidence_path = bundle / str(manifest["tier2_evidence_inputs_path"])
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
            "tier2_evidence_inputs_path": str(evidence_path),
            "tier2_evidence_inputs_sha256": sha256_file(evidence_path),
        },
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
    receipt = build_receipt(bundle, manifest, results, before, after)
    write_atomic(output, canonical_json(receipt))
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    args = parser.parse_args()
    receipt = generate_receipt(
        Path(args.bundle).resolve(strict=True),
        Path(args.output).absolute(),
        Path(args.repo_root).resolve(strict=True),
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
