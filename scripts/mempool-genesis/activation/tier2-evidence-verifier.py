#!/usr/bin/env python3
"""Validate one MGACT package against the current Tier 2 v3 engine state."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

MAX_EVIDENCE_BYTES = 64 * 1024
MAX_STATE_BYTES = 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_KEYS = {
    "schema",
    "candidate_root",
    "summary",
    "paths",
    "invariants",
    "commands",
    "known_limits",
}
EXPECTED_ROUTE = {
    "provider": "claude",
    "model": "claude-opus-5",
    "effort": "high",
    "auth_source": "profile",
}
TIER2_ENGINE_MODE = 0o755
SEALED_ENGINE_LAUNCHER = """\
import os
import sys

engine_path = sys.argv[1]
sealed_path = sys.argv[2]
with open(sealed_path, "rb", buffering=0) as source:
    payload = source.read()
sys.argv = [engine_path, *sys.argv[3:]]
namespace = {
    "__name__": "__main__",
    "__file__": engine_path,
    "__package__": None,
    "__cached__": None,
}
exec(compile(payload, engine_path, "exec"), namespace)
"""


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


def require_private_file(path: Path, max_bytes: int) -> os.stat_result:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > max_bytes
    ):
        raise ValueError(f"unsafe private file: {path}")
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise ValueError(f"unsafe private parent directory: {path.parent}")
    return metadata


def load_private_json(path: Path, max_bytes: int) -> tuple[dict[str, object], bytes]:
    require_private_file(path, max_bytes)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = b""
        while chunk := os.read(descriptor, 1024 * 1024):
            raw += chunk
            if len(raw) > max_bytes:
                raise ValueError(f"private JSON exceeds size limit: {path}")
    finally:
        os.close(descriptor)
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return value, raw


def validate_relative_path(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Tier 2 evidence path is not a string")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or value in {"", "."}
        or ".." in pure.parts
        or "\\" in value
        or str(pure) != value
    ):
        raise ValueError(f"invalid Tier 2 evidence path: {value!r}")
    return value


def validate_evidence(value: dict[str, object], candidate_root: Path) -> tuple[str, ...]:
    if set(value) != EVIDENCE_KEYS or value.get("schema") != "tier2-evidence-v3":
        raise ValueError("Tier 2 evidence must use the current tier2-evidence-v3 schema")
    if value.get("candidate_root") != str(candidate_root):
        raise ValueError("Tier 2 evidence is bound to a different candidate root")
    if not isinstance(value.get("summary"), str) or not str(value["summary"]).strip():
        raise ValueError("Tier 2 evidence summary is absent")
    paths_raw = value.get("paths")
    if not isinstance(paths_raw, list) or not paths_raw or len(paths_raw) > 40:
        raise ValueError("Tier 2 evidence paths are absent or exceed the engine bound")
    paths = tuple(validate_relative_path(item) for item in paths_raw)
    if len(set(paths)) != len(paths):
        raise ValueError("Tier 2 evidence paths contain a duplicate")
    for key, maximum in (("invariants", 12), ("known_limits", None)):
        items = value.get(key)
        if not isinstance(items, list) or (maximum is not None and len(items) > maximum):
            raise ValueError(f"Tier 2 evidence {key} are invalid")
        if any(not isinstance(item, str) or not item.strip() for item in items):
            raise ValueError(f"Tier 2 evidence {key} contain an invalid item")
    commands = value.get("commands")
    if not isinstance(commands, list) or len(commands) > 20:
        raise ValueError("Tier 2 evidence commands exceed the engine bound")
    for command in commands:
        if not isinstance(command, dict) or set(command) != {
            "kind",
            "argv",
            "exit_code",
            "output",
        }:
            raise ValueError("Tier 2 evidence command fields mismatch")
        if command.get("kind") != "result":
            raise ValueError("Tier 2 evidence command kind is invalid")
        argv = command.get("argv")
        if not isinstance(argv, list) or not argv or any(
            not isinstance(argument, str) or not argument for argument in argv
        ):
            raise ValueError("Tier 2 evidence command argv is invalid")
        if not isinstance(command.get("exit_code"), int) or isinstance(command.get("exit_code"), bool):
            raise ValueError("Tier 2 evidence command exit code is invalid")
        if not isinstance(command.get("output"), str):
            raise ValueError("Tier 2 evidence command output is invalid")
    return paths


def validate_state(
    state: dict[str, object],
    state_raw: bytes,
    evidence: dict[str, object],
    evidence_raw: bytes,
    candidate_root: Path,
    paths: tuple[str, ...],
) -> dict[str, object]:
    if state.get("state_schema") != "tier2-state-v3":
        raise ValueError("Tier 2 state does not use the current tier2-state-v3 schema")
    if state.get("producer_provider") != "gpt" or "escalate" in state:
        raise ValueError("Tier 2 state does not record the current GPT producer route")
    route = state.get("route")
    if not isinstance(route, dict) or set(route) != {
        "provider",
        "model",
        "effort",
        "auth_source",
        "reviewer_identity",
    }:
        raise ValueError("Tier 2 state review route is invalid")
    for key, expected in EXPECTED_ROUTE.items():
        if route.get(key) != expected:
            raise ValueError(f"Tier 2 state review route mismatch: {key}")
    reviewer_identity = route.get("reviewer_identity")
    if not isinstance(reviewer_identity, str) or not reviewer_identity.strip():
        raise ValueError("Tier 2 state reviewer identity is absent")
    if state.get("status") != "closed":
        raise ValueError("Tier 2 state is not terminal")
    token_path = state.get("token_path")
    if not isinstance(token_path, str) or not Path(token_path).is_absolute():
        raise ValueError("Tier 2 state launch-token path is invalid")
    if os.path.lexists(token_path):
        raise ValueError("Tier 2 state still has an unclaimed launch token")
    if state.get("transport_override") is not False:
        raise ValueError("Tier 2 state used a forbidden transport override")
    revision = state.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision not in (1, 2):
        raise ValueError("Tier 2 state revision is invalid")
    prior_state, prior_verdict = state.get("prior_state"), state.get("prior_verdict")
    if revision == 1 and (prior_state is not None or prior_verdict is not None):
        raise ValueError("Tier 2 revision 1 carries invalid prior-state data")
    if revision == 2 and (
        not isinstance(prior_state, str)
        or not Path(prior_state).is_absolute()
        or not isinstance(prior_verdict, dict)
        or prior_verdict.get("verdict") != "FAIL"
    ):
        raise ValueError("Tier 2 revision 2 does not bind a revision-1 FAIL")
    if state.get("bundle") != evidence:
        raise ValueError("Tier 2 state is bound to different evidence")
    if state.get("bundle_sha256") != sha256_bytes(evidence_raw):
        raise ValueError("Tier 2 state evidence digest mismatch")
    frozen = state.get("fingerprint")
    if (
        not isinstance(frozen, dict)
        or frozen.get("candidate_root") != str(candidate_root)
        or frozen.get("changed_paths") != sorted(paths)
        or not isinstance(frozen.get("base_commit"), str)
        or not HEX64.fullmatch(str(frozen.get("status_sha256", "")))
        or not HEX64.fullmatch(str(frozen.get("diff_sha256", "")))
        or not isinstance(frozen.get("untracked_files"), list)
    ):
        raise ValueError("Tier 2 state candidate fingerprint mismatch")
    scope_id = state.get("scope_id")
    ledger_path = state.get("ledger_path")
    if (
        not isinstance(scope_id, str)
        or not scope_id.strip()
        or not isinstance(ledger_path, str)
        or not Path(ledger_path).is_absolute()
    ):
        raise ValueError("Tier 2 state scope or ledger binding is absent")
    verdict = state.get("verdict")
    if not isinstance(verdict, dict) or set(verdict) != {
        "verdict",
        "findings",
        "evidence_gaps",
        "reviewer_identity",
    }:
        raise ValueError("Tier 2 terminal result contract is invalid")
    verdict_name = verdict.get("verdict")
    if verdict_name not in ("PASS", "PASS WITH RISKS"):
        raise ValueError("Tier 2 terminal result is not accepted")
    findings = verdict.get("findings")
    gaps = verdict.get("evidence_gaps")
    if not isinstance(findings, list) or not isinstance(gaps, list) or any(
        not isinstance(gap, str) for gap in gaps
    ):
        raise ValueError("Tier 2 terminal result findings or evidence gaps are invalid")
    severities = []
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != {"severity", "description"}:
            raise ValueError("Tier 2 terminal result finding fields mismatch")
        severity, description = finding.get("severity"), finding.get("description")
        if severity not in ("LOW", "MEDIUM", "HIGH") or not isinstance(description, str):
            raise ValueError("Tier 2 terminal result finding is invalid")
        severities.append(severity)
    if verdict_name == "PASS" and findings:
        raise ValueError("Tier 2 PASS result cannot contain findings")
    if verdict_name == "PASS WITH RISKS" and (
        not findings or any(severity != "LOW" for severity in severities)
    ):
        raise ValueError("Tier 2 PASS WITH RISKS result requires LOW-only findings")
    if verdict.get("reviewer_identity") != reviewer_identity:
        raise ValueError("Tier 2 terminal result reviewer identity mismatch")
    state_id = state.get("state_id")
    lineage_id = state.get("lineage_id")
    if not isinstance(state_id, str) or not state_id or not isinstance(lineage_id, str) or not lineage_id:
        raise ValueError("Tier 2 state or lineage identity is absent")
    return {
        "lineage_id": lineage_id,
        "state_id": state_id,
        "revision": revision,
        "verdict": verdict["verdict"],
        "reviewer_identity": reviewer_identity,
        "evidence_digest": sha256_bytes(evidence_raw),
        "state_digest": sha256_bytes(state_raw),
        "candidate_fingerprint": sha256_bytes(canonical_json(frozen)),
        "verdict_digest": sha256_bytes(canonical_json(verdict)),
    }


def open_sealed_engine(path: Path, expected_digest: str) -> int:
    if not HEX64.fullmatch(expected_digest):
        raise ValueError("Tier 2 engine digest is invalid")
    source = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    sealed = -1
    try:
        metadata = os.fstat(source)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != TIER2_ENGINE_MODE
        ):
            raise ValueError("unsafe installed Tier 2 engine")
        sealed = os.memfd_create("mgact-tier2-v3-engine", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        digest = hashlib.sha256()
        while chunk := os.read(source, 1024 * 1024):
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(sealed, view)
                if written <= 0:
                    raise OSError("short write while freezing the Tier 2 engine")
                view = view[written:]
        if digest.hexdigest() != expected_digest:
            raise ValueError("installed Tier 2 engine hash mismatch")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
        fcntl.fcntl(sealed, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(sealed, fcntl.F_GET_SEALS) & seals != seals:
            raise ValueError("Tier 2 engine memfd is not fully sealed")
        os.lseek(sealed, 0, os.SEEK_SET)
        return sealed
    except Exception:
        if sealed >= 0:
            os.close(sealed)
        raise
    finally:
        os.close(source)


def run_engine_check(engine: Path, engine_digest: str, state_path: Path) -> None:
    descriptor = open_sealed_engine(engine, engine_digest)
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                SEALED_ENGINE_LAUNCHER,
                str(engine),
                f"/proc/self/fd/{descriptor}",
                "check",
                "--state",
                str(state_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            env={
                "HOME": str(Path.home()),
                "LC_ALL": "C",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            pass_fds=(descriptor,),
        )
    finally:
        os.close(descriptor)
    if completed.returncode != 0:
        detail = completed.stderr.strip()
        raise ValueError(f"Tier 2 v3 check rejected closure: {detail or completed.returncode}")
    if completed.stdout.splitlines() != ["OK"]:
        raise ValueError("Tier 2 v3 check returned an invalid response")


def check(
    state_path: Path,
    evidence_path: Path,
    candidate_root: Path,
    engine: Path,
    engine_digest: str,
) -> dict[str, object]:
    candidate_root = candidate_root.resolve(strict=True)
    if not candidate_root.is_dir():
        raise ValueError("candidate root is not a directory")
    evidence, evidence_raw = load_private_json(evidence_path, MAX_EVIDENCE_BYTES)
    paths = validate_evidence(evidence, candidate_root)
    state, state_raw = load_private_json(state_path, MAX_STATE_BYTES)
    acceptance = validate_state(
        state,
        state_raw,
        evidence,
        evidence_raw,
        candidate_root,
        paths,
    )
    run_engine_check(engine, engine_digest, state_path)
    state_after, state_after_raw = load_private_json(state_path, MAX_STATE_BYTES)
    evidence_after, evidence_after_raw = load_private_json(evidence_path, MAX_EVIDENCE_BYTES)
    if state_after != state or state_after_raw != state_raw:
        raise ValueError("Tier 2 state changed during the install gate")
    if evidence_after != evidence or evidence_after_raw != evidence_raw:
        raise ValueError("Tier 2 evidence changed during the install gate")
    return {
        "ok": True,
        "subcommand": "check",
        "state_schema": "tier2-state-v3",
        "producer_provider": "gpt",
        "route": EXPECTED_ROUTE,
        **acceptance,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("check", nargs="?")
    parser.add_argument("--state", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--engine-sha256", required=True)
    args = parser.parse_args()
    if args.check != "check":
        raise ValueError("the only supported subcommand is check")
    value = check(
        Path(args.state).resolve(strict=True),
        Path(args.evidence).resolve(strict=True),
        Path(args.candidate_root).resolve(strict=True),
        Path(args.engine).resolve(strict=True),
        args.engine_sha256,
    )
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"mgact-tier2-v3: {error}", file=sys.stderr)
        raise SystemExit(1)
