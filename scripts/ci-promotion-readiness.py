#!/usr/bin/env python3
"""Fail-closed verifier for Buzz promotion, canary, deploy, and rollback evidence."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, NoReturn
from urllib.parse import urlsplit
import uuid


SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE = re.compile(r"^[0-9a-f]{128}$")
JOB_ID = re.compile(r"^[A-Za-z0-9_]{1,64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
CI_EVENT_KINDS = {46101, 46102, 46103, 46104, 46105, 46106}
RUN_STATES = {
    "queued", "running", "success", "failure", "cancelled", "timed_out",
    "infrastructure_failure",
}
JOB_STATES = {"queued", "running", "success", "failure", "cancelled", "timed_out", "skipped"}
RUN_TRANSITIONS = {
    "queued": {"running", "cancelled", "infrastructure_failure"},
    "running": {"success", "failure", "cancelled", "timed_out", "infrastructure_failure"},
}
JOB_TRANSITIONS = {
    "queued": {"running", "cancelled"},
    "running": {"success", "failure", "cancelled", "timed_out", "skipped"},
}
TM_IDS = [f"TM-{number:02d}" for number in range(1, 18)]
PROBE_IDS = ["P-i", "P-ii", "P-iii", "P-iv", "P-v", "P-vi"]
REPOSITORY = "only21mil/buzz"
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


class GateError(Exception):
    """An acceptance invariant was not satisfied."""


def refuse(message: str) -> NoReturn:
    raise GateError(message)


def expect(condition: bool, message: str) -> None:
    if not condition:
        refuse(message)


def obj(value: Any, path: str) -> dict[str, Any]:
    expect(isinstance(value, dict), f"{path} must be an object")
    return value


def array(value: Any, path: str) -> list[Any]:
    expect(isinstance(value, list), f"{path} must be an array")
    return value


def field(container: dict[str, Any], name: str, path: str) -> Any:
    expect(name in container, f"{path}.{name} is required")
    return container[name]


def text(value: Any, path: str) -> str:
    expect(isinstance(value, str) and bool(value), f"{path} must be a non-empty string")
    return value


def integer(value: Any, path: str) -> int:
    expect(isinstance(value, int) and not isinstance(value, bool), f"{path} must be an integer")
    return value


def boolean(value: Any, path: str) -> bool:
    expect(isinstance(value, bool), f"{path} must be a boolean")
    return value


def positive_integer(value: Any, path: str) -> int:
    result = integer(value, path)
    expect(result >= 1, f"{path} must be a positive integer")
    return result


def exact_fields(
    container: dict[str, Any], required: set[str], optional: set[str], path: str
) -> None:
    missing = required - set(container)
    unknown = set(container) - required - optional
    expect(not missing, f"{path} is missing fields: {sorted(missing)}")
    expect(not unknown, f"{path} has unknown fields: {sorted(unknown)}")


def nonempty_unique_strings(value: Any, path: str) -> list[str]:
    result = [text(item, f"{path}[]") for item in array(value, path)]
    expect(bool(result), f"{path} must not be empty")
    expect(len(result) == len(set(result)), f"{path} must be unique")
    return result


def job_ids(value: Any, path: str) -> list[str]:
    result = nonempty_unique_strings(value, path)
    expect(all(JOB_ID.fullmatch(item) is not None for item in result),
           f"{path} contains an invalid static job ID")
    return result


def relay_http_origin(value: Any, path: str) -> tuple[str, str, int]:
    raw = text(value, path)
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        refuse(f"{path} is not a valid relay URL")
    scheme = parsed.scheme
    expect(scheme in ("http", "https") and parsed.hostname is not None,
           f"{path} must use http or https")
    expect(parsed.username is None and parsed.password is None and "@" not in parsed.netloc,
           f"{path} must not contain credentials")
    expect("?" not in raw and "#" not in raw and parsed.path in ("", "/"),
           f"{path} must be an origin without path, query, or fragment")
    assert parsed.hostname is not None
    default_port = 443 if scheme == "https" else 80
    hostname = parsed.hostname.lower()
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != default_port:
        authority = f"{authority}:{port}"
    expect(raw == f"{scheme}://{authority}", f"{path} must be a canonical relay origin")
    return scheme, hostname, port or default_port


def validate_relay_evidence_url(
    value: Any, relay_origin: tuple[str, str, int], expected_path: str, path: str
) -> str:
    raw = text(value, path)
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        refuse(f"{path} is not a valid evidence URL")
    expect(parsed.scheme in ("http", "https") and parsed.hostname is not None,
           f"{path} must use http or https")
    expect(parsed.username is None and parsed.password is None and "@" not in parsed.netloc,
           f"{path} has forbidden credentials")
    expect("?" not in raw and "#" not in raw,
           f"{path} has a forbidden query or fragment")
    candidate_origin = (
        parsed.scheme,
        parsed.hostname,
        port or (443 if parsed.scheme == "https" else 80),
    )
    expect(candidate_origin == relay_origin, f"{path} is off relay origin")
    expect(parsed.path == expected_path, f"{path} does not match the exact evidence path")
    return raw


def event_id(value: Any, path: str) -> str:
    return sha256(value, path)


def signature(value: Any, path: str) -> str:
    result = text(value, path)
    expect(SIGNATURE.fullmatch(result) is not None, f"{path} must be a lowercase Schnorr signature")
    return result


def run_uuid(value: Any, path: str) -> str:
    result = text(value, path)
    try:
        parsed = uuid.UUID(result)
    except ValueError:
        refuse(f"{path} must be a canonical UUID")
    expect(str(parsed) == result, f"{path} must be a canonical UUID")
    return result


def point_add(
    left: tuple[int, int] | None, right: tuple[int, int] | None
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, SECP256K1_P - 2, SECP256K1_P)
    else:
        slope = (y2 - y1) * pow(x2 - x1, SECP256K1_P - 2, SECP256K1_P)
    slope %= SECP256K1_P
    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    return x3, (slope * (x1 - x3) - y1) % SECP256K1_P


def point_multiply(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    def double(value: tuple[int, int, int]) -> tuple[int, int, int]:
        x, y, z = value
        if y == 0 or z == 0:
            return 0, 1, 0
        y2 = y * y % SECP256K1_P
        s = 4 * x * y2 % SECP256K1_P
        m = 3 * x * x % SECP256K1_P
        x3 = (m * m - 2 * s) % SECP256K1_P
        y3 = (m * (s - x3) - 8 * y2 * y2) % SECP256K1_P
        return x3, y3, 2 * y * z % SECP256K1_P

    def add(left: tuple[int, int, int], right: tuple[int, int, int]) -> tuple[int, int, int]:
        x1, y1, z1 = left
        x2, y2, z2 = right
        if z1 == 0:
            return right
        if z2 == 0:
            return left
        z1_squared = z1 * z1 % SECP256K1_P
        z2_squared = z2 * z2 % SECP256K1_P
        u1 = x1 * z2_squared % SECP256K1_P
        u2 = x2 * z1_squared % SECP256K1_P
        s1 = y1 * z2 * z2_squared % SECP256K1_P
        s2 = y2 * z1 * z1_squared % SECP256K1_P
        if u1 == u2:
            return double(left) if s1 == s2 else (0, 1, 0)
        h = (u2 - u1) % SECP256K1_P
        r = (s2 - s1) % SECP256K1_P
        h2 = h * h % SECP256K1_P
        h3 = h2 * h % SECP256K1_P
        u1_h2 = u1 * h2 % SECP256K1_P
        x3 = (r * r - h3 - 2 * u1_h2) % SECP256K1_P
        y3 = (r * (u1_h2 - x3) - s1 * h3) % SECP256K1_P
        return x3, y3, h * z1 * z2 % SECP256K1_P

    result = (0, 1, 0)
    addend = (point[0], point[1], 1)
    while scalar:
        if scalar & 1:
            result = add(result, addend)
        addend = double(addend)
        scalar >>= 1
    if result[2] == 0:
        return None
    inverse = pow(result[2], SECP256K1_P - 2, SECP256K1_P)
    inverse_squared = inverse * inverse % SECP256K1_P
    return (result[0] * inverse_squared % SECP256K1_P,
            result[1] * inverse_squared * inverse % SECP256K1_P)


def tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_digest + tag_digest + payload).digest()


def verify_schnorr(pubkey_hex: str, message: bytes, signature_hex: str) -> bool:
    pubkey_x = int(pubkey_hex, 16)
    if pubkey_x >= SECP256K1_P:
        return False
    y_squared = (pow(pubkey_x, 3, SECP256K1_P) + 7) % SECP256K1_P
    pubkey_y = pow(y_squared, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if pow(pubkey_y, 2, SECP256K1_P) != y_squared:
        return False
    if pubkey_y & 1:
        pubkey_y = SECP256K1_P - pubkey_y
    raw_signature = bytes.fromhex(signature_hex)
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    if r >= SECP256K1_P or s >= SECP256K1_N:
        return False
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", raw_signature[:32] + bytes.fromhex(pubkey_hex) + message),
        "big",
    ) % SECP256K1_N
    public_point = (pubkey_x, pubkey_y)
    negated = (public_point[0], (-public_point[1]) % SECP256K1_P)
    recovered = point_add(point_multiply(s, SECP256K1_G), point_multiply(challenge, negated))
    return recovered is not None and recovered[1] % 2 == 0 and recovered[0] == r


def canonical_tags(value: Any, path: str) -> list[list[str]]:
    result: list[list[str]] = []
    for index, raw_tag in enumerate(array(value, path)):
        tag_path = f"{path}[{index}]"
        tag = array(raw_tag, tag_path)
        expect(bool(tag) and all(isinstance(part, str) for part in tag),
               f"{tag_path} must contain strings and a non-empty tag name")
        expect(bool(tag[0]), f"{tag_path} must contain strings and a non-empty tag name")
        result.append(tag)
    return result


def validate_wire_event(
    raw_event: Any, path: str, *, require_cursor: bool
) -> tuple[dict[str, Any], int, str, str, int | None, list[list[str]]]:
    event = obj(raw_event, path)
    required = {"id", "pubkey", "created_at", "kind", "tags", "content", "sig", "stored"}
    if require_cursor:
        required.add("watch_cursor")
    exact_fields(event, required, set(), path)
    event_id_value = event_id(field(event, "id", path), f"{path}.id")
    pubkey = sha256(field(event, "pubkey", path), f"{path}.pubkey")
    created_at = integer(field(event, "created_at", path), f"{path}.created_at")
    expect(created_at >= 0, f"{path}.created_at must be non-negative")
    kind = integer(field(event, "kind", path), f"{path}.kind")
    tags = canonical_tags(field(event, "tags", path), f"{path}.tags")
    raw_content = text(field(event, "content", path), f"{path}.content")
    signature_value = signature(field(event, "sig", path), f"{path}.sig")
    expect(field(event, "stored", path) is True, f"{path} was not stored")
    serialized = json.dumps(
        [0, pubkey, created_at, kind, tags, raw_content],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    computed_id = hashlib.sha256(serialized).hexdigest()
    expect(computed_id == event_id_value, f"{path} canonical event ID mismatch")
    expect(verify_schnorr(pubkey, bytes.fromhex(event_id_value), signature_value),
           f"{path} Schnorr signature is invalid")
    try:
        content = obj(json.loads(raw_content), f"{path}.content")
    except json.JSONDecodeError as error:
        refuse(f"{path}.content is invalid JSON: {error}")
    cursor = positive_integer(field(event, "watch_cursor", path), f"{path}.watch_cursor") \
        if require_cursor else None
    return content, kind, event_id_value, pubkey, cursor, tags


def validate_ci_tags(
    tags: list[list[str]], channel_id: str, content: dict[str, Any], kind: int, path: str
) -> None:
    expected: dict[str, list[str]] = {
        "h": ["h", channel_id],
        "a": ["a", text(content["target_repo_a"], f"{path}.target_repo_a")],
        "run": ["run", run_uuid(content["run_id"], f"{path}.run_id")],
        "workflow": ["workflow", text(content["workflow_id"], f"{path}.workflow_id")],
        "c": ["c", sha40(content["tip_oid"], f"{path}.tip_oid")],
        "attempt": ["attempt", str(positive_integer(content["attempt"], f"{path}.attempt"))],
    }
    if kind in (46102, 46103, 46104):
        expected["job"] = ["job", text(content["job_id"], f"{path}.job_id")]
    if kind != 46100:
        expected["e"] = ["e", event_id(content["request_event_id"],
                                               f"{path}.request_event_id"), "", "request"]
    if kind == 46103:
        expected["x"] = ["x", sha256(content["log_sha256"], f"{path}.log_sha256")]
    elif kind == 46104:
        expected["x"] = ["x", sha256(content["sha256"], f"{path}.sha256")]
    reserved = {"h", "a", "run", "workflow", "c", "attempt", "job", "e", "x"}
    for name in reserved:
        matching = [tag for tag in tags if tag[0] == name]
        if name in expected:
            expect(matching == [expected[name]], f"{path} {name} tag does not match signed content")
        else:
            expect(not matching, f"{path} has forbidden reserved {name} tag")


def sha40(value: Any, path: str) -> str:
    result = text(value, path)
    expect(SHA40.fullmatch(result) is not None, f"{path} must be a full lowercase Git SHA-1")
    return result


def sha256(value: Any, path: str) -> str:
    result = text(value, path)
    expect(SHA256.fullmatch(result) is not None, f"{path} must be a lowercase SHA-256")
    return result


def image_id(value: Any, path: str) -> str:
    result = text(value, path)
    expect(IMAGE_ID.fullmatch(result) is not None, f"{path} must be sha256:<64 lowercase hex>")
    return result


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def secure_regular_file(path: Path, label: str) -> None:
    expect(path.is_absolute(), f"{label} path must be absolute")
    expect(path.exists(), f"{label} is missing: {path}")
    expect(not path.is_symlink() and path.is_file(), f"{label} must be a regular non-symlink file")
    mode = path.stat().st_mode
    expect(stat.S_IMODE(mode) == 0o600, f"{label} must have mode 0600")


def load_json(path: Path, label: str) -> dict[str, Any]:
    secure_regular_file(path, label)
    try:
        with path.open(encoding="utf-8") as source:
            return obj(json.load(source), label)
    except (OSError, json.JSONDecodeError) as error:
        refuse(f"{label} is unreadable or invalid JSON: {error}")


def parse_utc(value: Any, path: str) -> int:
    raw = text(value, path)
    expect(raw.endswith("Z"), f"{path} must be UTC RFC3339 ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError:
        refuse(f"{path} is not valid RFC3339")
    return int(parsed.timestamp())


def git(repo: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    if check and result.returncode != 0:
        refuse(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result


def validate_source(bundle: dict[str, Any], candidate_dir: Path) -> tuple[str, str, str]:
    candidate = sha40(field(bundle, "candidate_sha", "evidence"), "evidence.candidate_sha")
    base = sha40(field(bundle, "base_sha", "evidence"), "evidence.base_sha")
    tree = sha40(field(bundle, "tree_sha", "evidence"), "evidence.tree_sha")

    expect(candidate_dir.is_absolute(), "candidate-dir must be absolute")
    expect(candidate_dir.is_dir(), "candidate-dir must be an existing directory")
    actual_head = git(candidate_dir, "rev-parse", "--verify", "HEAD^{commit}").stdout.strip()
    actual_tree = git(candidate_dir, "rev-parse", "--verify", "HEAD^{tree}").stdout.strip()
    expect(actual_head == candidate, f"candidate checkout HEAD {actual_head} does not match {candidate}")
    expect(actual_tree == tree, f"candidate tree {actual_tree} does not match {tree}")
    git(candidate_dir, "cat-file", "-e", f"{base}^{{commit}}")
    ancestor = git(candidate_dir, "merge-base", "--is-ancestor", base, candidate, check=False)
    expect(ancestor.returncode == 0, f"base {base} is not an ancestor of candidate {candidate}")

    status = git(candidate_dir, "status", "--porcelain=v1", "--untracked-files=all").stdout.splitlines()
    allowed = {"?? pre-freeze-receipt.json", "?? protected-ci-receipt.json"}
    dirty = [entry for entry in status if entry not in allowed]
    if dirty:
        refuse(f"candidate checkout is dirty: {dirty[0]}")

    source = obj(field(bundle, "source", "evidence"), "evidence.source")
    expect(sha40(field(source, "checkout_sha", "evidence.source"), "evidence.source.checkout_sha") == candidate,
           "source checkout_sha does not match candidate")
    expect(boolean(field(source, "clean", "evidence.source"), "evidence.source.clean"),
           "source clean attestation must be true")
    return candidate, base, tree


def validate_named_receipt(
    descriptor: dict[str, Any],
    label: str,
    expected_source: str,
    candidate: str,
    base: str,
    now: int,
    max_age: int,
) -> tuple[str, dict[str, Any]]:
    exact_fields(descriptor, {"path", "sha256"}, set(), label)
    path = Path(text(field(descriptor, "path", label), f"{label}.path"))
    expected_digest = sha256(field(descriptor, "sha256", label), f"{label}.sha256")
    secure_regular_file(path, label)
    actual_digest = file_sha256(path)
    expect(actual_digest == expected_digest, f"{label} digest does not match retained file")
    receipt = load_json(path, label)
    expect(field(receipt, "schema_version", label) == 1, f"{label} schema_version must be 1")
    expect(field(receipt, "source", label) == expected_source, f"{label} source mismatch")
    expect(field(receipt, "repository", label) == REPOSITORY, f"{label} repository mismatch")
    expect(sha40(field(receipt, "head_sha", label), f"{label}.head_sha") == candidate,
           f"{label} head_sha does not match candidate")
    expect(field(receipt, "overall", label) == "PASS", f"{label} overall must be PASS")
    recorded_at = parse_utc(field(receipt, "timestamp", label), f"{label}.timestamp")
    expect(recorded_at <= now + 300, f"{label} timestamp is too far in the future")
    expect(now - recorded_at <= max_age, f"{label} is stale")
    checks = array(field(receipt, "checks", label), f"{label}.checks")
    expect(bool(checks), f"{label}.checks must not be empty")
    expect(all(obj(check, f"{label}.checks[]").get("status") == "PASS" for check in checks),
           f"{label} contains a non-PASS check")
    if expected_source == "pre-freeze":
        expect(sha40(field(receipt, "base_sha", label), f"{label}.base_sha") == base,
               "pre-freeze receipt base_sha mismatch")
    else:
        expect(receipt.get("protected") is True, "protected-CI receipt must attest protected=true")
        expect(receipt.get("full_exact_head") is True,
               "protected-CI receipt must attest full_exact_head=true")
    return actual_digest, receipt


def validate_acceptance_verdict(
    descriptor: dict[str, Any], candidate: str
) -> tuple[str, dict[str, Any]]:
    label = "evidence_files.acceptance_verdict"
    exact_fields(descriptor, {"path", "sha256"}, set(), label)
    path = Path(text(field(descriptor, "path", label), f"{label}.path"))
    expected_digest = sha256(field(descriptor, "sha256", label), f"{label}.sha256")
    secure_regular_file(path, label)
    actual_digest = file_sha256(path)
    expect(actual_digest == expected_digest, "acceptance verdict digest mismatch")
    verdict = load_json(path, label)
    expect(verdict.get("candidate_sha") == candidate, "acceptance verdict candidate mismatch")
    expect(verdict.get("green") is True, "acceptance verdict is not green")
    security = obj(verdict.get("security"), "acceptance verdict security")
    probes = obj(verdict.get("probes"), "acceptance verdict probes")
    expect(security == {"passed": 17, "total": 17}, "acceptance verdict must pass all 17 TM checks")
    expect(probes == {"passed_runs": 12, "total_runs": 12},
           "acceptance verdict must pass all six probes twice")
    expect(verdict.get("missing") == [], "acceptance verdict has missing checks")
    expect(verdict.get("failed") == [], "acceptance verdict has failed checks")
    expect(verdict.get("sha_conflicts") == [], "acceptance verdict has SHA conflicts")
    return actual_digest, verdict


def validate_acceptance_records(
    descriptor: dict[str, Any], candidate: str
) -> str:
    label = "evidence_files.acceptance_records"
    exact_fields(descriptor, {"path", "sha256"}, set(), label)
    path = Path(text(field(descriptor, "path", label), f"{label}.path"))
    expected_digest = sha256(field(descriptor, "sha256", label), f"{label}.sha256")
    secure_regular_file(path, label)
    actual_digest = file_sha256(path)
    expect(actual_digest == expected_digest, "acceptance records digest mismatch")
    records: list[dict[str, Any]] = []
    try:
        for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            expect(bool(raw_line.strip()), f"acceptance records line {line_number} is empty")
            records.append(obj(json.loads(raw_line), f"acceptance records line {line_number}"))
    except (OSError, json.JSONDecodeError) as error:
        refuse(f"acceptance records are unreadable or invalid JSONL: {error}")

    expected_keys = {
        "suite", "test_id", "title", "candidate_sha", "pass", "evidence_ref",
        "executor", "host", "started_at", "finished_at",
    }
    observed: set[tuple[str, str, int | None]] = set()
    for index, record in enumerate(records):
        record_path = f"acceptance_records[{index}]"
        suite = field(record, "suite", record_path)
        expect(suite in ("security", "probe"), f"{record_path}.suite is invalid")
        required_keys = expected_keys | ({"run"} if suite == "probe" else set())
        expect(set(record) == required_keys, f"{record_path} fields are incomplete or unknown")
        test_id = text(field(record, "test_id", record_path), f"{record_path}.test_id")
        expect(sha40(field(record, "candidate_sha", record_path), f"{record_path}.candidate_sha") == candidate,
               f"{record_path} candidate SHA mismatch")
        expect(boolean(field(record, "pass", record_path), f"{record_path}.pass"),
               f"{record_path} did not pass")
        for name in ("title", "evidence_ref", "executor", "host"):
            text(field(record, name, record_path), f"{record_path}.{name}")
        started = integer(field(record, "started_at", record_path), f"{record_path}.started_at")
        finished = integer(field(record, "finished_at", record_path), f"{record_path}.finished_at")
        expect(0 <= started <= finished, f"{record_path} timestamps are out of order")
        run: int | None = None
        if suite == "security":
            expect(test_id in TM_IDS, f"{record_path} has an unknown threat-model check")
        else:
            expect(test_id in PROBE_IDS, f"{record_path} has an unknown named probe")
            run = integer(field(record, "run", record_path), f"{record_path}.run")
            expect(run in (1, 2), f"{record_path}.run must be 1 or 2")
        key = (suite, test_id, run)
        expect(key not in observed, f"{record_path} duplicates {suite}/{test_id}/{run}")
        observed.add(key)

    expected = {("security", test_id, None) for test_id in TM_IDS}
    expected.update({("probe", test_id, run) for test_id in PROBE_IDS for run in (1, 2)})
    expect(observed == expected, "acceptance records do not contain all 17 TM checks and six probes twice")
    return actual_digest


def validate_protected_ci(section: dict[str, Any], candidate: str) -> list[str]:
    path = "protected_ci"
    expect(sha40(field(section, "head_sha", path), f"{path}.head_sha") == candidate,
           "protected CI head does not match candidate")
    expect(boolean(field(section, "protected", path), f"{path}.protected"),
           "protected CI must be protected")
    expect(field(section, "conclusion", path) == "success", "protected CI conclusion must be success")
    contexts = array(field(section, "contexts", path), f"{path}.contexts")
    expect(bool(contexts), "protected CI contexts must not be empty")
    names: list[str] = []
    for index, raw_context in enumerate(contexts):
        context_path = f"{path}.contexts[{index}]"
        context = obj(raw_context, context_path)
        names.append(text(field(context, "name", context_path), f"{context_path}.name"))
        expect(field(context, "conclusion", context_path) == "success",
               f"{context_path} conclusion must be success")
        expect(sha40(field(context, "head_sha", context_path), f"{context_path}.head_sha") == candidate,
               f"{context_path} head_sha mismatch")
        run_url = text(field(context, "run_url", context_path), f"{context_path}.run_url")
        expect(run_url.startswith("https://"), f"{context_path}.run_url must use https")
    expect(len(names) == len(set(names)), "protected CI context names must be unique")
    return sorted(names)


def validate_tier2(section: dict[str, Any], candidate: str, now: int) -> dict[str, Any]:
    path = "tier2"
    for name in ("eligible_commit", "checked_commit"):
        expect(sha40(field(section, name, path), f"{path}.{name}") == candidate,
               f"tier2 {name} mismatch")
    expect(integer(field(section, "check_exit_code", path), f"{path}.check_exit_code") == 0,
           "tier2 commit check must exit 0")
    verdict = field(section, "verdict", path)
    expect(verdict in ("PASS", "PASS WITH RISKS"), "tier2 verdict must be terminal PASS")
    reviewer = text(field(section, "reviewer", path), f"{path}.reviewer")
    expect(reviewer.startswith("claude:"), "GPT-produced candidate requires a Claude reviewer identity")
    expect(field(section, "model", path) == "claude-opus-5", "tier2 model must be claude-opus-5")
    expect(field(section, "effort", path) == "high", "tier2 effort must be high")
    prepared_at = integer(field(section, "prepared_at", path), f"{path}.prepared_at")
    reviewed_at = integer(field(section, "reviewed_at", path), f"{path}.reviewed_at")
    expires_at = integer(field(section, "expires_at", path), f"{path}.expires_at")
    expect(prepared_at <= reviewed_at <= now, "tier2 timestamps are out of order")
    expect(expires_at > reviewed_at, "tier2 expiry must follow review")
    expect(expires_at - prepared_at <= 5400, "tier2 state window exceeds 5,400 seconds")
    expect(now <= expires_at, "tier2 review is stale")
    return {
        "lineage": text(field(section, "lineage", path), f"{path}.lineage"),
        "state_sha256": sha256(field(section, "state_sha256", path), f"{path}.state_sha256"),
        "fingerprint": sha256(field(section, "fingerprint", path), f"{path}.fingerprint"),
        "reviewer": reviewer,
        "verdict": verdict,
        "remaining_seconds": expires_at - now,
    }


def validate_artifacts(section: dict[str, Any], candidate: str) -> dict[str, Any]:
    path = "artifacts"
    image_ref = text(field(section, "image_ref", path), f"{path}.image_ref")
    expect(image_ref == f"localhost/buzz-relay:{candidate}", "artifact image_ref is not candidate-pinned")
    ids = [image_id(value, f"{path}.image_ids[]") for value in array(field(section, "image_ids", path), f"{path}.image_ids")]
    expect(bool(ids) and len(ids) == len(set(ids)), "artifact image_ids must be non-empty and unique")
    running = image_id(field(section, "running_image_id", path), f"{path}.running_image_id")
    expect(running in ids, "running image ID is not one of the built image IDs")
    binary = sha256(field(section, "binary_sha256", path), f"{path}.binary_sha256")
    expect(sha40(field(section, "oci_revision", path), f"{path}.oci_revision") == candidate,
           "OCI revision does not match candidate")
    required = integer(field(section, "required_migration", path), f"{path}.required_migration")
    database = integer(field(section, "database_migration", path), f"{path}.database_migration")
    expect(required >= 0 and database == required, "database migration does not match image requirement")
    return {"image_ref": image_ref, "image_ids": ids, "running_image_id": running,
            "binary_sha256": binary, "migration": database}


def validate_log_auth(section: dict[str, Any], path: str) -> dict[str, Any]:
    authorized = integer(field(section, "authorized_status", path), f"{path}.authorized_status")
    unauthorized = integer(field(section, "unauthorized_status", path), f"{path}.unauthorized_status")
    expect(authorized == 200, f"{path} authorized request must return 200")
    expect(unauthorized in (401, 403), f"{path} unauthorized request must return 401 or 403")
    expect(integer(field(section, "redirects", path), f"{path}.redirects") == 0,
           f"{path} must not redirect")
    digest = sha256(field(section, "sha256", path), f"{path}.sha256")
    expect(sha256(field(section, "computed_sha256", path), f"{path}.computed_sha256") == digest,
           f"{path} digest mismatch")
    byte_count = integer(field(section, "byte_count", path), f"{path}.byte_count")
    byte_cap = integer(field(section, "byte_cap", path), f"{path}.byte_cap")
    expect(0 < byte_count <= byte_cap, f"{path} byte count exceeds cap")
    return {"sha256": digest, "byte_count": byte_count}


def validate_status_history(
    history: list[tuple[int, dict[str, Any]]], transitions: dict[str, set[str]], path: str
) -> str:
    ordered = sorted(history)
    sequences = [positive_integer(item[1]["sequence"], f"{path}.sequence") for item in ordered]
    expect(sequences == list(range(1, len(sequences) + 1)), f"{path} sequence is not gap-free")
    states = [text(item[1]["state"], f"{path}.state") for item in ordered]
    expect(states[0] == "queued", f"{path} must begin queued")
    for previous, current in zip(states, states[1:]):
        expect(current in transitions.get(previous, set()),
               f"{path} has illegal transition {previous}->{current}")
    expect(states[-1] not in transitions, f"{path} is not terminal")
    return states[-1]


def validate_ci_event_evidence(
    section: dict[str, Any], candidate: str, base: str, path: str, expected_run_state: str
) -> dict[str, Any]:
    exact_fields(
        section,
        {"channel_id", "relay_url", "authorized_relay_signers", "requests", "events", "decoded_logs"},
        set(),
        path,
    )
    channel_id = run_uuid(field(section, "channel_id", path), f"{path}.channel_id")
    relay_origin = relay_http_origin(field(section, "relay_url", path), f"{path}.relay_url")
    authorized = [sha256(value, f"{path}.authorized_relay_signers[]")
                  for value in array(field(section, "authorized_relay_signers", path),
                                     f"{path}.authorized_relay_signers")]
    expect(bool(authorized) and len(authorized) == len(set(authorized)),
           f"{path}.authorized_relay_signers must be non-empty and unique")

    request_required = {
        "schema_version", "request_type", "target_repo_a", "pr_root_event_id",
        "source_clone_url", "immutable_source_ref", "tip_oid", "source_branch", "base_ref",
        "base_oid", "workflow_id", "workflow_digest", "job_ids", "run_id", "attempt",
        "trigger_event_id", "actor", "timeout_seconds", "idempotency_key", "issued_at", "expires_at",
    }
    requests: dict[str, dict[str, Any]] = {}
    request_order: list[str] = []
    initial_request_id = ""
    initial_content: dict[str, Any] | None = None
    raw_requests = array(field(section, "requests", path), f"{path}.requests")
    expect(bool(raw_requests), f"{path}.requests must not be empty")
    for index, raw_request in enumerate(raw_requests):
        request_path = f"{path}.requests[{index}]"
        request_content, kind, request_id, request_pubkey, _, tags = validate_wire_event(
            raw_request, request_path, require_cursor=False
        )
        expect(kind == 46100, f"{request_path}.kind must be 46100")
        exact_fields(
            request_content,
            request_required,
            {"pr_update_event_id", "parent_attempt", "parent_run_id"},
            f"{request_path}.content",
        )
        expect(request_content["schema_version"] == 1,
               f"{request_path}.content schema_version must be 1")
        request_type = text(request_content["request_type"], f"{request_path}.content.request_type")
        expect(request_type in ("run", "rerun"), f"{request_path}.content request_type is unknown")
        actor = sha256(request_content["actor"], f"{request_path}.content.actor")
        expect(request_pubkey == actor, f"{request_path} signer does not match actor")
        tip_oid = sha40(request_content["tip_oid"], f"{request_path}.content.tip_oid")
        expect(tip_oid == candidate, f"{request_path}.content tip_oid does not match candidate")
        base_oid = sha40(request_content["base_oid"], f"{request_path}.content.base_oid")
        expect(base_oid == base, f"{request_path}.content base_oid does not match top-level base_sha")
        run_id = run_uuid(request_content["run_id"], f"{request_path}.content.run_id")
        attempt = positive_integer(request_content["attempt"], f"{request_path}.content.attempt")
        selected = job_ids(request_content["job_ids"], f"{request_path}.content.job_ids")
        for name in ("pr_root_event_id", "trigger_event_id"):
            event_id(request_content[name], f"{request_path}.content.{name}")
        if "pr_update_event_id" in request_content:
            event_id(request_content["pr_update_event_id"], f"{request_path}.content.pr_update_event_id")
        expected_trigger = request_content.get("pr_update_event_id", request_content["pr_root_event_id"])
        expect(request_content["trigger_event_id"] == expected_trigger,
               f"{request_path}.content trigger_event_id is not the effective PR event")
        for name in ("target_repo_a", "workflow_id", "source_clone_url", "immutable_source_ref",
                     "source_branch", "base_ref", "idempotency_key"):
            text(request_content[name], f"{request_path}.content.{name}")
        sha256(request_content["workflow_digest"], f"{request_path}.content.workflow_digest")
        issued_at = integer(request_content["issued_at"], f"{request_path}.content.issued_at")
        expires_at = integer(request_content["expires_at"], f"{request_path}.content.expires_at")
        positive_integer(request_content["timeout_seconds"], f"{request_path}.content.timeout_seconds")
        expect(0 <= issued_at < expires_at, f"{request_path}.content expiry is invalid")
        validate_ci_tags(tags, channel_id, request_content, kind, f"{request_path}.content")
        if request_type == "run":
            expect(attempt == 1 and "parent_attempt" not in request_content
                   and "parent_run_id" not in request_content,
                   f"{request_path}.content run must be attempt one without a parent")
            expect(initial_content is None, f"{path} must contain exactly one initial request")
            initial_content = request_content
            initial_request_id = request_id
        else:
            expect(len(selected) == 1 and attempt > 1,
                   f"{request_path}.content rerun must select one job after attempt one")
            parent_attempt = positive_integer(request_content.get("parent_attempt"),
                                              f"{request_path}.content.parent_attempt")
            expect(attempt == parent_attempt + 1,
                   f"{request_path}.content rerun parent_attempt is not contiguous")
            expect(request_content.get("parent_run_id") == run_id,
                   f"{request_path}.content rerun parent_run_id mismatch")
        expect(request_id not in requests, f"{request_path}.id is duplicated")
        requests[request_id] = request_content
        request_order.append(request_id)

    expect(initial_content is not None, f"{path} has no initial run request")
    expect(requests[request_order[0]]["request_type"] == "run",
           f"{path} initial run request must be first")
    immutable_request_fields = (
        "target_repo_a", "pr_root_event_id", "pr_update_event_id", "source_clone_url",
        "immutable_source_ref", "tip_oid", "source_branch", "base_ref", "base_oid",
        "workflow_id", "workflow_digest", "run_id", "trigger_event_id",
    )
    for request_content in requests.values():
        for name in immutable_request_fields:
            expect(request_content.get(name) == initial_content.get(name),
                   f"{path} rerun request changed immutable {name}")

    target_repo_a = initial_content["target_repo_a"]
    tip_oid = initial_content["tip_oid"]
    base_oid = initial_content["base_oid"]
    workflow_id = initial_content["workflow_id"]
    workflow_digest = initial_content["workflow_digest"]
    selected_jobs = initial_content["job_ids"]
    run_id = initial_content["run_id"]
    actor = initial_content["actor"]
    for request_id_value in request_order[1:]:
        if requests[request_id_value]["request_type"] == "rerun":
            expect(requests[request_id_value]["job_ids"][0] in selected_jobs,
                   f"{path} rerun request selected an unknown initial job")

    raw_events = array(field(section, "events", path), f"{path}.events")
    expect(bool(raw_events), f"{path}.events must not be empty")
    observed_ids = set(requests)
    observed_kinds: set[int] = set()
    observed_signers: set[str] = set()
    cursors: list[int] = []
    run_histories: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    job_histories: dict[tuple[str, int], list[tuple[int, dict[str, Any]]]] = {}
    log_events: dict[str, tuple[str, int, int]] = {}
    artifact_events: dict[str, tuple[str, int, int]] = {}
    finalized: tuple[int, dict[str, Any]] | None = None
    teardown: tuple[int, dict[str, Any]] | None = None

    common = {"schema_version", "request_event_id", "run_id", "workflow_id", "target_repo_a", "tip_oid"}
    for index, raw_event in enumerate(raw_events):
        event_path = f"{path}.events[{index}]"
        content, kind, current_id, pubkey, cursor, tags = validate_wire_event(
            raw_event, event_path, require_cursor=True
        )
        expect(kind in CI_EVENT_KINDS, f"{event_path}.kind is not a promotion history kind")
        observed_kinds.add(kind)
        expect(current_id not in observed_ids, f"{event_path}.event_id is duplicated")
        observed_ids.add(current_id)
        observed_signers.add(pubkey)
        expect(pubkey in authorized, f"{event_path} signer is not authorized")
        assert cursor is not None
        cursors.append(cursor)
        content_path = f"{event_path}.content"

        if kind == 46101:
            required = common | {"base_oid", "attempt", "sequence", "state", "job_ids", "relay_signer"}
            optional = {"conclusion", "reason", "started_at", "finished_at"}
        elif kind == 46102:
            required = common | {
                "base_oid", "job_id", "name", "attempt", "sequence", "state", "required",
                "skip_policy", "selected_job_instance", "also_reruns", "artifact_refs", "relay_signer",
            }
            optional = {"parent_attempt", "conclusion", "reason", "started_at", "finished_at", "log_ref"}
        elif kind == 46103:
            required = common | {
                "job_id", "attempt", "log_sha256", "byte_length", "cap_bytes", "truncated",
                "created_at", "relay_signer",
            }
            optional = {"url", "inline"}
        elif kind == 46104:
            required = common | {
                "job_id", "attempt", "artifact_id", "name", "media_type", "sha256",
                "byte_length", "url", "created_at", "relay_signer",
            }
            optional = set()
        elif kind == 46105:
            required = common | {"attempt", "finalized_job_attempts", "finalized_at", "relay_signer"}
            optional = set()
        else:
            required = common | {
                "base_oid", "workflow_digest", "attempt", "leases", "lease_empty", "teardown_at",
                "relay_signer",
            }
            optional = set()
        exact_fields(content, required, optional, content_path)
        expect(field(content, "schema_version", content_path) == 1,
               f"{content_path}.schema_version must be 1")
        request_event_id = event_id(field(content, "request_event_id", content_path),
                                    f"{content_path}.request_event_id")
        expect(request_event_id in requests, f"{content_path} request_event_id is not a signed request")
        bound_request = requests[request_event_id]
        expect(run_uuid(field(content, "run_id", content_path), f"{content_path}.run_id") == run_id,
               f"{content_path} run_id mismatch")
        expect(text(field(content, "workflow_id", content_path), f"{content_path}.workflow_id") == workflow_id,
               f"{content_path} workflow_id mismatch")
        expect(text(field(content, "target_repo_a", content_path),
                    f"{content_path}.target_repo_a") == target_repo_a,
               f"{content_path} repository coordinate mismatch")
        expect(sha40(field(content, "tip_oid", content_path), f"{content_path}.tip_oid") == tip_oid,
               f"{content_path} tip_oid mismatch")
        expect(sha256(field(content, "relay_signer", content_path),
                      f"{content_path}.relay_signer") == pubkey,
               f"{content_path} relay_signer does not match event pubkey")
        if "base_oid" in content:
            expect(sha40(content["base_oid"], f"{content_path}.base_oid") == base_oid,
                   f"{content_path} base_oid mismatch")
            expect(content["base_oid"] == base, f"{content_path} base_oid does not match top-level base_sha")
        if "workflow_digest" in content:
            expect(sha256(content["workflow_digest"], f"{content_path}.workflow_digest") == workflow_digest,
                   f"{content_path} workflow_digest mismatch")
        attempt = positive_integer(content["attempt"], f"{content_path}.attempt")
        expect(bound_request["attempt"] == attempt,
               f"{content_path} attempt does not match signed request")
        validate_ci_tags(tags, channel_id, content, kind, content_path)

        if kind == 46101:
            job_ids(content["job_ids"], f"{content_path}.job_ids")
            state = text(content["state"], f"{content_path}.state")
            expect(state in RUN_STATES, f"{content_path}.state is unknown")
            run_histories.setdefault(request_event_id, []).append((cursor, content))
        elif kind == 46102:
            job_id_value = text(content["job_id"], f"{content_path}.job_id")
            expect(job_id_value in selected_jobs, f"{content_path}.job_id was not requested")
            state = text(content["state"], f"{content_path}.state")
            expect(state in JOB_STATES, f"{content_path}.state is unknown")
            expect(isinstance(content["required"], bool), f"{content_path}.required must be boolean")
            expect(content["skip_policy"] in ("allow", "forbid"), f"{content_path}.skip_policy is unknown")
            text(content["selected_job_instance"], f"{content_path}.selected_job_instance")
            refs = array(content["artifact_refs"], f"{content_path}.artifact_refs")
            expect(len(refs) == len(set(refs)), f"{content_path}.artifact_refs are duplicated")
            fanout = [text(value, f"{content_path}.also_reruns[]")
                      for value in array(content["also_reruns"], f"{content_path}.also_reruns")]
            expect(len(fanout) == len(set(fanout)) and job_id_value not in fanout,
                   f"{content_path}.also_reruns is invalid")
            expect(all(JOB_ID.fullmatch(value) is not None and value in selected_jobs for value in fanout),
                   f"{content_path}.also_reruns contains an unknown job")
            job_histories.setdefault((job_id_value, attempt), []).append((cursor, content))
        elif kind == 46103:
            job_id_value = text(content["job_id"], f"{content_path}.job_id")
            expect(job_id_value in selected_jobs, f"{content_path}.job_id was not requested")
            expect(("url" in content) != ("inline" in content),
                   f"{content_path} must contain exactly one of url or inline")
            if "url" in content:
                expected_path = (
                    f"/ci/logs/{request_event_id}/{run_id}/{job_id_value}/{attempt}/"
                    f"{content['log_sha256']}"
                )
                validate_relay_evidence_url(
                    content["url"], relay_origin, expected_path, f"{content_path}.url"
                )
            expect(field(content, "truncated", content_path) is False, f"{content_path} is truncated")
            byte_length = positive_integer(content["byte_length"], f"{content_path}.byte_length")
            expect(byte_length <= positive_integer(content["cap_bytes"], f"{content_path}.cap_bytes"),
                   f"{content_path} exceeds its byte cap")
            log_digest = sha256(content["log_sha256"], f"{content_path}.log_sha256")
            log_events[current_id] = (job_id_value, attempt, integer(content["created_at"],
                                                                     f"{content_path}.created_at"))
            decoded_logs = obj(field(section, "decoded_logs", path), f"{path}.decoded_logs")
            expect(current_id in decoded_logs, f"{content_path} has no decoded log evidence")
            encoded = text(decoded_logs[current_id], f"{path}.decoded_logs.{current_id}")
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except ValueError:
                refuse(f"{path}.decoded_logs.{current_id} is not canonical base64")
            expect(base64.b64encode(decoded).decode() == encoded,
                   f"{path}.decoded_logs.{current_id} is not canonical base64")
            expect(len(decoded) == byte_length, f"{content_path} decoded log byte length mismatch")
            expect(hashlib.sha256(decoded).hexdigest() == log_digest,
                   f"{content_path} decoded log digest mismatch")
        elif kind == 46104:
            job_id_value = text(content["job_id"], f"{content_path}.job_id")
            expect(job_id_value in selected_jobs, f"{content_path}.job_id was not requested")
            artifact_digest = sha256(content["sha256"], f"{content_path}.sha256")
            positive_integer(content["byte_length"], f"{content_path}.byte_length")
            for name in ("artifact_id", "name", "media_type"):
                text(content[name], f"{content_path}.{name}")
            expected_path = (
                f"/ci/artifacts/{request_event_id}/{run_id}/{job_id_value}/{attempt}/"
                f"{content['artifact_id']}/{artifact_digest}"
            )
            validate_relay_evidence_url(
                content["url"], relay_origin, expected_path, f"{content_path}.url"
            )
            artifact_events[current_id] = (job_id_value, attempt, integer(content["created_at"],
                                                                          f"{content_path}.created_at"))
        elif kind == 46105:
            expect(finalized is None, f"{path} has more than one kind 46105 event")
            finalized = (cursor, content)
        else:
            expect(teardown is None, f"{path} has more than one kind 46106 event")
            teardown = (cursor, content)

    expect(set(obj(field(section, "decoded_logs", path), f"{path}.decoded_logs")) == set(log_events),
           f"{path}.decoded_logs does not exactly match signed log events")
    expect(cursors == list(range(1, len(cursors) + 1)), f"{path}.events watch cursors are not gap-free")
    expect(len(observed_signers) == 1, f"{path}.events must bind one relay signer")
    relay_signer = next(iter(observed_signers))
    if expected_run_state == "success":
        expect(observed_kinds == CI_EVENT_KINDS,
               f"{path}.events successful kind coverage must deduplicate to 46101 through 46106")
        expect(finalized is not None and teardown is not None,
               f"{path}.events must contain one kind 46105 and one kind 46106 fact")
    else:
        expect(observed_kinds == CI_EVENT_KINDS - {46105, 46106},
               f"{path}.events deliberate-red kind coverage must deduplicate to 46101 through 46104")
        expect(finalized is None and teardown is None,
               f"{path}.events deliberate-red history must not contain terminal evidence facts")

    selected_attempts: dict[str, int] = {}
    job_attempt_ranges: dict[str, list[int]] = {}
    job_request_ids: dict[tuple[str, int], str] = {}
    job_terminals: dict[tuple[str, int], dict[str, Any]] = {}
    immutable_manifests: dict[str, tuple[Any, ...]] = {}
    for job_id_value in selected_jobs:
        job_attempts = sorted(attempt for job, attempt in job_histories if job == job_id_value)
        expect(bool(job_attempts), f"{path} has no status stream for job {job_id_value}")
        expect(job_attempts == list(range(1, job_attempts[-1] + 1)),
               f"{path} job {job_id_value} attempt lineage is not contiguous")
        job_attempt_ranges[job_id_value] = job_attempts
        selected_attempts[job_id_value] = job_attempts[-1]
        for attempt in job_attempts:
            history_path = f"{path} job {job_id_value} attempt {attempt}"
            ordered_history = sorted(job_histories[(job_id_value, attempt)])
            manifest_fields = ("name", "required", "skip_policy", "selected_job_instance",
                               "parent_attempt", "also_reruns")
            manifest = tuple(json.dumps(item[1].get(name), sort_keys=True) for item in ordered_history
                             for name in manifest_fields)
            width = len(manifest_fields)
            expect(all(manifest[offset:offset + width] == manifest[:width]
                       for offset in range(0, len(manifest), width)),
                   f"{history_path} changed its immutable job manifest")
            stable_manifest = tuple(ordered_history[0][1].get(name)
                                    for name in ("name", "required", "skip_policy", "selected_job_instance"))
            if job_id_value in immutable_manifests:
                expect(immutable_manifests[job_id_value] == stable_manifest,
                       f"{history_path} changed its immutable job manifest across attempts")
            else:
                immutable_manifests[job_id_value] = stable_manifest
            parent_attempt = ordered_history[0][1].get("parent_attempt")
            if attempt == 1:
                expect(parent_attempt is None, f"{history_path} attempt one has a parent_attempt")
            else:
                expect(parent_attempt == attempt - 1,
                       f"{history_path} parent_attempt is not contiguous")
            terminal = validate_status_history(job_histories[(job_id_value, attempt)],
                                               JOB_TRANSITIONS, history_path)
            terminal_content = ordered_history[-1][1]
            expect(terminal_content.get("conclusion") == terminal,
                   f"{history_path} terminal outcome does not match state")
            request_ids = {item[1]["request_event_id"] for item in ordered_history}
            expect(len(request_ids) == 1,
                   f"{history_path} is not bound to one signed request")
            job_request_ids[(job_id_value, attempt)] = next(iter(request_ids))
            job_terminals[(job_id_value, attempt)] = terminal_content
            if attempt < job_attempts[-1]:
                expect(terminal == "failure", f"{history_path} must fail before a rerun")

    evolving_attempts = {job: 1 for job in selected_jobs}
    for request_index, request_id_value in enumerate(request_order):
        request_content = requests[request_id_value]
        attempt = request_content["attempt"]
        observed_jobs = {
            job for (job, _), request_id_for_job in job_request_ids.items()
            if request_id_for_job == request_id_value
        }
        if request_index == 0:
            expect(observed_jobs == set(selected_jobs), f"{path} attempt one job graph mismatch")
        else:
            selected_job = request_content["job_ids"][0]
            parent_attempt = request_content["parent_attempt"]
            expect(evolving_attempts[selected_job] == parent_attempt,
                   f"{path} rerun parent_attempt is stale for selected job")
            expect((selected_job, attempt) in job_histories,
                   f"{path} rerun request has no selected job history")
            selected_history = sorted(job_histories[(selected_job, attempt)])
            fanout = set(selected_history[0][1]["also_reruns"])
            expect(observed_jobs == {selected_job} | fanout,
                   f"{path} rerun fanout does not match signed selected job history")
            expect((selected_job, parent_attempt) in job_terminals,
                   f"{path} rerun request has no parent job history")
            prior = job_terminals[(selected_job, parent_attempt)]
            expect(prior["state"] == "failure",
                   f"{path} rerun parent job is not a terminal failure")
            for job in observed_jobs:
                expect(evolving_attempts[job] == attempt - 1,
                       f"{path} rerun fanout does not advance each job contiguously")
                evolving_attempts[job] = attempt
        for job in observed_jobs:
            history = job_histories[(job, attempt)]
            expect(all(item[1]["request_event_id"] == request_id_value for item in history),
                   f"{path} job history is not bound to its signed request")
        run_jobs = [job_ids(item[1]["job_ids"], f"{path} run request {request_index}.job_ids")
                    for item in run_histories.get(request_id_value, [])]
        expect(bool(run_jobs) and all(set(value) == observed_jobs for value in run_jobs),
               f"{path} run job manifest does not match the selected attempt graph")
        expect(all(item[1]["request_event_id"] == request_id_value
                   for item in run_histories[request_id_value]),
               f"{path} run history is not bound to its signed request")
    expect(evolving_attempts == selected_attempts,
           f"{path} request lineage does not select the final per-job attempt graph")

    maximum_attempt = max(selected_attempts.values())
    expect(set(run_histories) == set(request_order),
           f"{path} run history does not exactly match signed requests")
    terminal_run: tuple[int, dict[str, Any]] | None = None
    for request_index, request_id_value in enumerate(request_order):
        attempt = requests[request_id_value]["attempt"]
        history_path = f"{path} run request {request_index} attempt {attempt}"
        terminal_state = validate_status_history(
            run_histories[request_id_value], RUN_TRANSITIONS, history_path
        )
        terminal_content_for_attempt = sorted(run_histories[request_id_value])[-1][1]
        expect(terminal_content_for_attempt.get("conclusion") == terminal_state,
               f"{history_path} terminal outcome does not match state")
        if request_index < len(request_order) - 1:
            expect(terminal_state == "failure", f"{history_path} must fail before a rerun")
        else:
            expect(terminal_state == expected_run_state,
                   f"{history_path} must conclude {expected_run_state}")
            terminal_run = sorted(run_histories[request_id_value])[-1]
    expect(terminal_run is not None, f"{path} has no final terminal run")

    final_job_states = {
        job: sorted(job_histories[(job, attempt)])[-1][1]
        for job, attempt in selected_attempts.items()
    }
    if expected_run_state == "success":
        for job, terminal_content in final_job_states.items():
            terminal_good = terminal_content["state"] == "success" or (
                terminal_content["state"] == "skipped" and terminal_content["skip_policy"] == "allow"
            )
            expect(terminal_good, f"{path} final job {job} is not terminal-good")
    else:
        expect(any(content["state"] == "failure" for content in final_job_states.values()),
               f"{path} deliberate-red evidence has no failed final job")

    validated_result = {
        "request_event_id": request_order[-1],
        "initial_request_event_id": initial_request_id,
        "request_event_ids": request_order,
        "rerun_request_event_ids": request_order[1:],
        "run_id": run_id,
        "actor": actor,
        "relay_signer": relay_signer,
        "target_repo_a": target_repo_a,
        "workflow_id": workflow_id,
        "workflow_digest": workflow_digest,
        "job_ids": selected_jobs,
        "selected_job_attempts": selected_attempts,
        "tip_oid": tip_oid,
        "base_oid": base_oid,
        "attempts": sorted({requests[request_id]["attempt"] for request_id in request_order}),
        "job_attempts": {
            job: job_attempt_ranges[job] for job in sorted(job_attempt_ranges)
        },
        "terminal_events": 1,
        "log_digests": sorted(
            sha256(json.loads(event["content"])["log_sha256"], f"{path}.log_digest")
            for event in raw_events if event["kind"] == 46103
        ),
    }
    if expected_run_state == "failure":
        return validated_result

    finalized_cursor, finalized_content = finalized
    expect(finalized_content["request_event_id"] == request_order[-1],
           f"{path} kind 46105 is not bound to the final signed request")
    expect(positive_integer(finalized_content["attempt"], f"{path}.kind46105.attempt") == maximum_attempt,
           f"{path} kind 46105 top-level attempt mismatch")
    finalized_entries = array(finalized_content["finalized_job_attempts"],
                              f"{path}.kind46105.finalized_job_attempts")
    finalized_graph: dict[str, int] = {}
    used_logs: set[str] = set()
    used_artifacts: set[str] = set()
    finalized_at = integer(finalized_content["finalized_at"], f"{path}.kind46105.finalized_at")
    for index, raw_entry in enumerate(finalized_entries):
        entry_path = f"{path}.kind46105.finalized_job_attempts[{index}]"
        entry = obj(raw_entry, entry_path)
        exact_fields(entry, {"job_id", "attempt", "log_ref", "artifact_refs"}, set(), entry_path)
        job_id_value = text(entry["job_id"], f"{entry_path}.job_id")
        attempt = positive_integer(entry["attempt"], f"{entry_path}.attempt")
        expect(job_id_value not in finalized_graph, f"{entry_path} duplicates a job")
        finalized_graph[job_id_value] = attempt
        log_ref = event_id(entry["log_ref"], f"{entry_path}.log_ref")
        expect(log_ref in log_events and log_events[log_ref][:2] == (job_id_value, attempt),
               f"{entry_path}.log_ref is not bound to the selected job attempt")
        expect(log_ref not in used_logs, f"{entry_path}.log_ref is duplicated")
        used_logs.add(log_ref)
        expect(log_events[log_ref][2] <= finalized_at, f"{entry_path}.log_ref was not stored before finalization")
        refs = [event_id(value, f"{entry_path}.artifact_refs[]")
                for value in array(entry["artifact_refs"], f"{entry_path}.artifact_refs")]
        expect(len(refs) == len(set(refs)), f"{entry_path}.artifact_refs are duplicated")
        for ref in refs:
            expect(ref in artifact_events and artifact_events[ref][:2] == (job_id_value, attempt),
                   f"{entry_path}.artifact_refs is not bound to the selected job attempt")
            expect(ref not in used_artifacts, f"{entry_path}.artifact_refs contains a reused event")
            expect(artifact_events[ref][2] <= finalized_at,
                   f"{entry_path}.artifact_refs was not stored before finalization")
            used_artifacts.add(ref)
    expect(finalized_graph == selected_attempts, f"{path} kind 46105 selected job-attempt graph mismatch")
    selected_logs = {
        event_id_value for event_id_value, (job, attempt, _) in log_events.items()
        if selected_attempts.get(job) == attempt
    }
    selected_artifacts = {
        event_id_value for event_id_value, (job, attempt, _) in artifact_events.items()
        if selected_attempts.get(job) == attempt
    }
    expect(used_logs == selected_logs,
           f"{path} kind 46105 does not bind every selected log event exactly once")
    expect(used_artifacts == selected_artifacts,
           f"{path} kind 46105 does not bind every selected artifact event exactly once")

    teardown_cursor, teardown_content = teardown
    expect(teardown_content["request_event_id"] == request_order[-1],
           f"{path} kind 46106 is not bound to the final signed request")
    expect(positive_integer(teardown_content["attempt"], f"{path}.kind46106.attempt") == maximum_attempt,
           f"{path} kind 46106 top-level attempt mismatch")
    expect(teardown_content["lease_empty"] is True, f"{path} kind 46106 lease_empty must be true")
    leases = array(teardown_content["leases"], f"{path}.kind46106.leases")
    lease_tuples: list[tuple[str, int, str]] = []
    for index, raw_lease in enumerate(leases):
        lease_path = f"{path}.kind46106.leases[{index}]"
        lease = obj(raw_lease, lease_path)
        exact_fields(lease, {"job_id", "attempt", "lease_id"}, set(), lease_path)
        lease_tuples.append((text(lease["job_id"], f"{lease_path}.job_id"),
                             positive_integer(lease["attempt"], f"{lease_path}.attempt"),
                             text(lease["lease_id"], f"{lease_path}.lease_id")))
    expect(lease_tuples == sorted(lease_tuples), f"{path} kind 46106 leases are not strictly ordered")
    expect(len(lease_tuples) == len(set(lease_tuples)), f"{path} kind 46106 leases are duplicated")
    expect(len({item[2] for item in lease_tuples}) == len(lease_tuples),
           f"{path} kind 46106 lease IDs are duplicated")
    expect({(job, attempt) for job, attempt, _ in lease_tuples} == set(selected_attempts.items()),
           f"{path} kind 46106 lease graph does not match selected job attempts")

    terminal_cursor, terminal_content = terminal_run
    expect(finalized_cursor < terminal_cursor and teardown_cursor < terminal_cursor,
           f"{path} terminal run was stored before kind 46105 and kind 46106")
    finished_at = integer(field(terminal_content, "finished_at", f"{path}.terminal_success"),
                          f"{path}.terminal_success.finished_at")
    teardown_at = integer(teardown_content["teardown_at"], f"{path}.kind46106.teardown_at")
    expect(finished_at >= finalized_at and finished_at >= teardown_at,
           f"{path} terminal run timestamp precedes evidence or teardown")
    return validated_result


def validate_staging(section: dict[str, Any], candidate: str, base: str) -> dict[str, Any]:
    path = "staging"
    exact_fields(section, {
        "candidate_sha", "absent_policy_status", "configured_policy_status", "root_executor_handoff",
        "advertised_bounds_sha256", "enforced_bounds_sha256", "scenarios", "event_evidence", "log",
    }, set(), path)
    expect(sha40(field(section, "candidate_sha", path), f"{path}.candidate_sha") == candidate,
           "staging candidate mismatch")
    expect(integer(field(section, "absent_policy_status", path), f"{path}.absent_policy_status") == 503,
           "absent-policy staging check must return 503")
    expect(integer(field(section, "configured_policy_status", path), f"{path}.configured_policy_status") == 200,
           "configured-policy staging check must return 200")
    expect(boolean(field(section, "root_executor_handoff", path), f"{path}.root_executor_handoff"),
           "staging did not prove the root-executor handoff")
    advertised = sha256(field(section, "advertised_bounds_sha256", path), f"{path}.advertised_bounds_sha256")
    enforced = sha256(field(section, "enforced_bounds_sha256", path), f"{path}.enforced_bounds_sha256")
    expect(advertised == enforced, "advertised and enforced broker bounds differ")
    scenarios = obj(field(section, "scenarios", path), f"{path}.scenarios")
    required_scenarios = {
        "success", "policy_refusal", "teardown_failure", "restart_recovery", "unaccepted_refusal"
    }
    expect(set(scenarios) == required_scenarios, "staging scenarios are incomplete or unknown")
    expect(all(scenarios[name] == "PASS" for name in required_scenarios),
           "a staging scenario did not pass")
    event_evidence = validate_ci_event_evidence(
        obj(field(section, "event_evidence", path), f"{path}.event_evidence"), candidate, base,
        f"{path}.event_evidence", "success",
    )
    log = validate_log_auth(obj(field(section, "log", path), f"{path}.log"), f"{path}.log")
    expect(log["sha256"] in event_evidence["log_digests"],
           "staging authenticated log is not bound to signed decoded log evidence")
    return {
        **event_evidence,
        "log": log,
    }


def validate_retry(section: dict[str, Any], event_evidence: dict[str, Any], path: str) -> dict[str, Any]:
    exact_fields(section, {
        "request_id", "rerun_request_id", "first_run_id", "duplicate_run_id", "attempts",
        "workspaces", "terminal_events",
    }, set(), path)
    request_id = event_id(field(section, "request_id", path), f"{path}.request_id")
    expect(request_id == event_evidence["initial_request_event_id"],
           f"{path} request_id is not the canonical signed initial request")
    rerun_request_id = event_id(field(section, "rerun_request_id", path), f"{path}.rerun_request_id")
    expect(event_evidence["rerun_request_event_ids"] == [rerun_request_id],
           f"{path} rerun_request_id is not the canonical signed rerun request")
    first = run_uuid(field(section, "first_run_id", path), f"{path}.first_run_id")
    duplicate = run_uuid(field(section, "duplicate_run_id", path), f"{path}.duplicate_run_id")
    expect(first == duplicate, f"{path} duplicate request created a second run")
    attempts = array(field(section, "attempts", path), f"{path}.attempts")
    expect(attempts == [1, 2], f"{path} must prove bounded attempts 1 and 2")
    expect(attempts == event_evidence["attempts"],
           f"{path} attempts do not match canonical signed rerun lineage")
    workspaces = array(field(section, "workspaces", path), f"{path}.workspaces")
    expect(len(workspaces) == 2 and len(set(workspaces)) == 2,
           f"{path} retry attempts must use distinct workspaces")
    expect(integer(field(section, "terminal_events", path), f"{path}.terminal_events") == 1,
           f"{path} must publish one terminal event")
    expect(first == event_evidence["run_id"],
           f"{path} run_id does not match canonical signed event evidence")
    return {"request_id": request_id, "run_id": first, "attempts": attempts}


def validate_canary(
    section: dict[str, Any], candidate: str, base: str, staging: dict[str, Any]
) -> dict[str, Any]:
    path = "production_canary"
    exact_fields(section, {"candidate_sha", "accepted_executed", "unaccepted_refused", "event_evidence", "retry"},
                 set(), path)
    expect(sha40(field(section, "candidate_sha", path), f"{path}.candidate_sha") == candidate,
           "production canary candidate mismatch")
    expect(boolean(field(section, "accepted_executed", path), f"{path}.accepted_executed"),
           "accepted code path did not execute")
    expect(boolean(field(section, "unaccepted_refused", path), f"{path}.unaccepted_refused"),
           "unaccepted code path was not refused")
    event_evidence = validate_ci_event_evidence(
        obj(field(section, "event_evidence", path), f"{path}.event_evidence"), candidate, base,
        f"{path}.event_evidence", "success",
    )
    parity_fields = ("target_repo_a", "workflow_id", "workflow_digest", "job_ids", "relay_signer")
    for name in parity_fields:
        expect(event_evidence[name] == staging[name], f"staging/canary parity mismatch for {name}")
    retry = validate_retry(obj(field(section, "retry", path), f"{path}.retry"),
                           event_evidence, f"{path}.retry")
    return {
        **event_evidence,
        "retry": retry,
    }


def validate_deliberate_red(
    section: dict[str, Any], candidate: str, base: str, canary: dict[str, Any],
    protected_contexts: list[str]
) -> dict[str, Any]:
    path = "deliberate_red"
    exact_fields(section, {
        "system_sha", "red_sha", "accepted_commit", "required_check", "conclusion", "merge_allowed",
        "protected_rule", "terminal_events", "first_run_id", "duplicate_run_id", "parity",
        "event_evidence",
    }, set(), path)
    expect(sha40(field(section, "system_sha", path), f"{path}.system_sha") == candidate,
           "deliberate-red system SHA mismatch")
    red_sha = sha40(field(section, "red_sha", path), f"{path}.red_sha")
    expect(red_sha != candidate, "deliberate-red commit must differ from system candidate")
    expect(boolean(field(section, "accepted_commit", path), f"{path}.accepted_commit"),
           "deliberate-red commit must be accepted before execution")
    required_check = text(field(section, "required_check", path), f"{path}.required_check")
    expect(required_check in protected_contexts,
           "deliberate-red required check is not one of the protected exact-head contexts")
    expect(field(section, "conclusion", path) == "failure", "deliberate-red run must fail")
    expect(field(section, "merge_allowed", path) is False, "deliberate-red commit did not block merge")
    expect(field(section, "protected_rule", path) is True, "deliberate-red check was not protected")
    expect(integer(field(section, "terminal_events", path), f"{path}.terminal_events") == 1,
           "deliberate-red run must publish one terminal event")
    event_evidence = validate_ci_event_evidence(
        obj(field(section, "event_evidence", path), f"{path}.event_evidence"), red_sha, base,
        f"{path}.event_evidence", "failure",
    )
    first = run_uuid(field(section, "first_run_id", path), f"{path}.first_run_id")
    expect(run_uuid(field(section, "duplicate_run_id", path), f"{path}.duplicate_run_id") == first,
           "deliberate-red duplicate request created a second run")
    expect(first == event_evidence["run_id"],
           "deliberate-red run_id does not match canonical signed event evidence")
    expect(event_evidence["terminal_events"] == 1,
           "deliberate-red signed history does not contain one final terminal event")
    parity = obj(field(section, "parity", path), f"{path}.parity")
    exact_fields(parity, {"target_repo_a", "workflow_id", "workflow_digest", "job_ids", "relay_signer"},
                 set(), f"{path}.parity")
    expected = {
        "target_repo_a": canary["target_repo_a"],
        "workflow_id": canary["workflow_id"],
        "workflow_digest": canary["workflow_digest"],
        "job_ids": canary["job_ids"],
        "relay_signer": canary["relay_signer"],
    }
    expect(parity == expected, "deliberate-red parity does not match the accepted canary contract")
    for name, expected_value in expected.items():
        expect(event_evidence[name] == expected_value,
               f"deliberate-red signed event parity mismatch for {name}")
    return {"red_sha": red_sha, "run_id": first, "merge_blocked": True}


def validate_deploy_rollback(
    deployment: dict[str, Any], rollback: dict[str, Any], candidate: str, artifacts: dict[str, Any]
) -> dict[str, Any]:
    path = "deployment"
    expect(sha40(field(deployment, "commit_sha", path), f"{path}.commit_sha") == candidate,
           "deployment commit mismatch")
    expect(field(deployment, "image_ref", path) == artifacts["image_ref"], "deployment image_ref mismatch")
    expect(image_id(field(deployment, "running_image_id", path), f"{path}.running_image_id") == artifacts["running_image_id"],
           "deployment running image mismatch")
    expect(sha256(field(deployment, "binary_sha256", path), f"{path}.binary_sha256") == artifacts["binary_sha256"],
           "deployment binary mismatch")
    expect(sha40(field(deployment, "oci_revision", path), f"{path}.oci_revision") == candidate,
           "deployment OCI revision mismatch")
    expect(integer(field(deployment, "database_migration", path), f"{path}.database_migration") == artifacts["migration"],
           "deployment migration mismatch")
    expect(boolean(field(deployment, "dump_before_swap", path), f"{path}.dump_before_swap"),
           "deployment dump was not recorded before swap")
    dump_digest = sha256(field(deployment, "dump_sha256", path), f"{path}.dump_sha256")
    expect(field(deployment, "readiness", path) is True and field(deployment, "nip11", path) is True,
           "deployment readiness or NIP-11 failed")
    started = integer(field(deployment, "started_at", path), f"{path}.started_at")
    swapped = integer(field(deployment, "swapped_at", path), f"{path}.swapped_at")
    finished = integer(field(deployment, "finished_at", path), f"{path}.finished_at")
    expect(started <= swapped <= finished, "deployment timestamps are out of order")
    log = validate_log_auth(obj(field(deployment, "log", path), f"{path}.log"), f"{path}.log")

    compatible = obj(field(rollback, "compatible", "rollback"), "rollback.compatible")
    current = integer(field(compatible, "current_migration", "rollback.compatible"),
                      "rollback.compatible.current_migration")
    prior_required = integer(field(compatible, "prior_required_migration", "rollback.compatible"),
                             "rollback.compatible.prior_required_migration")
    expect(current <= prior_required, "compatible rollback exceeds prior migration requirement")
    prior_image = image_id(field(compatible, "prior_image_id", "rollback.compatible"),
                           "rollback.compatible.prior_image_id")
    prior_binary = sha256(field(compatible, "prior_binary_sha256", "rollback.compatible"),
                          "rollback.compatible.prior_binary_sha256")
    prior_dump = sha256(field(compatible, "prior_dump_sha256", "rollback.compatible"),
                        "rollback.compatible.prior_dump_sha256")
    expect(prior_dump == dump_digest, "compatible rollback prior dump is not the pre-swap dump")
    expect(field(compatible, "mode", "rollback.compatible") == "restored",
           "compatible rollback must restore")
    expect(field(compatible, "restore_attempted", "rollback.compatible") is True,
           "compatible rollback was not attempted")
    expect(image_id(field(compatible, "restored_image_id", "rollback.compatible"),
                    "rollback.compatible.restored_image_id") == prior_image,
           "compatible rollback restored wrong image")
    expect(sha256(field(compatible, "restored_binary_sha256", "rollback.compatible"),
                  "rollback.compatible.restored_binary_sha256") == prior_binary,
           "compatible rollback restored wrong binary")
    expect(sha256(field(compatible, "restored_dump_sha256", "rollback.compatible"),
                  "rollback.compatible.restored_dump_sha256") == prior_dump,
           "compatible rollback restored wrong dump")
    expect(field(compatible, "readiness", "rollback.compatible") is True and
           field(compatible, "nip11", "rollback.compatible") is True,
           "compatible rollback did not recover health")

    advanced = obj(field(rollback, "advanced", "rollback"), "rollback.advanced")
    advanced_current = integer(field(advanced, "current_migration", "rollback.advanced"),
                               "rollback.advanced.current_migration")
    advanced_prior = integer(field(advanced, "prior_required_migration", "rollback.advanced"),
                             "rollback.advanced.prior_required_migration")
    expect(advanced_current > advanced_prior, "advanced rollback case did not exceed prior migration")
    expect(field(advanced, "mode", "rollback.advanced") == "refused",
           "advanced rollback must be refused")
    expect(field(advanced, "restore_attempted", "rollback.advanced") is False,
           "advanced rollback attempted an unsafe restore")
    expect(field(advanced, "reason", "rollback.advanced") == "migration_advanced",
           "advanced rollback refusal reason mismatch")
    return {"dump_sha256": dump_digest, "log": log, "compatible_restored": True,
            "advanced_refused": True}


def validate_landing(section: dict[str, Any], candidate: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in ("relay_sha", "mirror_sha", "merge_sha"):
        value = sha40(field(section, name, "landing"), f"landing.{name}")
        expect(value == candidate, f"landing {name} does not match candidate")
        result[name] = value
    return result


def validate_bundle(bundle: dict[str, Any], candidate_dir: Path, now: int, max_age: int) -> dict[str, Any]:
    exact_fields(bundle, {
        "schema_version", "repository", "candidate_sha", "base_sha", "tree_sha", "source",
        "evidence_files", "protected_ci", "tier2", "artifacts", "staging", "production_canary",
        "deliberate_red", "deployment", "rollback", "landing",
    }, set(), "evidence")
    expect(field(bundle, "schema_version", "evidence") == 1, "evidence schema_version must be 1")
    expect(field(bundle, "repository", "evidence") == REPOSITORY, "evidence repository mismatch")
    candidate, base, tree = validate_source(bundle, candidate_dir)

    evidence_files = obj(field(bundle, "evidence_files", "evidence"), "evidence.evidence_files")
    exact_fields(
        evidence_files,
        {"pre_freeze", "protected_ci", "acceptance_verdict", "acceptance_records"},
        {"collection_manifest"},
        "evidence.evidence_files",
    )
    pre_digest, _ = validate_named_receipt(
        obj(field(evidence_files, "pre_freeze", "evidence.evidence_files"), "evidence_files.pre_freeze"),
        "evidence_files.pre_freeze", "pre-freeze", candidate, base, now, max_age,
    )
    ci_digest, _ = validate_named_receipt(
        obj(field(evidence_files, "protected_ci", "evidence.evidence_files"), "evidence_files.protected_ci"),
        "evidence_files.protected_ci", "protected-ci", candidate, base, now, max_age,
    )
    acceptance_digest, _ = validate_acceptance_verdict(
        obj(field(evidence_files, "acceptance_verdict", "evidence.evidence_files"),
            "evidence_files.acceptance_verdict"), candidate,
    )
    acceptance_records_digest = validate_acceptance_records(
        obj(field(evidence_files, "acceptance_records", "evidence.evidence_files"),
            "evidence_files.acceptance_records"), candidate,
    )
    collection_manifest_digest = None
    if "collection_manifest" in evidence_files:
        descriptor = obj(
            evidence_files["collection_manifest"], "evidence_files.collection_manifest"
        )
        exact_fields(
            descriptor,
            {"path", "sha256"},
            set(),
            "evidence_files.collection_manifest",
        )
        manifest_path = Path(text(
            descriptor["path"], "evidence_files.collection_manifest.path"
        ))
        secure_regular_file(manifest_path, "evidence_files.collection_manifest")
        collection_manifest_digest = file_sha256(manifest_path)
        expect(
            collection_manifest_digest
            == sha256(descriptor["sha256"], "evidence_files.collection_manifest.sha256"),
            "collection manifest digest does not match retained sidecar",
        )
    contexts = validate_protected_ci(obj(field(bundle, "protected_ci", "evidence"), "protected_ci"), candidate)
    tier2 = validate_tier2(obj(field(bundle, "tier2", "evidence"), "tier2"), candidate, now)
    artifacts = validate_artifacts(obj(field(bundle, "artifacts", "evidence"), "artifacts"), candidate)
    staging = validate_staging(obj(field(bundle, "staging", "evidence"), "staging"), candidate, base)
    canary = validate_canary(obj(field(bundle, "production_canary", "evidence"), "production_canary"),
                             candidate, base, staging)
    deliberate_red = validate_deliberate_red(
        obj(field(bundle, "deliberate_red", "evidence"), "deliberate_red"),
        candidate, base, canary, contexts,
    )
    deploy_rollback = validate_deploy_rollback(
        obj(field(bundle, "deployment", "evidence"), "deployment"),
        obj(field(bundle, "rollback", "evidence"), "rollback"), candidate, artifacts,
    )
    landing = validate_landing(obj(field(bundle, "landing", "evidence"), "landing"), candidate)

    return {
        "schema_version": 1,
        "kind": "buzz-promotion-readiness-receipt",
        "repository": REPOSITORY,
        "candidate_sha": candidate,
        "base_sha": base,
        "tree_sha": tree,
        "generated_at": now,
        "overall": "PASS",
        "identities": {
            "image_ref": artifacts["image_ref"],
            "image_ids": artifacts["image_ids"],
            "running_image_id": artifacts["running_image_id"],
            "binary_sha256": artifacts["binary_sha256"],
            "migration": artifacts["migration"],
            "ci_contexts": contexts,
            "tier2": tier2,
            "relay_sha": landing["relay_sha"],
            "mirror_sha": landing["mirror_sha"],
            "merge_sha": landing["merge_sha"],
            "staging_signer": staging["relay_signer"],
            "canary_run_id": canary["run_id"],
            "deliberate_red_sha": deliberate_red["red_sha"],
        },
        "gates": {
            "source": "PASS",
            "pre_freeze": "PASS",
            "protected_ci": "PASS",
            "tier2": "PASS",
            "threat_model": {"passed": 17, "total": 17},
            "probes": {"passed_runs": 12, "total_runs": 12},
            "staging": "PASS",
            "production_canary": "PASS",
            "staging_canary_parity": "PASS",
            "accepted_and_unaccepted_paths": "PASS",
            "idempotent_retries": "PASS",
            "deliberate_red_merge_block": "PASS",
            "deploy_and_rollback": "PASS",
            "log_authentication": "PASS",
        },
        "evidence": {
            "pre_freeze_sha256": pre_digest,
            "protected_ci_sha256": ci_digest,
            "acceptance_verdict_sha256": acceptance_digest,
            "acceptance_records_sha256": acceptance_records_digest,
            **(
                {"collection_manifest_sha256": collection_manifest_digest}
                if collection_manifest_digest is not None else {}
            ),
            "dump_sha256": deploy_rollback["dump_sha256"],
        },
    }


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n").encode()


def write_receipt(path: Path, payload: bytes, candidate_dir: Path) -> None:
    expect(path.is_absolute(), "receipt path must be absolute")
    candidate_root = candidate_dir.resolve()
    output = path.resolve(strict=False)
    expect(not output.is_relative_to(candidate_root), "receipt must be written outside the candidate checkout")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".promotion-receipt.", delete=False) as temporary:
        temporary.write(payload)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, path)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--candidate-dir", required=True, type=Path)
    result.add_argument("--evidence", required=True, type=Path)
    result.add_argument("--receipt", required=True, type=Path)
    result.add_argument("--now", required=True, type=int, help="UTC epoch used for deterministic freshness checks")
    result.add_argument("--max-evidence-age", type=int, default=86400)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        expect(arguments.now >= 0, "--now must be non-negative")
        expect(arguments.max_evidence_age > 0, "--max-evidence-age must be positive")
        evidence_path = arguments.evidence.resolve()
        bundle = load_json(evidence_path, "promotion evidence")
        receipt = validate_bundle(bundle, arguments.candidate_dir.resolve(),
                                  arguments.now, arguments.max_evidence_age)
        receipt["evidence"]["bundle_sha256"] = file_sha256(evidence_path)
        payload = canonical_bytes(receipt)
        write_receipt(arguments.receipt, payload, arguments.candidate_dir.resolve())
        sys.stdout.buffer.write(payload)
        return 0
    except GateError as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
