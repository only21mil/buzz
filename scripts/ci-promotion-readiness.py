#!/usr/bin/env python3
"""Fail-closed verifier for Buzz promotion, canary, deploy, and rollback evidence."""

from __future__ import annotations

import argparse
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


SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
RECORD_KINDS = [46101, 46102, 46103, 46104, 46105, 46106]
TM_IDS = [f"TM-{number:02d}" for number in range(1, 18)]
PROBE_IDS = ["P-i", "P-ii", "P-iii", "P-iv", "P-v", "P-vi"]
REPOSITORY = "only21mil/buzz"


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


def validate_staging(section: dict[str, Any], candidate: str) -> dict[str, Any]:
    path = "staging"
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
    expect(sha40(field(section, "immutable_request_sha", path), f"{path}.immutable_request_sha") == candidate,
           "immutable request retrieval did not bind candidate")
    records = array(field(section, "records", path), f"{path}.records")
    expect(records == RECORD_KINDS, "staging must record kinds 46101 through 46106 exactly once")
    signer = sha256(field(section, "signer", path), f"{path}.signer")
    expect(field(section, "conclusion", path) == "success", "staging conclusion must be success")
    log = validate_log_auth(obj(field(section, "log", path), f"{path}.log"), f"{path}.log")
    return {
        "signer": signer,
        "job_set_sha256": sha256(field(section, "job_set_sha256", path), f"{path}.job_set_sha256"),
        "evidence_sha256": sha256(field(section, "evidence_sha256", path), f"{path}.evidence_sha256"),
        "teardown_sha256": sha256(field(section, "teardown_sha256", path), f"{path}.teardown_sha256"),
        "log": log,
    }


def validate_retry(section: dict[str, Any], path: str) -> dict[str, Any]:
    request_id = text(field(section, "request_id", path), f"{path}.request_id")
    first = text(field(section, "first_run_id", path), f"{path}.first_run_id")
    duplicate = text(field(section, "duplicate_run_id", path), f"{path}.duplicate_run_id")
    expect(first == duplicate, f"{path} duplicate request created a second run")
    attempts = array(field(section, "attempts", path), f"{path}.attempts")
    expect(attempts == [1, 2], f"{path} must prove bounded attempts 1 and 2")
    workspaces = array(field(section, "workspaces", path), f"{path}.workspaces")
    expect(len(workspaces) == 2 and len(set(workspaces)) == 2,
           f"{path} retry attempts must use distinct workspaces")
    expect(integer(field(section, "terminal_events", path), f"{path}.terminal_events") == 1,
           f"{path} must publish one terminal event")
    return {"request_id": request_id, "run_id": first, "attempts": attempts}


def validate_canary(section: dict[str, Any], candidate: str, staging: dict[str, Any]) -> dict[str, Any]:
    path = "production_canary"
    expect(sha40(field(section, "candidate_sha", path), f"{path}.candidate_sha") == candidate,
           "production canary candidate mismatch")
    expect(integer(field(section, "initial_concurrency", path), f"{path}.initial_concurrency") == 0,
           "production canary must start at concurrency zero")
    expect(integer(field(section, "enabled_concurrency", path), f"{path}.enabled_concurrency") == 1,
           "production canary must enable exactly one slot")
    expect(boolean(field(section, "accepted_executed", path), f"{path}.accepted_executed"),
           "accepted code path did not execute")
    expect(boolean(field(section, "unaccepted_refused", path), f"{path}.unaccepted_refused"),
           "unaccepted code path was not refused")
    expect(boolean(field(section, "signed", path), f"{path}.signed"), "canary records were not signed")
    expect(boolean(field(section, "allowed_kinds_only", path), f"{path}.allowed_kinds_only"),
           "canary accepted a record kind outside signed policy")
    expect(array(field(section, "records", path), f"{path}.records") == RECORD_KINDS,
           "canary must record kinds 46101 through 46106 exactly once")
    signer = sha256(field(section, "signer", path), f"{path}.signer")
    expect(signer == staging["signer"], "staging and canary signer identities differ")
    expect(field(section, "conclusion", path) == "success", "production canary must conclude success")
    retry = validate_retry(obj(field(section, "retry", path), f"{path}.retry"), f"{path}.retry")
    return {
        "run_id": text(field(section, "run_id", path), f"{path}.run_id"),
        "signer": signer,
        "log_sha256": sha256(field(section, "log_sha256", path), f"{path}.log_sha256"),
        "evidence_sha256": sha256(field(section, "evidence_sha256", path), f"{path}.evidence_sha256"),
        "teardown_sha256": sha256(field(section, "teardown_sha256", path), f"{path}.teardown_sha256"),
        "retry": retry,
    }


def validate_deliberate_red(section: dict[str, Any], candidate: str) -> dict[str, Any]:
    path = "deliberate_red"
    expect(sha40(field(section, "system_sha", path), f"{path}.system_sha") == candidate,
           "deliberate-red system SHA mismatch")
    red_sha = sha40(field(section, "red_sha", path), f"{path}.red_sha")
    expect(red_sha != candidate, "deliberate-red commit must differ from system candidate")
    expect(boolean(field(section, "accepted_commit", path), f"{path}.accepted_commit"),
           "deliberate-red commit must be accepted before execution")
    expect(text(field(section, "required_check", path), f"{path}.required_check"),
           "deliberate-red required check is missing")
    expect(field(section, "conclusion", path) == "failure", "deliberate-red run must fail")
    expect(field(section, "merge_allowed", path) is False, "deliberate-red commit did not block merge")
    expect(field(section, "protected_rule", path) is True, "deliberate-red check was not protected")
    expect(integer(field(section, "terminal_events", path), f"{path}.terminal_events") == 1,
           "deliberate-red run must publish one terminal event")
    first = text(field(section, "first_run_id", path), f"{path}.first_run_id")
    expect(text(field(section, "duplicate_run_id", path), f"{path}.duplicate_run_id") == first,
           "deliberate-red duplicate request created a second run")
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
    expect(field(bundle, "schema_version", "evidence") == 1, "evidence schema_version must be 1")
    expect(field(bundle, "repository", "evidence") == REPOSITORY, "evidence repository mismatch")
    candidate, base, tree = validate_source(bundle, candidate_dir)

    evidence_files = obj(field(bundle, "evidence_files", "evidence"), "evidence.evidence_files")
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
    contexts = validate_protected_ci(obj(field(bundle, "protected_ci", "evidence"), "protected_ci"), candidate)
    tier2 = validate_tier2(obj(field(bundle, "tier2", "evidence"), "tier2"), candidate, now)
    artifacts = validate_artifacts(obj(field(bundle, "artifacts", "evidence"), "artifacts"), candidate)
    staging = validate_staging(obj(field(bundle, "staging", "evidence"), "staging"), candidate)
    canary = validate_canary(obj(field(bundle, "production_canary", "evidence"), "production_canary"),
                             candidate, staging)
    deliberate_red = validate_deliberate_red(obj(field(bundle, "deliberate_red", "evidence"),
                                                  "deliberate_red"), candidate)
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
            "staging_signer": staging["signer"],
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
