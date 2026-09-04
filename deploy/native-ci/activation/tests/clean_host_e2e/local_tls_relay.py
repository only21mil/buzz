#!/usr/bin/env python3
"""Loopback TLS relay that enforces the production relay's CI admission rules.

The rules mirror ``crates/buzz-relay`` for the routes the native-CI daemons use:
``POST /events`` (api/bridge.rs ``submit_event`` and handlers/ingest.rs),
``POST /query`` (api/bridge.rs ``query_events``: the exact-event read-back
controld issues before it re-signs a refused publication),
``GET /ci/control/accepted`` (api/ci.rs ``next_accepted_control``), and
``PUT|GET /ci/logs|artifacts/...`` (api/ci.rs evidence write/read). Every request
carries a NIP-98 token; the token pubkey is the only identity the relay knows.

Two opt-in fault modes are armed by a flag file the guest writes before the
relay starts. ``stale-terminal-publication-recovery`` answers the first publish
of the terminal kind-46101 run status with the production drift refusal and
stores nothing, so controld must read the event back through ``POST /query``
before it re-signs and publishes again. The relay records the refused id and
whether that read-back happened next to the flag, so the guest can prove the
fault fired and the recovery path ran (M11 failed exactly there: no query).
``stale-terminal-replay-before-grant`` expires every active kind-46107 grant the
moment the first terminal kind-46101 run status arrives, so that publish and
every later status from the ci-event key is refused with the production
``invalid CI envelope: unauthorized CI status signer`` until a new grant is
accepted. The guest runs the prior activation's canary under it (its terminal
publish is refused after its grant expired, the run stays pending, as the
2026-09-03 run did in production) and then the candidate activation, whose
controld replays that pending terminal at startup, before its own grant is
approved (the M12 failure). The relay records the expiry, every unauthorized
refusal, every read-back of a refused id, and the first terminal status it
accepts after the expiry (the replay under the new grant).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import ssl
import stat
import struct
import threading
import time
from urllib.parse import parse_qs, urlsplit

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
REPO_COORDINATE = re.compile(r"^30617:[0-9a-f]{64}:[^:]+$")
LOG_PATH = re.compile(r"^/ci/logs/([^/]+)/([^/]+)/([^/]+)/([^/]+)/([^/]+)$")
ARTIFACT_PATH = re.compile(r"^/ci/artifacts/([^/]+)/([^/]+)/([^/]+)/([^/]+)/([^/]+)/([^/]+)$")
JOB_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
ARTIFACT_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
MAX_BODY = 64 * 1024
MAX_OWNER_RECORD_BYTES = 4 * 1024
MAX_AUTH = 16 * 1024
# handlers/ingest.rs MAX_TIMESTAMP_DRIFT_SECS and MAX_EVENT_CONTENT_BYTES.
MAX_EVENT_DRIFT = 900
MAX_CONTENT_BYTES = 256 * 1024
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
# buzz-auth nip98.rs TIMESTAMP_TOLERANCE_SECS.
MAX_TOKEN_DRIFT = 60
KIND_DELETION = 5
KIND_CI_REQUEST = 46_100
KIND_CI_RUN_STATUS = 46_101
KIND_CI_JOB_STATUS = 46_102
KIND_CI_LOG_REFERENCE = 46_103
KIND_CI_ARTIFACT_REFERENCE = 46_104
KIND_CI_EVIDENCE_FINALIZED = 46_105
KIND_CI_TEARDOWN_ATTESTATION = 46_106
KIND_CI_STATUS_MIN = 46_101
KIND_CI_STATUS_MAX = 46_106
KIND_CI_GRANT = 46_107
# buzz-core ci.rs CiRunState: every other state is terminal.
OPEN_RUN_STATES = frozenset({"queued", "running"})
FAULT_STALE_TERMINAL = "stale-terminal-publication-recovery"
FAULT_REPLAY_BEFORE_GRANT = "stale-terminal-replay-before-grant"
RELAY_FAULTS = frozenset({FAULT_STALE_TERMINAL, FAULT_REPLAY_BEFORE_GRANT})
# buzz-core ci.rs CiValidationError("unauthorized CI status signer") displayed
# through its "invalid CI envelope: {0}" prefix; api/bridge.rs returns it as
# HTTP 400 {"error": ...}. controld matches this exact string.
UNAUTHORIZED_STATUS_SIGNER = "invalid CI envelope: unauthorized CI status signer"
FAULT_RECORD_NAME = "fault-fired.json"
PROTOCOL_RECORD_NAME = "protocol-verdict.json"
TRANSCRIPT_RECORD_NAME = "protocol-transcript.json"
EVIDENCE_READS_RECORD_NAME = "evidence-reads.json"
EVIDENCE_READS_SCHEMA = "buzz-ci-loopback-evidence-reads/v1"
EXPORT_AUTHORIZATION_DIGEST_DOMAIN = b"buzz-ci-acceptance-export-authority:v1\0"
EXPORT_ORIGIN = "https://relay.test.invalid:3443"
EXPORT_LOG = ("job.log", "54e15345b0e920fd0b3c3864422c336f4f66f023b5b2a9cf7874c8a6fe2984ff", 131)
EXPORT_ARTIFACT = ("result", "result.json", "fde27be36048dd6a5bdc9961882391f46102d86dac76c106787dba9ff7551d66", 107)
TRANSCRIPT_SCHEMA = "buzz-ci-loopback-relay-transcript/v2"
VERDICT_SCHEMA = "buzz-ci-loopback-relay-verdict/v2"
TEMPLATE_NAMES = ("run_event", "grant_event", "rerun_event", "tombstone_event", "failure_run_event")
LIVE_TEMPLATE_NAMES = ("run_event", "grant_event", "failure_run_event", "rerun_event", "tombstone_event")
EXPECTED_RECEIPT_STAGES = (
    "capacity_zero_closed", "capacity_one_open", "manifest_identity", "approval_grant",
    "grant_resume", "first_attempt_terminal", "authenticated_export",
    "failed_manifest_identity", "failed_attempt_running", "failed_attempt_terminal",
    "rerun_separation", "cancellation_terminal", "tombstone_folding",
    "controller_restart_recovery", "runner_restart_recovery", "prepare_capacity_zero",
)
MAX_QUERY_FILTERS = 16
# handlers/ingest.rs: kinds that bypass the generic member-or-open gate.
MEMBERSHIP_EXEMPT_KINDS = frozenset({9021, 9007, 40003, 9002, 9005, 9008})
GRANT_ROLES = frozenset({"owner", "admin"})
MEMBER_ROLES = GRANT_ROLES | {"member"}


class RelayError(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RelayError("duplicate JSON field")
        result[key] = value
    return result


class Refusal(Exception):
    """One production-shaped refusal: HTTP status and the relay's message."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def parse_evidence_path(path: str) -> dict[str, object]:
    """Parse the two canonical production evidence routes without normalization."""
    match = LOG_PATH.fullmatch(path)
    evidence_type = "log"
    if match is None:
        match = ARTIFACT_PATH.fullmatch(path)
        evidence_type = "artifact"
    if match is None:
        raise Refusal(404, "not found")
    components = match.groups()
    request_id, run_id, job_id, attempt_raw = components[:4]
    artifact_id = components[4] if evidence_type == "artifact" else None
    sha256 = components[5] if evidence_type == "artifact" else components[4]
    if (
        HEX64.fullmatch(request_id) is None or UUID.fullmatch(run_id) is None
        or JOB_ID.fullmatch(job_id) is None
        or re.fullmatch(r"[1-9][0-9]*", attempt_raw) is None
        or int(attempt_raw) > 0xFFFFFFFF
        or artifact_id is not None and (
            ARTIFACT_ID.fullmatch(artifact_id) is None or artifact_id in {".", ".."}
        )
        or HEX64.fullmatch(sha256) is None
    ):
        raise Refusal(404, f"CI {evidence_type} not found")
    return {
        "type": evidence_type, "request_id": request_id, "run_id": run_id,
        "job_id": job_id, "attempt": int(attempt_raw), "artifact_id": artifact_id,
        "sha256": sha256, "path": path,
    }


def evidence_route_arity(path: str) -> bool:
    """Recognize only router-matched evidence paths, without parsing coordinates."""
    parts = path.split("/")
    return (
        len(parts) == 8 and parts[:3] == ["", "ci", "logs"]
        or len(parts) == 9 and parts[:3] == ["", "ci", "artifacts"]
    )


def valid_header_value(value: object) -> bool:
    """Match http::HeaderValue::from_str for visible ASCII and horizontal tabs."""
    return (
        isinstance(value, str) and bool(value) and value.isascii()
        and all(character == "\t" or 0x20 <= ord(character) <= 0x7E for character in value)
    )


def tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + payload).digest()


def inverse(value: int) -> int:
    return pow(value, P - 2, P)


def point_add(left: tuple[int, int] | None, right: tuple[int, int] | None) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None
    slope = (3 * x1 * x1 * inverse(2 * y1)) % P if left == right else ((y2 - y1) * inverse(x2 - x1)) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def point_mul(scalar: int, point: tuple[int, int] | None = G) -> tuple[int, int] | None:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def lift_x(x: int) -> tuple[int, int] | None:
    if x >= P:
        return None
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if pow(y, 2, P) != (pow(x, 3, P) + 7) % P:
        return None
    return x, y if y % 2 == 0 else P - y


def schnorr_verify(message: bytes, public_hex: str, signature_hex: str) -> bool:
    if len(message) != 32 or HEX64.fullmatch(public_hex) is None or HEX128.fullmatch(signature_hex) is None:
        return False
    public = bytes.fromhex(public_hex)
    signature = bytes.fromhex(signature_hex)
    point = lift_x(int.from_bytes(public, "big"))
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if point is None or r >= P or s >= N:
        return False
    challenge = int.from_bytes(tagged_hash("BIP0340/challenge", signature[:32] + public + message), "big") % N
    negative = (point[0], (-point[1]) % P)
    computed = point_add(point_mul(s), point_mul(challenge, negative))
    return computed is not None and computed[1] % 2 == 0 and computed[0] == r


def event_id(event: dict[str, object]) -> str:
    serialized = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        ensure_ascii=False, separators=(",", ":"),
    ).encode()
    return hashlib.sha256(serialized).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def template_preimage(event: dict[str, object]) -> list[object]:
    return [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]]


def validate_closed_verdict(value: object) -> dict[str, object]:
    """Validate the exact nested v2 verdict exported beyond the guest."""
    top = {
        "schema_version", "state", "reason", "sealed", "template_set_sha256",
        "actor_event_ids", "observed_actor_event_ids", "run_ids", "transcript",
        "receipt", "run_a", "run_b", "sealed_projection_sha256", "foreign_pending_event_id",
    }
    if not isinstance(value, dict) or set(value) != top:
        raise RelayError("closed verdict shape rejected")
    actor = value.get("actor_event_ids")
    api = actor.get("api_order") if isinstance(actor, dict) else None
    live = actor.get("live_order") if isinstance(actor, dict) else None
    run_ids = value.get("run_ids")
    transcript = value.get("transcript")
    receipt = value.get("receipt")
    run_a = value.get("run_a")
    run_b = value.get("run_b")
    receipt_fields = {
        "sha256", "run_id", "checks", "zero_phases", "manifest_digest", "export_subject",
        "export_authorization_digest", "export_request_digest", "export_attempt_id",
        "export_evidence_set_digest", "export_objects_sha256", "export_generation",
    }
    run_a_fields = {
        "request_event_id", "selected_job_attempts", "log_event_ids", "artifact_event_ids",
        "evidence_finalized_event_id", "teardown_attestation_event_id", "terminal_event_id",
    }
    run_b_fields = {
        "initial_request_event_id", "final_request_event_id", "failure_log_event_id",
        "failure_job_event_id", "failure_run_event_id", "rerun_request_event_id",
        "cancel_job_event_id", "cancel_run_event_id", "tombstone_event_id", "final_fact_count",
    }
    hex_fields = [value.get("template_set_sha256"), value.get("sealed_projection_sha256")]
    if isinstance(receipt, dict):
        hex_fields += [receipt.get(name) for name in (
            "sha256", "manifest_digest", "export_subject", "export_authorization_digest",
            "export_request_digest", "export_evidence_set_digest",
            "export_objects_sha256",
        )]
    lists_ready = (
        isinstance(run_a, dict) and isinstance(run_b, dict)
        and isinstance(run_a.get("log_event_ids"), list)
        and isinstance(run_a.get("artifact_event_ids"), list)
    )
    bound_event_ids = [] if not lists_ready else [
        *run_a["log_event_ids"], *run_a["artifact_event_ids"],
        run_a.get("evidence_finalized_event_id"), run_a.get("teardown_attestation_event_id"),
        run_a.get("terminal_event_id"), run_b.get("failure_log_event_id"),
        run_b.get("failure_job_event_id"), run_b.get("failure_run_event_id"),
        run_b.get("cancel_job_event_id"), run_b.get("cancel_run_event_id"),
    ]
    if (
        value.get("schema_version") != VERDICT_SCHEMA or value.get("state") != "green"
        or value.get("reason") is not None or value.get("sealed") is not True
        or not isinstance(actor, dict) or set(actor) != {"api_order", "live_order"}
        or not isinstance(api, list) or len(api) != 5
        or any(not isinstance(item, str) or HEX64.fullmatch(item) is None for item in api)
        or len(set(api)) != 5
        or live != [api[index] for index in (0, 1, 4, 2, 3)]
        or value.get("observed_actor_event_ids") != live
        or not isinstance(run_ids, dict) or set(run_ids) != {"run_a", "run_b"}
        or any(not isinstance(item, str) or UUID.fullmatch(item) is None for item in run_ids.values())
        or run_ids["run_a"] == run_ids["run_b"]
        or not isinstance(transcript, dict) or set(transcript) != {"sha256", "event_count", "last_cursor"}
        or not isinstance(transcript.get("event_count"), int) or isinstance(transcript["event_count"], bool)
        or transcript["event_count"] < 1 or transcript.get("last_cursor") != transcript["event_count"]
        or not isinstance(run_a, dict)
        or not isinstance(run_a.get("artifact_event_ids"), list)
        or transcript["event_count"] != 27 + len(run_a["artifact_event_ids"])
        or not isinstance(receipt, dict) or set(receipt) != receipt_fields
        or receipt.get("checks") != 16 or receipt.get("zero_phases") != [17, 18]
        or not _positive_safe_integer(receipt.get("export_generation"))
        or not isinstance(receipt.get("run_id"), str) or re.fullmatch(r"[0-9a-f]{32}", receipt["run_id"]) is None
        or set(run_a) != run_a_fields
        or not isinstance(run_b, dict) or set(run_b) != run_b_fields
        or run_a.get("request_event_id") != api[0]
        or run_b.get("initial_request_event_id") != api[4]
        or run_b.get("final_request_event_id") != api[2]
        or run_b.get("rerun_request_event_id") != api[2]
        or run_b.get("tombstone_event_id") != api[3]
        or run_b.get("final_fact_count") != 0
        or not isinstance(run_a.get("selected_job_attempts"), list) or len(run_a["selected_job_attempts"]) != 1
        or not isinstance(run_a["selected_job_attempts"][0], dict)
        or set(run_a["selected_job_attempts"][0]) != {"job_id", "attempt"}
        or run_a["selected_job_attempts"][0].get("attempt") != 1
        or not isinstance(run_a["selected_job_attempts"][0].get("job_id"), str)
        or not run_a["selected_job_attempts"][0]["job_id"]
        or not isinstance(run_a.get("log_event_ids"), list) or len(run_a["log_event_ids"]) != 1
        or not isinstance(run_a.get("artifact_event_ids"), list) or len(run_a["artifact_event_ids"]) != 1
        or any(not isinstance(item, str) or HEX64.fullmatch(item) is None for item in (
            bound_event_ids
        ))
        or len(set(bound_event_ids)) != len(bound_event_ids)
        or set(api) & set(bound_event_ids)
        or any(not isinstance(item, str) or HEX64.fullmatch(item) is None for item in hex_fields)
        or not isinstance(receipt.get("export_attempt_id"), str)
        or HEX32.fullmatch(receipt["export_attempt_id"]) is None
        or not isinstance(transcript.get("sha256"), str) or HEX64.fullmatch(transcript["sha256"]) is None
        or value.get("foreign_pending_event_id") is not None and (
            not isinstance(value["foreign_pending_event_id"], str)
            or HEX64.fullmatch(value["foreign_pending_event_id"]) is None
            or value["foreign_pending_event_id"] in set(api) | set(bound_event_ids)
        )
    ):
        raise RelayError("closed verdict binding rejected")
    return value


def export_authorization_digest(
    origin: str, subject: str, generation: int, request_id: str, run_id: str, job_id: str,
) -> str:
    """Recompute the frozen, bearer-free two-object GET authorization transcript."""
    if (
        origin != EXPORT_ORIGIN or HEX64.fullmatch(subject) is None or subject == "0" * 64
        or not _positive_safe_integer(generation) or HEX64.fullmatch(request_id) is None
        or UUID.fullmatch(run_id) is None or JOB_ID.fullmatch(job_id) is None
    ):
        raise ValueError("export authority input rejected")
    log_name, log_sha, log_bytes = EXPORT_LOG
    artifact_id, artifact_name, artifact_sha, artifact_bytes = EXPORT_ARTIFACT
    plan = (
        ("log", log_name, log_sha, log_bytes, f"{origin}/ci/logs/{request_id}/{run_id}/{job_id}/1/{log_sha}"),
        ("artifact", artifact_name, artifact_sha, artifact_bytes,
         f"{origin}/ci/artifacts/{request_id}/{run_id}/{job_id}/1/{artifact_id}/{artifact_sha}"),
    )
    transcript = bytearray(EXPORT_AUTHORIZATION_DIGEST_DOMAIN)
    for kind, name, digest, byte_length, url in plan:
        for field in (
            "GET", url, subject, str(generation), request_id, run_id, job_id, "1",
            kind, name, digest, str(byte_length),
        ):
            encoded = field.encode()
            transcript.extend(struct.pack(">Q", len(encoded)))
            transcript.extend(encoded)
    return hashlib.sha256(transcript).hexdigest()


def validate_acceptance_template(value: object, *, label: str) -> dict[str, object]:
    """Close and derive one frozen five-preimage actor authority."""
    fields = {
        "actor", "time_reference", "export_subject", "export_generation",
        "export_authorization_digest", "failure_selector", *TEMPLATE_NAMES,
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} acceptance template shape rejected")
    actor = value.get("actor")
    if (
        not isinstance(actor, dict) or set(actor) != {"public_key", "generation"}
        or not isinstance(actor.get("public_key"), str) or HEX64.fullmatch(actor["public_key"]) is None
        or not isinstance(actor.get("generation"), int) or isinstance(actor["generation"], bool)
        or actor["generation"] < 1
        or not isinstance(value.get("time_reference"), int) or isinstance(value["time_reference"], bool)
        or value["time_reference"] < 1
    ):
        raise ValueError(f"{label} acceptance actor rejected")
    expected_kinds = (KIND_CI_REQUEST, KIND_CI_GRANT, KIND_CI_REQUEST, KIND_DELETION, KIND_CI_REQUEST)
    preimages: list[list[object]] = []
    envelopes: dict[str, dict[str, object]] = {}
    for name, kind in zip(TEMPLATE_NAMES, expected_kinds, strict=True):
        item = value.get(name)
        if (
            not isinstance(item, list) or len(item) != 6 or item[0] != 0
            or item[1] != actor["public_key"]
            or not isinstance(item[2], int) or isinstance(item[2], bool) or item[2] < 1
            or item[3] != kind or not isinstance(item[4], list) or not isinstance(item[5], str)
            or canonical_json(item) != json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode()
        ):
            raise ValueError(f"{label} acceptance preimage rejected: {name}")
        preimages.append(item)
        if kind in {KIND_CI_REQUEST, KIND_CI_GRANT}:
            try:
                content = json.loads(item[5], object_pairs_hook=reject_duplicates)
            except (json.JSONDecodeError, RelayError) as error:
                raise ValueError(f"{label} acceptance content rejected: {name}") from error
            if not isinstance(content, dict):
                raise ValueError(f"{label} acceptance content rejected: {name}")
            if canonical_json(content).decode() != item[5]:
                raise ValueError(f"{label} acceptance content is not canonical: {name}")
            envelopes[name] = content
    ids = [hashlib.sha256(canonical_json(item)).hexdigest() for item in preimages]
    if len(set(ids)) != 5:
        raise ValueError(f"{label} acceptance event IDs are not unique")
    run, grant, rerun, failure = (
        envelopes["run_event"], envelopes["grant_event"], envelopes["rerun_event"],
        envelopes["failure_run_event"],
    )
    run_id, failure_run_id = run.get("run_id"), failure.get("run_id")
    if (
        run.get("request_type") != "run" or run.get("attempt") != 1
        or failure.get("request_type") != "run" or failure.get("attempt") != 1
        or rerun.get("request_type") != "rerun" or rerun.get("attempt") != 2
        or not isinstance(run_id, str) or UUID.fullmatch(run_id) is None
        or not isinstance(failure_run_id, str) or UUID.fullmatch(failure_run_id) is None
        or run_id == failure_run_id or rerun.get("run_id") != failure_run_id
        or rerun.get("parent_run_id") != failure_run_id or rerun.get("parent_attempt") != 1
        or grant.get("target_repo_a") != run.get("target_repo_a")
        or grant.get("signer_pubkey") is None
        or preimages[3][4] != [["e", ids[2]]] or preimages[3][5] != ""
    ):
        raise ValueError(f"{label} acceptance lineage rejected")
    selector = value["failure_selector"]
    if not isinstance(selector, dict) or list(selector) != [
        "schema_version", "selector", "job_id", "run_id", "attempt", "sha256",
    ]:
        raise ValueError(f"{label} failure selector shape rejected")
    jobs = failure.get("job_ids")
    if (
        selector.get("schema_version") != "buzz-ci-capacity-one-fixture-selector/v1"
        or selector.get("selector") != "deterministic-failure"
        or not isinstance(jobs, list) or len(jobs) != 1
        or selector.get("job_id") != jobs[0] or selector.get("run_id") != failure_run_id
        or selector.get("attempt") != failure.get("attempt") or selector.get("attempt") != 1
    ):
        raise ValueError(f"{label} failure selector binding rejected")
    selector_preimage = (
        "buzz-ci:capacity-one:fixture-selector:v1\n"
        f"{selector['schema_version']}\n{selector['selector']}\n{selector['job_id']}\n"
        f"{str(failure_run_id).replace('-', '')}\n1\n"
    ).encode()
    if selector.get("sha256") != hashlib.sha256(selector_preimage).hexdigest():
        raise ValueError(f"{label} failure selector digest rejected")
    live_ids = [ids[TEMPLATE_NAMES.index(name)] for name in LIVE_TEMPLATE_NAMES]
    export_subject = value.get("export_subject")
    export_generation = value.get("export_generation")
    if (
        not isinstance(export_subject, str) or HEX64.fullmatch(export_subject) is None
        or export_subject == "0" * 64
        or not _positive_safe_integer(export_generation)
        or value.get("export_authorization_digest") != export_authorization_digest(
            EXPORT_ORIGIN, export_subject, export_generation, ids[0], str(run_id),
            str(run.get("job_ids", [""])[0]),
        )
    ):
        raise ValueError(f"{label} export authority rejected")
    return {
        "actor": actor["public_key"], "api_ids": ids, "live_ids": live_ids,
        "id_to_name": dict(zip(ids, TEMPLATE_NAMES, strict=True)),
        "preimages": dict(zip(TEMPLATE_NAMES, preimages, strict=True)),
        "run": run, "failure_run": failure, "rerun": rerun, "grant": grant,
        "run_id": run_id, "failure_run_id": failure_run_id,
        "template_set_sha256": hashlib.sha256(canonical_json({name: value[name] for name in TEMPLATE_NAMES})).hexdigest(),
        "failure_selector": selector,
        "export_subject": export_subject, "export_generation": export_generation,
        "export_authorization_digest": value["export_authorization_digest"],
    }


def verify_event(value: object) -> dict[str, object]:
    fields = {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}
    if not isinstance(value, dict) or set(value) != fields:
        raise RelayError("event shape rejected")
    if (
        not isinstance(value["pubkey"], str) or HEX64.fullmatch(value["pubkey"]) is None
        or not isinstance(value["created_at"], int) or isinstance(value["created_at"], bool) or value["created_at"] < 1
        or not isinstance(value["kind"], int) or isinstance(value["kind"], bool) or not 0 <= value["kind"] <= 65535
        or not isinstance(value["tags"], list) or not isinstance(value["content"], str)
        or not isinstance(value["id"], str) or HEX64.fullmatch(value["id"]) is None
        or not isinstance(value["sig"], str) or HEX128.fullmatch(value["sig"]) is None
    ):
        raise RelayError("event fields rejected")
    for tag in value["tags"]:
        if not isinstance(tag, list) or not tag or any(not isinstance(item, str) for item in tag):
            raise RelayError("event tags rejected")
    computed = event_id(value)
    if value["id"] != computed or not schnorr_verify(bytes.fromhex(computed), value["pubkey"], value["sig"]):
        raise RelayError("event signature rejected")
    return value


def tag_value(tags: list[list[str]], name: str, *, required: bool = True) -> str | None:
    values = [tag[1] for tag in tags if len(tag) == 2 and tag[0] == name]
    if len(values) != (1 if required else 0) and not (not required and len(values) == 1):
        raise RelayError("NIP-98 tag multiplicity rejected")
    return values[0] if values else None


def verify_nip98(header: str, method: str, url: str, body: bytes, now: int | None = None) -> dict[str, object]:
    """Verify one NIP-98 token and return its event; the caller reads `pubkey` and `id`."""
    if not header.startswith("Nostr ") or len(header) > MAX_AUTH:
        raise RelayError("NIP-98 authorization rejected")
    try:
        raw = base64.b64decode(header[6:], validate=True)
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, RelayError) as error:
        raise RelayError("NIP-98 encoding rejected") from error
    event = verify_event(value)
    current = int(time.time()) if now is None else now
    if event["kind"] != 27235 or event["content"] != "" or abs(current - event["created_at"]) > MAX_TOKEN_DRIFT:
        raise RelayError("NIP-98 kind, content, or time rejected")
    tags = event["tags"]
    if tag_value(tags, "u") != url or tag_value(tags, "method") != method:
        raise RelayError("NIP-98 request binding rejected")
    payload_values = [tag[1] for tag in tags if len(tag) == 2 and tag[0] == "payload"]
    if body:
        if payload_values != [hashlib.sha256(body).hexdigest()]:
            raise RelayError("NIP-98 payload binding rejected")
    elif payload_values:
        raise RelayError("NIP-98 empty payload binding rejected")
    return event


def verify_nip98_preauth(
    header: str, method: str, url: str, *, now: int | None = None,
) -> dict[str, object]:
    """Verify a body-bearing token except for its payload digest."""
    if not header.startswith("Nostr ") or len(header) > MAX_AUTH:
        raise RelayError("NIP-98 authorization rejected")
    try:
        raw = base64.b64decode(header[6:], validate=True)
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, RelayError) as error:
        raise RelayError("NIP-98 encoding rejected") from error
    event = verify_event(value)
    current = int(time.time()) if now is None else now
    if event["kind"] != 27235 or event["content"] != "" or abs(current - event["created_at"]) > MAX_TOKEN_DRIFT:
        raise RelayError("NIP-98 kind, content, or time rejected")
    tags = event["tags"]
    if tag_value(tags, "u") != url or tag_value(tags, "method") != method:
        raise RelayError("NIP-98 request binding rejected")
    payload = [tag[1] for tag in tags if len(tag) == 2 and tag[0] == "payload"]
    if len(payload) != 1 or HEX64.fullmatch(payload[0]) is None:
        raise RelayError("NIP-98 payload binding rejected")
    return event


def first_tag(tags: list[list[str]], name: str) -> str | None:
    return next((tag[1] for tag in tags if len(tag) >= 2 and tag[0] == name), None)


def parse_content(event: dict[str, object], what: str) -> dict[str, object]:
    try:
        content = json.loads(str(event["content"]), object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, RelayError) as error:
        raise Refusal(400, f"invalid: {what} content is not valid JSON") from error
    if not isinstance(content, dict):
        raise Refusal(400, f"invalid: {what} content is not an object")
    return content


class RelayState:
    """One community, one channel roster, one static CI signer set.

    ``members`` maps pubkey to role (owner, admin, member), the relay's
    ``channel_members`` row. ``static_signers`` is the relay operator's
    ``BUZZ_CI_STATUS_SIGNER_PUBKEYS``; grants accepted through kind 46107 add
    to it per repository and window.
    """

    def __init__(
        self, object_root: Path, origin: str, channel_id: str, visibility: str,
        members: dict[str, str], static_signers: set[str],
        candidate_acceptance: dict[str, object] | None = None,
        prior_acceptance: dict[str, object] | None = None,
        acceptance_fixture: dict[str, object] | None = None,
        export_generation: int | None = None,
    ) -> None:
        if UUID.fullmatch(channel_id) is None or visibility not in {"open", "private"}:
            raise ValueError("relay channel rejected")
        if any(HEX64.fullmatch(key) is None or role not in MEMBER_ROLES for key, role in members.items()):
            raise ValueError("relay roster rejected")
        if any(HEX64.fullmatch(key) is None for key in static_signers):
            raise ValueError("relay signer set rejected")
        if export_generation is not None and not _positive_safe_integer(export_generation):
            raise ValueError("relay export generation rejected")
        self.object_root = object_root
        self.origin = origin.rstrip("/")
        self.channel_id = channel_id
        self.visibility = visibility
        self.members = dict(members)
        self.static_signers = set(static_signers)
        self.candidate_acceptance = candidate_acceptance
        self.prior_acceptance = prior_acceptance
        self.acceptance_fixture = acceptance_fixture
        self.export_generation = export_generation
        self.events: dict[str, dict[str, object]] = {}
        self.event_channels: dict[str, str | None] = {}
        self.accepted: list[tuple[int, str, dict[str, object]]] = []
        self.grants: list[tuple[str, str, int, int | None]] = []
        self.run_ids: set[tuple[str, str]] = set()
        self.run_requests: dict[tuple[str, str], dict[int, str]] = {}
        self.run_events: dict[str, list[tuple[int, dict[str, object], dict[str, object]]]] = {}
        self.final_facts: dict[str, set[int]] = {}
        self.object_owners: dict[str, set[tuple[object, ...]]] = {}
        self.evidence_reads: list[dict[str, object]] = self._recover_evidence_reads()
        self.query_callers: list[str] = []
        self.ci_cursor = 0
        self.seen_tokens: set[str] = set()
        self.pending_tokens: set[str] = set()
        self.cursor = 0
        self.lock = threading.Lock()
        self.fault: str | None = None
        self.fault_root: Path | None = None
        self.stale_event_id: str | None = None
        self.stale_queried = False
        self.grants_expired_at: int | None = None
        self.refused_event_ids: list[str] = []
        self.queried_event_ids: list[str] = []
        self.replayed_event_id: str | None = None
        self.transcript_cursor = 0
        self.transcript_events: list[dict[str, object]] = []
        self.observed_actor_event_ids: list[str] = []
        self.prior_actor_event_ids: list[str] = []
        self.foreign_pending_event: dict[str, object] | None = None
        self.candidate_sealed = False
        self.sealed_projection_sha256: str | None = None

    def _recover_evidence_reads(self) -> list[dict[str, object]]:
        """Recover the last directory-durable GET record after a relay restart."""
        root = self.object_root.parent
        try:
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            return []
        try:
            try:
                raw = _read_regular_at(directory, EVIDENCE_READS_RECORD_NAME, MAX_BODY)
            except FileNotFoundError:
                return []
        finally:
            os.close(directory)
        try:
            value = json.loads(raw, object_pairs_hook=reject_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError, RelayError) as error:
            raise ValueError("relay evidence read recovery rejected") from error
        fields = {
            "type", "path", "request_event_id", "run_id", "job_id", "attempt",
            "artifact_id", "sha256", "byte_length", "subject",
        }
        reads = value.get("reads") if isinstance(value, dict) else None
        if (
            canonical_json(value) + b"\n" != raw
            or set(value) != {"schema_version", "export_generation", "reads"}
            or value.get("schema_version") != EVIDENCE_READS_SCHEMA
            or value.get("export_generation") != self.export_generation
            or not isinstance(reads, list)
            or any(not isinstance(item, dict) or set(item) != fields for item in reads)
        ):
            raise ValueError("relay evidence read recovery rejected")
        return [dict(item) for item in reads]

    def classify_actor_event(self, event: dict[str, object]) -> tuple[str, str] | None:
        """Map an actor event to one frozen template before any state change."""
        if self.candidate_acceptance is None:
            return None
        identifier = str(event["id"])
        candidate_name = self.candidate_acceptance["id_to_name"].get(identifier)
        prior_name = None if self.prior_acceptance is None else self.prior_acceptance["id_to_name"].get(identifier)
        if candidate_name is not None:
            expected = self.candidate_acceptance["preimages"][candidate_name]
            if template_preimage(event) != expected:
                raise Refusal(400, "invalid: acceptance event differs from frozen preimage")
            if identifier not in self.events:
                position = len(self.observed_actor_event_ids)
                expected_live = self.candidate_acceptance["live_ids"]
                if position >= len(expected_live) or identifier != expected_live[position]:
                    raise Refusal(409, "conflict: acceptance actor event order differs")
            return "candidate", str(candidate_name)
        if prior_name is not None:
            if self.fault != FAULT_REPLAY_BEFORE_GRANT:
                raise Refusal(409, "conflict: prior acceptance event is not active")
            expected = self.prior_acceptance["preimages"][prior_name]
            if template_preimage(event) != expected:
                raise Refusal(400, "invalid: prior acceptance event differs from frozen preimage")
            if identifier not in self.events:
                expected_prior = self.prior_acceptance["live_ids"][:2]
                position = len(self.prior_actor_event_ids)
                if position >= len(expected_prior) or identifier != expected_prior[position]:
                    raise Refusal(409, "conflict: prior acceptance actor event order differs")
            return "prior", str(prior_name)
        if event["pubkey"] == self.candidate_acceptance["actor"] and int(event["kind"]) in {
            KIND_DELETION, KIND_CI_REQUEST, KIND_CI_GRANT,
        }:
            raise Refusal(409, "conflict: unknown acceptance actor event")
        return None

    def note_actor_event(self, classification: tuple[str, str] | None, event: dict[str, object]) -> None:
        if classification is None:
            return
        partition, _name = classification
        if partition == "candidate":
            self.observed_actor_event_ids.append(str(event["id"]))
            if self.observed_actor_event_ids == self.candidate_acceptance["live_ids"]:
                self.candidate_sealed = True
        else:
            self.prior_actor_event_ids.append(str(event["id"]))

    def is_candidate_event(self, event: dict[str, object]) -> bool:
        if self.candidate_acceptance is None:
            return False
        if str(event["id"]) in self.candidate_acceptance["api_ids"]:
            return True
        if KIND_CI_STATUS_MIN <= int(event["kind"]) <= KIND_CI_STATUS_MAX:
            try:
                return parse_content(event, "CI event").get("run_id") in {
                    self.candidate_acceptance["run_id"], self.candidate_acceptance["failure_run_id"],
                }
            except Refusal:
                return False
        return False

    def write_protocol_transcript(self) -> None:
        if self.candidate_acceptance is None:
            return
        root = self.object_root.parent
        record = {
            "schema_version": TRANSCRIPT_SCHEMA,
            "template_set_sha256": self.candidate_acceptance["template_set_sha256"],
            "actor_event_ids": {
                "api_order": self.candidate_acceptance["api_ids"],
                "live_order": self.candidate_acceptance["live_ids"],
            },
            "observed_actor_event_ids": self.observed_actor_event_ids,
            "events": self.transcript_events,
            "sealed": self.candidate_sealed,
            "sealed_projection_sha256": self.sealed_projection_sha256,
            "foreign_pending_event_ids": self.prior_actor_event_ids,
            "foreign_pending_event": self.foreign_pending_event,
        }
        pending = root / (TRANSCRIPT_RECORD_NAME + ".next")
        pending.write_bytes(canonical_json(record) + b"\n")
        pending.chmod(0o400)
        pending.replace(root / TRANSCRIPT_RECORD_NAME)

    def record_evidence_read(
        self, caller: str, path: dict[str, object], byte_length: int,
    ) -> None:
        """Durably record the authenticated objects used by Stage 7 closure."""
        record = {
            "type": path["type"], "path": path["path"],
            "request_event_id": path["request_id"], "run_id": path["run_id"],
            "job_id": path["job_id"], "attempt": path["attempt"],
            "artifact_id": path["artifact_id"], "sha256": path["sha256"],
            "byte_length": byte_length, "subject": caller,
        }
        next_reads = [*self.evidence_reads, record]
        body = canonical_json({
            "schema_version": EVIDENCE_READS_SCHEMA,
            "export_generation": self.export_generation,
            "reads": next_reads,
        }) + b"\n"
        root = self.object_root.parent
        pending = root / (
            f".{EVIDENCE_READS_RECORD_NAME}.{os.getpid()}.{threading.get_ident()}."
            f"{os.urandom(8).hex()}.next"
        )
        try:
            with pending.open("xb") as handle:
                os.fchmod(handle.fileno(), 0o400)
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            pending.replace(root / EVIDENCE_READS_RECORD_NAME)
        finally:
            try:
                pending.unlink()
            except FileNotFoundError:
                pass
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.evidence_reads = next_reads

    def record_transcript_event(self, event: dict[str, object]) -> None:
        if not self.is_candidate_event(event):
            return
        self.transcript_cursor += 1
        self.transcript_events.append({
            "cursor": self.transcript_cursor,
            "event": event,
        })
        if self.candidate_sealed and self.sealed_projection_sha256 is None:
            self.sealed_projection_sha256 = hashlib.sha256(canonical_json(self.transcript_events)).hexdigest()
        self.write_protocol_transcript()

    def record_ci_event(self, event: dict[str, object]) -> None:
        """Retain relay acceptance order and the validated envelope for verdict parity."""
        kind = int(event["kind"])
        if not KIND_CI_REQUEST <= kind <= KIND_CI_TEARDOWN_ATTESTATION:
            return
        content = parse_content(event, "CI event")
        run_id = content.get("run_id")
        if not isinstance(run_id, str):
            return
        self.ci_cursor += 1
        self.run_events.setdefault(run_id, []).append((self.ci_cursor, event, content))
        if kind in {KIND_CI_EVIDENCE_FINALIZED, KIND_CI_TEARDOWN_ATTESTATION}:
            self.final_facts.setdefault(run_id, set()).add(kind)

    def rerun_allowed(self, channel: str, content: dict[str, object]) -> bool:
        """A rerun extends one failed job on an unsealed run, exactly once."""
        run_id = content.get("run_id")
        attempt = content.get("attempt")
        parent_attempt = content.get("parent_attempt")
        jobs = content.get("job_ids")
        if (
            not isinstance(run_id, str) or not isinstance(attempt, int) or isinstance(attempt, bool)
            or not isinstance(parent_attempt, int) or isinstance(parent_attempt, bool)
            or attempt != parent_attempt + 1
            or not isinstance(jobs, list) or len(jobs) != 1 or not isinstance(jobs[0], str)
        ):
            return False
        requests = self.run_requests.get((channel, run_id), {})
        if parent_attempt not in requests or attempt in requests or self.final_facts.get(run_id):
            return False
        terminals = [
            envelope for _cursor, event, envelope in self.run_events.get(run_id, [])
            if event["kind"] == KIND_CI_JOB_STATUS
            and envelope.get("job_id") == jobs[0]
            and envelope.get("attempt") == parent_attempt
            and envelope.get("state") == "failure"
        ]
        return len(terminals) == 1

    def closed_verdict(self, run_id: str) -> dict[str, object]:
        """Reduce one successful run using relay order as the ordering authority."""
        events = self.run_events.get(run_id, [])
        successes = [item for item in events if item[1]["kind"] == KIND_CI_RUN_STATUS and item[2].get("state") == "success"]
        evidence = [item for item in events if item[1]["kind"] == KIND_CI_EVIDENCE_FINALIZED]
        teardown = [item for item in events if item[1]["kind"] == KIND_CI_TEARDOWN_ATTESTATION]
        reason: str | None = None
        if len(successes) != 1 or len(evidence) != 1 or len(teardown) != 1:
            reason = "terminal success requires exactly one evidence and teardown fact"
        else:
            terminal_cursor, _terminal_event, terminal = successes[0]
            evidence_cursor, _evidence_event, fact = evidence[0]
            teardown_cursor = teardown[0][0]
            finalized = fact.get("finalized_job_attempts")
            if evidence_cursor >= terminal_cursor or teardown_cursor >= terminal_cursor:
                reason = "terminal run success was accepted before its terminal facts"
            elif not isinstance(finalized, list) or not finalized:
                reason = "evidence-finalized fact does not link the selected durable evidence"
            else:
                selected_jobs = {
                    envelope.get("job_id") for _cursor, event, envelope in events
                    if event["kind"] == KIND_CI_JOB_STATUS
                    and envelope.get("attempt") == fact.get("attempt")
                    and envelope.get("state") == "success" and envelope.get("required", True) is True
                }
                finalized_jobs = {
                    item.get("job_id") for item in finalized if isinstance(item, dict)
                }
                if selected_jobs != finalized_jobs or None in finalized_jobs:
                    reason = "evidence-finalized fact does not link the selected durable evidence"
                for item in finalized:
                    if reason is not None:
                        break
                    if not isinstance(item, dict):
                        reason = "evidence-finalized fact does not link the selected durable evidence"
                        break
                    job_id, attempt, log_ref = item.get("job_id"), item.get("attempt"), item.get("log_ref")
                    artifact_refs = item.get("artifact_refs")
                    statuses = [
                        envelope for _cursor, event, envelope in events
                        if event["kind"] == KIND_CI_JOB_STATUS and envelope.get("job_id") == job_id
                        and envelope.get("attempt") == attempt and envelope.get("state") == "success"
                    ]
                    refs = [
                        (cursor, event, envelope) for cursor, event, envelope in events
                        if str(event["id"]) == log_ref and event["kind"] == KIND_CI_LOG_REFERENCE
                    ]
                    artifacts = {
                        str(event["id"]): (cursor, envelope) for cursor, event, envelope in events
                        if event["kind"] == KIND_CI_ARTIFACT_REFERENCE
                    }
                    finalized_at = fact.get("finalized_at")
                    if (
                        len(statuses) != 1 or len(refs) != 1 or not isinstance(artifact_refs, list)
                        or not isinstance(finalized_at, int) or isinstance(finalized_at, bool)
                        or statuses[0].get("log_ref") != log_ref
                        or set(statuses[0].get("artifact_refs", [])) != set(artifact_refs)
                        or refs[0][0] >= evidence_cursor or refs[0][2].get("created_at", finalized_at + 1) > finalized_at
                        or refs[0][2].get("job_id") != job_id or refs[0][2].get("attempt") != attempt
                        or any(
                            artifact not in artifacts or artifacts[artifact][0] >= evidence_cursor
                            or artifacts[artifact][1].get("created_at", finalized_at + 1) > finalized_at
                            or artifacts[artifact][1].get("job_id") != job_id
                            or artifacts[artifact][1].get("attempt") != attempt
                            for artifact in artifact_refs
                        )
                    ):
                        reason = "evidence-finalized fact does not link the selected durable evidence"
                        break
            if terminal.get("attempt") != fact.get("attempt") or teardown[0][2].get("attempt") != fact.get("attempt"):
                reason = "evidence-finalized fact does not match terminal attempt"
        return {"state": "green" if reason is None else "infrastructure_failure", "reason": reason}

    def arm_fault(self, flag: Path) -> None:
        """Read the guest's flag file; an unknown mode is a configuration error."""
        mode = flag.read_bytes().decode().strip()
        if mode not in RELAY_FAULTS:
            raise ValueError("relay fault mode rejected")
        self.fault = mode
        self.fault_root = flag.parent

    def refuses_as_stale(self, event: dict[str, object]) -> bool:
        """Stale-terminal fault, one shot: the first terminal run status fails
        the production drift check and is not stored. The caller holds ``lock``."""
        if self.fault != FAULT_STALE_TERMINAL or self.stale_event_id is not None or event["kind"] != KIND_CI_RUN_STATUS:
            return False
        try:
            state = parse_content(event, "CI event").get("state")
        except Refusal:
            return False
        if not isinstance(state, str) or state in OPEN_RUN_STATES:
            return False
        self.stale_event_id = str(event["id"])
        self.write_fault_record()
        return True

    def note_query(self, ids: set[str] | None, kinds: list[object]) -> None:
        """Record the exact-event read-back of a refused publication."""
        if ids is None or KIND_CI_RUN_STATUS not in kinds:
            return
        if self.fault == FAULT_STALE_TERMINAL:
            if self.stale_event_id is None or self.stale_queried or self.stale_event_id not in ids:
                return
            self.stale_queried = True
            self.write_fault_record()
        elif self.fault == FAULT_REPLAY_BEFORE_GRANT:
            read_back = [event_id for event_id in self.refused_event_ids if event_id in ids and event_id not in self.queried_event_ids]
            if not read_back:
                return
            self.queried_event_ids.extend(read_back)
            self.write_fault_record()

    def expires_grants_before(self, event: dict[str, object], now: int) -> None:
        """Replay-before-grant fault, one shot: the first terminal run status
        finds every active grant expired at ``now`` (production: the 2026-09-03
        run's terminal arrived after its 600 s grant window). The caller holds
        ``lock``; the ordinary signer check then refuses the event."""
        if self.fault != FAULT_REPLAY_BEFORE_GRANT or self.grants_expired_at is not None or event["kind"] != KIND_CI_RUN_STATUS:
            return
        try:
            state = parse_content(event, "CI event").get("state")
        except Refusal:
            return
        if not isinstance(state, str) or state in OPEN_RUN_STATES:
            return
        self.grants = [
            (repo, signer, valid_from, now if valid_until is None or valid_until > now else valid_until)
            for repo, signer, valid_from, valid_until in self.grants
        ]
        self.grants_expired_at = now
        self.write_fault_record()

    def note_unauthorized(self, event: dict[str, object]) -> None:
        """Record one unauthorized-signer refusal after the grant expiry."""
        if self.fault != FAULT_REPLAY_BEFORE_GRANT or self.grants_expired_at is None:
            return
        self.refused_event_ids.append(str(event["id"]))
        self.write_fault_record()

    def note_terminal_accepted(self, event: dict[str, object]) -> None:
        """Record the first terminal run status accepted after the expiry: the
        replay of the pending terminal under the next activation's grant."""
        if self.fault != FAULT_REPLAY_BEFORE_GRANT or self.grants_expired_at is None or self.replayed_event_id is not None or event["kind"] != KIND_CI_RUN_STATUS:
            return
        state = parse_content(event, "CI event").get("state")
        if not isinstance(state, str) or state in OPEN_RUN_STATES:
            return
        content = parse_content(event, "CI event")
        if self.candidate_acceptance is not None:
            if (
                self.prior_acceptance is None
                or content.get("run_id") != self.prior_acceptance["run_id"]
                or content.get("request_event_id") != self.prior_acceptance["api_ids"][0]
                or content.get("attempt") != 1 or state != "success"
                or event.get("pubkey") != self.prior_acceptance["grant"].get("signer_pubkey")
                or str(event["id"]) not in self.refused_event_ids
            ):
                return
        self.replayed_event_id = str(event["id"])
        if self.prior_acceptance is not None:
            self.foreign_pending_event = event
        self.write_fault_record()
        if self.candidate_acceptance is not None:
            self.write_protocol_transcript()

    def fault_record(self) -> dict[str, object]:
        if self.fault == FAULT_REPLAY_BEFORE_GRANT:
            return {
                "mode": self.fault, "grants_expired_at": self.grants_expired_at,
                "refused_event_ids": list(self.refused_event_ids), "queried_event_ids": list(self.queried_event_ids),
                "replayed_event_id": self.replayed_event_id,
            }
        return {"mode": self.fault, "refused_event_id": self.stale_event_id, "queried": self.stale_queried}

    def write_fault_record(self) -> None:
        assert self.fault_root is not None
        record = json.dumps(self.fault_record(), sort_keys=True, separators=(",", ":")).encode() + b"\n"
        pending = self.fault_root / (FAULT_RECORD_NAME + ".next")
        pending.write_bytes(record)
        pending.chmod(0o400)
        pending.replace(self.fault_root / FAULT_RECORD_NAME)

    def visible_to(self, event: dict[str, object], caller: str) -> bool:
        # api/bridge.rs event_in_accessible_channel: a channel-scoped event is
        # readable only by a member (or by anyone when the channel is open).
        channel = self.event_channels.get(str(event["id"]))
        if channel is None:
            return True
        return channel == self.channel_id and (caller in self.members or self.visibility == "open")

    def active_signers(self, target_repo_a: str, now: int) -> set[str]:
        signers = set(self.static_signers)
        for repo, signer, valid_from, valid_until in self.grants:
            if repo == target_repo_a and valid_from <= now and (valid_until is None or valid_until > now):
                signers.add(signer)
        return signers

    def require_membership(self, channel: str, pubkey: str) -> None:
        # handlers/ingest.rs check_channel_membership: member, or open channel.
        if channel != self.channel_id:
            raise Refusal(400, "restricted: not a channel member")
        if pubkey not in self.members and self.visibility != "open":
            raise Refusal(400, "restricted: not a channel member")

    def require_signer(self, target_repo_a: str, pubkey: str, now: int) -> None:
        # api/ci.rs authorize_ci_signer.
        if pubkey not in self.active_signers(target_repo_a, now):
            raise Refusal(403, "CI signer is not authorized")

    def request_repository(self, request_id: str) -> str:
        event = self.events.get(request_id)
        if event is None or event["kind"] != KIND_CI_REQUEST:
            raise Refusal(404, "CI request not found")
        return str(parse_content(event, "CI request")["target_repo_a"])


def authenticate_once(
    state: RelayState, header: str, method: str, url: str, body: bytes, *, now: int | None = None,
) -> str:
    """Authenticate and consume one NIP-98 token atomically before any lookup."""
    try:
        token = verify_nip98(header, method, url, body, now=now)
    except RelayError as error:
        raise Refusal(401, f"NIP-98: {error}") from error
    with state.lock:
        identifier = str(token["id"])
        if identifier in state.seen_tokens or identifier in state.pending_tokens:
            raise Refusal(401, "NIP-98: replayed authorization")
        state.seen_tokens.add(identifier)
    return str(token["pubkey"])


def evidence_owner(
    channel: str, request: dict[str, object], path: dict[str, object],
) -> tuple[object, ...]:
    return (
        channel, request.get("target_repo_a"), request.get("tip_oid"), path["request_id"],
        path["run_id"], path["job_id"], path["attempt"], path["artifact_id"], path["sha256"],
    )


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _remove_stale_atomic_links(directory: int, name: str, metadata: os.stat_result) -> None:
    """Remove only this publisher's abandoned same-inode temporary links."""
    if metadata.st_nlink <= 1:
        return
    prefix = f".{name}."
    for entry in os.listdir(directory):
        if not entry.startswith(prefix) or not entry.endswith(".next"):
            continue
        try:
            candidate = os.stat(entry, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if (
            stat.S_ISREG(candidate.st_mode)
            and (candidate.st_dev, candidate.st_ino) == (metadata.st_dev, metadata.st_ino)
        ):
            os.unlink(entry, dir_fd=directory)
    os.fsync(directory)


def _read_regular_at(directory: int, name: str, maximum: int, mode: int = 0o400) -> bytes:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=directory,
    )
    try:
        metadata = os.fstat(descriptor)
        _remove_stale_atomic_links(directory, name, metadata)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != mode or metadata.st_size > maximum
        ):
            raise OSError("unsafe evidence object")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise OSError("short evidence object")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError("evidence object grew while reading")
        after = os.fstat(descriptor)
        if (
            after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
            after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ) != (
            metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
        ):
            raise OSError("evidence object changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _atomic_create_at(directory: int, name: str, raw: bytes, mode: int = 0o400) -> bool:
    """Publish one same-directory temporary file with no replacement."""
    temporary = f".{name}.{os.getpid()}.{threading.get_ident()}.{os.urandom(8).hex()}.next"
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode, dir_fd=directory,
    )
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    created = False
    try:
        os.link(
            temporary, name, src_dir_fd=directory, dst_dir_fd=directory,
            follow_symlinks=False,
        )
        created = True
        os.fsync(directory)
    except FileExistsError:
        pass
    finally:
        os.unlink(temporary, dir_fd=directory)
    return created


def _owner_record(channel: str, request: dict[str, object], path: dict[str, object]) -> tuple[str, bytes]:
    values = evidence_owner(channel, request, path)
    record = {
        "schema_version": "buzz-ci-loopback-evidence-owner/v1",
        "channel_id": values[0], "target_repo_a": values[1], "tip_oid": values[2],
        "request_event_id": values[3], "run_id": values[4], "job_id": values[5],
        "attempt": values[6], "artifact_id": values[7], "sha256": values[8],
    }
    raw = canonical_json(record) + b"\n"
    return ".owner-" + hashlib.sha256(raw).hexdigest(), raw


def store_evidence_object(
    state: RelayState, path: dict[str, object], request: dict[str, object], channel: str, raw: bytes,
) -> None:
    digest = hashlib.sha256(raw).hexdigest()
    if digest != path["sha256"]:
        raise Refusal(400, "digest mismatch")
    directory = os.open(
        state.object_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    object_created = False
    try:
        owner_name, owner_raw = _owner_record(channel, request, path)
        try:
            existing_owner = _read_regular_at(directory, owner_name, MAX_OWNER_RECORD_BYTES)
        except FileNotFoundError:
            existing_owner = None
        except OSError as error:
            raise Refusal(409, "object ownership collision") from error
        if existing_owner is not None and existing_owner != owner_raw:
            raise Refusal(409, "object ownership collision")

        object_created = _atomic_create_at(directory, digest, raw)
        if not object_created:
            try:
                existing = _read_regular_at(directory, digest, MAX_EVIDENCE_BYTES)
            except OSError as error:
                raise Refusal(409, "object collision") from error
            if existing != raw:
                raise Refusal(409, "object collision")
        if existing_owner is None and not _atomic_create_at(directory, owner_name, owner_raw):
            try:
                existing_owner = _read_regular_at(directory, owner_name, MAX_OWNER_RECORD_BYTES)
            except OSError as error:
                raise Refusal(409, "object ownership collision") from error
            if existing_owner != owner_raw:
                raise Refusal(409, "object ownership collision")
    except Refusal:
        if object_created:
            try:
                os.unlink(digest, dir_fd=directory)
                os.fsync(directory)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(directory)
    state.object_owners.setdefault(digest, set()).add(evidence_owner(channel, request, path))


def _valid_ci_tags(
    tags: object, channel: str, content: dict[str, object], *, job: bool, request: bool,
    digest: str | None,
) -> bool:
    if not isinstance(tags, list) or any(
        not isinstance(tag, list) or any(not isinstance(part, str) for part in tag) for tag in tags
    ):
        return False
    expected: dict[str, list[str]] = {
        "h": ["h", channel], "a": ["a", str(content.get("target_repo_a"))],
        "run": ["run", str(content.get("run_id"))],
        "workflow": ["workflow", str(content.get("workflow_id"))],
        "c": ["c", str(content.get("tip_oid"))],
        "attempt": ["attempt", str(content.get("attempt"))],
    }
    if job:
        expected["job"] = ["job", str(content.get("job_id"))]
    if not request:
        expected["e"] = ["e", str(content.get("request_event_id")), "", "request"]
    if digest is not None:
        expected["x"] = ["x", digest]
    reserved = {"h", "a", "run", "workflow", "c", "attempt", "job", "e", "x"}
    for name in reserved:
        matching = [tag for tag in tags if tag and tag[0] == name]
        if name in expected:
            if matching != [expected[name]]:
                return False
        elif matching:
            return False
    return True


def _positive_safe_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 9_007_199_254_740_991


def _valid_request_event(event: dict[str, object], content: dict[str, object], channel: str) -> bool:
    job_ids = content.get("job_ids")
    tip = content.get("tip_oid")
    base = content.get("base_oid")
    return (
        content.get("schema_version") == 1 and content.get("actor") == event.get("pubkey")
        and content.get("request_type") in {"run", "rerun"}
        and isinstance(content.get("run_id"), str) and UUID.fullmatch(content["run_id"]) is not None
        and isinstance(content.get("target_repo_a"), str)
        and REPO_COORDINATE.fullmatch(content["target_repo_a"]) is not None
        and isinstance(content.get("workflow_id"), str) and bool(content["workflow_id"])
        and isinstance(tip, str) and len(tip) in {40, 64} and re.fullmatch(r"[0-9a-f]+", tip) is not None
        and isinstance(base, str) and len(base) == len(tip) and re.fullmatch(r"[0-9a-f]+", base) is not None
        and isinstance(job_ids, list) and bool(job_ids)
        and all(isinstance(value, str) and JOB_ID.fullmatch(value) is not None for value in job_ids)
        and len(set(job_ids)) == len(job_ids)
        and _positive_safe_integer(content.get("attempt"))
        and _valid_ci_tags(event.get("tags"), channel, content, job=False, request=True, digest=None)
    )


def _valid_reference_event(
    event: dict[str, object], content: dict[str, object], channel: str,
    origin: str, path: dict[str, object],
) -> bool:
    digest = str(path["sha256"])
    common = (
        content.get("schema_version") == 1
        and content.get("relay_signer") == event.get("pubkey")
        and _positive_safe_integer(content.get("created_at"))
        and _valid_ci_tags(event.get("tags"), channel, content, job=True, request=False, digest=digest)
        and content.get("url") == origin + str(path["path"])
    )
    if not common:
        return False
    if path["type"] == "log":
        return (
            content.get("log_sha256") == digest and content.get("inline") is None
            and content.get("truncated") is False
            and isinstance(content.get("byte_length"), int) and not isinstance(content["byte_length"], bool)
            and isinstance(content.get("cap_bytes"), int) and not isinstance(content["cap_bytes"], bool)
            and 0 <= content["byte_length"] <= content["cap_bytes"] <= MAX_EVIDENCE_BYTES
        )
    return (
        content.get("artifact_id") == path["artifact_id"]
        and isinstance(content.get("name"), str) and bool(content["name"])
        and content.get("sha256") == digest
        and isinstance(content.get("byte_length"), int) and not isinstance(content["byte_length"], bool)
        and 0 <= content["byte_length"] <= MAX_EVIDENCE_BYTES
        and valid_header_value(content.get("media_type"))
    )


def _valid_success_terminal(
    event: dict[str, object], content: dict[str, object], channel: str,
) -> bool:
    started = content.get("started_at")
    finished = content.get("finished_at")
    artifacts = content.get("artifact_refs")
    fanout = content.get("also_reruns")
    return (
        content.get("schema_version") == 1 and content.get("relay_signer") == event.get("pubkey")
        and content.get("state") == "success" and _positive_safe_integer(content.get("sequence"))
        and content.get("parent_attempt") is None
        and _positive_safe_integer(started) and _positive_safe_integer(finished) and finished >= started
        and isinstance(content.get("name"), str) and bool(content["name"])
        and isinstance(content.get("required"), bool) and content.get("skip_policy") in {"allow", "forbid"}
        and isinstance(content.get("selected_job_instance"), str) and bool(content["selected_job_instance"])
        and isinstance(fanout, list)
        and all(isinstance(value, str) and JOB_ID.fullmatch(value) is not None for value in fanout)
        and len(set(fanout)) == len(fanout)
        and content.get("job_id") not in fanout
        and (content.get("log_ref") is None or isinstance(content.get("log_ref"), str)
             and HEX64.fullmatch(content["log_ref"]) is not None)
        and isinstance(artifacts, list)
        and all(isinstance(value, str) and HEX64.fullmatch(value) is not None for value in artifacts)
        and len(set(artifacts)) == len(artifacts)
        and _valid_ci_tags(event.get("tags"), channel, content, job=True, request=False, digest=None)
    )


def _valid_transcript_ci_event(
    event: dict[str, object], content: dict[str, object], request: dict[str, object],
    request_id: str, channel: str, origin: str,
) -> bool:
    """Validate the production CI envelope fields used by verdict closure."""
    kind = int(event["kind"])
    attempt = content.get("attempt")
    common = (
        content.get("schema_version") == 1
        and content.get("relay_signer") == event.get("pubkey")
        and content.get("request_event_id") == request_id
        and content.get("run_id") == request.get("run_id")
        and content.get("workflow_id") == request.get("workflow_id")
        and content.get("target_repo_a") == request.get("target_repo_a")
        and content.get("tip_oid") == request.get("tip_oid")
        and attempt == request.get("attempt") and _positive_safe_integer(attempt)
    )
    if not common:
        return False
    job_kind = kind in {KIND_CI_JOB_STATUS, KIND_CI_LOG_REFERENCE, KIND_CI_ARTIFACT_REFERENCE}
    digest = content.get("log_sha256") if kind == KIND_CI_LOG_REFERENCE else (
        content.get("sha256") if kind == KIND_CI_ARTIFACT_REFERENCE else None
    )
    if not _valid_ci_tags(
        event.get("tags"), channel, content, job=job_kind, request=False,
        digest=str(digest) if digest is not None else None,
    ):
        return False
    if kind == KIND_CI_RUN_STATUS:
        jobs = content.get("job_ids")
        return (
            content.get("base_oid") == request.get("base_oid")
            and _positive_safe_integer(content.get("sequence"))
            and content.get("state") in {"queued", "running", "success", "failure", "cancelled"}
            and jobs == request.get("job_ids") and isinstance(jobs, list)
            and len(set(jobs)) == len(jobs)
            and _valid_status_times(content)
        )
    if kind == KIND_CI_JOB_STATUS:
        artifacts = content.get("artifact_refs")
        fanout = content.get("also_reruns")
        parent = content.get("parent_attempt")
        log_ref = content.get("log_ref")
        return (
            content.get("base_oid") == request.get("base_oid")
            and content.get("job_id") in request.get("job_ids", [])
            and isinstance(content.get("name"), str) and bool(content["name"])
            and _positive_safe_integer(content.get("sequence"))
            and content.get("state") in {"queued", "running", "success", "failure", "cancelled"}
            and isinstance(content.get("required"), bool)
            and content.get("skip_policy") in {"allow", "forbid"}
            and isinstance(content.get("selected_job_instance"), str) and bool(content["selected_job_instance"])
            and isinstance(fanout, list) and all(isinstance(item, str) and JOB_ID.fullmatch(item) for item in fanout)
            and len(set(fanout)) == len(fanout) and content.get("job_id") not in fanout
            and (attempt == 1 and parent is None or isinstance(parent, int) and parent >= 1 and attempt == parent + 1)
            and (log_ref is None or isinstance(log_ref, str) and HEX64.fullmatch(log_ref) is not None)
            and isinstance(artifacts, list)
            and all(isinstance(item, str) and HEX64.fullmatch(item) is not None for item in artifacts)
            and len(set(artifacts)) == len(artifacts)
            and _valid_status_times(content)
        )
    if kind in {KIND_CI_LOG_REFERENCE, KIND_CI_ARTIFACT_REFERENCE}:
        url = content.get("url")
        if not isinstance(url, str):
            return False
        try:
            path = parse_evidence_path(urlsplit(url).path)
        except Refusal:
            return False
        return _valid_reference_event(event, content, channel, origin, path)
    if kind == KIND_CI_EVIDENCE_FINALIZED:
        return (
            _positive_safe_integer(content.get("finalized_at"))
            and isinstance(content.get("finalized_job_attempts"), list)
            and bool(content["finalized_job_attempts"])
        )
    if kind == KIND_CI_TEARDOWN_ATTESTATION:
        return (
            content.get("base_oid") == request.get("base_oid")
            and content.get("workflow_digest") == request.get("workflow_digest")
            and _positive_safe_integer(content.get("teardown_at"))
            and isinstance(content.get("leases"), list) and bool(content["leases"])
            and content.get("lease_empty") is True
        )
    return False
def _valid_status_times(content: dict[str, object]) -> bool:
    terminal = content.get("state") not in OPEN_RUN_STATES
    started, finished = content.get("started_at"), content.get("finished_at")
    if not terminal:
        return started is None and finished is None
    return _positive_safe_integer(started) and _positive_safe_integer(finished) and finished >= started


def read_evidence_object(
    state: RelayState, caller: str, path: dict[str, object], *, now: int,
) -> tuple[bytes, dict[str, str]]:
    """Resolve a member-visible object through its signed reference and terminal selection."""
    evidence_type = str(path["type"])
    hidden = f"CI {evidence_type} not found"
    request_event = state.events.get(str(path["request_id"]))
    channel = None if request_event is None else state.event_channels.get(str(path["request_id"]))
    if (
        request_event is None or request_event.get("id") != path["request_id"]
        or request_event.get("kind") != KIND_CI_REQUEST or channel != state.channel_id
    ):
        raise Refusal(404, hidden)
    try:
        verify_event(request_event)
        request = parse_content(request_event, "CI request")
    except (RelayError, Refusal) as error:
        raise Refusal(404, hidden) from error
    if (
        caller not in state.members or not _valid_request_event(request_event, request, str(channel))
        or request.get("run_id") != path["run_id"] or request.get("attempt") != path["attempt"]
        or not isinstance(request.get("job_ids"), list) or path["job_id"] not in request["job_ids"]
        or not isinstance(request.get("target_repo_a"), str)
        or REPO_COORDINATE.fullmatch(request["target_repo_a"]) is None
    ):
        raise Refusal(404, hidden)
    active_signers = state.active_signers(request["target_repo_a"], now)
    reference_kind = KIND_CI_LOG_REFERENCE if evidence_type == "log" else KIND_CI_ARTIFACT_REFERENCE
    references: list[tuple[str, dict[str, object]]] = []
    terminals: list[dict[str, object]] = []
    for identifier, event in state.events.items():
        if state.event_channels.get(identifier) != channel or event.get("pubkey") not in active_signers:
            continue
        if event.get("kind") not in {reference_kind, KIND_CI_JOB_STATUS}:
            continue
        try:
            verify_event(event)
            if event.get("id") != identifier:
                continue
            content = parse_content(event, "CI event")
        except (RelayError, Refusal):
            continue
        shared = (
            content.get("request_event_id") == path["request_id"]
            and content.get("run_id") == path["run_id"]
            and content.get("workflow_id") == request.get("workflow_id")
            and content.get("target_repo_a") == request.get("target_repo_a")
            and content.get("tip_oid") == request.get("tip_oid")
            and content.get("job_id") == path["job_id"] and content.get("attempt") == path["attempt"]
        )
        if not shared:
            continue
        if event["kind"] == reference_kind:
            if _valid_reference_event(event, content, str(channel), state.origin, path):
                references.append((identifier, content))
        elif content.get("base_oid") == request.get("base_oid") and _valid_success_terminal(
            event, content, str(channel),
        ):
            terminals.append(content)
    if len(references) != 1:
        raise Refusal(404, hidden)
    reference_id, reference = references[0]
    selected = any(
        terminal.get("log_ref") == reference_id if evidence_type == "log"
        else isinstance(terminal.get("artifact_refs"), list) and reference_id in terminal["artifact_refs"]
        for terminal in terminals
    )
    owner_name, owner_raw = _owner_record(str(channel), request, path)
    directory = None
    if not selected:
        raise Refusal(404, hidden)
    try:
        directory = os.open(
            state.object_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        if _read_regular_at(directory, owner_name, MAX_OWNER_RECORD_BYTES) != owner_raw:
            raise OSError("evidence owner differs")
        raw = _read_regular_at(directory, str(path["sha256"]), MAX_EVIDENCE_BYTES)
    except OSError as error:
        raise Refusal(404, hidden) from error
    finally:
        if directory is not None:
            os.close(directory)
    byte_length = reference["byte_length"]
    if len(raw) != byte_length or hashlib.sha256(raw).hexdigest() != path["sha256"]:
        raise Refusal(503, f"CI {evidence_type} unavailable")
    media_type = "application/octet-stream" if evidence_type == "log" else str(reference["media_type"])
    return raw, {
        "Content-Type": media_type, "Content-Length": str(byte_length),
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "Digest": "sha-256=" + base64.b64encode(bytes.fromhex(str(path["sha256"]))).decode(),
    }


def admit_event(state: RelayState, token_pubkey: str, event: dict[str, object], now: int) -> tuple[str | None, bool]:
    """Apply the production POST /events rules; return (channel, accepted).

    Raises :class:`Refusal` with the relay's status and message. The caller
    holds ``state.lock``.
    """
    kind = int(event["kind"])
    tags = event["tags"]
    assert isinstance(tags, list)
    if state.refuses_as_stale(event) or abs(int(event["created_at"]) - now) > MAX_EVENT_DRIFT:
        raise Refusal(400, "invalid: event timestamp too far from server time")
    if len(str(event["content"]).encode()) > MAX_CONTENT_BYTES:
        raise Refusal(400, "invalid: content exceeds maximum size")
    if event["pubkey"] != token_pubkey:
        raise Refusal(403, "invalid: event pubkey does not match authenticated identity")
    pubkey = str(event["pubkey"])
    identifier = str(event["id"])
    actor_classification = state.classify_actor_event(event)
    if identifier in state.events:
        return state.event_channels.get(identifier), False
    channel = first_tag(tags, "h")
    if kind == KIND_DELETION:
        targets = [tag[1] for tag in tags if len(tag) >= 2 and tag[0] == "e"]
        if len(targets) != 1:
            raise Refusal(400, "invalid: deletion events must reference exactly one target via e or a tag")
        target = state.events.get(targets[0])
        if target is None:
            raise Refusal(400, "invalid: target event not found")
        if target["pubkey"] != pubkey:
            raise Refusal(400, "invalid: must be event author")
        channel = state.event_channels.get(targets[0])
    if KIND_CI_REQUEST <= kind <= KIND_CI_GRANT and channel is None:
        raise Refusal(400, "invalid: CI events require a channel h tag")
    if channel is not None and kind not in MEMBERSHIP_EXEMPT_KINDS:
        state.require_membership(channel, pubkey)
    if kind == KIND_CI_GRANT:
        if state.members.get(pubkey) not in GRANT_ROLES:
            raise Refusal(403, "restricted: only a channel owner or admin may issue a CI signer grant")
        content = parse_content(event, "CI grant")
        valid_from = content.get("valid_from")
        valid_until = content.get("valid_until")
        if (
            set(content) - {"schema_version", "target_repo_a", "signer_pubkey", "valid_from", "valid_until"}
            or content.get("schema_version") != 1
            or not isinstance(content.get("target_repo_a"), str)
            or REPO_COORDINATE.fullmatch(content["target_repo_a"]) is None
            or not isinstance(content.get("signer_pubkey"), str)
            or HEX64.fullmatch(content["signer_pubkey"]) is None
            or not isinstance(valid_from, int) or isinstance(valid_from, bool)
            or valid_until is not None and (not isinstance(valid_until, int) or isinstance(valid_until, bool))
            or valid_until is not None and valid_until <= valid_from
        ):
            raise Refusal(400, "invalid: CI grant content rejected")
    elif kind == KIND_CI_REQUEST:
        content = parse_content(event, "CI request")
        run_id = content.get("run_id")
        if content.get("actor") != pubkey:
            raise Refusal(400, "invalid: request actor does not match event signer")
        if not isinstance(run_id, str) or UUID.fullmatch(run_id) is None or first_tag(tags, "run") != run_id:
            raise Refusal(400, "invalid: CI request run tag rejected")
        if not isinstance(content.get("target_repo_a"), str) or first_tag(tags, "a") != content["target_repo_a"]:
            raise Refusal(400, "invalid: CI request repository tag rejected")
        # buzz-db ci.rs prepare_request: an initial request must create its
        # run; a rerun (attempt 2 or later) must find the run it extends.
        attempt = content.get("attempt")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise Refusal(400, "invalid: CI request attempt rejected")
        exists = (channel, run_id) in state.run_ids
        if event["id"] not in state.events:
            if attempt == 1 and exists:
                raise Refusal(400, "invalid: CI run ID or initial request event ID already exists")
            if attempt > 1 and not exists:
                raise Refusal(400, "invalid: CI rerun names an unknown run")
            if attempt > 1 and state.final_facts.get(str(run_id)):
                raise Refusal(409, "conflict: CI run is already bound to terminal evidence and cannot be rerun")
            if attempt > 1 and not state.rerun_allowed(str(channel), content):
                raise Refusal(400, "invalid: CI rerun does not extend the selected failed job attempt")
    elif KIND_CI_STATUS_MIN <= kind <= KIND_CI_STATUS_MAX:
        content = parse_content(event, "CI event")
        if content.get("relay_signer") != pubkey:
            raise Refusal(400, "invalid: status signer does not match event signer")
        if not isinstance(content.get("target_repo_a"), str):
            raise Refusal(400, "invalid: CI event missing target_repo_a")
        # handlers/ingest.rs: the signer set is the static set plus the grants
        # active for (channel, target_repo_a) at ingest time; buzz-core
        # validate_signed_ci_event refuses any other signer with this message.
        state.expires_grants_before(event, now)
        if pubkey not in state.active_signers(content["target_repo_a"], now):
            state.note_unauthorized(event)
            raise Refusal(400, UNAUTHORIZED_STATUS_SIGNER)
        if state.candidate_acceptance is not None:
            current_runs = {state.candidate_acceptance["run_id"], state.candidate_acceptance["failure_run_id"]}
            prior_runs = set() if state.prior_acceptance is None else {
                state.prior_acceptance["run_id"], state.prior_acceptance["failure_run_id"],
            }
            if content.get("run_id") not in current_runs | prior_runs:
                raise Refusal(409, "conflict: foreign CI event is outside the acceptance partition")
            if content.get("run_id") in prior_runs:
                if state.fault != FAULT_REPLAY_BEFORE_GRANT:
                    raise Refusal(409, "conflict: prior CI event is not active")
                if state.observed_actor_event_ids and identifier not in state.refused_event_ids:
                    raise Refusal(409, "conflict: foreign CI event is not the named pending replay")
        if state.candidate_acceptance is not None and content.get("run_id") in current_runs:
            if state.candidate_sealed:
                raise Refusal(409, "conflict: sealed acceptance transcript cannot be mutated")
            run_id = str(content["run_id"])
            attempt = content.get("attempt")
            requests = state.run_requests.get((str(channel), run_id), {})
            request_id = content.get("request_event_id")
            request_event = state.events.get(str(request_id))
            if (
                not isinstance(attempt, int) or isinstance(attempt, bool)
                or requests.get(attempt) != request_id
                or request_event is None
            ):
                raise Refusal(400, "invalid: CI event request provenance rejected")
            request = parse_content(request_event, "CI request")
            shared = ("run_id", "workflow_id", "target_repo_a", "tip_oid")
            if any(content.get(name) != request.get(name) for name in shared):
                raise Refusal(400, "invalid: CI event request provenance rejected")
            if kind in {KIND_CI_RUN_STATUS, KIND_CI_JOB_STATUS, KIND_CI_TEARDOWN_ATTESTATION} \
                    and content.get("base_oid") != request.get("base_oid"):
                raise Refusal(400, "invalid: CI event request provenance rejected")
            if kind in {KIND_CI_EVIDENCE_FINALIZED, KIND_CI_TEARDOWN_ATTESTATION}:
                if run_id != state.candidate_acceptance["run_id"]:
                    raise Refusal(409, "conflict: failure run cannot publish terminal facts")
                latest = requests[max(requests)] if requests else None
                if request_id != latest:
                    raise Refusal(409, "conflict: terminal fact does not name the latest request")
    state.events[identifier] = event
    state.event_channels[identifier] = channel
    state.note_actor_event(actor_classification, event)
    state.record_ci_event(event)
    if KIND_CI_STATUS_MIN <= kind <= KIND_CI_STATUS_MAX:
        state.note_terminal_accepted(event)
    if kind == KIND_CI_GRANT:
        content = parse_content(event, "CI grant")
        state.grants.append((
            str(content["target_repo_a"]), str(content["signer_pubkey"]),
            int(content["valid_from"]), None if content.get("valid_until") is None else int(content["valid_until"]),
        ))
    if kind == KIND_CI_REQUEST:
        assert channel is not None
        content = parse_content(event, "CI request")
        run_id = str(content["run_id"])
        state.run_ids.add((channel, run_id))
        state.run_requests.setdefault((channel, run_id), {})[int(content["attempt"])] = identifier
        state.cursor += 1
        state.accepted.append((state.cursor, channel, event))
    state.record_transcript_event(event)
    return channel, True


def hex_list(filter_value: dict[str, object], name: str) -> set[str] | None:
    values = filter_value.get(name)
    if values is None:
        return None
    if not isinstance(values, list) or any(not isinstance(item, str) or HEX64.fullmatch(item) is None for item in values):
        raise Refusal(400, f"invalid filters: {name}")
    return set(values)


def bounded_int(filter_value: dict[str, object], name: str) -> int | None:
    value = filter_value.get(name)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise Refusal(400, f"invalid filters: {name}")
    return value


def query_events(state: RelayState, caller: str, raw: bytes) -> list[dict[str, object]]:
    """Apply the production POST /query rules; return the matching events.

    api/bridge.rs ``query_events_authed``: the body is a JSON array of filters;
    the kind gates run before any read; results are limited to channels the
    caller can access and follow the ``created_at DESC, id ASC`` order. The
    caller holds ``state.lock``.
    """
    expected_query_subject = None if state.candidate_acceptance is None \
        else state.candidate_acceptance["grant"].get("signer_pubkey")
    if expected_query_subject is not None and caller != expected_query_subject:
        raise Refusal(403, "restricted: CI query signer differs")
    try:
        filters = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RelayError) as error:
        raise Refusal(400, "invalid filters: body is not JSON") from error
    if not isinstance(filters, list) or not filters or len(filters) > MAX_QUERY_FILTERS or any(not isinstance(item, dict) for item in filters):
        raise Refusal(400, "invalid filters: expected an array of filter objects")
    results: list[dict[str, object]] = []
    for filter_value in filters:
        kinds = filter_value.get("kinds")
        # handlers/req.rs p_gated_filters_authorized: a filter that names no
        # kind can match every gated kind, so the relay refuses it before any
        # read. controld always names the exact kind (source.rs
        # publication_exists); the stub applies the gate regardless of `ids`.
        if (
            not isinstance(kinds, list) or not kinds
            or any(not isinstance(kind, int) or isinstance(kind, bool) or not 0 <= kind <= 65535 for kind in kinds)
        ):
            raise Refusal(403, "restricted: p-gated kinds require #p tag matching your pubkey")
        ids = hex_list(filter_value, "ids")
        state.note_query(ids, kinds)
        authors = hex_list(filter_value, "authors")
        since = bounded_int(filter_value, "since")
        until = bounded_int(filter_value, "until")
        limit = bounded_int(filter_value, "limit")
        matched = [
            event for event in state.events.values()
            if event["kind"] in kinds
            and (ids is None or event["id"] in ids)
            and (authors is None or event["pubkey"] in authors)
            and (since is None or int(event["created_at"]) >= since)
            and (until is None or int(event["created_at"]) <= until)
            and state.visible_to(event, caller)
        ]
        matched.sort(key=lambda event: (-int(event["created_at"]), str(event["id"])))
        results.extend(matched if limit is None else matched[:limit])
    state.query_callers.append(caller)
    return results


def _content(record: dict[str, object]) -> dict[str, object]:
    event = record.get("event")
    if not isinstance(event, dict):
        raise RelayError("transcript event rejected")
    try:
        content = json.loads(str(event["content"]), object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, RelayError) as error:
        raise RelayError("transcript event content rejected") from error
    if not isinstance(content, dict) or canonical_json(content).decode() != event["content"]:
        raise RelayError("transcript event content is not canonical")
    return content


def _matching(
    records: list[dict[str, object]], kind: int, run_id: str, **fields: object,
) -> list[dict[str, object]]:
    matched = []
    for record in records:
        event = record.get("event")
        if not isinstance(event, dict) or event.get("kind") != kind:
            continue
        content = _content(record) if kind != KIND_DELETION else {}
        if content.get("run_id") == run_id and all(content.get(name) == value for name, value in fields.items()):
            matched.append(record)
    return matched


def validate_evidence_reads(
    raw: bytes, generation: int, subject: str,
    log_record: dict[str, object], artifact_record: dict[str, object],
) -> None:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RelayError("authenticated evidence read record is not JSON") from error
    if canonical_json(value) + b"\n" != raw or not isinstance(value, dict) or set(value) != {
        "schema_version", "export_generation", "reads",
    } or value.get("schema_version") != EVIDENCE_READS_SCHEMA \
            or value.get("export_generation") != generation:
        raise RelayError("authenticated evidence read record differs")
    expected: list[dict[str, object]] = []
    for evidence_type, record in (("log", log_record), ("artifact", artifact_record)):
        event = record.get("event")
        content = _content(record)
        url = content.get("url")
        if not isinstance(event, dict) or not isinstance(url, str):
            raise RelayError("authenticated evidence read reference differs")
        parsed_url = urlsplit(url)
        if (
            f"{parsed_url.scheme}://{parsed_url.netloc}" != EXPORT_ORIGIN
            or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment
            or url != EXPORT_ORIGIN + parsed_url.path
        ):
            raise RelayError("authenticated evidence read URL differs")
        try:
            path = parse_evidence_path(parsed_url.path)
        except Refusal as error:
            raise RelayError("authenticated evidence read URL differs") from error
        digest = content.get("log_sha256") if evidence_type == "log" else content.get("sha256")
        if (
            path["type"] != evidence_type or path["request_id"] != content.get("request_event_id")
            or path["run_id"] != content.get("run_id") or path["job_id"] != content.get("job_id")
            or path["attempt"] != content.get("attempt") or path["sha256"] != digest
            or path["artifact_id"] != (None if evidence_type == "log" else content.get("artifact_id"))
        ):
            raise RelayError("authenticated evidence read URL differs")
        expected.append({
            "type": evidence_type, "path": parsed_url.path,
            "request_event_id": path["request_id"], "run_id": path["run_id"],
            "job_id": path["job_id"], "attempt": path["attempt"],
            "artifact_id": path["artifact_id"], "sha256": path["sha256"],
            "byte_length": content.get("byte_length"), "subject": subject,
        })
    if value.get("reads") != expected:
        raise RelayError("authenticated evidence GET plan differs")


def build_closed_verdict(
    acceptance_template: object,
    fixture: object,
    transcript_raw: bytes,
    receipt_raw: bytes,
    evidence_reads_raw: bytes,
    *,
    foreign_pending_event_id: str | None = None,
    prior_acceptance_template: object | None = None,
    fault_mode: str | None = None,
) -> dict[str, object]:
    """Recompute the M15 close verdict from a sealed relay transcript and receipt."""
    authority = validate_acceptance_template(acceptance_template, label="candidate")
    if not isinstance(fixture, dict):
        raise RelayError("acceptance fixture rejected")
    if authority["failure_selector"] is None or fixture.get("failure_selector") != authority["failure_selector"]:
        raise RelayError("candidate failure selector differs from acceptance fixture")
    try:
        transcript = json.loads(transcript_raw, object_pairs_hook=reject_duplicates)
        receipt = json.loads(receipt_raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RelayError("protocol close input is not JSON") from error
    if canonical_json(transcript) + b"\n" != transcript_raw or canonical_json(receipt) + b"\n" != receipt_raw:
        raise RelayError("protocol close input is not canonical JSON")
    transcript_fields = {
        "schema_version", "template_set_sha256", "actor_event_ids", "observed_actor_event_ids",
        "events", "sealed", "sealed_projection_sha256", "foreign_pending_event_ids",
        "foreign_pending_event",
    }
    if (
        not isinstance(transcript, dict) or set(transcript) != transcript_fields
        or transcript.get("schema_version") != TRANSCRIPT_SCHEMA
        or transcript.get("template_set_sha256") != authority["template_set_sha256"]
        or transcript.get("actor_event_ids") != {"api_order": authority["api_ids"], "live_order": authority["live_ids"]}
        or transcript.get("observed_actor_event_ids") != authority["live_ids"]
        or transcript.get("sealed") is not True
        or not isinstance(transcript.get("events"), list) or not transcript["events"]
    ):
        raise RelayError("relay transcript binding rejected")
    records = transcript["events"]
    request_by_id = {
        str(authority["api_ids"][0]): authority["run"],
        str(authority["api_ids"][4]): authority["failure_run"],
        str(authority["api_ids"][2]): authority["rerun"],
    }
    if any(
        not isinstance(record, dict) or set(record) != {"cursor", "event"}
        or record.get("cursor") != index
        for index, record in enumerate(records, 1)
    ):
        raise RelayError("relay transcript cursor rejected")
    for record in records:
        event = record["event"]
        try:
            verified = verify_event(event)
        except RelayError as error:
            raise RelayError("relay transcript signature rejected") from error
        if canonical_json(verified) != canonical_json(event):
            raise RelayError("relay transcript event encoding rejected")
        if event["kind"] != KIND_DELETION and event["id"] not in authority["api_ids"]:
            content = _content(record)
            if event["kind"] in {KIND_CI_LOG_REFERENCE, KIND_CI_ARTIFACT_REFERENCE}:
                url = content.get("url")
                if isinstance(url, str):
                    parsed_url = urlsplit(url)
                    if (
                        f"{parsed_url.scheme}://{parsed_url.netloc}" != EXPORT_ORIGIN
                        or url != EXPORT_ORIGIN + parsed_url.path
                    ):
                        raise RelayError("authenticated evidence read URL differs")
            request_id = content.get("request_event_id")
            request = request_by_id.get(str(request_id))
            if request is None or not _valid_transcript_ci_event(
                event, content, request, str(request_id), str(first_tag(event["tags"], "h")),
                EXPORT_ORIGIN,
            ):
                raise RelayError("relay transcript CI envelope rejected")
    sealed_projection = hashlib.sha256(canonical_json(records)).hexdigest()
    if transcript.get("sealed_projection_sha256") != sealed_projection:
        raise RelayError("relay sealed projection changed")
    actor_ids = [
        str(record["event"]["id"]) for record in records
        if isinstance(record.get("event"), dict) and str(record["event"].get("id")) in authority["api_ids"]
    ]
    if actor_ids != authority["live_ids"]:
        raise RelayError("relay actor transcript rejected")
    foreign_actor_ids = transcript.get("foreign_pending_event_ids")
    foreign_event = transcript.get("foreign_pending_event")
    if foreign_pending_event_id is None:
        if foreign_actor_ids != [] or foreign_event is not None or prior_acceptance_template is not None or fault_mode is not None:
            raise RelayError("foreign pending event partition rejected")
    else:
        if fault_mode != FAULT_REPLAY_BEFORE_GRANT or prior_acceptance_template is None:
            raise RelayError("foreign pending event mode rejected")
        prior = validate_acceptance_template(prior_acceptance_template, label="prior")
        try:
            verified_foreign = verify_event(foreign_event)
            foreign_content = _content({"event": verified_foreign})
        except RelayError as error:
            raise RelayError("foreign pending event signature rejected") from error
        if (
            foreign_actor_ids != prior["live_ids"][:2]
            or set(prior["api_ids"]) & set(authority["api_ids"])
            or prior["actor"] != authority["actor"]
            or {prior["run_id"], prior["failure_run_id"]}
                & {authority["run_id"], authority["failure_run_id"]}
            or foreign_pending_event_id in set(authority["api_ids"])
            or HEX64.fullmatch(foreign_pending_event_id) is None
            or verified_foreign.get("id") != foreign_pending_event_id
            or verified_foreign.get("pubkey") != prior["grant"].get("signer_pubkey")
            or verified_foreign.get("kind") != KIND_CI_RUN_STATUS
            or foreign_content.get("run_id") != prior["run_id"]
            or foreign_content.get("request_event_id") != prior["api_ids"][0]
            or foreign_content.get("attempt") != 1 or foreign_content.get("state") != "success"
        ):
            raise RelayError("foreign pending event identity rejected")

    run_a = str(authority["run_id"])
    run_b = str(authority["failure_run_id"])
    job_id = fixture.get("job_id")
    if not isinstance(job_id, str):
        raise RelayError("fixture job identity rejected")

    def exact_states(kind: int, run_id: str, request_id: str, states: list[str]) -> list[dict[str, object]]:
        found = _matching(records, kind, run_id, request_event_id=request_id)
        observed = [_content(record).get("state") for record in found]
        if observed != states or [_content(record).get("sequence") for record in found] != list(range(1, len(states) + 1)):
            raise RelayError("relay status transition rejected")
        return found

    run_a_request = authority["api_ids"][0]
    run_b_request = authority["api_ids"][4]
    rerun_request = authority["api_ids"][2]
    run_a_status = exact_states(KIND_CI_RUN_STATUS, run_a, run_a_request, ["queued", "running", "success"])
    run_a_job = exact_states(KIND_CI_JOB_STATUS, run_a, run_a_request, ["queued", "running", "success"])
    run_b_status = exact_states(KIND_CI_RUN_STATUS, run_b, run_b_request, ["queued", "running", "failure"])
    run_b_job = exact_states(KIND_CI_JOB_STATUS, run_b, run_b_request, ["queued", "running", "failure"])
    rerun_status = exact_states(KIND_CI_RUN_STATUS, run_b, rerun_request, ["queued", "running", "cancelled"])
    rerun_job = exact_states(KIND_CI_JOB_STATUS, run_b, rerun_request, ["queued", "running", "cancelled"])
    for group, attempt in ((run_a_job, 1), (run_b_job, 1), (rerun_job, 2)):
        if any(_content(record).get("job_id") != job_id or _content(record).get("attempt") != attempt for record in group):
            raise RelayError("relay job lineage rejected")
    if any(_content(record).get("attempt") != attempt for group, attempt in (
        (run_a_status, 1), (run_b_status, 1), (rerun_status, 2),
    ) for record in group):
        raise RelayError("relay run lineage rejected")
    if any(_content(record).get("parent_attempt") != 1 for record in rerun_job):
        raise RelayError("relay rerun parent rejected")

    run_a_logs = _matching(records, KIND_CI_LOG_REFERENCE, run_a, request_event_id=run_a_request, attempt=1, job_id=job_id)
    run_a_artifacts = _matching(records, KIND_CI_ARTIFACT_REFERENCE, run_a, request_event_id=run_a_request, attempt=1, job_id=job_id)
    run_b_logs = _matching(records, KIND_CI_LOG_REFERENCE, run_b, request_event_id=run_b_request, attempt=1, job_id=job_id)
    run_b_artifacts = _matching(records, KIND_CI_ARTIFACT_REFERENCE, run_b)
    expected_log = fixture.get("expected_log")
    expected_failure_log = fixture.get("expected_failure_log")
    expected_artifacts = fixture.get("expected_artifacts")
    if (
        len(run_a_logs) != 1 or len(run_b_logs) != 1 or run_b_artifacts
        or not isinstance(expected_log, dict) or not isinstance(expected_failure_log, dict)
        or not isinstance(expected_artifacts, list) or len(expected_artifacts) != 1
        or len(run_a_artifacts) != 1
    ):
        raise RelayError("relay evidence cardinality rejected")
    for record, expected in ((run_a_logs[0], expected_log), (run_b_logs[0], expected_failure_log)):
        content = _content(record)
        if content.get("log_sha256") != expected.get("sha256") or content.get("byte_length") != expected.get("bytes"):
            raise RelayError("relay deterministic log rejected")
    observed_artifacts = [
        {"name": _content(record).get("name"), "sha256": _content(record).get("sha256"), "bytes": _content(record).get("byte_length")}
        for record in run_a_artifacts
    ]
    if observed_artifacts != expected_artifacts:
        raise RelayError("relay selected artifacts rejected")
    run_a_log_id = str(run_a_logs[0]["event"]["id"])
    artifact_ids = [str(record["event"]["id"]) for record in run_a_artifacts]
    failure_log_id = str(run_b_logs[0]["event"]["id"])
    if (
        _content(run_a_job[-1]).get("log_ref") != run_a_log_id
        or _content(run_a_job[-1]).get("artifact_refs") != artifact_ids
        or _content(run_b_job[-1]).get("log_ref") != failure_log_id
        or _content(run_b_job[-1]).get("artifact_refs") != []
        or any(_content(record).get("log_ref") is not None or _content(record).get("artifact_refs") != [] for record in rerun_job)
    ):
        raise RelayError("relay terminal evidence selection rejected")

    evidence = _matching(records, KIND_CI_EVIDENCE_FINALIZED, run_a)
    teardown = _matching(records, KIND_CI_TEARDOWN_ATTESTATION, run_a)
    failure_facts = _matching(records, KIND_CI_EVIDENCE_FINALIZED, run_b) + _matching(records, KIND_CI_TEARDOWN_ATTESTATION, run_b)
    if len(evidence) != 1 or len(teardown) != 1 or failure_facts:
        raise RelayError("relay final fact cardinality rejected")
    evidence_content, teardown_content = _content(evidence[0]), _content(teardown[0])
    selected = [{"job_id": job_id, "attempt": 1, "log_ref": run_a_log_id, "artifact_refs": artifact_ids}]
    leases = teardown_content.get("leases")
    if (
        evidence_content.get("request_event_id") != run_a_request
        or evidence_content.get("attempt") != 1
        or evidence_content.get("finalized_job_attempts") != selected
        or teardown_content.get("request_event_id") != run_a_request
        or teardown_content.get("attempt") != 1
        or teardown_content.get("lease_empty") is not True
        or not isinstance(leases, list) or len(leases) != 1
        or [(item.get("job_id"), item.get("attempt"), item.get("lease_id")) for item in leases if isinstance(item, dict)]
            != sorted((item.get("job_id"), item.get("attempt"), item.get("lease_id")) for item in leases if isinstance(item, dict))
        or {(item.get("job_id"), item.get("attempt")) for item in leases if isinstance(item, dict)} != {(job_id, 1)}
    ):
        raise RelayError("relay final facts rejected")
    if not (
        run_a_job[-1]["cursor"] < evidence[0]["cursor"] < run_a_status[-1]["cursor"]
        and teardown[0]["cursor"] < run_a_status[-1]["cursor"]
    ):
        raise RelayError("relay final fact order rejected")

    tombstone_id = authority["api_ids"][3]
    tombstones = [record for record in records if record["event"].get("id") == tombstone_id]
    if len(tombstones) != 1 or tombstones[0]["event"].get("tags") != [["e", rerun_request]] \
            or rerun_status[-1]["cursor"] >= tombstones[0]["cursor"] \
            or rerun_job[-1]["cursor"] >= tombstones[0]["cursor"]:
        raise RelayError("relay rerun tombstone rejected")

    bound_records = [
        *[record for record in records if record["event"].get("id") in authority["api_ids"]],
        *run_a_status, *run_a_job, *run_a_logs, *run_a_artifacts, *evidence, *teardown,
        *run_b_status, *run_b_job, *run_b_logs, *rerun_status, *rerun_job,
    ]
    bound_ids = [str(record["event"]["id"]) for record in bound_records]
    transcript_ids = [str(record["event"]["id"]) for record in records]
    if len(set(transcript_ids)) != len(transcript_ids) or sorted(bound_ids) != sorted(transcript_ids):
        raise RelayError("relay transcript contains an unbound or duplicate event")

    receipt_fields = {"schema_version", "outcome", "scenario_sha256", "integrated_candidate_sha", "run_id", "checks", "zero_transition"}
    if (
        not isinstance(receipt, dict) or set(receipt) != receipt_fields
        or receipt.get("outcome") != "pass" or receipt.get("run_id") != fixture.get("run_id")
        or not isinstance(receipt.get("checks"), list) or len(receipt["checks"]) != 16
        or [(item.get("sequence"), item.get("stage"), item.get("outcome")) for item in receipt["checks"] if isinstance(item, dict)]
            != [(index, stage, "pass") for index, stage in enumerate(EXPECTED_RECEIPT_STAGES, 1)]
        or not isinstance(receipt.get("zero_transition"), dict)
        or [(item.get("sequence"), item.get("operation"), item.get("outcome")) for item in receipt["zero_transition"].get("phases", []) if isinstance(item, dict)]
            != [(17, "finalize_capacity_zero", "pass"), (18, "prove_capacity_zero", "pass")]
    ):
        raise RelayError("acceptance receipt closure rejected")
    export = receipt["checks"][6].get("export")
    first_terminal_attempt = receipt["checks"][5].get("snapshot", {}).get("run", {}).get("attempts", [])
    exported_terminal_attempt = receipt["checks"][6].get("snapshot", {}).get("run", {}).get("attempts", [])
    terminal_attempt = first_terminal_attempt[0] if isinstance(first_terminal_attempt, list) and len(first_terminal_attempt) == 1 else None
    exported_attempt = exported_terminal_attempt[0] if isinstance(exported_terminal_attempt, list) and len(exported_terminal_attempt) == 1 else None
    if (
        not isinstance(export, dict) or export.get("authenticated") is not True
        or not isinstance(terminal_attempt, dict) or exported_attempt != terminal_attempt
        or export.get("attempt_id") != terminal_attempt.get("attempt_id")
        or export.get("evidence_set_digest") != terminal_attempt.get("evidence_set_digest")
        or not isinstance(export.get("attempt_id"), str) or HEX32.fullmatch(export["attempt_id"]) is None
        or not isinstance(export.get("evidence_set_digest"), str) or HEX64.fullmatch(export["evidence_set_digest"]) is None
        or export.get("manifest_digest") != terminal_attempt.get("manifest_digest")
        or export.get("manifest_digest") != fixture.get("manifest_digest")
        or export.get("request_digest") != fixture.get("request_digest")
        or not isinstance(fixture.get("export_generation"), int)
        or isinstance(fixture["export_generation"], bool) or fixture["export_generation"] < 1
        or export.get("generation") != fixture["export_generation"]
        or export.get("subject") != fixture.get("export_subject")
        or export.get("authorization_digest") != fixture.get("export_authorization_digest")
        or fixture.get("export_subject") != authority["export_subject"]
        or fixture.get("export_generation") != authority["export_generation"]
        or fixture.get("export_authorization_digest") != authority["export_authorization_digest"]
        or export.get("objects") != [expected_log, *expected_artifacts]
    ):
        raise RelayError("authenticated export binding rejected")
    validate_evidence_reads(
        evidence_reads_raw, export["generation"], export["subject"],
        run_a_logs[0], run_a_artifacts[0],
    )

    verdict = {
        "schema_version": VERDICT_SCHEMA,
        "state": "green", "reason": None, "sealed": True,
        "template_set_sha256": authority["template_set_sha256"],
        "actor_event_ids": {"api_order": authority["api_ids"], "live_order": authority["live_ids"]},
        "observed_actor_event_ids": authority["live_ids"],
        "run_ids": {"run_a": run_a, "run_b": run_b},
        "transcript": {"sha256": hashlib.sha256(transcript_raw).hexdigest(), "event_count": len(records), "last_cursor": len(records)},
        "receipt": {
            "sha256": hashlib.sha256(receipt_raw).hexdigest(), "run_id": receipt["run_id"],
            "checks": 16, "zero_phases": [17, 18], "manifest_digest": export["manifest_digest"],
            "export_subject": export["subject"], "export_authorization_digest": export["authorization_digest"],
            "export_request_digest": export["request_digest"],
            "export_attempt_id": export["attempt_id"],
            "export_evidence_set_digest": export["evidence_set_digest"],
            "export_objects_sha256": hashlib.sha256(canonical_json(export["objects"])).hexdigest(),
            "export_generation": export["generation"],
        },
        "run_a": {
            "request_event_id": run_a_request,
            "selected_job_attempts": [{"job_id": job_id, "attempt": 1}],
            "log_event_ids": [run_a_log_id], "artifact_event_ids": artifact_ids,
            "evidence_finalized_event_id": evidence[0]["event"]["id"],
            "teardown_attestation_event_id": teardown[0]["event"]["id"],
            "terminal_event_id": run_a_status[-1]["event"]["id"],
        },
        "run_b": {
            "initial_request_event_id": run_b_request, "final_request_event_id": rerun_request,
            "failure_log_event_id": failure_log_id,
            "failure_job_event_id": run_b_job[-1]["event"]["id"],
            "failure_run_event_id": run_b_status[-1]["event"]["id"],
            "rerun_request_event_id": rerun_request,
            "cancel_job_event_id": rerun_job[-1]["event"]["id"],
            "cancel_run_event_id": rerun_status[-1]["event"]["id"],
            "tombstone_event_id": tombstone_id, "final_fact_count": 0,
        },
        "sealed_projection_sha256": sealed_projection,
        "foreign_pending_event_id": foreign_pending_event_id,
    }
    return validate_closed_verdict(verdict)


class Handler(BaseHTTPRequestHandler):
    server: "RelayServer"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _json(self, status: int, value: object) -> None:
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self, maximum: int = MAX_BODY) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            return None
        if not 0 <= length <= maximum:
            return None
        raw = self.rfile.read(length)
        return raw if len(raw) == length else None

    def _evidence_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError as error:
            raise Refusal(411, "content length required") from error
        if length < 0:
            raise Refusal(411, "content length required")
        if length > MAX_EVIDENCE_BYTES:
            raise Refusal(413, "CI evidence exceeds byte limit")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise Refusal(400, "CI evidence length mismatch")
        return raw

    def _raw(self, status: int, raw: bytes, headers: dict[str, str]) -> None:
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def _authenticate(self, method: str, body: bytes) -> str:
        """Return the token pubkey; raise Refusal(401) like verify_bridge_auth."""
        return authenticate_once(
            self.server.state, self.headers.get("Authorization", ""), method,
            self.server.state.origin + self.path, body,
        )

    def _refuse(self, refusal: Refusal) -> None:
        self._json(refusal.status, {"error": refusal.message})

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        try:
            if parsed.path == "/ci/logs" or parsed.path.startswith("/ci/logs/") \
                    or parsed.path == "/ci/artifacts" or parsed.path.startswith("/ci/artifacts/"):
                caller = self._authenticate("GET", b"")
                if parsed.query or parsed.fragment:
                    raise Refusal(404, "not found")
                evidence_path = parse_evidence_path(parsed.path)
                with self.server.state.lock:
                    raw, headers = read_evidence_object(
                        self.server.state, caller, evidence_path, now=int(time.time()),
                    )
                    self.server.state.record_evidence_read(caller, evidence_path, len(raw))
                self._raw(200, raw, headers)
                return
            if parsed.path != "/ci/control/accepted":
                raise Refusal(404, "not found")
            caller = self._authenticate("GET", b"")
            try:
                query = parse_qs(parsed.query, strict_parsing=True)
                if set(query) != {"channel_id", "after_cursor", "limit"} or any(len(values) != 1 for values in query.values()):
                    raise ValueError("query shape")
                channel = query["channel_id"][0]
                after = int(query["after_cursor"][0])
                limit = int(query["limit"][0])
            except (KeyError, ValueError, IndexError) as error:
                raise Refusal(400, "invalid query") from error
            if UUID.fullmatch(channel) is None or after < 0 or limit != 1:
                raise Refusal(400, "invalid query")
            accepted = None
            with self.server.state.lock:
                for cursor, event_channel, event in self.server.state.accepted:
                    if cursor > after and event_channel == channel:
                        # api/ci.rs next_accepted_control: a non-empty result
                        # is gated on the caller's signer authority for the
                        # request's repository; an empty result is not.
                        repository = str(parse_content(event, "CI request")["target_repo_a"])
                        self.server.state.require_signer(repository, caller, int(time.time()))
                        accepted = {"channel_id": channel, "watch_cursor": cursor, "event": event}
                        break
        except Refusal as refusal:
            self._refuse(refusal)
            return
        self._json(200, {"accepted": accepted})

    def do_POST(self) -> None:
        raw = self._body()
        try:
            if self.path not in {"/events", "/query"} or raw is None:
                raise Refusal(404, "not found")
            caller = self._authenticate("POST", raw)
            if self.path == "/query":
                with self.server.state.lock:
                    found = query_events(self.server.state, caller, raw)
                self._json(200, found)
                return
            try:
                event = verify_event(json.loads(raw, object_pairs_hook=reject_duplicates))
            except (json.JSONDecodeError, RelayError) as error:
                raise Refusal(400, f"invalid event: {error}") from error
            with self.server.state.lock:
                _channel, accepted = admit_event(self.server.state, caller, event, int(time.time()))
        except Refusal as refusal:
            self._refuse(refusal)
            return
        self._json(200, {
            "event_id": event["id"], "accepted": accepted,
            "message": "stored" if accepted else "duplicate:stored",
        })

    def do_PUT(self) -> None:
        parsed = urlsplit(self.path)
        reserved_id: str | None = None
        try:
            if parsed.query or parsed.fragment:
                raise Refusal(404, "not found")
            evidence_path = parse_evidence_path(parsed.path)
            try:
                token = verify_nip98_preauth(
                    self.headers.get("Authorization", ""), "PUT",
                    self.server.state.origin + self.path,
                )
            except RelayError as error:
                raise Refusal(401, f"NIP-98: {error}") from error
            caller = str(token["pubkey"])
            reserved_id = str(token["id"])
            with self.server.state.lock:
                if reserved_id in self.server.state.seen_tokens \
                        or reserved_id in self.server.state.pending_tokens:
                    raise Refusal(401, "NIP-98: replayed authorization")
                self.server.state.pending_tokens.add(reserved_id)
                # api/ci.rs put_ci_evidence: the request event must exist and
                # the caller must be an authorized signer for its repository.
                request_event = self.server.state.events.get(str(evidence_path["request_id"]))
                channel = self.server.state.event_channels.get(str(evidence_path["request_id"]))
                if request_event is None or request_event.get("kind") != KIND_CI_REQUEST or channel is None:
                    raise Refusal(404, "CI request not found")
                request = parse_content(request_event, "CI request")
                if (
                    request.get("run_id") != evidence_path["run_id"]
                    or request.get("attempt") != evidence_path["attempt"]
                    or not isinstance(request.get("job_ids"), list)
                    or evidence_path["job_id"] not in request["job_ids"]
                ):
                    raise Refusal(404, "CI request not found")
                repository = str(request.get("target_repo_a"))
                self.server.state.require_signer(repository, caller, int(time.time()))
            raw = self._evidence_body()
            try:
                verified = verify_nip98(
                    self.headers.get("Authorization", ""), "PUT",
                    self.server.state.origin + self.path, raw,
                )
            except RelayError as error:
                raise Refusal(401, f"NIP-98: {error}") from error
            if verified["id"] != reserved_id or verified["pubkey"] != caller:
                raise Refusal(401, "NIP-98: identity changed")
            with self.server.state.lock:
                if reserved_id not in self.server.state.pending_tokens:
                    raise Refusal(401, "NIP-98: replayed authorization")
                store_evidence_object(self.server.state, evidence_path, request, str(channel), raw)
                self.server.state.pending_tokens.remove(reserved_id)
                self.server.state.seen_tokens.add(reserved_id)
                reserved_id = None
        except Refusal as refusal:
            self._refuse(refusal)
            return
        finally:
            if reserved_id is not None:
                with self.server.state.lock:
                    self.server.state.pending_tokens.discard(reserved_id)
        self._json(200, {
            "url": self.server.state.origin + parsed.path,
            "sha256": evidence_path["sha256"], "byte_length": len(raw),
        })


class RelayServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[int, int] | tuple[str, int], state: RelayState) -> None:
        super().__init__(address, Handler)
        self.state = state


def state_from_config(config: object, object_root: Path) -> RelayState:
    if (
        not isinstance(config, dict)
        or set(config) != {
            "origin", "channel", "ci_status_signer_pubkeys", "candidate_acceptance",
            "prior_acceptance", "acceptance_fixture", "export_generation",
        }
        or not isinstance(config["origin"], str)
        or not isinstance(config["channel"], dict)
        or set(config["channel"]) != {"id", "visibility", "members"}
        or not isinstance(config["channel"]["members"], dict)
        or not isinstance(config["ci_status_signer_pubkeys"], list)
        or not isinstance(config["acceptance_fixture"], dict)
        or not _positive_safe_integer(config["export_generation"])
    ):
        raise ValueError("relay public config rejected")
    channel = config["channel"]
    candidate = validate_acceptance_template(config["candidate_acceptance"], label="candidate")
    prior = None
    if config["prior_acceptance"] is not None:
        prior = validate_acceptance_template(config["prior_acceptance"], label="prior")
        if (
            set(candidate["api_ids"]) & set(prior["api_ids"])
            or {candidate["run_id"], candidate["failure_run_id"]}
                & {prior["run_id"], prior["failure_run_id"]}
        ):
            raise ValueError("candidate and prior acceptance identities overlap")
    fixture = config["acceptance_fixture"]
    if (
        fixture.get("run_id") != str(candidate["run_id"]).replace("-", "")
        or fixture.get("failure_run_id") != str(candidate["failure_run_id"]).replace("-", "")
        or fixture.get("request_digest") != candidate["api_ids"][0]
        or fixture.get("grant_event_id") != candidate["api_ids"][1]
        or fixture.get("failure_request_digest") != candidate["api_ids"][4]
        or fixture.get("failure_selector") != candidate["failure_selector"]
        or fixture.get("export_generation") != config["export_generation"]
        or fixture.get("export_subject") != candidate["export_subject"]
        or fixture.get("export_authorization_digest") != candidate["export_authorization_digest"]
        or config.get("origin") != EXPORT_ORIGIN
        or channel["members"].get(candidate["export_subject"]) not in MEMBER_ROLES
    ):
        raise ValueError("relay acceptance fixture differs from candidate templates")
    return RelayState(
        object_root, config["origin"], str(channel["id"]), str(channel["visibility"]),
        {str(key): str(role) for key, role in channel["members"].items()},
        {str(key) for key in config["ci_status_signer_pubkeys"]},
        candidate, prior, fixture, config["export_generation"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-config", type=Path, required=True)
    parser.add_argument("--object-root", type=Path, required=True)
    parser.add_argument("--fault-flag", type=Path, help="opt-in fault mode file; absent means no fault")
    arguments = parser.parse_args()
    try:
        config = json.loads(arguments.public_config.read_bytes())
        arguments.object_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        state = state_from_config(config, arguments.object_root)
        if arguments.fault_flag is not None and arguments.fault_flag.is_file():
            state.arm_fault(arguments.fault_flag)
    except (OSError, ValueError):
        return 1
    server = RelayServer(("127.0.0.1", 3443), state)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(arguments.certificate, arguments.private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
