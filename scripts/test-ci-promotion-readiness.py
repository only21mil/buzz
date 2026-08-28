#!/usr/bin/env python3
"""Hermetic tests for ci-promotion-readiness.py."""

from __future__ import annotations

import copy
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("ci-promotion-readiness.py")
PRODUCER_SCRIPT = Path(__file__).with_name("populate-ci-promotion-relay-origin.py")
REPO_ROOT = SCRIPT.parent.parent
SPEC = importlib.util.spec_from_file_location("ci_promotion_readiness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
READINESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READINESS)
PRODUCER_SPEC = importlib.util.spec_from_file_location("ci_promotion_relay_origin", PRODUCER_SCRIPT)
assert PRODUCER_SPEC is not None and PRODUCER_SPEC.loader is not None
PRODUCER = importlib.util.module_from_spec(PRODUCER_SPEC)
PRODUCER_SPEC.loader.exec_module(PRODUCER)
NOW = 1_787_832_000
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
IMAGE_A = f"sha256:{'1' * 64}"
IMAGE_B = f"sha256:{'2' * 64}"
PRIOR_IMAGE = f"sha256:{'3' * 64}"
LOG_BYTES = b"canonical native CI log\n"
LOG_DIGEST = hashlib.sha256(LOG_BYTES).hexdigest()
ACTOR_SECRET = 3
RERUN_ACTOR_SECRET = 7
SIGNER_SECRET = 5


def xonly_pubkey(secret: int) -> str:
    point = READINESS.point_multiply(secret, READINESS.SECP256K1_G)
    assert point is not None
    return point[0].to_bytes(32, "big").hex()


def schnorr_sign(secret: int, message: bytes) -> str:
    point = READINESS.point_multiply(secret, READINESS.SECP256K1_G)
    assert point is not None
    adjusted = secret if point[1] % 2 == 0 else READINESS.SECP256K1_N - secret
    pubkey = point[0].to_bytes(32, "big")
    aux = b"\x00" * 32
    mask = READINESS.tagged_hash("BIP0340/aux", aux)
    nonce_input = bytes(a ^ b for a, b in zip(adjusted.to_bytes(32, "big"), mask))
    nonce = int.from_bytes(
        READINESS.tagged_hash("BIP0340/nonce", nonce_input + pubkey + message), "big"
    ) % READINESS.SECP256K1_N
    assert nonce != 0
    nonce_point = READINESS.point_multiply(nonce, READINESS.SECP256K1_G)
    assert nonce_point is not None
    if nonce_point[1] % 2:
        nonce = READINESS.SECP256K1_N - nonce
        nonce_point = READINESS.point_multiply(nonce, READINESS.SECP256K1_G)
        assert nonce_point is not None
    r = nonce_point[0].to_bytes(32, "big")
    challenge = int.from_bytes(
        READINESS.tagged_hash("BIP0340/challenge", r + pubkey + message), "big"
    ) % READINESS.SECP256K1_N
    signature = r + ((nonce + challenge * adjusted) % READINESS.SECP256K1_N).to_bytes(32, "big")
    return signature.hex()


def run(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def write_jsonl(path: Path, values: list[dict]) -> None:
    path.write_text("".join(json.dumps(value, sort_keys=True) + "\n" for value in values),
                    encoding="utf-8")
    path.chmod(0o600)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PromotionReadinessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "repo"
        self.evidence_dir = self.root / "evidence"
        self.repo.mkdir()
        self.evidence_dir.mkdir(mode=0o700)
        run(["git", "init", "-q"], self.repo)
        run(["git", "config", "user.name", "Test User"], self.repo)
        run(["git", "config", "user.email", "test@example.invalid"], self.repo)
        (self.repo / "source.txt").write_text("base\n", encoding="utf-8")
        run(["git", "add", "source.txt"], self.repo)
        run(["git", "commit", "-q", "-m", "base"], self.repo)
        self.base = run(["git", "rev-parse", "HEAD"], self.repo)
        (self.repo / "source.txt").write_text("candidate\n", encoding="utf-8")
        run(["git", "add", "source.txt"], self.repo)
        run(["git", "commit", "-q", "-m", "candidate"], self.repo)
        self.candidate = run(["git", "rev-parse", "HEAD"], self.repo)
        self.tree = run(["git", "rev-parse", "HEAD^{tree}"], self.repo)
        self.red_sha = "f" * 40 if self.candidate != "f" * 40 else "e" * 40
        timestamp = dt.datetime.fromtimestamp(NOW - 60, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")

        self.pre_freeze_path = self.evidence_dir / "pre-freeze.json"
        write_json(self.pre_freeze_path, {
            "schema_version": 1,
            "source": "pre-freeze",
            "repository": "only21mil/buzz",
            "head_sha": self.candidate,
            "base_sha": self.base,
            "timestamp": timestamp,
            "overall": "PASS",
            "checks": [{"name": "source", "status": "PASS"}],
        })
        self.protected_ci_path = self.evidence_dir / "protected-ci.json"
        write_json(self.protected_ci_path, {
            "schema_version": 1,
            "source": "protected-ci",
            "repository": "only21mil/buzz",
            "head_sha": self.candidate,
            "timestamp": timestamp,
            "overall": "PASS",
            "protected": True,
            "full_exact_head": True,
            "checks": [{"name": "required", "status": "PASS"}],
        })
        self.acceptance_path = self.evidence_dir / "acceptance-verdict.json"
        write_json(self.acceptance_path, {
            "candidate_sha": self.candidate,
            "security": {"passed": 17, "total": 17},
            "probes": {"passed_runs": 12, "total_runs": 12},
            "green": True,
            "missing": [],
            "failed": [],
            "sha_conflicts": [],
        })
        self.acceptance_records_path = self.evidence_dir / "acceptance-records.jsonl"
        records = []
        for number in range(1, 18):
            records.append(self.acceptance_record("security", f"TM-{number:02d}"))
        for probe in ("P-i", "P-ii", "P-iii", "P-iv", "P-v", "P-vi"):
            for run_number in (1, 2):
                records.append(self.acceptance_record("probe", probe, run=run_number))
        write_jsonl(self.acceptance_records_path, records)
        self.bundle = self.valid_bundle()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def acceptance_record(self, suite: str, test_id: str, *, run: int | None = None) -> dict:
        record = {
            "suite": suite,
            "test_id": test_id,
            "title": f"Canonical {test_id}",
            "candidate_sha": self.candidate,
            "pass": True,
            "evidence_ref": f"sha256:{DIGEST_A}",
            "executor": "hermetic-test",
            "host": "test.invalid",
            "started_at": NOW - 20,
            "finished_at": NOW - 10,
        }
        if run is not None:
            record["run"] = run
        return record

    def signed_event_evidence(
        self, run_id: str, *, tip_oid: str | None = None, retry: bool = False,
        terminal_state: str = "success", jobs: tuple[str, ...] = ("build",),
        rerun_job: str = "build", also_reruns: tuple[str, ...] = (),
        reruns: tuple[tuple[str, tuple[str, ...]], ...] | None = None,
        rerun_actor_secret: int = ACTOR_SECRET,
    ) -> dict:
        def fixed_id(label: str) -> str:
            return hashlib.sha256(f"{run_id}:{label}".encode()).hexdigest()

        actor = xonly_pubkey(ACTOR_SECRET)
        signer = xonly_pubkey(SIGNER_SECRET)
        candidate = tip_oid or self.candidate
        assert jobs and rerun_job in jobs and set(also_reruns) <= set(jobs) - {rerun_job}
        target_repo_a = f"30617:{actor}:buzz"
        workflow_id = "ci"
        workflow_digest = DIGEST_C
        channel_id = "46bba699-8251-43c7-943e-66be58376585"
        creation_counter = 0

        def tags_for(kind: int, content: dict) -> list[list[str]]:
            tags = [
                ["h", channel_id], ["a", content["target_repo_a"]], ["run", content["run_id"]],
                ["workflow", content["workflow_id"]], ["c", content["tip_oid"]],
                ["attempt", str(content["attempt"])],
            ]
            if kind in (46102, 46103, 46104):
                tags.append(["job", content["job_id"]])
            if kind != 46100:
                tags.append(["e", content["request_event_id"], "", "request"])
            if kind == 46103:
                tags.append(["x", content["log_sha256"]])
            elif kind == 46104:
                tags.append(["x", content["sha256"]])
            return tags

        def wire_event(kind: int, content: dict, secret: int, *, cursor: int | None = None) -> dict:
            nonlocal creation_counter
            creation_counter += 1
            pubkey = xonly_pubkey(secret)
            created_at = NOW - 500 + creation_counter
            raw_content = json.dumps(content, sort_keys=True, separators=(",", ":"))
            tags = tags_for(kind, content)
            serialized = json.dumps(
                [0, pubkey, created_at, kind, tags, raw_content], separators=(",", ":")
            ).encode()
            identifier = hashlib.sha256(serialized).hexdigest()
            event = {
                "id": identifier,
                "pubkey": pubkey,
                "created_at": created_at,
                "kind": kind,
                "tags": tags,
                "content": raw_content,
                "sig": schnorr_sign(secret, bytes.fromhex(identifier)),
                "stored": True,
            }
            if cursor is not None:
                event["watch_cursor"] = cursor
            return event

        rerun_specs = reruns if reruns is not None else (
            ((rerun_job, also_reruns),) if retry else ()
        )
        selected_attempts = {job_id: 1 for job_id in jobs}
        request_specs: list[tuple[int, list[str], int | None, int]] = [
            (1, list(jobs), None, ACTOR_SECRET)
        ]
        for selected_job, fanout in rerun_specs:
            assert selected_job in jobs and set(fanout) <= set(jobs) - {selected_job}
            parent_attempt = selected_attempts[selected_job]
            attempt = parent_attempt + 1
            assert all(selected_attempts[job_id] == parent_attempt for job_id in fanout)
            request_specs.append((attempt, [selected_job, *fanout], parent_attempt,
                                  rerun_actor_secret))
            for job_id in (selected_job, *fanout):
                selected_attempts[job_id] = attempt

        def request_content(
            request_index: int, attempt: int, active_jobs: list[str],
            parent_attempt: int | None, request_actor: str,
        ) -> dict:
            content = {
                    "schema_version": 1,
                    "request_type": "run" if request_index == 0 else "rerun",
                    "target_repo_a": target_repo_a,
                    "pr_root_event_id": fixed_id("pr-root"),
                    "pr_update_event_id": fixed_id("pr-update"),
                    "source_clone_url": "https://example.invalid/only21mil/buzz.git",
                    "immutable_source_ref": f"refs/buzz/{candidate}",
                    "tip_oid": candidate,
                    "source_branch": "sats/test",
                    "base_ref": "refs/heads/main",
                    "base_oid": self.base,
                    "workflow_id": workflow_id,
                    "workflow_digest": workflow_digest,
                    "job_ids": list(jobs) if request_index == 0 else [active_jobs[0]],
                    "run_id": run_id,
                    "attempt": attempt,
                    "trigger_event_id": fixed_id("pr-update"),
                    "actor": request_actor,
                    "timeout_seconds": 600,
                    "idempotency_key": f"idempotency-{run_id}-{request_index}-{attempt}",
                    "issued_at": NOW - 120,
                    "expires_at": NOW + 480,
            }
            if parent_attempt is not None:
                content["parent_attempt"] = parent_attempt
                content["parent_run_id"] = run_id
            return content

        requests = []
        for request_index, (attempt, active_jobs, parent_attempt, secret) in enumerate(request_specs):
            request_actor = xonly_pubkey(secret)
            requests.append(wire_event(
                46100,
                request_content(request_index, attempt, active_jobs, parent_attempt, request_actor),
                secret,
            ))
        events: list[dict] = []
        decoded_logs: dict[str, str] = {}
        final_refs: dict[str, tuple[int, str, str]] = {}
        cursor = 0

        def append(kind: int, content: dict) -> dict:
            nonlocal cursor
            cursor += 1
            event = wire_event(kind, content, SIGNER_SECRET, cursor=cursor)
            events.append(event)
            return event

        for request_index, ((attempt, active_jobs, parent_attempt, _), request) in enumerate(
            zip(request_specs, requests)
        ):
            request_event_id = request["id"]
            base_content = {
                "schema_version": 1, "request_event_id": request_event_id, "run_id": run_id,
                "workflow_id": workflow_id, "target_repo_a": target_repo_a, "tip_oid": candidate,
            }
            final_request = request_index == len(request_specs) - 1
            run_state = terminal_state if final_request else "failure"

            def run_status(sequence: int, status: str) -> dict:
                content = {
                    **base_content, "base_oid": self.base, "attempt": attempt, "sequence": sequence,
                    "state": status, "job_ids": active_jobs, "relay_signer": signer,
                }
                if status != "queued":
                    content["started_at"] = NOW - 30
                if status not in ("queued", "running"):
                    content["conclusion"] = status
                    content["finished_at"] = NOW - 1
                return content

            def job_status(job_id: str, sequence: int, status: str) -> dict:
                fanout = active_jobs[1:] if request_index > 0 and job_id == active_jobs[0] else []
                content = {
                    **base_content, "base_oid": self.base, "job_id": job_id,
                    "name": job_id.replace("_", " ").title(),
                    "attempt": attempt, "sequence": sequence, "state": status, "required": True,
                    "skip_policy": "forbid", "selected_job_instance": job_id,
                    "also_reruns": fanout,
                    "artifact_refs": [], "relay_signer": signer,
                }
                if parent_attempt is not None:
                    content["parent_attempt"] = parent_attempt
                if status != "queued":
                    content["started_at"] = NOW - 25
                if status not in ("queued", "running"):
                    content["conclusion"] = status
                    content["finished_at"] = NOW - 10
                return content

            append(46101, run_status(1, "queued"))
            append(46101, run_status(2, "running"))
            for job_id in active_jobs:
                append(46102, job_status(job_id, 1, "queued"))
                append(46102, job_status(job_id, 2, "running"))
                selected_final = selected_attempts[job_id] == attempt
                job_state = terminal_state if selected_final and final_request else (
                    "success" if selected_final else "failure"
                )
                terminal_job = job_status(job_id, 3, job_state)
                if selected_final:
                    log = append(46103, {
                        **base_content, "job_id": job_id, "attempt": attempt,
                        "log_sha256": LOG_DIGEST, "byte_length": len(LOG_BYTES),
                        "cap_bytes": 1024, "truncated": False,
                        "url": f"https://relay.example.invalid/ci/logs/{request_event_id}/{run_id}/{job_id}/{attempt}/{LOG_DIGEST}",
                        "created_at": NOW - 15, "relay_signer": signer,
                    })
                    decoded_logs[log["id"]] = base64.b64encode(LOG_BYTES).decode()
                    artifact = append(46104, {
                        **base_content, "job_id": job_id, "attempt": attempt,
                        "artifact_id": f"artifact-{job_id}-{attempt}", "name": "result.json",
                        "media_type": "application/json", "sha256": DIGEST_B, "byte_length": 64,
                        "url": (
                            f"https://relay.example.invalid/ci/artifacts/{request_event_id}/"
                            f"{run_id}/{job_id}/{attempt}/artifact-{job_id}-{attempt}/{DIGEST_B}"
                        ),
                        "created_at": NOW - 14, "relay_signer": signer,
                    })
                    terminal_job["log_ref"] = log["id"]
                    terminal_job["artifact_refs"] = [artifact["id"]]
                    final_refs[job_id] = (attempt, log["id"], artifact["id"])
                append(46102, terminal_job)
            if final_request:
                assert set(final_refs) == set(jobs)
                append(46105, {
                    **base_content, "attempt": attempt, "finalized_job_attempts": [
                        {"job_id": job_id, "attempt": final_refs[job_id][0],
                         "log_ref": final_refs[job_id][1],
                         "artifact_refs": [final_refs[job_id][2]]}
                        for job_id in jobs
                    ], "finalized_at": NOW - 8, "relay_signer": signer,
                })
                append(46106, {
                    **base_content, "base_oid": self.base, "workflow_digest": workflow_digest,
                    "attempt": attempt, "leases": [
                        {"job_id": job_id, "attempt": final_refs[job_id][0],
                         "lease_id": f"lease-{job_id}-{final_refs[job_id][0]}"}
                        for job_id in sorted(jobs)
                    ],
                    "lease_empty": True, "teardown_at": NOW - 5, "relay_signer": signer,
                })
            append(46101, run_status(3, run_state))

        evidence = {
            "channel_id": channel_id,
            "authorized_relay_signers": [signer],
            "requests": requests,
            "events": events,
            "decoded_logs": decoded_logs,
        }
        return PRODUCER.populate_event_evidence(
            evidence,
            PRODUCER.canonical_relay_origin("wss://relay.example.invalid/"),
            "fixture.event_evidence",
        )

    def valid_bundle(self) -> dict:
        staging_run_id = "11111111-1111-4111-8111-111111111111"
        canary_run_id = "22222222-2222-4222-8222-222222222222"
        red_run_id = "33333333-3333-4333-8333-333333333333"
        staging_evidence = self.signed_event_evidence(staging_run_id)
        canary_evidence = self.signed_event_evidence(canary_run_id, retry=True)
        red_evidence = self.signed_event_evidence(
            red_run_id, tip_oid=self.red_sha, terminal_state="failure"
        )
        actor = xonly_pubkey(ACTOR_SECRET)
        signer = xonly_pubkey(SIGNER_SECRET)
        log = {
            "authorized_status": 200,
            "unauthorized_status": 403,
            "redirects": 0,
            "sha256": LOG_DIGEST,
            "computed_sha256": LOG_DIGEST,
            "byte_count": len(LOG_BYTES),
            "byte_cap": 1024,
        }
        return {
            "schema_version": 1,
            "repository": "only21mil/buzz",
            "candidate_sha": self.candidate,
            "base_sha": self.base,
            "tree_sha": self.tree,
            "source": {"checkout_sha": self.candidate, "clean": True},
            "evidence_files": {
                "pre_freeze": {"path": str(self.pre_freeze_path), "sha256": digest(self.pre_freeze_path)},
                "protected_ci": {"path": str(self.protected_ci_path), "sha256": digest(self.protected_ci_path)},
                "acceptance_verdict": {"path": str(self.acceptance_path), "sha256": digest(self.acceptance_path)},
                "acceptance_records": {"path": str(self.acceptance_records_path),
                                       "sha256": digest(self.acceptance_records_path)},
            },
            "protected_ci": {
                "head_sha": self.candidate,
                "protected": True,
                "conclusion": "success",
                "contexts": [
                    {"name": "buzz-native-ci", "head_sha": self.candidate, "conclusion": "success",
                     "run_url": "https://ci.example.invalid/run/0"},
                    {"name": "build", "head_sha": self.candidate, "conclusion": "success",
                     "run_url": "https://ci.example.invalid/run/1"},
                    {"name": "test", "head_sha": self.candidate, "conclusion": "success",
                     "run_url": "https://ci.example.invalid/run/2"},
                ],
            },
            "tier2": {
                "eligible_commit": self.candidate,
                "checked_commit": self.candidate,
                "check_exit_code": 0,
                "verdict": "PASS",
                "reviewer": "claude:test-reviewer",
                "model": "claude-opus-5",
                "effort": "high",
                "lineage": "lineage-1",
                "state_sha256": DIGEST_A,
                "fingerprint": DIGEST_B,
                "prepared_at": NOW - 100,
                "reviewed_at": NOW - 50,
                "expires_at": NOW + 5_000,
            },
            "artifacts": {
                "image_ref": f"localhost/buzz-relay:{self.candidate}",
                "image_ids": [IMAGE_B, IMAGE_A],
                "running_image_id": IMAGE_A,
                "binary_sha256": DIGEST_C,
                "oci_revision": self.candidate,
                "required_migration": 35,
                "database_migration": 35,
            },
            "staging": {
                "candidate_sha": self.candidate,
                "absent_policy_status": 503,
                "configured_policy_status": 200,
                "root_executor_handoff": True,
                "advertised_bounds_sha256": DIGEST_A,
                "enforced_bounds_sha256": DIGEST_A,
                "scenarios": {
                    "success": "PASS",
                    "policy_refusal": "PASS",
                    "teardown_failure": "PASS",
                    "restart_recovery": "PASS",
                    "unaccepted_refusal": "PASS",
                },
                "event_evidence": staging_evidence,
                "log": copy.deepcopy(log),
            },
            "production_canary": {
                "candidate_sha": self.candidate,
                "accepted_executed": True,
                "unaccepted_refused": True,
                "event_evidence": canary_evidence,
                "retry": {
                    "request_id": canary_evidence["requests"][0]["id"],
                    "rerun_request_id": canary_evidence["requests"][1]["id"],
                    "first_run_id": canary_run_id,
                    "duplicate_run_id": canary_run_id,
                    "attempts": [1, 2],
                    "workspaces": ["workspace-1", "workspace-2"],
                    "terminal_events": 1,
                },
            },
            "deliberate_red": {
                "system_sha": self.candidate,
                "red_sha": self.red_sha,
                "accepted_commit": True,
                "required_check": "buzz-native-ci",
                "conclusion": "failure",
                "merge_allowed": False,
                "protected_rule": True,
                "terminal_events": 1,
                "first_run_id": red_run_id,
                "duplicate_run_id": red_run_id,
                "parity": {
                    "target_repo_a": f"30617:{actor}:buzz",
                    "workflow_id": "ci",
                    "workflow_digest": DIGEST_C,
                    "job_ids": ["build"],
                    "relay_signer": signer,
                },
                "event_evidence": red_evidence,
            },
            "deployment": {
                "commit_sha": self.candidate,
                "image_ref": f"localhost/buzz-relay:{self.candidate}",
                "running_image_id": IMAGE_A,
                "binary_sha256": DIGEST_C,
                "oci_revision": self.candidate,
                "database_migration": 35,
                "dump_before_swap": True,
                "dump_sha256": DIGEST_B,
                "readiness": True,
                "nip11": True,
                "started_at": NOW - 40,
                "swapped_at": NOW - 30,
                "finished_at": NOW - 20,
                "log": copy.deepcopy(log),
            },
            "rollback": {
                "compatible": {
                    "mode": "restored",
                    "current_migration": 35,
                    "prior_required_migration": 35,
                    "prior_image_id": PRIOR_IMAGE,
                    "prior_binary_sha256": DIGEST_A,
                    "prior_dump_sha256": DIGEST_B,
                    "restore_attempted": True,
                    "restored_image_id": PRIOR_IMAGE,
                    "restored_binary_sha256": DIGEST_A,
                    "restored_dump_sha256": DIGEST_B,
                    "readiness": True,
                    "nip11": True,
                },
                "advanced": {
                    "mode": "refused",
                    "current_migration": 36,
                    "prior_required_migration": 35,
                    "restore_attempted": False,
                    "reason": "migration_advanced",
                },
            },
            "landing": {
                "relay_sha": self.candidate,
                "mirror_sha": self.candidate,
                "merge_sha": self.candidate,
            },
        }

    @staticmethod
    def event_content(event: dict) -> dict:
        return json.loads(event["content"])

    @staticmethod
    def resign_event(event: dict, content: dict, *, secret: int = SIGNER_SECRET) -> None:
        event["content"] = json.dumps(content, sort_keys=True, separators=(",", ":"))
        serialized = json.dumps(
            [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
            separators=(",", ":"),
        ).encode()
        event["id"] = hashlib.sha256(serialized).hexdigest()
        event["sig"] = schnorr_sign(secret, bytes.fromhex(event["id"]))

    def invoke(self, bundle: dict, *, now: int = NOW) -> subprocess.CompletedProcess[str]:
        bundle_path = self.evidence_dir / "bundle.json"
        receipt_path = self.evidence_dir / "receipt.json"
        write_json(bundle_path, bundle)
        return subprocess.run(
            [sys.executable, str(SCRIPT),
             "--candidate-dir", str(self.repo),
             "--evidence", str(bundle_path),
             "--receipt", str(receipt_path),
             "--now", str(now)],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_refused(self, bundle: dict, message: str, *, now: int = NOW) -> None:
        result = self.invoke(bundle, now=now)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)

    def test_valid_bundle_is_deterministic_and_complete(self) -> None:
        first = self.invoke(self.bundle)
        self.assertEqual(first.returncode, 0, first.stderr)
        first_bytes = (self.evidence_dir / "receipt.json").read_bytes()
        second = self.invoke(self.bundle)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_bytes, (self.evidence_dir / "receipt.json").read_bytes())
        receipt = json.loads(first_bytes)
        self.assertEqual(receipt["overall"], "PASS")
        self.assertEqual(receipt["gates"]["threat_model"], {"passed": 17, "total": 17})
        self.assertEqual(receipt["gates"]["probes"], {"passed_runs": 12, "total_runs": 12})
        self.assertEqual(receipt["gates"]["staging_canary_parity"], "PASS")
        self.assertEqual(receipt["identities"]["relay_sha"], self.candidate)
        self.assertEqual(receipt["identities"]["mirror_sha"], self.candidate)
        kinds = [event["kind"] for event in self.bundle["staging"]["event_evidence"]["events"]]
        self.assertEqual(kinds.count(46101), 3)
        self.assertEqual(kinds.count(46102), 3)
        self.assertEqual(set(kinds), {46101, 46102, 46103, 46104, 46105, 46106})

    def test_json_schemas_are_parseable(self) -> None:
        for name in ("promotion-evidence.schema.json", "promotion-readiness-receipt.schema.json"):
            schema = json.loads((REPO_ROOT / "docs" / "ci" / name).read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        evidence_schema = json.loads(
            (REPO_ROOT / "docs" / "ci" / "promotion-evidence.schema.json").read_text(encoding="utf-8")
        )
        self.assertIn("signed_ci_event_evidence", evidence_schema["$defs"])
        self.assertEqual(
            evidence_schema["$defs"]["signed_ci_event"]["properties"]["kind"]["enum"],
            [46101, 46102, 46103, 46104, 46105, 46106],
        )
        self.assertNotIn("record_kinds", evidence_schema["$defs"])
        canary_properties = evidence_schema["properties"]["production_canary"]["properties"]
        self.assertNotIn("initial_concurrency", canary_properties)
        self.assertNotIn("enabled_concurrency", canary_properties)
        relay_schema = evidence_schema["$defs"]["signed_ci_event_evidence"]["properties"][
            "relay_url"
        ]
        self.assertEqual(relay_schema["pattern"], "^https?://[^/?#]+$")

    def test_relay_origin_producer_populates_every_live_evidence_section(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        for section in PRODUCER.SECTIONS:
            bundle[section]["event_evidence"].pop("relay_url")
        populated = PRODUCER.populate_promotion_evidence(
            bundle, "wss://Relay.Example.Invalid:443/"
        )
        for section in PRODUCER.SECTIONS:
            self.assertEqual(
                populated[section]["event_evidence"]["relay_url"],
                "https://relay.example.invalid",
            )
        result = self.invoke(populated)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_relay_origin_producer_cli_uses_config_and_writes_private_output(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        for section in PRODUCER.SECTIONS:
            bundle[section]["event_evidence"].pop("relay_url")
        source = self.evidence_dir / "unpopulated.json"
        output = self.evidence_dir / "populated.json"
        write_json(source, bundle)
        environment = os.environ.copy()
        environment["BUZZ_RELAY_URL"] = "ws://127.0.0.1:3000/"
        result = subprocess.run(
            [sys.executable, str(PRODUCER_SCRIPT), "--input", str(source), "--output", str(output)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        populated = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(all(
            populated[section]["event_evidence"]["relay_url"] == "http://127.0.0.1:3000"
            for section in PRODUCER.SECTIONS
        ))
        missing_environment = os.environ.copy()
        missing_environment.pop("BUZZ_RELAY_URL", None)
        missing = subprocess.run(
            [sys.executable, str(PRODUCER_SCRIPT), "--input", str(source),
             "--output", str(self.evidence_dir / "missing-config.json")],
            check=False,
            capture_output=True,
            text=True,
            env=missing_environment,
        )
        self.assertEqual(missing.returncode, 2)
        self.assertIn("no relay fallback", missing.stderr)

    def test_relay_origin_producer_refuses_missing_or_hostile_config(self) -> None:
        with self.assertRaisesRegex(PRODUCER.EvidenceError, "no relay fallback"):
            PRODUCER.configured_relay_origin(None, {})
        hostile = (
            "https://user@relay.example.invalid",
            "https://relay.example.invalid?token=secret",
            "https://relay.example.invalid#secret",
            "https://relay.example.invalid/path",
            "ftp://relay.example.invalid",
            " https://relay.example.invalid",
            "https://relay..example.invalid",
        )
        for value in hostile:
            with self.subTest(value=value):
                with self.assertRaises(PRODUCER.EvidenceError):
                    PRODUCER.canonical_relay_origin(value)

    def test_relay_origin_producer_refuses_conflicting_evidence(self) -> None:
        with self.assertRaisesRegex(PRODUCER.EvidenceError, "conflicts"):
            PRODUCER.populate_promotion_evidence(
                self.bundle, "https://other-relay.example.invalid"
            )

    def test_verifier_requires_the_canonical_relay_origin(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["staging"]["event_evidence"]["relay_url"] = \
            "https://relay.example.invalid:443"
        self.assert_refused(bundle, "canonical relay origin")

    def test_wrong_sha_is_refused(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["landing"]["mirror_sha"] = self.red_sha
        self.assert_refused(bundle, "landing mirror_sha")

    def test_wrong_image_is_refused(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["artifacts"]["running_image_id"] = PRIOR_IMAGE
        self.assert_refused(bundle, "not one of the built image IDs")

    def test_stale_tier2_review_is_refused(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["tier2"]["expires_at"] = NOW - 1
        self.assert_refused(bundle, "tier2 review is stale")

    def test_rollback_migration_limit_is_enforced(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["rollback"]["compatible"]["current_migration"] = 36
        self.assert_refused(bundle, "compatible rollback exceeds")

    def test_deliberate_red_must_block_merge(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["deliberate_red"]["merge_allowed"] = True
        self.assert_refused(bundle, "did not block merge")

    def test_deliberate_red_must_match_canary_parity(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["deliberate_red"]["parity"]["workflow_digest"] = DIGEST_A
        self.assert_refused(bundle, "deliberate-red parity")

    def test_signed_event_signer_binding_is_required(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = bundle["staging"]["event_evidence"]["events"][0]
        event["pubkey"] = DIGEST_C
        self.assert_refused(bundle, "canonical event ID mismatch")

    def test_status_sequence_must_be_gap_free(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = bundle["staging"]["event_evidence"]["events"][1]
        content = self.event_content(event)
        content["sequence"] = 3
        self.resign_event(event, content)
        self.assert_refused(bundle, "sequence is not gap-free")

    def test_attempt_binding_is_required(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["staging"]["event_evidence"]["events"]
                     if item["kind"] == 46103)
        content = self.event_content(event)
        content["attempt"] = 2
        self.resign_event(event, content)
        self.assert_refused(bundle, "attempt does not match signed request")

    def test_immutable_coordinate_binding_is_required(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["staging"]["event_evidence"]["events"]
                     if item["kind"] == 46106)
        content = self.event_content(event)
        content["tip_oid"] = self.red_sha
        self.resign_event(event, content)
        self.assert_refused(bundle, "tip_oid mismatch")

    def test_evidence_finalization_must_bind_durable_refs(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["staging"]["event_evidence"]["events"]
                     if item["kind"] == 46105)
        content = self.event_content(event)
        content["finalized_job_attempts"][0]["log_ref"] = DIGEST_C
        self.resign_event(event, content)
        self.assert_refused(bundle, "log_ref is not bound")

    def test_teardown_must_bind_exact_selected_graph(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["staging"]["event_evidence"]["events"]
                     if item["kind"] == 46106)
        content = self.event_content(event)
        content["leases"][0]["attempt"] = 2
        self.resign_event(event, content)
        self.assert_refused(bundle, "lease graph does not match")

    def test_terminal_success_must_follow_evidence_and_teardown(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        events = bundle["staging"]["event_evidence"]["events"]
        terminal = next(item for item in events
                        if item["kind"] == 46101 and self.event_content(item)["state"] == "success")
        finalized = next(item for item in events if item["kind"] == 46105)
        teardown = next(item for item in events if item["kind"] == 46106)
        terminal["watch_cursor"], finalized["watch_cursor"], teardown["watch_cursor"] = 8, 9, 10
        events.sort(key=lambda item: item["watch_cursor"])
        self.assert_refused(bundle, "terminal run was stored before")

    def test_unknown_event_kind_fails_closed(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["staging"]["event_evidence"]["events"]
                     if item["kind"] == 46104)
        event["kind"] = 46999
        self.resign_event(event, self.event_content(event))
        self.assert_refused(bundle, "not a promotion history kind")

    def test_ci_grant_kind_cannot_masquerade_as_run_history(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["staging"]["event_evidence"]["events"]
                     if item["kind"] == 46104)
        event["kind"] = 46107
        self.resign_event(event, self.event_content(event))
        self.assert_refused(bundle, "not a promotion history kind")

    def test_unknown_signed_field_fails_closed(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["staging"]["event_evidence"]["events"]
                     if item["kind"] == 46105)
        content = self.event_content(event)
        content["tombstone"] = True
        self.resign_event(event, content)
        self.assert_refused(bundle, "unknown fields")

    def test_unknown_status_state_fails_closed(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = bundle["staging"]["event_evidence"]["events"][0]
        content = self.event_content(event)
        content["state"] = "activated"
        self.resign_event(event, content)
        self.assert_refused(bundle, "state is unknown")

    def test_caller_signature_verified_claim_is_rejected(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["staging"]["event_evidence"]["requests"][0]["signature_verified"] = True
        self.assert_refused(bundle, "unknown fields")

    def test_canonical_event_id_is_recomputed(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["staging"]["event_evidence"]["events"][0]["id"] = DIGEST_A
        self.assert_refused(bundle, "canonical event ID mismatch")

    def test_schnorr_signature_is_verified(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["staging"]["event_evidence"]["events"][0]["sig"] = "0" * 128
        self.assert_refused(bundle, "Schnorr signature is invalid")

    def test_signed_tags_are_bound_to_content(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = bundle["staging"]["event_evidence"]["events"][0]
        event["tags"][0][1] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        self.resign_event(event, self.event_content(event))
        self.assert_refused(bundle, "h tag does not match signed content")

    def test_every_history_base_oid_is_top_level_bound(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = bundle["staging"]["event_evidence"]["events"][0]
        content = self.event_content(event)
        content["base_oid"] = self.red_sha
        self.resign_event(event, content)
        self.assert_refused(bundle, "base_oid mismatch")

    def test_skip_policy_cannot_change_inside_job_history(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["staging"]["event_evidence"]["events"]
                     if item["kind"] == 46102 and self.event_content(item)["sequence"] == 2)
        content = self.event_content(event)
        content["skip_policy"] = "allow"
        self.resign_event(event, content)
        self.assert_refused(bundle, "changed its immutable job manifest")

    def test_terminal_outcome_cannot_equivocate_with_state(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["staging"]["event_evidence"]["events"]
                     if item["kind"] == 46102 and self.event_content(item)["state"] == "success")
        content = self.event_content(event)
        content["conclusion"] = "failure"
        self.resign_event(event, content)
        self.assert_refused(bundle, "terminal outcome does not match state")

    def test_run_id_must_be_a_canonical_uuid(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = bundle["staging"]["event_evidence"]["requests"][0]
        content = self.event_content(event)
        content["run_id"] = "caller-chosen-run"
        self.resign_event(event, content, secret=ACTOR_SECRET)
        self.assert_refused(bundle, "must be a canonical UUID")

    def test_rerun_parent_attempt_is_signed_and_contiguous(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = bundle["production_canary"]["event_evidence"]["requests"][1]
        content = self.event_content(event)
        content["parent_attempt"] = 2
        self.resign_event(event, content, secret=ACTOR_SECRET)
        self.assert_refused(bundle, "parent_attempt is not contiguous")

    def test_selected_job_instance_is_immutable(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["staging"]["event_evidence"]["events"]
                     if item["kind"] == 46102 and self.event_content(item)["sequence"] == 2)
        content = self.event_content(event)
        content["selected_job_instance"] = "build_matrix_alt"
        self.resign_event(event, content)
        self.assert_refused(bundle, "changed its immutable job manifest")

    def test_signed_rerun_fanout_rejects_unknown_jobs(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        event = next(item for item in bundle["production_canary"]["event_evidence"]["events"]
                     if item["kind"] == 46102 and self.event_content(item)["attempt"] == 2)
        content = self.event_content(event)
        content["also_reruns"] = ["ghost"]
        self.resign_event(event, content)
        self.assert_refused(bundle, "also_reruns contains an unknown job")

    def test_mixed_job_attempt_ranges_are_returned_per_job(self) -> None:
        evidence = self.signed_event_evidence(
            "55555555-5555-4555-8555-555555555555",
            retry=True,
            jobs=("build", "lint"),
        )
        result = READINESS.validate_ci_event_evidence(
            evidence, self.candidate, self.base, "mixed", "success"
        )
        self.assertEqual(result["attempts"], [1, 2])
        self.assertEqual(result["job_attempts"], {"build": [1, 2], "lint": [1]})
        self.assertEqual(result["selected_job_attempts"], {"build": 2, "lint": 1})

    def test_signed_fanout_requires_the_fanout_jobs_correct_attempt(self) -> None:
        evidence = self.signed_event_evidence(
            "66666666-6666-4666-8666-666666666666",
            retry=True,
            jobs=("build", "lint"),
        )
        for event in evidence["events"]:
            if event["kind"] != 46102:
                continue
            content = self.event_content(event)
            if content["job_id"] == "build" and content["attempt"] == 2:
                content["also_reruns"] = ["lint"]
                self.resign_event(event, content)
        with self.assertRaisesRegex(READINESS.GateError, "rerun fanout"):
            READINESS.validate_ci_event_evidence(
                evidence, self.candidate, self.base, "mixed", "success"
            )

    def test_signed_fanout_accepts_all_jobs_at_the_rerun_attempt(self) -> None:
        evidence = self.signed_event_evidence(
            "77777777-7777-4777-8777-777777777777",
            retry=True,
            jobs=("build", "lint"),
            also_reruns=("lint",),
        )
        result = READINESS.validate_ci_event_evidence(
            evidence, self.candidate, self.base, "mixed", "success"
        )
        self.assertEqual(result["job_attempts"], {"build": [1, 2], "lint": [1, 2]})
        self.assertEqual(result["selected_job_attempts"], {"build": 2, "lint": 2})

    def test_distinct_jobs_may_each_have_attempt_two_requests(self) -> None:
        evidence = self.signed_event_evidence(
            "88888888-8888-4888-8888-888888888888",
            jobs=("build", "lint"),
            reruns=(("build", ()), ("lint", ())),
        )
        result = READINESS.validate_ci_event_evidence(
            evidence, self.candidate, self.base, "per-job", "success"
        )
        self.assertEqual(
            [self.event_content(request)["attempt"] for request in evidence["requests"]],
            [1, 2, 2],
        )
        self.assertEqual(result["job_attempts"], {"build": [1, 2], "lint": [1, 2]})
        self.assertEqual(result["selected_job_attempts"], {"build": 2, "lint": 2})

    def test_rerun_actor_may_differ_from_initial_actor(self) -> None:
        evidence = self.signed_event_evidence(
            "99999999-9999-4999-8999-999999999999",
            retry=True,
            rerun_actor_secret=RERUN_ACTOR_SECRET,
        )
        result = READINESS.validate_ci_event_evidence(
            evidence, self.candidate, self.base, "rerun-actor", "success"
        )
        actors = [self.event_content(request)["actor"] for request in evidence["requests"]]
        self.assertEqual(actors, [xonly_pubkey(ACTOR_SECRET), xonly_pubkey(RERUN_ACTOR_SECRET)])
        self.assertEqual(result["actor"], actors[0])

    def test_log_and_artifact_urls_reject_unsafe_or_unbound_locations(self) -> None:
        cases = {
            "off relay origin": ("off relay origin", lambda url: url.replace(
                "relay.example.invalid", "attacker.example.invalid"
            )),
            "forbidden credentials": (
                "forbidden credentials", lambda url: url.replace("https://", "https://user@")
            ),
            "forbidden query": ("forbidden query or fragment", lambda url: f"{url}?token=secret"),
            "forbidden fragment": ("forbidden query or fragment", lambda url: f"{url}#secret"),
            "wrong exact path": (
                "exact evidence path", lambda url: url.replace("/ci/", "/ci/wrong/", 1)
            ),
        }
        for kind, label in ((46103, "log"), (46104, "artifact")):
            for case, (expected_error, mutate) in cases.items():
                with self.subTest(kind=kind, case=case):
                    evidence = self.signed_event_evidence(
                        f"aaaaaaaa-aaaa-4aaa-8aaa-{kind:012d}"
                    )
                    event = next(item for item in evidence["events"] if item["kind"] == kind)
                    content = self.event_content(event)
                    content["url"] = mutate(content["url"])
                    self.resign_event(event, content)
                    with self.assertRaisesRegex(READINESS.GateError, expected_error):
                        READINESS.validate_ci_event_evidence(
                            evidence, self.candidate, self.base, label, "success"
                        )

    def test_decoded_log_bytes_must_match_signed_digest(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        logs = bundle["staging"]["event_evidence"]["decoded_logs"]
        log_id = next(iter(logs))
        logs[log_id] = base64.b64encode(b"x" * len(LOG_BYTES)).decode()
        self.assert_refused(bundle, "decoded log digest mismatch")

    def test_retry_section_binds_the_signed_rerun_request(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["production_canary"]["retry"]["rerun_request_id"] = DIGEST_A
        self.assert_refused(bundle, "canonical signed rerun request")

    def test_deliberate_red_is_bound_to_its_signed_red_history(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["deliberate_red"]["event_evidence"] = copy.deepcopy(
            bundle["staging"]["event_evidence"]
        )
        self.assert_refused(bundle, "tip_oid does not match candidate")

    def test_log_authentication_is_required(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["staging"]["log"]["unauthorized_status"] = 200
        self.assert_refused(bundle, "unauthorized request")

    def test_duplicate_request_must_be_idempotent(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["production_canary"]["retry"]["duplicate_run_id"] = \
            "44444444-4444-4444-8444-444444444444"
        self.assert_refused(bundle, "created a second run")

    def test_accepted_and_unaccepted_paths_are_required(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["production_canary"]["unaccepted_refused"] = False
        self.assert_refused(bundle, "unaccepted code path")

    def test_dirty_checkout_is_refused_before_receipt(self) -> None:
        (self.repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        self.assert_refused(self.bundle, "candidate checkout is dirty")

    def test_mismatched_protected_ci_receipt_is_refused(self) -> None:
        receipt = json.loads(self.protected_ci_path.read_text(encoding="utf-8"))
        receipt["head_sha"] = self.red_sha
        write_json(self.protected_ci_path, receipt)
        bundle = copy.deepcopy(self.bundle)
        bundle["evidence_files"]["protected_ci"]["sha256"] = digest(self.protected_ci_path)
        self.assert_refused(bundle, "head_sha does not match")

    def test_world_readable_evidence_is_refused(self) -> None:
        self.pre_freeze_path.chmod(0o644)
        self.assert_refused(self.bundle, "mode 0600")

    def test_incomplete_tm_probe_verdict_is_refused(self) -> None:
        verdict = json.loads(self.acceptance_path.read_text(encoding="utf-8"))
        verdict["security"]["passed"] = 16
        write_json(self.acceptance_path, verdict)
        bundle = copy.deepcopy(self.bundle)
        bundle["evidence_files"]["acceptance_verdict"]["sha256"] = digest(self.acceptance_path)
        self.assert_refused(bundle, "all 17 TM checks")

    def test_named_probe_record_is_required(self) -> None:
        records = self.acceptance_records_path.read_text(encoding="utf-8").splitlines()
        write_jsonl(self.acceptance_records_path, [json.loads(line) for line in records[:-1]])
        bundle = copy.deepcopy(self.bundle)
        bundle["evidence_files"]["acceptance_records"]["sha256"] = digest(self.acceptance_records_path)
        self.assert_refused(bundle, "six probes twice")

    def test_secret_value_is_not_logged(self) -> None:
        secret = "test-secret-must-never-appear"
        bundle = copy.deepcopy(self.bundle)
        bundle["artifacts"]["image_ref"] = secret
        result = self.invoke(bundle)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(secret, result.stdout + result.stderr)
        receipt = self.evidence_dir / "receipt.json"
        if receipt.exists():
            self.assertNotIn(secret, receipt.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
