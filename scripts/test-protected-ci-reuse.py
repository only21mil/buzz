#!/usr/bin/env python3
"""Exercise real reuse acquisition and workflow skip boundaries without GitHub."""
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location("reuse", Path(__file__).with_name("protected-ci-reuse.py"))
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)
BASE, SOURCE, LANDED, TREE = (letter * 40 for letter in "abcd")


class FakeAPI:
    def __init__(self, source, run, pr, landed, check):
        self.source, self.run, self.pr, self.landed, self.check = source, run, pr, landed, check
        self.main = LANDED
        self.job_conclusion = "success"
        self.artifacts = True
        self.corrupt_digest = False
        self.archive_extra = False
        self.evidence = []

    def one(self, endpoint):
        suffix = endpoint.removeprefix(reuse.PREFIX)
        if suffix == "/git/ref/heads/main":
            return {"object": {"sha": self.main}}
        if suffix == f"/git/commits/{LANDED}":
            return self.landed
        if suffix == "/pulls/42":
            return self.pr
        if suffix == "/actions/runs/100":
            return self.run
        raise AssertionError(endpoint)

    def archive(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as bundle:
            bundle.writestr("protected-ci-reuse.json", json.dumps(self.source))
            if self.archive_extra:
                bundle.writestr("surprise", "untrusted")
        return output.getvalue()

    def raw(self, endpoint):
        if endpoint == reuse.PREFIX + "/actions/artifacts/500/zip":
            return self.archive()
        raise AssertionError(endpoint)

    def pages(self, endpoint, kind):
        suffix = endpoint.removeprefix(reuse.PREFIX)
        if suffix == f"/commits/{LANDED}/pulls":
            return [self.pr]
        if suffix == f"/actions/workflows/ci.yml/runs?head_sha={SOURCE}&event=pull_request":
            return [self.run]
        if suffix == "/actions/runs/100/artifacts":
            return [{"id": 500, "name": "ci-reuse-1-unit-tests", "expired": False,
                     "digest": "sha256:" + ("0" * 64 if self.corrupt_digest else hashlib.sha256(self.archive()).hexdigest())}] if self.artifacts else []
        if suffix == f"/commits/{SOURCE}/check-runs?filter=all":
            return [self.check]
        if suffix == "/actions/runs/100/attempts/1/jobs":
            return [{"id": 80, "name": "Unit Tests", "status": "completed", "conclusion": self.job_conclusion}]
        raise AssertionError(endpoint)


class ReuseTests(unittest.TestCase):
    def setUp(self):
        self.context = {"environment": {"ImageVersion": "20260906.1"}, "versions": {"rustc": "1.91", "os_packages": "xorriso=1"}}
        self.authority = {"required_checks": [{"name": "Unit Tests", "integration_id": 15368}], "strict": True}
        self.run = {"id": 100, "run_attempt": 1, "status": "completed", "conclusion": "success", "event": "pull_request",
                    "path": reuse.WORKFLOW, "head_repository": {"full_name": reuse.REPO}, "head_sha": SOURCE,
                    "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "check_suite_id": 300}
        self.pr = {"number": 42, "merged": True, "merged_at": "2026-09-07T00:00:00Z", "state": "closed", "draft": False,
                   "merged_by": {"id": 7}, "head": {"sha": SOURCE, "repo": {"full_name": reuse.REPO}},
                   "base": {"ref": "main", "repo": {"full_name": reuse.REPO}}, "merge_commit_sha": LANDED}
        self.landed = {"sha": LANDED, "tree": {"sha": TREE}, "parents": [{"sha": BASE}, {"sha": SOURCE}]}
        self.source = {"schema_version": 1, "mode": "source", "repository": reuse.REPO, "job": "unit-tests",
                       "run_id": 100, "run_attempt": 1, "head_sha": SOURCE, "base_sha": BASE, "tested_sha": "e" * 40,
                       "tree_sha": TREE, "pull_request": 42, "workflow_sha256": hashlib.sha256(Path(reuse.WORKFLOW).read_bytes()).hexdigest(),
                       "context": copy.deepcopy(self.context), "authority": copy.deepcopy(self.authority)}
        self.check = {"id": 800, "name": "Unit Tests", "head_sha": SOURCE, "status": "completed", "conclusion": "success",
                      "app": {"id": 15368, "slug": "github-actions"}, "check_suite": {"id": 300},
                      "started_at": "2026-09-07T00:00:00Z", "completed_at": "2026-09-07T01:00:00Z",
                      "html_url": "https://github.com/only21mil/buzz/actions/runs/100/job/80",
                      "details_url": "https://github.com/only21mil/buzz/actions/runs/100/job/80"}
        self.api = FakeAPI(self.source, self.run, self.pr, self.landed, self.check)

    def acquire(self):
        with patch.object(reuse, "authority", return_value=self.authority), patch.object(reuse, "command", return_value=LANDED):
            return reuse.acquire_reuse(self.api, "unit-tests", LANDED, self.context)

    def refuse(self):
        with self.assertRaises((reuse.Refusal, reuse.receipt.ReceiptError)):
            self.acquire()

    def test_distinct_candidate_synthetic_and_landed_sha_reuses_identical_tree(self):
        result = self.acquire()
        self.assertEqual(result["mode"], "reused")
        self.assertEqual(result["head_sha"], LANDED)
        self.assertEqual(result["source_proof"]["head_sha"], SOURCE)
        self.assertEqual(result["source_proof"]["mode"], "source")
        self.assertEqual(result["protected_checks"][0]["check_run_id"], 800)

    def test_changed_tree(self):
        self.landed["tree"]["sha"] = "f" * 40
        self.refuse()

    def test_reversed_or_added_parent(self):
        self.landed["parents"].reverse()
        self.refuse()

    def test_workflow_change(self):
        self.source["workflow_sha256"] = "0" * 64
        self.refuse()

    def test_runner_context_change(self):
        self.context["environment"]["ImageVersion"] = "new-image"
        self.refuse()

    def test_resolved_dependency_change(self):
        self.context["versions"]["os_packages"] = "xorriso=2"
        self.refuse()

    def test_protection_change(self):
        self.authority["strict"] = False
        self.refuse()

    def test_wrong_repo_or_event(self):
        for field, bad in [("event", "workflow_dispatch"), ("path", ".github/workflows/untrusted.yml")]:
            with self.subTest(field=field):
                old = self.run[field]
                self.run[field] = bad
                self.refuse()
                self.run[field] = old

    def test_unmerged_or_wrong_pr_authority(self):
        for field, value in [("merged", False), ("merge_commit_sha", SOURCE), ("merged_by", None)]:
            with self.subTest(field=field):
                old = self.pr[field]
                self.pr[field] = value
                self.refuse()
                self.pr[field] = old

    def test_fork_refused(self):
        self.pr["head"]["repo"]["full_name"] = "attacker/buzz"
        self.refuse()

    def test_failed_or_pending_or_cancelled_source(self):
        for status, conclusion in [("completed", "failure"), ("in_progress", None), ("completed", "cancelled")]:
            self.run.update(status=status, conclusion=conclusion)
            self.refuse()

    def test_failed_job_despite_successful_run(self):
        self.api.job_conclusion = "failure"
        self.refuse()

    def test_failed_required_check_despite_successful_run(self):
        self.check["conclusion"] = "failure"
        self.refuse()

    def test_required_check_wrong_app_or_suite(self):
        self.check["app"]["id"] = 1
        self.refuse()
        self.check["app"]["id"] = 15368
        self.check["check_suite"]["id"] = 99
        self.refuse()

    def test_changed_run_attempt_cannot_reuse_old_artifact(self):
        self.source["run_attempt"] = 2
        self.refuse()

    def test_old_run_expired(self):
        self.run["updated_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).isoformat()
        self.refuse()

    def test_main_moved(self):
        self.api.main = "f" * 40
        self.refuse()

    def test_source_artifact_is_required_not_legacy_receipt_relabel(self):
        self.api.artifacts = False
        self.refuse()

    def test_reused_proof_cannot_become_source(self):
        self.source["mode"] = "reused"
        self.refuse()

    def test_corrupt_digest_and_extra_archive_file(self):
        self.api.corrupt_digest = True
        self.refuse()
        self.api.corrupt_digest = False
        self.api.archive_extra = True
        self.refuse()

    def test_workflow_keeps_exact_main_contexts_and_fresh_sensitive_checks(self):
        workflow = Path(reuse.WORKFLOW).read_text()
        blocks = dict(re.findall(r"(?ms)^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:|\Z)", workflow))
        for job in ("rust-lint", "unit-tests", "desktop-smoke-e2e"):
            block = blocks[job]
            self.assertIn("id: reuse", block)
            self.assertIn("checks: read", block)
            self.assertIn("if: steps.reuse.outputs.reused != 'true'", block)
            self.assertIn("Retain protected result provenance", block)
            self.assertNotIn("reused", re.search(r"(?m)^    if: (.*)$", block)[1])
        for job in ("security", "desktop-build-macos", "server-cross-compile", "mobile", "backend-integration", "relay-e2e"):
            self.assertNotIn("id: reuse", blocks[job])
        canary = Path(".github/workflows/relay_e2e_canary.yml").read_text()
        self.assertNotIn("protected-ci-reuse", canary)


if __name__ == "__main__":
    unittest.main()
