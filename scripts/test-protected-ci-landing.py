#!/usr/bin/env python3
"""Hermetic provider/receipt tests for one qualification and no merge workflow."""
from __future__ import annotations
import base64
import copy
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parent.parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

m = load("landing", ROOT / "scripts/protected-ci-landing.py")
f = load("receipt_fixtures", ROOT / "scripts/test-protected-ci-receipt.py")
HEAD, BASE, LAND, TESTED, TREE = (c * 40 for c in "abcde")
NOW = dt.datetime(2026, 9, 1, 12, 2, tzinfo=dt.timezone.utc)
BINDINGS = {p: "f" * 64 for p in m.POLICY_FILES}
REQUIRED = sorted({"Backend Integration (relay e2e)", "Dead Token Reference Guard", "Desktop", "Desktop Build (macOS)",
                   "Desktop E2E Integration", "Desktop E2E Relay", "Desktop Release Candidate", "Detect Changed Paths",
                   "Mobile", "Relay E2E", "Rust Lint", "Security", "Unit Tests", "Web", "relay_e2e_canary"})

class Provider(f.FakeClient):
    def __init__(self):
        super().__init__()
        self.rules[0]["parameters"]["required_status_checks"] = [{"context": n, "integration_id": 15368} for n in REQUIRED]
        self.workflows = {}
        self.jobs = {}
        for n, (path, event) in enumerate(((m.CI, "pull_request"), (m.CANARY, "workflow_dispatch"), (m.DRC, "pull_request")), 1):
            run = {"id": n, "path": path, "event": event, "head_sha": HEAD, "run_attempt": 2 if n == 2 else 1,
                   "run_started_at": f.STAMP, "check_suite_id": n + 1000, "status": "completed", "conclusion": "success", "updated_at": f.COMPLETED,
                   "repository": {"full_name": m.r.REPOSITORY}, "head_repository": {"full_name": m.r.REPOSITORY}}
            self.workflows[path] = run
            names = [*m.JOBS.values(), *m.AGGREGATES] if n == 1 else ["relay_e2e_canary" if n == 2 else "Desktop Release Candidate"]
            self.jobs[n] = [{"id": n * 100 + i, "run_id": n, "run_attempt": run["run_attempt"], "head_sha": HEAD,
                             "name": name, "status": "completed", "conclusion": "success", "completed_at": f.COMPLETED,
                             "html_url": f"https://github.com/only21mil/buzz/actions/runs/{n}/job/{n * 100 + i}"}
                            for i, name in enumerate(names)]
        self.runs = []
        for jobs in self.jobs.values():
            for job in jobs:
                if job["name"] not in REQUIRED: continue
                check = f.check_run(job["name"], job["id"])
                check["check_suite"]["id"] = job["run_id"] + 1000
                check["html_url"] = check["details_url"] = job["html_url"]
                self.runs.append(check)
        self.source = f.receipt.build_receipt(self, 17, HEAD, "main")
        self.raw = f.receipt.canonical_json(self.source)
        self.pr.update(merged=True, state="closed", merge_commit_sha=LAND, merged_by={"id": 1})
        self.base_ref_sha = LAND
        self.commits = {sha: {"sha": sha, "tree": {"sha": TREE}, "parents": [{"sha": BASE}, {"sha": HEAD}]} for sha in (HEAD, LAND, TESTED)}
        self.epoch = ""
        self.advisory = "d" * 40
        self.proofs, self.artifacts, self.archives = {}, [], {}
        for key, name in m.JOBS.items():
            job = next(j for j in self.jobs[1] if j["name"] == name)
            versions = {k: "fixture" for k in ("python3", "rustc", "cargo", "just", "node", "pnpm", "flutter", "java", "gradle", "os_packages_sha256", "python_packages_sha256")}
            context = {"execution": "premerge-source-snapshot", "event": "pull_request", "base_ref": "main", "policy": m.POLICY,
                       "environment": {"RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "ImageVersion": "20260901.1", "BUZZ_CI_REUSE_EPOCH": ""},
                       "versions": versions}
            if key in {"backend-integration", "relay-e2e", "desktop-integration-1", "desktop-integration-2"}:
                context["service_images"] = {name: "sha256:" + "f" * 64 for name in ("buzz-postgres", "buzz-redis", "buzz-minio", "buzz-minio-init")}
            if key.startswith("server-"):
                context["cross_image"] = {"reference": f"ghcr.io/cross-rs/{key.removeprefix('server-')}@sha256:" + "d" * 64,
                                          "image_id": "sha256:" + "f" * 64}
            if key == "mobile": context["android_dependencies_sha256"] = "f" * 64
            if key == "security": context["advisory_sha"] = self.advisory
            self.proofs[key] = {"schema_version": 1, "mode": "source", "repository": m.r.REPOSITORY, "job": key,
                                "run_id": 1, "run_attempt": 1, "head_sha": HEAD, "base_sha": BASE, "pull_request": 17,
                                "tested_sha": TESTED, "tree_sha": TREE, "bindings": copy.deepcopy(BINDINGS), "context": context}
            self.artifacts.append({"id": job["id"], "name": f"qualification-1-{key}", "expired": False,
                                   "workflow_run": {"id": 1, "head_sha": HEAD}})
            self.pack(key)
        self.home, self.gh = Path("/nonexistent-fixture"), m.r.GH_PATH

    def pack(self, key):
        artifact = next(a for a in self.artifacts if a["name"].endswith("-" + key))
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("protected-ci-qualification.json", json.dumps(self.proofs[key]))
        raw = out.getvalue()
        artifact["digest"] = "sha256:" + m.digest_bytes(raw)
        self.archives[f"{m.PREFIX}/actions/artifacts/{artifact['id']}/zip"] = raw

    def runner(self, command, **kwargs):
        return subprocess.CompletedProcess(command, 0, self.archives[command[-1]], b"")

    def serve(self, endpoint):
        if endpoint == m.PREFIX + "/actions/variables/BUZZ_CI_REUSE_EPOCH":
            return {"name": "BUZZ_CI_REUSE_EPOCH", "value": self.epoch}
        if endpoint == "/repos/RustSec/advisory-db/git/ref/heads/main":
            return {"object": {"sha": self.advisory}}
        if "/actions/runs/" in endpoint:
            return copy.deepcopy(next(v for v in self.workflows.values() if v["id"] == int(endpoint.rsplit("/", 1)[1])))
        if "/git/commits/" in endpoint:
            return copy.deepcopy(self.commits[endpoint.rsplit("/", 1)[1]])
        return super().serve(endpoint)

    def pages(self, endpoint, kind):
        if kind == "runs":
            name = endpoint.split("/workflows/", 1)[1].split("/", 1)[0]
            return [copy.deepcopy(self.workflows[".github/workflows/" + name])]
        if kind == "jobs": return copy.deepcopy(self.jobs[int(endpoint.split("/runs/", 1)[1].split("/", 1)[0])])
        if kind == "artifacts": return copy.deepcopy(self.artifacts)
        return super().pages(endpoint, kind)

class LandingTests(unittest.TestCase):
    def setUp(self):
        self.p = Provider()
        self.stack = __import__("contextlib").ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.dict(os.environ, {"GH_TOKEN": "public-fixture"}))
        self.stack.enter_context(mock.patch.object(m, "verify_policy_bytes"))
        self.stack.enter_context(mock.patch.object(m, "bindings", return_value=BINDINGS))
        self.canonical = self.stack.enter_context(mock.patch.object(m, "canonical_main", return_value={"repository": m.CANONICAL, "ref": "refs/heads/main", "sha": LAND}))
        self.desktop = self.stack.enter_context(mock.patch.object(m, "desktop_identity", return_value={"mode": "executed", "check": "desktop_release.py verify-main", "head_sha": LAND}))

    def acquire(self):
        return m.acquire(self.p, LAND, self.p.raw, HEAD, BASE, NOW)

    def test_whole_source_accepted_and_receipt_replayed_without_rewriting(self):
        before = bytes(self.p.raw)
        result = self.acquire()
        self.assertEqual(base64.b64decode(result["source_receipt_bytes"]), before)
        self.assertEqual(len(result["qualification"]["jobs"]), len(m.JOBS))
        self.assertTrue(all(x["source_check"]["head_sha"] == HEAD for x in result["qualification"]["checks"]))
        self.assertFalse(result["full_exact_head"])
        self.assertTrue(result["full_verified_landing"])
        self.assertEqual(m.validate(result, m.r.REPOSITORY, LAND, "main", NOW, 86400), result)
        self.assertEqual(self.desktop.call_args.args, (LAND,))
        self.assertEqual(self.canonical.call_count, 2)

    def test_verified_landing_matches_discriminated_receipt_schema(self):
        checker = f.receipt.shutil.which("check-jsonschema")
        self.assertIsNotNone(checker)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(m.r.canonical_json(self.acquire()))
            result = subprocess.run([checker, "--schemafile", str(f.SCHEMA), str(path)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_identity_context_and_authority_refusals(self):
        mutations = {
            "candidate": lambda p: p.pr["head"].update(sha="9" * 40),
            "canonical mirror": lambda p: setattr(p, "base_ref_sha", HEAD),
            "parents": lambda p: p.commits[LAND].update(parents=[{"sha": HEAD}, {"sha": BASE}]),
            "source tree": lambda p: p.commits[HEAD]["tree"].update(sha="9" * 40),
            "tested tree": lambda p: p.commits[TESTED]["tree"].update(sha="9" * 40),
            "tested parents": lambda p: p.commits[TESTED].update(parents=[{"sha": HEAD}, {"sha": BASE}]),
            "workflow": lambda p: p.workflows[m.CI].update(path=m.DRC),
            "workflow event": lambda p: p.workflows[m.CI].update(event="push"),
            "untrusted fork": lambda p: p.workflows[m.CI]["head_repository"].update(full_name="evil/buzz"),
            "stale run": lambda p: p.workflows[m.CI].update(updated_at="2026-08-28T12:00:00Z"),
            "failed run": lambda p: p.workflows[m.CI].update(conclusion="failure"),
            "new attempt": lambda p: p.workflows[m.CANARY].update(run_attempt=3),
            "epoch": lambda p: setattr(p, "epoch", "changed"),
            "advisories": lambda p: setattr(p, "advisory", "9" * 40),
            "required app": lambda p: p.rules[0]["parameters"]["required_status_checks"][0].update(integration_id=9),
            "ruleset": lambda p: setattr(p, "ruleset_enforcement", "disabled"),
            "archive digest": lambda p: p.artifacts[0].update(digest="sha256:" + "0" * 64),
            "missing proof": lambda p: p.artifacts.pop(),
            "expired proof": lambda p: p.artifacts[0].update(expired=True),
            "artifact run": lambda p: p.artifacts[0]["workflow_run"].update(id=900),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                self.p = Provider()
                mutate(self.p)
                with self.assertRaises(m.r.ReceiptError): self.acquire()

    def test_source_proof_refusals(self):
        mutations = {
            "relabeled": lambda p: p.update(mode="reused"),
            "source SHA": lambda p: p.update(head_sha=LAND),
            "base SHA": lambda p: p.update(base_sha=LAND),
            "attempt": lambda p: p.update(run_attempt=2),
            "workflow bytes": lambda p: p["bindings"].update({m.CI: "0" * 64}),
            "policy": lambda p: p["context"].update(policy="unchecked"),
            "context event": lambda p: p["context"].update(event="push"),
            "dependency proof": lambda p: p["bindings"].clear(),
            "toolchain": lambda p: p["context"]["versions"].pop("python3"),
            "runner": lambda p: p["context"]["environment"].pop("ImageVersion"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                self.p = Provider()
                mutate(self.p.proofs["changes"])
                self.p.pack("changes")
                with self.assertRaises(m.r.ReceiptError): self.acquire()

    def test_service_and_compiler_image_evidence_is_required(self):
        def verify(key):
            job = next(job for job in self.p.jobs[1] if job["name"] == m.JOBS[key])
            m.verify_source_proof(self.p.proofs[key], key, job, self.p.workflows[m.CI],
                                  self.p.source, TREE, BINDINGS, "")
        for key in ("backend-integration", "relay-e2e", "desktop-integration-1", "desktop-integration-2"):
            for bad in (None, {}, {"buzz-postgres": "sha256:" + "f" * 64},
                        {name: "latest" for name in ("buzz-postgres", "buzz-redis", "buzz-minio", "buzz-minio-init")},
                        {name: None for name in ("buzz-postgres", "buzz-redis", "buzz-minio", "buzz-minio-init")},
                        {name: "sha256:" + "f" * 64 for name in ("buzz-postgres", "buzz-redis", "buzz-minio")}):
                with self.subTest(job=key, images=bad):
                    self.p = Provider()
                    self.p.proofs[key]["context"]["service_images"] = bad
                    with self.assertRaises(m.r.ReceiptError): verify(key)
        for key in ("server-x86_64-unknown-linux-musl", "server-aarch64-unknown-linux-musl"):
            for bad in (None, {}, {"reference": "latest", "image_id": "sha256:" + "f" * 64},
                        {"reference": "ghcr.io/cross-rs/wrong@sha256:" + "d" * 64, "image_id": "sha256:" + "f" * 64},
                        {"reference": f"ghcr.io/cross-rs/{key.removeprefix('server-')}@sha256:" + "d" * 64,
                         "image_id": None}):
                with self.subTest(job=key, image=bad):
                    self.p = Provider()
                    self.p.proofs[key]["context"]["cross_image"] = bad
                    with self.assertRaises(m.r.ReceiptError): verify(key)

    def test_failed_skipped_cancelled_pending_stale_or_ambiguous_latest_job(self):
        for mode in ("failure", "skipped", "cancelled", "pending", "stale", "ambiguous", "wrong source"):
            with self.subTest(mode=mode):
                self.p = Provider()
                job = copy.deepcopy(next(j for j in self.p.jobs[1] if j["name"] == "Desktop Smoke E2E (1)"))
                self.p.workflows[m.CI]["run_attempt"] = 2
                job["id"] += 10000
                job["run_attempt"] = 2
                if mode in ("failure", "skipped", "cancelled"): job["conclusion"] = mode
                if mode == "pending": job["status"] = "in_progress"
                if mode == "stale": job["completed_at"] = "2026-08-20T00:00:00Z"
                if mode == "wrong source": job["head_sha"] = LAND
                self.p.jobs[1].append(job)
                if mode == "ambiguous": self.p.jobs[1].append(copy.deepcopy(job))
                with self.assertRaises(m.r.ReceiptError): self.acquire()

    def test_successful_earlier_job_attempt_retained(self):
        self.p.workflows[m.CI]["run_attempt"] = 2
        result = self.acquire()
        self.assertEqual(result["qualification"]["jobs"][0]["source_job"]["run_attempt"], 1)
        self.assertEqual(result["qualification"]["workflow_runs"][m.CI]["run_attempt"], 2)

    def test_receipt_tampering_is_refused(self):
        valid = self.acquire()
        for field in ("head_sha", "source_receipt_sha256", "canonical", "landing_checks", "qualification", "evidence"):
            with self.subTest(field=field):
                value = copy.deepcopy(valid)
                if field == "canonical": value[field]["sha"] = HEAD
                elif field == "landing_checks": value[field] = []
                elif field == "qualification": value[field]["landed"]["parents"].reverse()
                elif field == "evidence": next(iter(value[field]["bodies"].values()))["id"] = 999
                else: value[field] = "0" * 40
                with self.assertRaises(m.r.ReceiptError): m.validate(value, m.r.REPOSITORY, LAND, "main", NOW, 86400)

    def test_canonical_refusal_and_desktop_refusal_stop_acquisition(self):
        for check in (self.canonical, self.desktop):
            check.side_effect = m.r.GateError("identity drift")
            with self.assertRaises(m.r.ReceiptError): self.acquire()
            check.side_effect = None

    def test_later_rerun_of_older_run_cannot_hide_behind_newer_success(self):
        newer = copy.deepcopy(self.p.workflows[m.CI])
        newer.update(id=2, run_started_at="2026-09-01T12:00:30Z", updated_at="2026-09-01T12:01:00Z")
        for status, conclusion in (("completed", "failure"), ("completed", "cancelled"),
                                   ("in_progress", None), ("queued", None)):
            with self.subTest(status=status, conclusion=conclusion):
                older = copy.deepcopy(self.p.workflows[m.CI])
                older.update(id=1, run_attempt=2, run_started_at="2026-09-01T12:01:00Z", updated_at="2026-09-01T12:01:30Z", status=status, conclusion=conclusion)
                api = mock.Mock()
                api.pages.return_value = [newer, older]
                api.one.side_effect = [newer, older]
                with self.assertRaises(m.r.ReceiptError): m.source_run(api, m.CI, "pull_request", HEAD, NOW)
        older.update(status="completed", conclusion="success")
        api.pages.side_effect = [[newer, older], [{"run_id": 2, "run_attempt": 1, "status": "completed", "completed_at": "2026-09-01T12:00:45Z"}]]
        api.one.side_effect = [newer, older]
        self.assertEqual(m.source_run(api, m.CI, "pull_request", HEAD, NOW)["id"], 1)
        api.pages.side_effect = [[newer, older], [{"run_id": 2, "run_attempt": 1, "status": "completed", "completed_at": "2026-09-01T12:01:15Z"}]]
        api.one.side_effect = [newer, older]
        with self.assertRaises(m.r.ReceiptError): m.source_run(api, m.CI, "pull_request", HEAD, NOW)
        newer["run_started_at"] = older["run_started_at"]
        api.pages.side_effect = [[newer, older]]
        api.one.side_effect = [newer, older]
        with self.assertRaises(m.r.ReceiptError): m.source_run(api, m.CI, "pull_request", HEAD, NOW)

    def test_live_reverify_rechecks_source_and_both_landing_identities(self):
        value = self.acquire()
        class FixedClock(dt.datetime):
            @classmethod
            def now(cls, tz=None): return NOW
        with mock.patch.object(m.dt, "datetime", FixedClock):
            m.reverify(value, self.p)
            self.assertEqual(self.desktop.call_count, 2)
            self.assertEqual(self.canonical.call_count, 4)
            self.p.workflows[m.CI]["conclusion"] = "failure"
            with self.assertRaises(m.r.ReceiptError): m.reverify(value, self.p)

    def test_complete_source_coverage_is_checked_before_merge(self):
        self.p.pr = f.pr_value()
        self.p.base_ref_sha = BASE
        result = m.verify_candidate(self.p, HEAD, BASE, self.p.raw, NOW)
        self.assertEqual(result["candidate_sha"], HEAD)
        self.assertNotIn("landed", result)
        self.assertEqual(self.canonical.call_args.args, (BASE,))
        self.desktop.assert_not_called()
        self.p.artifacts.pop()
        with self.assertRaises(m.r.ReceiptError): m.verify_candidate(self.p, HEAD, BASE, self.p.raw, NOW)

    def test_deliberate_successful_retry_updates_provider_proof_not_original_receipt(self):
        original = bytes(self.p.raw)
        self.p.workflows[m.CI]["run_attempt"] = 2
        job = copy.deepcopy(next(j for j in self.p.jobs[1] if j["name"] == "Security"))
        job.update(id=999, run_attempt=2, html_url="https://github.com/only21mil/buzz/actions/runs/1/job/999")
        self.p.jobs[1].append(job)
        check = copy.deepcopy(next(c for c in self.p.runs if c["name"] == "Security"))
        check.update(id=999, html_url=job["html_url"], details_url=job["html_url"])
        self.p.runs.append(check)
        artifact = next(a for a in self.p.artifacts if a["name"] == "qualification-1-security")
        artifact["name"] = "qualification-2-security"
        self.p.proofs["security"]["run_attempt"] = 2
        self.p.pack("security")
        result = self.acquire()
        security = next(j for j in result["qualification"]["jobs"] if j["job"] == "security")
        self.assertEqual(security["source_job"]["run_attempt"], 2)
        self.assertEqual(base64.b64decode(result["source_receipt_bytes"]), original)

    def test_unreadable_epoch_is_not_treated_as_an_unset_epoch(self):
        api = mock.Mock()
        api.one.side_effect = [{"message": "Not Found"}, {"permissions": {"admin": False}}]
        with self.assertRaises(m.r.ReceiptError): m.current_epoch(api)
        api.one.side_effect = [{"message": "Not Found"}, {"permissions": {"admin": True}}]
        self.assertEqual(m.current_epoch(api), "")

    def test_entrypoint_loads_only_exact_committed_helper_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            for name in ("protected-ci-receipt.py", "protected-ci-landing.py"):
                (root / "scripts" / name).write_bytes((ROOT / "scripts" / name).read_bytes())
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
            git("init", "-q")
            git("add", "scripts")
            git("-c", "user.name=Receipt Test", "-c", "user.email=fixture@example.invalid",
                "-c", "core.hooksPath=/dev/null", "commit", "-q", "--no-gpg-sign", "-s", "-m", "fixture")
            head = git("rev-parse", "HEAD")
            entrypoint = load("entrypoint", root / "scripts/protected-ci-receipt.py")
            module = entrypoint.landing_module(head)
            self.assertIs(module.r.GateError, entrypoint.GateError)
            (root / "scripts/protected-ci-landing.py").write_text("raise RuntimeError('must never execute')\n")
            with self.assertRaises(entrypoint.GateError): entrypoint.landing_module(head)

    def test_no_automatic_main_push_workflow_and_full_premerge_cross_link(self):
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            block = re.search(r"(?ms)^  push:\n(.*?)(?=^  [a-z_]+:|^\S|\Z)", path.read_text())
            if not block: continue
            value = block[1]
            self.assertNotRegex(value, r"branches:.*main", path.name)
            self.assertTrue("tags:" in value or "branches: [release]" in value, path.name)
        ci = (ROOT / m.CI).read_text()
        self.assertIn("CARGO_CMD: build", ci)
        self.assertNotIn("&& 'check' || 'build'", ci)
        self.assertEqual(ci.count("Capture successful qualification inputs"), 15)
        self.assertNotIn("  push:", (ROOT / m.DRC).read_text())
        self.assertIn("module.verify_main", (ROOT / "scripts/protected-ci-landing.py").read_text())


class BootstrapTests(unittest.TestCase):
    def test_each_landing_test_job_installs_its_schema_checker_first(self):
        blocks = dict(re.findall(r"(?ms)^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:|\Z)", (ROOT / m.CI).read_text()))
        covered = []
        for job, block in blocks.items():
            test = re.search(r"(?m)^        run: python3 scripts/test-protected-ci-landing.py$", block)
            if test is None: continue
            covered.append(job)
            self.assertRegex(block[:test.start()], r"(?m)^        run: python3 -m pip install [^\n]*check-jsonschema==0\.38\.0$", job)
        self.assertIn("changes", covered)

    def epoch_transport(self, directory, *, status=404, code=1, body=None, admin=True,
                        repo_status=200, repo_code=0, headers=True, raw_body=None):
        """Exercise real subprocess exit/stdout handling without a network or token."""
        root = Path(directory)
        epoch = m.PREFIX + "/actions/variables/BUZZ_CI_REUSE_EPOCH"
        body = {"message": "Not Found", "status": "404"} if body is None else body
        def response(http_status, value):
            header = (f"X-GitHub-Request-Id: fixture\r\nDate: {f.HTTP_DATE}\r\n" if headers else "")
            payload = json.dumps(value) if raw_body is None else raw_body
            return (f"HTTP/2.0 {http_status} fixture\r\n{header}\r\n" + payload).encode()
        responses = {epoch: [code, response(status, body).decode()],
                     m.PREFIX: [repo_code, response(repo_status, {"permissions": {"admin": admin}}).decode()]}
        executable = root / "gh"
        executable.write_text(f"#!{sys.executable}\n" +
                              "import json, pathlib, sys\n" +
                              f"responses = {responses!r}\n" +
                              "code, output = responses[sys.argv[-1]]\n" +
                              "pathlib.Path(__file__).with_suffix('.calls').open('a').write(sys.argv[-1] + '\\n')\n" +
                              "sys.stdout.buffer.write(output.encode())\n" +
                              "sys.stderr.write('gh: Not Found (HTTP 404)' if code else '')\n" +
                              "sys.exit(code)\n")
        executable.chmod(0o700)
        return m.r.GhClient(str(executable))

    def test_epoch_404_exit_one_requires_independent_admin_authority(self):
        for admin in (True, False, None, "true"):
            with self.subTest(admin=admin), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, {"GH_TOKEN": "public-fixture", "XDG_STATE_HOME": directory}, clear=True):
                client = self.epoch_transport(directory, admin=admin)
                if admin is True:
                    self.assertEqual(m.current_epoch(m.Evidence(client)), "")
                    self.assertEqual([request["status"] for request in client.requests], [404, 200])
                else:
                    with self.assertRaises(m.r.GateError): m.current_epoch(m.Evidence(client))
                self.assertEqual((Path(directory) / "gh.calls").read_text().splitlines(),
                                 [m.PREFIX + "/actions/variables/BUZZ_CI_REUSE_EPOCH", m.PREFIX])

    def test_epoch_transport_refuses_other_failures_and_malformed_missing_response(self):
        cases = [{"status": status} for status in (401, 403, 429, 500)]
        cases += [{"code": 2}, {"code": 4}, {"status": 200}, {"status": 200, "code": 0}, {"headers": False},
                  {"body": []}, {"body": {"message": "Forbidden"}},
                  {"body": {"message": "Not Found", "status": "403"}},
                  {"body": {"message": "Not Found", "value": "hidden"}},
                  {"repo_status": 404, "repo_code": 1}, {"repo_code": 1}, {"raw_body": "{"}]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, {"GH_TOKEN": "public-fixture", "XDG_STATE_HOME": directory}, clear=True):
                client = self.epoch_transport(directory, **case)
                with self.assertRaises(m.r.ProviderError): m.current_epoch(m.Evidence(client))

    def test_present_epoch_uses_successful_transport_without_admin_fallback(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(os.environ, {"GH_TOKEN": "public-fixture", "XDG_STATE_HOME": directory}, clear=True):
            client = self.epoch_transport(directory, status=200, code=0,
                                          body={"name": "BUZZ_CI_REUSE_EPOCH", "value": "rotation-2"})
            self.assertEqual(m.current_epoch(m.Evidence(client)), "rotation-2")
            self.assertEqual(len(client.requests), 1)

    def capture_environment(self, directory):
        event = Path(directory) / "event.json"
        event.write_text(json.dumps({"pull_request": f.pr_value()}))
        return {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event),
                "GITHUB_REPOSITORY": m.r.REPOSITORY, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "ImageVersion": "fixture"}

    def test_relay_capture_resolves_all_four_service_containers(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(os.environ, self.capture_environment(directory), clear=True), \
             mock.patch.object(m, "command_versions", return_value={}), mock.patch.object(m, "git", return_value=HEAD), \
             mock.patch.object(m, "bindings", return_value=BINDINGS), \
             mock.patch.object(m, "run", return_value=("sha256:" + "f" * 64).encode()) as run:
            captured = m.capture("relay-e2e")
            names = ("buzz-postgres", "buzz-redis", "buzz-minio", "buzz-minio-init")
            self.assertEqual(captured["context"].get("service_images"), {name: "sha256:" + "f" * 64 for name in names})
            self.assertEqual(run.call_args_list, [mock.call(["docker", "inspect", "--format={{.Image}}", name]) for name in names])

    def test_actual_cross_build_step_pins_and_captures_the_compiler_image(self):
        workflow = (ROOT / m.CI).read_text()
        block = workflow.split("      - name: Build server binaries\n", 1)[1].split("      - name:", 1)[0]
        command = textwrap.dedent(block.split("        run: |\n", 1)[1]).strip()
        for target in ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"):
            for resolution in ("valid", "mutable", "wrong target"):
                with self.subTest(target=target, resolution=resolution), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    reference = f"ghcr.io/cross-rs/{target}@sha256:" + "d" * 64
                    resolved = reference if resolution == "valid" else (f"ghcr.io/cross-rs/{target}:0.2.5" if resolution == "mutable" else reference.replace(target, "wrong"))
                    image_id = "sha256:" + "f" * 64
                    image_variable = "CROSS_TARGET_" + target.upper().replace("-", "_") + "_IMAGE"
                    (root / "docker").write_text(f"#!{sys.executable}\n" +
                        "import sys\n" +
                        f"expected = {{('pull', 'ghcr.io/cross-rs/{target}:0.2.5'): '', " +
                        f"('image', 'inspect', '--format', '{{{{index .RepoDigests 0}}}}', 'ghcr.io/cross-rs/{target}:0.2.5'): {resolved!r}, " +
                        f"('image', 'inspect', '--format={{{{.Id}}}}', {reference!r}): {image_id!r}}}\n" +
                        "assert tuple(sys.argv[1:]) in expected, sys.argv\n" +
                        "print(expected[tuple(sys.argv[1:])])\n")
                    (root / "cross").write_text(f"#!{sys.executable}\n" +
                        "import os, pathlib, sys\n" +
                        f"assert os.environ[{image_variable!r}] == {reference!r}\n" +
                        f"assert sys.argv[1:5] == ['build', '--release', '--target', {target!r}]\n" +
                        "pathlib.Path(__file__).with_suffix('.called').write_text('linked once')\n")
                    for name in ("docker", "cross"): (root / name).chmod(0o700)
                    environment = self.capture_environment(directory)
                    environment.update(PATH=directory, TARGET=target, CARGO_CMD="build", GITHUB_ENV=str(root / "github-env"))
                    result = subprocess.run(["/bin/bash", "-e", "-o", "pipefail", "-c", command],
                                            cwd=root, env=environment, capture_output=True)
                    if resolution != "valid":
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse((root / "cross.called").exists())
                        continue
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertEqual((root / "cross.called").read_text(), "linked once")
                    self.assertEqual((root / "github-env").read_text(), f"BUZZ_CROSS_IMAGE={reference}\n")
                    environment["BUZZ_CROSS_IMAGE"] = reference
                    with mock.patch.dict(os.environ, environment, clear=True), \
                         mock.patch.object(m, "command_versions", return_value={}), \
                         mock.patch.object(m, "git", return_value=HEAD), \
                         mock.patch.object(m, "bindings", return_value=BINDINGS):
                        captured = m.capture("server-" + target)
                        self.assertEqual(captured["context"].get("cross_image"), {"reference": reference, "image_id": image_id})
                        del os.environ["BUZZ_CROSS_IMAGE"]
                        with self.assertRaises(m.r.GateError): m.capture("server-" + target)

if __name__ == "__main__":
    unittest.main()
