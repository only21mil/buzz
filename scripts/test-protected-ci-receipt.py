#!/usr/bin/env python3
"""Hermetic tests for protected-ci-receipt.py."""

from __future__ import annotations

import copy
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("protected-ci-receipt.py")
SCHEMA = SCRIPT.parent.parent / "docs/ci/protected-ci-receipt.schema.json"
SPEC = importlib.util.spec_from_file_location("protected_ci_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)

HEAD = "a" * 40
BASE = "b" * 40
STAMP = "2026-09-01T12:00:00Z"
HTTP_DATE = "Tue, 01 Sep 2026 12:00:00 GMT"


def pr_value(number: int = 17) -> dict:
    return {
        "number": number,
        "state": "open",
        "draft": False,
        "html_url": f"https://github.com/only21mil/buzz/pull/{number}",
        "head": {
            "sha": HEAD,
            "ref": "sats/protected-ci",
            "repo": {"full_name": receipt.REPOSITORY},
        },
        "base": {
            "sha": BASE,
            "ref": "main",
            "repo": {"full_name": receipt.REPOSITORY},
        },
    }


def branch_rules() -> list[dict]:
    return [{
        "type": "required_status_checks",
        "ruleset_id": 20246414,
        "ruleset_source_type": "Repository",
        "ruleset_source": receipt.REPOSITORY,
        "parameters": {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [
                {"context": "build", "integration_id": 15368},
                {"context": "relay_e2e_canary", "integration_id": 15368},
                {"context": "test", "integration_id": 15368},
            ],
        },
    }]


def check_run(name: str, run_id: int, conclusion: str = "success",
              status: str = "completed", app_id: int = 15368,
              head: str = HEAD) -> dict:
    return {
        "id": run_id,
        "name": name,
        "head_sha": head,
        "status": status,
        "conclusion": conclusion,
        "started_at": STAMP,
        "completed_at": "2026-09-01T12:01:00Z" if status == "completed" else None,
        "html_url": f"https://github.com/only21mil/buzz/runs/{run_id}",
        "details_url": f"https://github.com/only21mil/buzz/actions/runs/{run_id}",
        "app": {"id": app_id, "slug": "github-actions"},
        "check_suite": {"id": run_id + 1000},
    }


class FakeClient:
    def __init__(self) -> None:
        self.identity = {
            "path": receipt.GH_PATH, "uid": receipt.GH_UID, "gid": receipt.GH_GID,
            "mode": "0755", "sha256": receipt.GH_SHA256,
        }
        self.requests: list[dict] = []
        self.pr = pr_value()
        self.base_ref_sha = BASE
        self.rules = branch_rules()
        self.runs = [
            check_run("build", 101), check_run("build", 100, "failure"),
            check_run("relay_e2e_canary", 301),
            check_run("relay_e2e_canary", 300, "failure"),
            check_run("test", 201),
        ]
        self.snapshot_calls = 0
        self.repository_calls = 0
        self.pr_calls = 0
        self.base_ref_calls = 0
        self.head_ref_calls = 0
        self.mutate_final_repository = None
        self.mutate_final_pr = None
        self.mutate_final_base_ref = None
        self.mutate_final_head_ref = None
        self.ruleset_calls = 0
        self.ruleset_enforcement = "active"
        self.mutate_second_ruleset = None
        self.mutate_second_snapshot = None

    def record(self, endpoint: str, page: int = 1) -> None:
        self.requests.append({
            "endpoint": endpoint, "page": page, "status": 200,
            "request_id": f"request-{len(self.requests) + 1}", "date": HTTP_DATE,
            "etag": None, "body_sha256": "c" * 64,
        })

    def one(self, endpoint: str):
        self.record(endpoint)
        if endpoint == "/user":
            return {"login": "sats", "id": 42}
        if endpoint == "/repos/only21mil/buzz":
            self.repository_calls += 1
            value = {"id": 77, "full_name": receipt.REPOSITORY, "default_branch": "main"}
            if self.repository_calls == 2 and self.mutate_final_repository:
                self.mutate_final_repository(value)
            return value
        if "/pulls/" in endpoint:
            self.pr_calls += 1
            value = copy.deepcopy(self.pr)
            if self.pr_calls == 3 and self.mutate_final_pr:
                self.mutate_final_pr(value)
            return value
        if endpoint.endswith("/git/ref/heads/main"):
            self.base_ref_calls += 1
            value = {"ref": "refs/heads/main",
                     "object": {"type": "commit", "sha": self.base_ref_sha}}
            if self.base_ref_calls == 3 and self.mutate_final_base_ref:
                self.mutate_final_base_ref(value)
            return value
        if endpoint.endswith("/git/ref/heads/sats%2Fprotected-ci"):
            self.head_ref_calls += 1
            value = {"ref": "refs/heads/sats/protected-ci",
                     "object": {"type": "commit", "sha": HEAD}}
            if self.head_ref_calls == 3 and self.mutate_final_head_ref:
                self.mutate_final_head_ref(value)
            return value
        if endpoint.endswith(f"/commits/{HEAD}"):
            return {"sha": HEAD}
        if "/compare/" in endpoint:
            return {"merge_base_commit": {"sha": BASE}, "behind_by": 0}
        if endpoint.endswith("/rulesets/20246414"):
            self.ruleset_calls += 1
            value = {
                "id": 20246414, "source_type": "Repository",
                "source": receipt.REPOSITORY, "enforcement": self.ruleset_enforcement,
                "name": "main protection", "target": "branch",
                "bypass_actors": [], "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
                "rules": [{"type": "required_status_checks"}],
            }
            if self.ruleset_calls == 2 and self.mutate_second_ruleset:
                self.mutate_second_ruleset(value)
            return value
        raise AssertionError(endpoint)

    def pages(self, endpoint: str, kind: str):
        self.record(endpoint)
        if kind == "array":
            self.snapshot_calls += 1
            value = copy.deepcopy(self.rules)
            if self.snapshot_calls == 2 and self.mutate_second_snapshot:
                self.mutate_second_snapshot(value)
            return value
        if "check-runs" in endpoint:
            if "filter=all" not in endpoint:
                raise AssertionError("check-runs acquisition must retain all attempts")
        return copy.deepcopy(self.runs)


class ReceiptTests(unittest.TestCase):
    def build(self, client: FakeClient | None = None) -> dict:
        return receipt.build_receipt(client or FakeClient(), 17, HEAD, "main")

    def test_happy_receipt_is_bound_sorted_and_records_superseded_failure(self) -> None:
        value = self.build()
        self.assertEqual(value["scope"], "pull-request")
        self.assertEqual(value["head_sha"], HEAD)
        self.assertEqual(value["pull_request"]["base_sha"], BASE)
        ruleset = value["protection"]["rulesets"][0]
        self.assertEqual(ruleset["enforcement"], "active")
        for field in ("metadata_sha256", "bypass_actors_sha256", "conditions_sha256",
                      "rules_sha256"):
            self.assertRegex(ruleset[field], r"^[0-9a-f]{64}$")
        self.assertEqual([item["name"] for item in value["checks"]],
                         ["build", "relay_e2e_canary", "test"])
        self.assertEqual(value["checks"][0]["check_run_id"], 101)
        self.assertEqual(value["checks"][0]["superseded"][0]["conclusion"], "failure")
        canary = value["checks"][1]
        self.assertEqual(canary["check_run_id"], 301)
        self.assertEqual(canary["superseded"][0]["check_run_id"], 300)
        self.assertEqual(canary["superseded"][0]["conclusion"], "failure")
        self.assertTrue(value["provider"]["requests"][-1]["endpoint"].endswith(
            "/git/ref/heads/sats%2Fprotected-ci"))
        self.assertEqual(receipt.canonical_json(value), receipt.canonical_json(json.loads(receipt.canonical_json(value))))

    def test_landed_main_scope_has_no_open_pr_dependency(self) -> None:
        client = FakeClient()
        client.base_ref_sha = HEAD
        value = receipt.build_main_receipt(client, HEAD, "main")
        self.assertEqual(value["scope"], "main")
        self.assertIsNone(value["pull_request"])
        self.assertEqual(value["protection"]["base_sha"], HEAD)
        self.assertTrue(value["provider"]["requests"][-1]["endpoint"].endswith(
            "/git/ref/heads/main"))
        now = dt.datetime(2026, 9, 1, 12, 5, tzinfo=dt.timezone.utc)
        receipt.validate_receipt(value, receipt.REPOSITORY, HEAD, "main", now, 600)
        with self.assertRaises(receipt.GateError):
            receipt.validate_receipt(value, receipt.REPOSITORY, HEAD, "pull-request", now, 600)

    def test_final_authority_reread_rejects_post_snapshot_drift(self) -> None:
        pr_mutations = [
            ("repository default", "mutate_final_repository",
             lambda value: value.update(default_branch="release")),
            ("pull request", "mutate_final_pr", lambda value: value.update(state="closed")),
            ("base ref", "mutate_final_base_ref",
             lambda value: value["object"].update(sha="d" * 40)),
            ("head ref", "mutate_final_head_ref",
             lambda value: value["object"].update(sha="d" * 40)),
        ]
        for name, attribute, mutation in pr_mutations:
            with self.subTest(name=name):
                client = FakeClient()
                setattr(client, attribute, mutation)
                with self.assertRaises(receipt.ReceiptError):
                    self.build(client)
        for name, attribute, mutation in (
            ("main default", "mutate_final_repository",
             lambda value: value.update(default_branch="release")),
            ("main ref", "mutate_final_base_ref",
             lambda value: value["object"].update(sha="d" * 40)),
        ):
            with self.subTest(name=name):
                client = FakeClient()
                client.base_ref_sha = HEAD
                setattr(client, attribute, mutation)
                with self.assertRaises(receipt.ReceiptError):
                    receipt.build_main_receipt(client, HEAD, "main")

    def test_safe_publish_is_create_only_mode_0600_and_canonical(self) -> None:
        value = self.build()
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            os.chmod(directory, 0o700)
            output = directory / "receipt.json"
            receipt.safe_publish(output, value)
            info = output.stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(output.read_bytes(), receipt.canonical_json(value))
            self.assertEqual(receipt.safe_read_receipt(output), receipt.canonical_json(value))
            with self.assertRaises(receipt.OutputError):
                receipt.safe_publish(output, value)

    def test_safe_publish_rejects_relative_symlink_and_unsafe_parent(self) -> None:
        value = self.build()
        with self.assertRaises(receipt.OutputError):
            receipt.safe_publish(Path("relative.json"), value)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o755)
            with self.assertRaises(receipt.OutputError):
                receipt.safe_publish(root / "bad.json", value)
            real = root / "real"
            real.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(receipt.OutputError):
                receipt.safe_publish(link / "bad.json", value)

    def test_safe_read_rejects_symlink_fifo_and_oversized_input(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            regular = root / "regular.json"
            regular.write_bytes(b"{}\n")
            os.chmod(regular, 0o600)
            symlink = root / "link.json"
            symlink.symlink_to(regular)
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o600)
            hardlink = root / "hardlink.json"
            os.link(regular, hardlink)
            oversized = root / "oversized.json"
            with oversized.open("wb") as stream:
                stream.truncate(receipt.MAX_RECEIPT_BYTES + 1)
            os.chmod(oversized, 0o600)
            for path in (symlink, fifo, regular, hardlink, oversized):
                with self.subTest(path=path.name), self.assertRaises(receipt.OutputError):
                    receipt.safe_read_receipt(path)

    def test_safe_publish_removes_only_its_inode_after_post_rename_failure(self) -> None:
        value = self.build()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            output = root / "receipt.json"
            real_fsync = receipt.os.fsync
            calls = 0

            def fail_second(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated directory fsync failure")
                return real_fsync(fd)

            with mock.patch.object(receipt.os, "fsync", side_effect=fail_second):
                with self.assertRaises(OSError):
                    receipt.safe_publish(output, value)
            self.assertFalse(output.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_pr_and_ref_invariants_fail_closed(self) -> None:
        mutations = [
            lambda p: p.update(state="closed"),
            lambda p: p.update(draft=True),
            lambda p: p["head"].update(sha="d" * 40),
            lambda p: p["head"]["repo"].update(full_name="fork/buzz"),
            lambda p: p["base"].update(ref="release"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                client = FakeClient()
                mutation(client.pr)
                with self.assertRaises(receipt.GateError):
                    self.build(client)

    def test_rules_require_strict_app_bound_unique_checks_and_stability(self) -> None:
        for mutation in (
            lambda rules: rules[0]["parameters"].update(strict_required_status_checks_policy=False),
            lambda rules: rules[0]["parameters"]["required_status_checks"][0].update(integration_id=None),
            lambda rules: rules[0]["parameters"]["required_status_checks"].append(
                {"context": "build", "integration_id": 999}),
        ):
            with self.subTest(mutation=mutation):
                client = FakeClient()
                mutation(client.rules)
                with self.assertRaises(receipt.GateError):
                    self.build(client)
        client = FakeClient()
        client.mutate_second_snapshot = lambda rules: rules[0]["parameters"].update(
            strict_required_status_checks_policy=False)
        with self.assertRaises(receipt.GateError):
            self.build(client)
        client = FakeClient()
        client.mutate_second_ruleset = lambda value: value["bypass_actors"].append(
            {"actor_id": 1, "actor_type": "Integration", "bypass_mode": "always"})
        with self.assertRaises(receipt.ProviderError):
            self.build(client)

    def test_rules_reject_zero_app_bound_required_checks(self) -> None:
        client = FakeClient()
        client.rules[0]["parameters"]["required_status_checks"] = []
        with self.assertRaisesRegex(receipt.GateError,
                                    "no app-bound required status checks apply"):
            self.build(client)

    def test_rules_reject_inactive_rulesets(self) -> None:
        client = FakeClient()
        client.ruleset_enforcement = "evaluate"
        with self.assertRaisesRegex(receipt.GateError, "ruleset 20246414 is not active"):
            self.build(client)

    def test_latest_matching_run_must_be_exact_head_success(self) -> None:
        mutations = [
            lambda runs: runs.__setitem__(0, check_run("build", 101, "failure")),
            lambda runs: runs.__setitem__(0, check_run("build", 101, None, "in_progress")),
            lambda runs: runs.__setitem__(0, check_run("build", 101, head="d" * 40)),
            lambda runs: runs.__setitem__(0, check_run("build", 101, app_id=999)),
            lambda runs: runs.__setitem__(slice(None), [run for run in runs if run["name"] != "build"]),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                client = FakeClient()
                mutation(client.runs)
                with self.assertRaises(receipt.GateError):
                    self.build(client)

    def test_gh_pagination_follows_same_origin_and_rejects_cycle(self) -> None:
        calls = []
        initial = (f"/repos/{receipt.REPOSITORY}/commits/{HEAD}/check-runs"
                   "?filter=all&per_page=100")
        second = (f"https://api.github.com/repos/{receipt.REPOSITORY}/commits/{HEAD}/check-runs"
                  "?filter=all&per_page=100&page=2")

        def runner(command, **kwargs):
            calls.append(command[-1])
            if len(calls) == 1:
                link = f'<{second}>; rel="next"'
                body = {"total_count": 2, "check_runs": [{"id": 1}]}
            else:
                link = f'<{second}>; rel="next"'
                body = {"total_count": 2, "check_runs": [{"id": 2}]}
            headers = ("HTTP/2 200 OK\r\nX-GitHub-Request-Id: id\r\n"
                       f"Date: {HTTP_DATE}\r\nLink: {link}\r\n\r\n")
            return subprocess.CompletedProcess(command, 0, headers + json.dumps(body), "")

        client = receipt.GhClient("/usr/bin/gh", runner=runner)
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test"}):
            with self.assertRaises(receipt.ProviderError):
                client.pages(initial, "checks")
        self.assertEqual(calls, [initial, second])
        with self.assertRaises(receipt.ProviderError):
            receipt.api_endpoint(second.replace("api.github.com", "evil.invalid"))
        with self.assertRaises(receipt.ProviderError):
            receipt.api_endpoint(initial.replace("filter=all", "filter=latest"))
        with self.assertRaises(receipt.ProviderError):
            receipt.api_endpoint(initial + "&page=1")
        with self.assertRaises(receipt.ProviderError):
            receipt.api_endpoint(initial + "&cache=true")
        with self.assertRaises(receipt.ProviderError):
            receipt.api_endpoint(f"/repos/{receipt.REPOSITORY}/issues?per_page=100")

    def test_gh_response_is_byte_bounded_before_json_parsing(self) -> None:
        # Pin the cap to a literal so raising the constant fails this test.
        self.assertEqual(receipt.MAX_GH_RESPONSE_BYTES, 4 * 1024 * 1024)

        def runner(command, **kwargs):
            headers = ("HTTP/2 200 OK\r\nX-GitHub-Request-Id: id\r\n"
                       f"Date: {HTTP_DATE}\r\n\r\n").encode()
            output = headers + b" " * (4 * 1024 * 1024 + 1)
            return subprocess.CompletedProcess(command, 0, output, b"")

        client = receipt.GhClient("/usr/bin/gh", runner=runner)
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test"}), \
             mock.patch.object(receipt.json, "loads") as loads:
            with self.assertRaisesRegex(receipt.ProviderError,
                                        "GitHub response exceeds the byte limit"):
                client.one("/user")
        loads.assert_not_called()

    def test_check_page_rejects_duplicate_ids_and_total_drift(self) -> None:
        responses = [
            (2, 1, f'<https://api.github.com/repos/{receipt.REPOSITORY}/commits/{HEAD}/check-runs'
                    '?filter=all&per_page=100&page=2>; rel="next"'),
            (3, 1, None),
        ]

        def runner(command, **kwargs):
            total, run_id, link = responses.pop(0)
            header = f"HTTP/2 200 OK\nX-GitHub-Request-Id: id\nDate: {HTTP_DATE}\n"
            if link:
                header += f"Link: {link}\n"
            body = json.dumps({"total_count": total, "check_runs": [{"id": run_id}]})
            return subprocess.CompletedProcess(command, 0, header + "\n" + body, "")

        with self.assertRaises(receipt.ProviderError):
            with mock.patch.dict(os.environ, {"GH_TOKEN": "test"}):
                receipt.GhClient("/usr/bin/gh", runner=runner).pages(
                    f"/repos/{receipt.REPOSITORY}/commits/{HEAD}/check-runs?filter=all&per_page=100",
                    "checks")

    def test_external_details_url_is_redacted_and_subprocess_env_is_minimal(self) -> None:
        client = FakeClient()
        client.runs[0]["details_url"] = "https://ci.example.invalid/build/101"
        value = self.build(client)
        self.assertIsNone(value["checks"][0]["details_url"])

        captured = {}

        def runner(command, **kwargs):
            captured.update(kwargs["env"])
            body = json.dumps({"login": "sats", "id": 42})
            output = f"HTTP/2 200 OK\nX-GitHub-Request-Id: id\nDate: {HTTP_DATE}\n\n{body}"
            return subprocess.CompletedProcess(command, 0, output, "")

        with mock.patch.dict(os.environ, {"GH_TOKEN": "secret", "LEAK_ME": "no"}, clear=True):
            receipt.GhClient("/usr/bin/gh", runner=runner).one("/user")
        self.assertEqual(set(captured), {"GH_TOKEN", "GH_PROMPT_DISABLED", "GH_HOST", "LC_ALL",
                                         "NO_COLOR"})
        self.assertNotIn("LEAK_ME", captured)

    def test_token_is_required_without_exposure(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(receipt.shutil, "which", return_value="/bin/true"):
            with self.assertRaisesRegex(receipt.ProviderError, "GH_TOKEN is required"):
                receipt.resolve_gh()

    def test_gh_path_and_digest_are_pinned(self) -> None:
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test"}), \
             mock.patch.object(receipt.shutil, "which", return_value="/usr/local/bin/gh"):
            with self.assertRaisesRegex(receipt.ProviderError, "must resolve exactly"):
                receipt.resolve_gh()
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test"}), \
             mock.patch.object(receipt.shutil, "which", return_value=receipt.GH_PATH), \
             mock.patch.object(receipt, "GH_SHA256", "0" * 64):
            with self.assertRaisesRegex(receipt.ProviderError, "digest mismatch"):
                receipt.resolve_gh()

    def test_validate_rejects_unknown_stale_and_head_mismatch(self) -> None:
        value = self.build()
        now = dt.datetime(2026, 9, 1, 12, 5, tzinfo=dt.timezone.utc)
        receipt.validate_receipt(value, receipt.REPOSITORY, HEAD, "pull-request", now, 600)
        changed = copy.deepcopy(value)
        changed["unknown"] = True
        with self.assertRaises(receipt.GateError):
            receipt.validate_receipt(changed, receipt.REPOSITORY, HEAD, "pull-request", now, 600)
        changed = copy.deepcopy(value)
        changed["checks"][0]["unknown"] = True
        with self.assertRaises(receipt.GateError):
            receipt.validate_receipt(changed, receipt.REPOSITORY, HEAD, "pull-request", now, 600)
        with self.assertRaises(receipt.GateError):
            receipt.validate_receipt(value, receipt.REPOSITORY, "d" * 40,
                                     "pull-request", now, 600)
        with self.assertRaises(receipt.GateError):
            receipt.validate_receipt(value, receipt.REPOSITORY, HEAD, "pull-request",
                                     now + dt.timedelta(hours=1), 600)

    def test_validate_cli_sanitizes_non_utf8_and_deep_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            path = root / "bad.json"
            arguments = [
                "validate", "--receipt", str(path), "--repository", receipt.REPOSITORY,
                "--head", HEAD, "--scope", "pull-request", "--max-age-seconds", "600",
            ]
            for payload in (b"\xff\n", ("[" * 2_000 + "]" * 2_000 + "\n").encode()):
                path.write_bytes(payload)
                os.chmod(path, 0o600)
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(receipt.main(arguments), 5)
                self.assertEqual(stderr.getvalue(),
                                 "protected-ci-receipt: receipt is not valid bounded UTF-8 JSON\n")

    def test_generated_receipt_matches_closed_schema(self) -> None:
        checker = receipt.shutil.which("check-jsonschema")
        self.assertIsNotNone(checker, "check-jsonschema is required by the test gate")
        with tempfile.TemporaryDirectory() as raw:
            instance = Path(raw) / "receipt.json"
            instance.write_bytes(receipt.canonical_json(self.build()))
            completed = subprocess.run(
                [checker, "--schemafile", str(SCHEMA), str(instance)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            client = FakeClient()
            client.base_ref_sha = HEAD
            instance.write_bytes(receipt.canonical_json(receipt.build_main_receipt(client, HEAD, "main")))
            completed = subprocess.run(
                [checker, "--schemafile", str(SCHEMA), str(instance)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
