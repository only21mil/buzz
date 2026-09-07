#!/usr/bin/env python3
"""Reuse selected tree-scoped CI work, retaining a separate exact-main proof.

This is a CI optimization, not merge/review/deployment authorization. A refusal
runs the ordinary job. Never change a source receipt's commit or conclusion.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

SPEC = importlib.util.spec_from_file_location("protected_receipt", Path(__file__).with_name("protected-ci-receipt.py"))
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)
REPO = "only21mil/buzz"
PREFIX = f"/repos/{REPO}"
WORKFLOW = ".github/workflows/ci.yml"
JOBS = {"rust-lint": "Rust Lint", "unit-tests": "Unit Tests", **{
    f"desktop-smoke-{n}": f"Desktop Smoke E2E ({n})" for n in range(1, 5)
}}
MAX_AGE = 86400
LIMIT = 4 * 1024 * 1024


class Refusal(Exception):
    pass


def need(condition, message):
    if not condition:
        raise Refusal(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    need(result.returncode == 0, f"context command unavailable: {args[0]}")
    return result.stdout.strip()


class API:
    """Read only, fixed-host API client. Never retain or print credentials."""
    def __init__(self):
        self.evidence = []
        self.config = tempfile.TemporaryDirectory(prefix="buzz-ci-reuse-gh-")

    def raw(self, endpoint):
        need(endpoint.startswith((PREFIX + "/", "/orgs/only21mil/", "/enterprises/only21mil/"))
             or endpoint == PREFIX, "API origin/repository mismatch")
        need(".." not in endpoint and "#" not in endpoint, "invalid API path")
        env = {key: value for key, value in os.environ.items()
               if key in ("PATH", "HOME", "GH_TOKEN", "SSL_CERT_FILE", "SSL_CERT_DIR")}
        env.update(GH_HOST="github.com", GH_PROMPT_DISABLED="1", GH_CONFIG_DIR=self.config.name)
        result = subprocess.run(["/usr/bin/gh", "api", "--hostname", "github.com", "--method", "GET",
                                 "-H", "X-GitHub-Api-Version: 2022-11-28", endpoint],
                                env=env, capture_output=True, timeout=60, check=False)
        need(result.returncode == 0, "GitHub evidence unavailable")
        need(len(result.stdout) <= LIMIT, "GitHub evidence exceeds size limit")
        return result.stdout

    def one(self, endpoint):
        body = json.loads(self.raw(endpoint))
        self.evidence.append({"endpoint": endpoint, "body": body, "sha256": digest(body)})
        return body

    def pages(self, endpoint, kind):
        key = {"checks": "check_runs", "runs": "workflow_runs", "jobs": "jobs", "artifacts": "artifacts"}.get(kind)
        values = []
        for page in range(1, 21):
            body = self.one(endpoint + ("&" if "?" in endpoint else "?") + f"per_page=100&page={page}")
            rows = body[key] if key else body
            need(isinstance(rows, list), "invalid GitHub page")
            values.extend(rows)
            if len(rows) < 100:
                return values
        raise Refusal("GitHub pagination limit exceeded")


def authority(api):
    repository = api.one(PREFIX)
    need(repository["full_name"] == REPO and repository["default_branch"] == "main", "repository authority changed")
    rules = api.pages(PREFIX + "/rules/branches/main", "array")
    required, rulesets, strict = receipt.required_checks(rules)
    active = []
    for ruleset in rulesets:
        # This optimization never exercises a merge bypass. GitHub hides bypass
        # actors from read-only workflow tokens; the canonical operator receipt
        # still binds those actors independently at delivery. Do not mistake
        # a missing private field for an empty bypass list or inject admin tokens.
        need(ruleset["source_type"] == "Repository" and ruleset["source"] == REPO,
             "source ruleset needs a separately qualified authority adapter")
        metadata = api.one(PREFIX + f"/rulesets/{ruleset['id']}")
        need(metadata["id"] == ruleset["id"] and metadata["source_type"] == "Repository"
             and metadata["source"] == REPO and metadata["enforcement"] == "active"
             and metadata["target"] == "branch", "ruleset authority changed")
        need(bool(metadata.get("updated_at")), "ruleset revision timestamp missing")
        active.append({key: metadata[key] for key in (
            "id", "source_type", "source", "enforcement", "target", "updated_at", "conditions", "rules")})
    return {"repository_id": repository["id"], "rules": rules, "required_checks": required,
            "rulesets": active, "strict": strict}


def context(job):
    """Execution inputs relevant to these jobs, measured after their setup steps.

    Whole-tree identity covers manifests, lockfiles, scripts and action pins.
    Resolved OS/Python packages and tool versions cover mutable setup inputs.
    Event, SHA, checkout path and cache-hit state are deliberately not inputs to
    these tree-scoped checks. Commit-sensitive release/build jobs are excluded.
    """
    env = {name: os.environ.get(name, "") for name in (
        "ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH", "CARGO_TERM_COLOR",
        "BUZZ_TEST_POSTGRES_PASSWORD", "BUZZ_CI_REUSE_EPOCH")}
    need(all(env[name] for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")),
         "runner image identity missing")
    # The test password is a fixed public fixture, never persist arbitrary env.
    need(env["BUZZ_TEST_POSTGRES_PASSWORD"] == "buzz_dev", "unexpected test fixture context")
    versions = {name: command([name, "--version"]) for name in ("rustc", "cargo", "just", "python3")}
    versions["os_packages"] = command(["dpkg-query", "-W", "-f=${Package}=${Version}\n"])
    if job == "unit-tests":
        versions["nextest"] = command(["cargo", "nextest", "--version"])
        versions["python_packages"] = sorted(json.loads(command(["python3", "-m", "pip", "list", "--format=json"])), key=lambda item: item["name"])
    if job.startswith("desktop-smoke-"):
        versions.update({name: command([name, "--version"]) for name in ("node", "pnpm")})
    # Record only non-secret, explicitly declared values.
    del env["BUZZ_TEST_POSTGRES_PASSWORD"]
    return {"environment": env, "versions": versions}


def capture(api, job, event, current_context):
    pr = event["pull_request"]
    need(pr["head"]["repo"]["full_name"] == REPO and pr["base"]["repo"]["full_name"] == REPO,
         "fork source is not eligible")
    need(pr["base"]["ref"] == "main" and not pr["draft"], "source is not an internal main candidate")
    head, base = pr["head"]["sha"], pr["base"]["sha"]
    need(api.one(PREFIX + "/git/ref/heads/main")["object"]["sha"] == base, "source base moved")
    tested = command(["git", "rev-parse", "HEAD"])
    tree = command(["git", "rev-parse", "HEAD^{tree}"])
    need(api.one(PREFIX + f"/git/commits/{head}")["tree"]["sha"] == tree, "tested merge tree differs from candidate")
    # Strict current-base testing permits synthetic PR merge SHA != head SHA.
    return {"schema_version": 1, "mode": "source", "repository": REPO, "job": job,
            "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "pull_request": pr["number"], "head_sha": head, "base_sha": base,
            "tested_sha": tested, "tree_sha": tree, "workflow_sha256": hashlib.sha256(Path(WORKFLOW).read_bytes()).hexdigest(),
            "context": current_context, "authority": authority(api)}


def validate_source(source, *, job, run, pr, landed, current_authority, current_context, workflow_hash):
    """Pure decision boundary, also used by the focused refusal tests."""
    need(source.get("schema_version") == 1 and source.get("mode") == "source", "source proof is missing or relabeled")
    need(source["repository"] == REPO and source["job"] == job, "source repository/job mismatch")
    need(source["run_id"] == run["id"] and source["run_attempt"] == run["run_attempt"], "source attempt mismatch")
    need(run["status"] == "completed" and run["conclusion"] == "success" and run["event"] == "pull_request",
         "source protected workflow did not succeed")
    need(run["path"] == WORKFLOW and run["head_repository"]["full_name"] == REPO, "untrusted source workflow")
    need(pr["merged"] is True and pr["state"] == "closed" and not pr["draft"] and (pr.get("merged_by") or {}).get("id"),
         "source has no merged pull-request authority")
    need(pr["head"]["repo"]["full_name"] == REPO and pr["base"]["repo"]["full_name"] == REPO
         and pr["base"]["ref"] == "main", "source PR authority mismatch")
    need(source["pull_request"] == pr["number"] and source["head_sha"] == pr["head"]["sha"] == run["head_sha"],
         "source candidate mismatch")
    need(pr["merge_commit_sha"] == landed["sha"], "source PR is not the landed merge")
    need([parent["sha"] for parent in landed["parents"]] == [source["base_sha"], source["head_sha"]],
         "landed ordered parents differ from tested base/candidate")
    need(source["tree_sha"] == landed["tree"]["sha"], "landed tree changed")
    need(source["workflow_sha256"] == workflow_hash, "workflow changed")
    need(source["context"] == current_context, "relevant execution context changed")
    need(source["authority"] == current_authority, "protected authority changed")
    return True


def acquire_reuse(api, job, head, current_context):
    need(re.fullmatch(r"[0-9a-f]{40}", head) is not None, "landed SHA must be exact")
    need(api.one(PREFIX + "/git/ref/heads/main")["object"]["sha"] == head, "main authority moved")
    landed = api.one(PREFIX + f"/git/commits/{head}")
    need(command(["git", "rev-parse", "HEAD"]) == head, "checkout is not landed commit")
    candidates = api.pages(PREFIX + f"/commits/{head}/pulls", "array")
    candidates = [pr for pr in candidates if pr.get("merge_commit_sha") == head and pr.get("merged_at")]
    need(len(candidates) == 1, "landed PR authority is ambiguous")
    pr = api.one(PREFIX + f"/pulls/{candidates[0]['number']}")
    source_head = pr["head"]["sha"]
    runs = api.pages(PREFIX + f"/actions/workflows/ci.yml/runs?head_sha={source_head}&event=pull_request", "runs")
    need(bool(runs), "no source CI workflow")
    run = max(runs, key=lambda item: item["id"])
    # Never fall back past a failed, cancelled, pending or rerun source attempt.
    run = api.one(PREFIX + f"/actions/runs/{run['id']}")
    completed = dt.datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00"))
    age = (dt.datetime.now(dt.timezone.utc) - completed).total_seconds()
    need(0 <= age <= MAX_AGE, "source protected result expired")
    artifact_name = f"ci-reuse-{run['run_attempt']}-{job}"
    artifacts = api.pages(PREFIX + f"/actions/runs/{run['id']}/artifacts", "artifacts")
    artifacts = [item for item in artifacts if item["name"] == artifact_name and not item["expired"]]
    need(len(artifacts) == 1, "source dependency/context proof missing or ambiguous")
    artifact = artifacts[0]
    archive = api.raw(PREFIX + f"/actions/artifacts/{artifact['id']}/zip")
    need(artifact.get("digest") == "sha256:" + hashlib.sha256(archive).hexdigest(), "source artifact digest mismatch")
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        need(bundle.namelist() == ["protected-ci-reuse.json"], "unexpected source artifact contents")
        need(bundle.getinfo("protected-ci-reuse.json").file_size <= LIMIT, "source proof exceeds size limit")
        source = json.loads(bundle.read("protected-ci-reuse.json"))
    current_authority = authority(api)
    validate_source(source, job=job, run=run, pr=pr, landed=landed,
                    current_authority=current_authority, current_context=current_context,
                    workflow_hash=hashlib.sha256(Path(WORKFLOW).read_bytes()).hexdigest())
    # Independently verify complete required contexts, including failures and
    # superseded attempts, using the same app-bound rules as delivery receipts.
    checks = receipt.select_checks(api.pages(PREFIX + f"/commits/{source_head}/check-runs?filter=all", "checks"),
                                   current_authority["required_checks"], source_head)
    jobs = api.pages(PREFIX + f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs")
    jobs = [item for item in jobs if item["name"] == JOBS[job]]
    need(len(jobs) == 1 and jobs[0]["status"] == "completed" and jobs[0]["conclusion"] == "success",
         "source job did not succeed in the bound attempt")
    # The workflow result and check suite must describe this same source run.
    protected_name = "Desktop" if job.startswith("desktop-smoke-") else JOBS[job]
    own_checks = [check for check in checks if check["name"] == protected_name]
    need(bool(own_checks), "source job has no protected check coverage")
    need(all(check["check_suite_id"] == run["check_suite_id"] for check in own_checks), "source required check belongs to another run")
    need(authority(api) == current_authority, "protection moved during reuse verification")
    need(api.one(PREFIX + f"/actions/runs/{run['id']}") == run, "source run changed during reuse verification")
    need(api.one(PREFIX + "/git/ref/heads/main")["object"]["sha"] == head, "main moved during reuse verification")
    return {"schema_version": 1, "mode": "reused", "repository": REPO, "job": job, "head_sha": head,
            "landed": landed, "pull_request": pr, "source_run": run, "source_job": jobs[0],
            "source_artifact": artifact, "source_proof": source, "protected_checks": checks,
            "authority": current_authority, "context": current_context,
            "canonical_refs": "GitHub main verified; Buzz relay readback remains a delivery gate",
            "review_and_approval": "Independent delivery gates remain required for the exact candidate"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", choices=JOBS, required=True)
    args = parser.parse_args()
    api = API()
    proof = {"schema_version": 1, "mode": "fresh", "job": args.job}
    try:
        need(os.environ.get("GITHUB_REPOSITORY") == REPO, "repository is not eligible")
        command(["git", "diff", "--quiet", "HEAD", "--"])
        current_context = context(args.job)
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
            proof = capture(api, args.job, event, current_context)
        elif os.environ.get("GITHUB_EVENT_NAME") == "push" and os.environ.get("GITHUB_REF") == "refs/heads/main":
            proof = acquire_reuse(api, args.job, os.environ["GITHUB_SHA"], current_context)
        else:
            raise Refusal("event requires fresh execution")
    except (Refusal, receipt.ReceiptError, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        # Never expose API response bodies or subprocess output in refusals.
        proof = {"schema_version": 1, "mode": "fresh", "job": args.job,
                 "reason": str(exc) if isinstance(exc, (Refusal, receipt.ReceiptError)) else "source evidence unavailable or malformed"}
    proof["api_evidence"] = api.evidence
    Path("protected-ci-reuse.json").write_text(json.dumps(proof, indent=2) + "\n")
    reused = proof["mode"] == "reused"
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"reused={'true' if reused else 'false'}\n")
    summary = (f"Verified protected-result reuse for {JOBS[args.job]} from run {proof['source_run']['id']} "
               f"attempt {proof['source_run']['run_attempt']} at {proof['source_proof']['head_sha']}. "
               f"Exact landed commit: {proof['head_sha']}. Full proof is in this job's ci-reuse artifact."
               if reused else f"Fresh {JOBS[args.job]} execution. {proof.get('reason', 'Capturing source proof for a later identical-tree merge.')} ")
    print(summary)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
        output.write(summary + "\n")


if __name__ == "__main__":
    main()
