#!/usr/bin/env python3
"""Qualify a landed tree using the trusted premerge execution snapshot.

No build/test process runs here. The source execution retains its own SHA,
runner, resolved dependencies and attempts; it never becomes a landed build.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("landing_receipt", ROOT / "scripts/protected-ci-receipt.py")
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)
PREFIX = f"/repos/{r.REPOSITORY}"
CANONICAL = "https://framework-desktop.tail69757d.ts.net:38443/git/73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812/buzz"
MAX_AGE = 86400
POLICY = "protected-source-qualification-v1"
CI = ".github/workflows/ci.yml"
CANARY = ".github/workflows/relay_e2e_canary.yml"
DRC = ".github/workflows/desktop-release-candidate.yml"
POLICY_FILES = ("scripts/protected-ci-receipt.py", "scripts/protected-ci-landing.py",
                "scripts/desktop_release.py", CI, CANARY, DRC)
JOBS = {
    "changes": "Detect Changed Paths", "rust-lint": "Rust Lint", "unit-tests": "Unit Tests",
    "desktop-core": "Desktop Core", "desktop-e2e-relay": "Desktop E2E Relay",
    "backend-integration": "Backend Integration (relay e2e)", "relay-e2e": "Relay E2E",
    "web": "Web", "mobile": "Mobile", "security": "Security",
    "dead-token-guard": "Dead Token Reference Guard", "desktop-build-macos": "Desktop Build (macOS)",
    **{f"desktop-smoke-{n}": f"Desktop Smoke E2E ({n})" for n in range(1, 5)},
    **{f"desktop-integration-{n}": f"Desktop E2E Integration ({n}/2)" for n in range(1, 3)},
    **{f"server-{target}": f"Server Cross-Compile ({target})" for target in (
        "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl")},
}
AGGREGATES = {"Desktop", "Desktop E2E Integration"}
RUST_JOBS = {"rust-lint", "unit-tests", "desktop-core", "desktop-e2e-relay", "backend-integration",
             "relay-e2e", "security", "desktop-build-macos", *[j for j in JOBS if j.startswith("server-")]}
JS_JOBS = {"desktop-core", "desktop-build-macos", "web", *[j for j in JOBS if j.startswith(("desktop-smoke-", "desktop-integration-"))]}
SERVICE_JOBS = {"backend-integration", "relay-e2e", "desktop-integration-1", "desktop-integration-2"}
SERVICE_CONTAINERS = ("buzz-postgres", "buzz-redis", "buzz-minio", "buzz-minio-init")


def run(argv, *, cwd=ROOT):
    result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=60, check=False)
    r.refuse(result.returncode == 0, f"qualification command failed: {argv[0]}")
    return result.stdout


def git(*args):
    return run(["git", *args]).decode().strip()


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def bindings(commit):
    """Resolve workflow/policy, tool manifests and lockfiles from Git, not a receipt."""
    paths = git("ls-tree", "-r", "--name-only", commit).splitlines()
    selected = [p for p in paths if p in POLICY_FILES or p.startswith("bin/") or
                re.search(r"(^|/)(Cargo\.(lock|toml)|.*lock.*|package\.json|pubspec\.yaml|.*\.gradle(\.kts)?|gradle-wrapper\.properties|rust-toolchain\.toml|deny\.toml)$", p)]
    return {p: digest_bytes(run(["git", "show", f"{commit}:{p}"])) for p in selected}


def verify_policy_bytes(head):
    for path in POLICY_FILES:
        r.refuse((ROOT / path).read_bytes() == run(["git", "show", f"{head}:{path}"]),
                 f"installed verifier/workflow differs from landed source: {path}")


def command_versions(job):
    commands = {"python3": ["python3", "--version"]}
    if job in RUST_JOBS:
        commands.update({tool: [tool, "--version"] for tool in ("rustc", "cargo", "just")})
    if job in JS_JOBS:
        commands.update({tool: [tool, "--version"] for tool in ("node", "pnpm")})
    if job == "mobile":
        commands.update(flutter=["flutter", "--version", "--machine"], java=["java", "--version"],
                        gradle=["gradle", "--version"])
    versions = {key: run(command).decode().strip() for key, command in commands.items()}
    packages = sorted((d.metadata.get("Name", ""), d.version) for d in importlib.metadata.distributions())
    versions["python_packages_sha256"] = r.sha256_json(packages)
    if os.environ.get("RUNNER_OS") == "Linux":
        versions["os_packages_sha256"] = digest_bytes(run(["dpkg-query", "-W", "-f=${Package}=${Version}\n"]))
    elif os.environ.get("RUNNER_OS") == "macOS":
        versions["xcode"] = run(["xcodebuild", "-version"]).decode().strip()
        versions["os"] = run(["sw_vers"]).decode().strip()
    return versions


def capture(job):
    r.refuse(job in JOBS, "unknown qualification job")
    # Other branches still execute ordinary CI, but cannot produce reuse evidence.
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        return {"schema_version": 1, "mode": "ineligible", "job": job}
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr = event["pull_request"]
    if not (os.environ.get("GITHUB_REPOSITORY") == r.REPOSITORY and
            pr["head"]["repo"]["full_name"] == pr["base"]["repo"]["full_name"] == r.REPOSITORY and
            pr["base"]["ref"] == "main" and not pr["draft"]):
        return {"schema_version": 1, "mode": "ineligible", "job": job}
    git("diff", "--quiet", "HEAD", "--")
    environment = {key: os.environ.get(key, "") for key in (
        "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion", "BUZZ_CI_REUSE_EPOCH")}
    r.refuse(all(environment[k] for k in ("RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")),
             "qualification runner image is unidentified")
    context = {"environment": environment, "versions": command_versions(job),
               "execution": "premerge-source-snapshot", "event": "pull_request",
               "base_ref": "main", "policy": POLICY}
    if job in SERVICE_JOBS:
        context["service_images"] = {name: run(["docker", "inspect", "--format={{.Image}}", name]).decode().strip()
                                     for name in SERVICE_CONTAINERS}
    if job.startswith("server-"):
        reference = os.environ.get("BUZZ_CROSS_IMAGE", "")
        r.refuse(re.fullmatch(rf"ghcr\.io/cross-rs/{re.escape(job.removeprefix('server-'))}@sha256:[0-9a-f]{{64}}", reference),
                 "cross compiler image is not pinned to its resolved digest")
        context["cross_image"] = {"reference": reference,
                                  "image_id": run(["docker", "image", "inspect", "--format={{.Id}}", reference]).decode().strip()}
    if job == "mobile":
        manifest = ROOT / "mobile/build/app/reports/buzz-runtime-dependencies.tsv"
        context["android_dependencies_sha256"] = digest_bytes(manifest.read_bytes())
    if job == "security":
        cache = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "advisory-dbs"
        databases = [p for p in cache.iterdir() if p.is_dir() and (p / ".git").exists()]
        r.refuse(len(databases) == 1, "security advisory database is not uniquely resolved")
        remote = run(["git", "remote", "get-url", "origin"], cwd=databases[0]).decode().strip().lower().removesuffix(".git")
        r.refuse(remote == "https://github.com/rustsec/advisory-db", "unqualified advisory database")
        context["advisory_sha"] = run(["git", "rev-parse", "HEAD"], cwd=databases[0]).decode().strip()
    return {"schema_version": 1, "mode": "source", "repository": r.REPOSITORY, "job": job,
            "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "head_sha": pr["head"]["sha"], "base_sha": pr["base"]["sha"], "pull_request": pr["number"],
            "tested_sha": git("rev-parse", "HEAD"), "tree_sha": git("rev-parse", "HEAD^{tree}"),
            "bindings": bindings("HEAD"), "context": context}


class Evidence:
    """Deduplicated exact response bodies, replayed in the same call order."""
    def __init__(self, client=None, retained=None):
        self.client = client
        self.data = retained or {"calls": [], "bodies": {}}
        self.position = 0

    def call(self, method, endpoint, kind=None):
        if self.client is None:
            r.refuse(self.position < len(self.data["calls"]), "landing evidence is incomplete")
            item = self.data["calls"][self.position]
            self.position += 1
            r.refuse(item[:3] == [method, endpoint, kind], "landing evidence is out of order")
            value = self.data["bodies"][item[3]]
            r.refuse(r.sha256_json(value) == item[3], "landing evidence body changed")
            return value
        if method == "one":
            value = self.client.one(endpoint)
        elif method == "pages":
            value = self.client.pages(endpoint, kind)
        else:
            value = self.archive(endpoint)
        digest = r.sha256_json(value)
        self.data["calls"].append([method, endpoint, kind, digest])
        self.data["bodies"][digest] = value
        return value

    def one(self, endpoint):
        return self.call("one", endpoint)

    def pages(self, endpoint, kind):
        return self.call("pages", endpoint, kind)

    def archive(self, endpoint):
        r.refuse(re.fullmatch(re.escape(PREFIX) + r"/actions/artifacts/[1-9][0-9]*/zip", endpoint),
                 "untrusted artifact endpoint")
        env = {"GH_TOKEN": os.environ.get("GH_TOKEN", ""), "GH_HOST": r.HOST,
               "GH_PROMPT_DISABLED": "1", "HOME": str(self.client.home)}
        r.refuse(bool(env["GH_TOKEN"]), "GH_TOKEN is required", r.ProviderError)
        result = self.client.runner([self.client.gh, "api", "--hostname", r.HOST, "--method", "GET", endpoint],
                                    env=env, capture_output=True, timeout=60, check=False)
        r.refuse(result.returncode == 0 and len(result.stdout) <= r.MAX_GH_RESPONSE_BYTES,
                 "immutable source archive unavailable", r.ProviderError)
        return base64.b64encode(result.stdout).decode()


def fresh(timestamp, now, label):
    parsed = dt.datetime.fromisoformat(r.iso8601(timestamp, label).replace("Z", "+00:00"))
    r.refuse(0 <= (now - parsed).total_seconds() <= MAX_AGE, f"{label} is stale or future-dated")


def current_epoch(api):
    body = api.one(PREFIX + "/actions/variables/BUZZ_CI_REUSE_EPOCH")
    if body.get("message") == "Not Found":
        # GitHub also hides unauthorized variables behind 404. Only an
        # independently confirmed repository admin may interpret absence.
        repo = api.one(PREFIX)
        r.refuse(repo.get("permissions", {}).get("admin") is True,
                 "cannot distinguish an unset epoch from insufficient variable-read authority")
        return ""
    r.refuse(body.get("name") == "BUZZ_CI_REUSE_EPOCH" and isinstance(body.get("value"), str),
             "invalidation epoch unavailable")
    return body["value"]


def selected_job(executions, name, run, now):
    jobs = [j for j in executions if j.get("name") == name]
    r.refuse(bool(jobs), f"source job missing: {name}")
    attempt = max(r.positive(j.get("run_attempt"), "job attempt") for j in jobs)
    jobs = [j for j in jobs if j["run_attempt"] == attempt]
    r.refuse(len(jobs) == 1, f"source job ambiguous: {name}")
    job = jobs[0]
    r.refuse(attempt <= r.positive(run["run_attempt"], "workflow attempt") and
             job.get("status") == "completed" and job.get("conclusion") == "success" and
             job.get("run_id") == run["id"] and job.get("head_sha") == run["head_sha"],
             f"latest source job is not a matching successful execution: {name}")
    fresh(job["completed_at"], now, f"source job {name}")
    return job


def source_run(api, path, event, head, now):
    runs = api.pages(PREFIX + f"/actions/workflows/{Path(path).name}/runs?head_sha={head}&event={event}&per_page=100", "runs")
    r.refuse(bool(runs), f"source workflow unavailable: {path}")
    # A rerun keeps its original run ID. Creation-ID ordering can therefore
    # hide a newer failure/rerun of an older workflow behind a newer green run.
    ids = [r.positive(item["id"], "workflow id") for item in runs]
    r.refuse(len(ids) == len(set(ids)), "ambiguous source workflow inventory")
    live = [api.one(PREFIX + f"/actions/runs/{run_id}") for run_id in ids]
    for run_id, item in zip(ids, live):
        r.refuse(item["id"] == run_id and item["head_sha"] == head and item["path"] == path and
                 item["event"] == event and item["head_repository"]["full_name"] == r.REPOSITORY,
                 "source workflow inventory changed")
        r.positive(item["run_attempt"], "source workflow attempt")
        r.refuse(item["status"] == "completed", "source workflow execution is still active")
    # GitHub defines run_started_at as the latest attempt's start and resets
    # it on rerun. updated_at can change for unrelated provider metadata.
    revision = lambda item: dt.datetime.fromisoformat(r.iso8601(item.get("run_started_at"), "latest workflow attempt start").replace("Z", "+00:00"))
    newest = max(revision(item) for item in live)
    latest = [item for item in live if revision(item) == newest]
    r.refuse(len(latest) == 1, "latest source workflow execution is ambiguous")
    run = latest[0]
    r.refuse(run["head_sha"] == head and run["path"] == path and
             run["event"] == event and run["head_repository"]["full_name"] == r.REPOSITORY and
             run["repository"]["full_name"] == r.REPOSITORY and
             run["status"] == "completed" and run["conclusion"] == "success",
             f"latest trusted workflow did not succeed: {path}")
    fresh(run["updated_at"], now, "source workflow")
    # Concurrent attempts cannot be ordered solely by start time: an older
    # attempt may still have been running when the selected execution began.
    for prior in live:
        if prior["id"] == run["id"]:
            continue
        jobs = api.pages(PREFIX + f"/actions/runs/{prior['id']}/attempts/{prior['run_attempt']}/jobs?per_page=100", "jobs")
        r.refuse(bool(jobs), "competing source attempt has no provable completion boundary")
        ends = []
        for job in jobs:
            r.refuse(job.get("run_attempt") == prior["run_attempt"] and job.get("run_id") == prior["id"] and
                     job.get("status") == "completed", "competing source attempt is incomplete")
            ends.append(dt.datetime.fromisoformat(r.iso8601(job.get("completed_at"), "competing job completion").replace("Z", "+00:00")))
        r.refuse(max(ends) < newest, "competing source attempt overlaps the selected execution")
    return run


def verify_source_proof(proof, key, job, run, source, target_tree, expected_bindings, epoch):
    r.exact_fields(proof, {"schema_version", "mode", "repository", "job", "run_id", "run_attempt", "head_sha",
                           "base_sha", "pull_request", "tested_sha", "tree_sha", "bindings", "context"}, "source proof")
    r.positive(proof.get("run_id"), "source run id")
    r.positive(proof.get("run_attempt"), "source job attempt")
    r.refuse(proof.get("schema_version") == 1 and proof.get("mode") == "source" and
             proof.get("repository") == r.REPOSITORY and proof.get("job") == key,
             "source proof is ineligible or relabeled")
    r.refuse(proof.get("run_id") == run["id"] and proof.get("run_attempt") == job["run_attempt"],
             "source proof attempt mismatch")
    r.refuse(proof.get("head_sha") == source["head_sha"] and
             proof.get("base_sha") == source["pull_request"]["base_sha"] and
             proof.get("pull_request") == source["pull_request"]["number"] and
             proof.get("tree_sha") == target_tree, "source proof Git identity mismatch")
    r.refuse(proof.get("bindings") == expected_bindings, "workflow, policy or dependency bindings changed")
    context = r.object_(proof.get("context"), "source context")
    r.refuse(context.get("execution") == "premerge-source-snapshot" and context.get("event") == "pull_request" and
             context.get("base_ref") == "main" and context.get("policy") == POLICY, "relevant execution context changed")
    env = r.object_(context.get("environment"), "source environment")
    r.refuse(env.get("BUZZ_CI_REUSE_EPOCH") == epoch, "external input invalidation epoch changed")
    for field in ("RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion"):
        r.text(env.get(field), f"source {field}")
    versions = r.object_(context.get("versions"), "resolved source versions")
    required = {"python3", "python_packages_sha256"}
    if key in RUST_JOBS: required.update(("rustc", "cargo", "just"))
    if key in JS_JOBS: required.update(("node", "pnpm"))
    if key == "mobile": required.update(("flutter", "java", "gradle"))
    required.update({"os_packages_sha256"} if env["RUNNER_OS"] == "Linux" else {"xcode", "os"})
    r.refuse(required <= versions.keys() and all(isinstance(versions[k], str) and versions[k] for k in required),
             "resolved source toolchain evidence missing")
    if key in SERVICE_JOBS:
        images = r.object_(context.get("service_images"), "resolved service images")
        r.refuse(set(images) == set(SERVICE_CONTAINERS) and
                 all(isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v) for v in images.values()),
                 "service dependency evidence missing")
    if key.startswith("server-"):
        image = r.object_(context.get("cross_image"), "resolved cross compiler image")
        reference, image_id = image.get("reference"), image.get("image_id")
        r.refuse(isinstance(reference, str) and
                 re.fullmatch(rf"ghcr\.io/cross-rs/{re.escape(key.removeprefix('server-'))}@sha256:[0-9a-f]{{64}}", reference) and
                 isinstance(image_id, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id),
                 "cross compiler dependency evidence missing")
    if key == "mobile":
        r.refuse(re.fullmatch(r"[0-9a-f]{64}", context.get("android_dependencies_sha256", "")),
                 "Android dependency evidence missing")


def readback(api, source, head, now, expected_bindings):
    """Resolve identities from live authority, or replay identical retained bodies."""
    repo = api.one(PREFIX)
    r.require_repository(repo, source["provider"]["repository_id"], "landing repository")
    r.require_ref(api.one(PREFIX + "/git/ref/heads/main"), "refs/heads/main", head)
    pr = api.one(PREFIX + f"/pulls/{source['pull_request']['number']}")
    candidate, base = source["head_sha"], source["pull_request"]["base_sha"]
    r.refuse(pr["head"]["sha"] == candidate and pr["head"]["repo"]["full_name"] == r.REPOSITORY and
             pr["base"]["repo"]["full_name"] == r.REPOSITORY and pr["base"]["ref"] == "main" and
             pr["state"] == "closed" and pr.get("merged") is True and not pr["draft"] and
             pr["merge_commit_sha"] == head and (pr.get("merged_by") or {}).get("id"),
             "closed pull request does not bind the reviewed candidate to this landing")
    landed = api.one(PREFIX + f"/git/commits/{head}")
    source_commit = api.one(PREFIX + f"/git/commits/{candidate}")
    r.refuse(landed["sha"] == head and [p["sha"] for p in landed["parents"]] == [base, candidate] and
             source_commit["sha"] == candidate and source_commit["tree"]["sha"] == landed["tree"]["sha"],
             "actual landing SHA, ordered parents or tree differs from qualified candidate")
    qualified = qualify_source(api, source, landed["tree"]["sha"], now, expected_bindings)
    r.require_ref(api.one(PREFIX + "/git/ref/heads/main"), "refs/heads/main", head)
    return {"landed": landed, "candidate": candidate, "base": base, "pull_request": pr["number"],
            "tree_sha": landed["tree"]["sha"], **qualified}


def qualify_source(api, source, target_tree, now, expected_bindings):
    """Prove actual source execution, independently of whether it has landed."""
    candidate, base = source["head_sha"], source["pull_request"]["base_sha"]
    snap = r.snapshot(api, *r.REPOSITORY.split("/"), candidate, "main")
    original = r.receipt_binding(source)
    r.refuse(all(snap[field] == original[field] for field in original if field != "checks"),
             "live source protection differs from the original premerge authority")
    epoch = current_epoch(api)
    ci = source_run(api, CI, "pull_request", candidate, now)
    canary = source_run(api, CANARY, "workflow_dispatch", candidate, now)
    drc = source_run(api, DRC, "pull_request", candidate, now)
    all_runs = {CI: ci, CANARY: canary, DRC: drc}
    executions = {path: api.pages(PREFIX + f"/actions/runs/{run['id']}/jobs?filter=all&per_page=100", "jobs")
                  for path, run in all_runs.items()}
    checks = []
    for check in snap["checks"]:
        path = CANARY if check["name"] == "relay_e2e_canary" else DRC if check["name"] == "Desktop Release Candidate" else CI
        r.refuse(check["name"] in {*JOBS.values(), *AGGREGATES, "relay_e2e_canary", "Desktop Release Candidate"},
                 "required context needs a reviewed qualification adapter")
        run_ = all_runs[path]
        job = selected_job(executions[path], check["name"], run_, now)
        r.refuse(check["check_suite_id"] == run_["check_suite_id"] and check["check_run_id"] == job["id"] and
                 check["html_url"] == job["html_url"], "required check is not the selected workflow job")
        if path == CANARY:
            r.refuse(job["run_attempt"] == run_["run_attempt"] == 2, "canary success needs the tested second attempt")
        checks.append({"mode": "verified-reuse", "source_check": check, "source_run_id": run_["id"],
                       "source_run_attempt": run_["run_attempt"], "source_job_attempt": job["run_attempt"]})
    artifacts = api.pages(PREFIX + f"/actions/runs/{ci['id']}/artifacts?per_page=100", "artifacts")
    proof_bindings = []
    for key, name in JOBS.items():
        job = selected_job(executions[CI], name, ci, now)
        label = f"qualification-{job['run_attempt']}-{key}"
        matches = [a for a in artifacts if a["name"] == label and not a["expired"]]
        r.refuse(len(matches) == 1, f"successful whole-job proof missing or ambiguous: {name}; qualify affected work")
        artifact = matches[0]
        r.refuse(artifact["workflow_run"]["id"] == ci["id"] and artifact["workflow_run"]["head_sha"] == candidate,
                 "artifact workflow provenance mismatch")
        archive = base64.b64decode(api.call("archive", PREFIX + f"/actions/artifacts/{artifact['id']}/zip"), validate=True)
        r.refuse(artifact.get("digest") == "sha256:" + digest_bytes(archive), "immutable archive digest changed")
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            r.refuse(bundle.namelist() == ["protected-ci-qualification.json"] and
                     bundle.getinfo("protected-ci-qualification.json").file_size <= 256 * 1024,
                     "unexpected qualification archive contents")
            proof = json.loads(bundle.read("protected-ci-qualification.json"))
        verify_source_proof(proof, key, job, ci, source, target_tree, expected_bindings, epoch)
        tested = api.one(PREFIX + f"/git/commits/{r.sha40(proof['tested_sha'], 'tested SHA')}")
        r.refuse(tested["sha"] == proof["tested_sha"] and tested["tree"]["sha"] == target_tree,
                 "provider tested tree differs")
        if tested["sha"] != candidate:
            r.refuse([p["sha"] for p in tested["parents"]] == [base, candidate], "tested merge ordered parents differ")
        if key == "security":
            advisory = api.one("/repos/RustSec/advisory-db/git/ref/heads/main")
            r.refuse(proof["context"].get("advisory_sha") == advisory["object"]["sha"],
                     "Security advisory input changed; qualify Security again")
        proof_bindings.append({"job": key, "source_job": job, "artifact": artifact, "source_proof": proof})
    # Re-read the changing authority after downloading all proofs.
    r.refuse(r.snapshot(api, *r.REPOSITORY.split("/"), candidate, "main") == snap,
             "source checks or authority changed during acquisition")
    for path, run_ in all_runs.items():
        r.refuse(api.pages(PREFIX + f"/actions/runs/{run_['id']}/jobs?filter=all&per_page=100", "jobs") == executions[path],
                 "source job execution changed during acquisition")
        r.refuse(source_run(api, path, run_["event"], candidate, now) == run_, "source execution moved during acquisition")
    r.refuse(current_epoch(api) == epoch, "execution context invalidated during acquisition")
    return {"checks": checks, "jobs": proof_bindings,
            "workflow_runs": all_runs, "epoch": epoch, "bindings": expected_bindings}


def canonical_main(head):
    value = run(["git", "ls-remote", "--exit-code", CANONICAL, "refs/heads/main"]).decode().splitlines()
    r.refuse(value == [f"{head}\trefs/heads/main"], "canonical Buzz main differs from actual GitHub landing")
    return {"repository": CANONICAL, "ref": "refs/heads/main", "sha": head}


def desktop_identity(head):
    # Execute the maintained exact-commit metadata gate in-process; substitute
    # only its API transport with the pinned read-only receipt client.
    path = ROOT / "scripts/desktop_release.py"
    data = path.read_bytes()
    r.refuse(data == run(["git", "show", f"{head}:scripts/desktop_release.py"]), "desktop verifier source differs")
    spec = importlib.util.spec_from_file_location("landing_desktop", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(path), "exec"), module.__dict__)
    module.ROOT = ROOT
    gh, identity = r.resolve_gh()
    client = r.GhClient(gh, identity)
    module.gh_json = lambda endpoint: client.one("/" + endpoint.lstrip("/"))
    previous_path = os.environ.get("PATH")
    try:
        # The maintained release-mode gate starts a metadata-only child. Its
        # gh/git resolution must use the same system clients, not caller PATH.
        os.environ["PATH"] = "/usr/bin:/bin"
        module.verify_main(argparse.Namespace(commit=head, repo=r.REPOSITORY))
    finally:
        if previous_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = previous_path
    return {"mode": "executed", "check": "desktop_release.py verify-main", "head_sha": head}


def verify_candidate(client, head, base, source_raw, now=None):
    """Check complete source reuse coverage before authorizing any landing."""
    now = now or dt.datetime.now(dt.timezone.utc)
    source = json.loads(source_raw)
    r.refuse(source_raw == r.canonical_json(source), "original source receipt is not canonical JSON")
    r.validate_receipt(source, r.REPOSITORY, head, "pull-request", now, MAX_AGE)
    r.refuse(source["pull_request"]["base_sha"] == base, "reviewed source base mismatch")
    verify_policy_bytes(head)
    r.reverify_receipt(source, client)
    canonical_main(base)
    api = Evidence(client)
    commit = api.one(PREFIX + f"/git/commits/{head}")
    r.refuse(commit["sha"] == head, "candidate commit identity mismatch")
    qualified = qualify_source(api, source, commit["tree"]["sha"], now, bindings(head))
    r.reverify_receipt(source, client)
    canonical_main(base)
    return {"schema_version": 1, "source": "protected-candidate-qualification", "repository": r.REPOSITORY,
            "candidate_sha": head, "base_sha": base, "tree_sha": commit["tree"]["sha"], "overall": "PASS",
            "timestamp": now.isoformat(), "source_receipt_sha256": digest_bytes(source_raw),
            "qualification": qualified, "evidence": api.data}


def acquire(client, head, source_raw, candidate, base, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    source = json.loads(source_raw)
    r.refuse(source_raw == r.canonical_json(source), "original source receipt is not canonical JSON")
    r.validate_receipt(source, r.REPOSITORY, candidate, "pull-request", now, MAX_AGE)
    r.refuse(source["pull_request"]["base_sha"] == base, "reviewed base differs from source qualification")
    verify_policy_bytes(head)
    expected = bindings(head)
    r.refuse(expected == bindings(candidate), "reviewed workflow/dependencies differ from actual landing")
    canonical = canonical_main(head)
    desktop = desktop_identity(head)
    api = Evidence(client)
    qualified = readback(api, source, head, now, expected)
    r.refuse(canonical_main(head) == canonical, "canonical authority moved")
    return {"schema_version": 2, "source": "protected-ci", "scope": "main", "repository": r.REPOSITORY,
            "head_sha": head, "timestamp": now.isoformat(), "overall": "PASS", "protected": True,
            "full_exact_head": False, "full_verified_landing": True, "policy": POLICY,
            "source_receipt_bytes": base64.b64encode(source_raw).decode(), "source_receipt_sha256": digest_bytes(source_raw),
            "provider_client": client.identity, "evidence": api.data, "qualification": qualified,
            "canonical": canonical, "landing_checks": [desktop]}


def validate(value, repository, head, scope, now, max_age):
    r.exact_fields(value, {"schema_version", "source", "scope", "repository", "head_sha", "timestamp", "overall",
                          "protected", "full_exact_head", "full_verified_landing", "policy", "source_receipt_bytes",
                          "source_receipt_sha256", "provider_client", "evidence", "qualification", "canonical", "landing_checks"}, "landing receipt")
    r.refuse(value["schema_version"] == 2 and value["source"] == "protected-ci" and scope == value["scope"] == "main" and
             value["repository"] == repository == r.REPOSITORY and value["head_sha"] == head and
             value["overall"] == "PASS" and value["protected"] is True and value["full_exact_head"] is False and
             value["full_verified_landing"] is True and value["policy"] == POLICY, "invalid landed qualification receipt")
    fresh(value["timestamp"], now, "landing receipt")
    timestamp = dt.datetime.fromisoformat(value["timestamp"].replace("Z", "+00:00"))
    r.refuse((now - timestamp).total_seconds() <= max_age, "landing receipt exceeds requested age")
    raw = base64.b64decode(value["source_receipt_bytes"], validate=True)
    r.refuse(digest_bytes(raw) == value["source_receipt_sha256"], "original source receipt bytes changed")
    source = json.loads(raw)
    r.validate_receipt(source, repository, value["qualification"]["candidate"], "pull-request", now, MAX_AGE)
    r.refuse(value["provider_client"] == source["provider"]["client"], "landing client identity changed")
    verify_policy_bytes(head)
    expected = bindings(head)
    api = Evidence(retained=value["evidence"])
    r.refuse(readback(api, source, head, now, expected) == value["qualification"], "retained source qualification changed")
    r.refuse(api.position == len(api.data["calls"]) and
             {item[3] for item in api.data["calls"]} == set(api.data["bodies"]), "extra retained evidence")
    r.refuse(value["canonical"] == {"repository": CANONICAL, "ref": "refs/heads/main", "sha": head}, "canonical receipt identity mismatch")
    r.refuse(value["landing_checks"] == [{"mode": "executed", "check": "desktop_release.py verify-main", "head_sha": head}],
             "landed desktop identity gate missing")
    return value


def reverify(value, client):
    now = dt.datetime.now(dt.timezone.utc)
    validate(value, r.REPOSITORY, value["head_sha"], "main", now, MAX_AGE)
    raw = base64.b64decode(value["source_receipt_bytes"], validate=True)
    canonical_main(value["head_sha"])
    qualified = readback(Evidence(client), json.loads(raw), value["head_sha"], now, bindings(value["head_sha"]))
    r.refuse(qualified == value["qualification"], "live source or landing authority differs from receipt")
    desktop_identity(value["head_sha"])
    canonical_main(value["head_sha"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("capture",))
    parser.add_argument("--job", choices=JOBS, required=True)
    args = parser.parse_args()
    try:
        proof = capture(args.job)
        Path("protected-ci-qualification.json").write_bytes(r.canonical_json(proof))
    except (r.ReceiptError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"qualification capture refused: {exc}", file=sys.stderr)
        raise SystemExit(4)
