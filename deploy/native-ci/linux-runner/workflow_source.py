#!/usr/bin/env python3
"""Materialize pinned Git objects and compile the reviewed native shell job subset.

Runs as the dedicated, credential-free materializer/runtime account. This module
is not an admission authority; its caller must first verify the v2 admission.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Callable

import yaml

ORIGIN = "https://github.com/only21mil/buzz.git"
CHECKOUT = "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
CAPTURE = 'python3 scripts/protected-ci-landing.py capture --job "$QUALIFICATION_JOB"'
MAX_FILES = 100_000
MAX_BLOB = 32 * 1024 * 1024
MAX_TREE = 1024 * 1024 * 1024


class Refused(ValueError):
    """An input cannot be executed by the reviewed profile."""


class UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: UniqueLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, (str, bool)) or key in result:
            raise Refused("duplicate or unsupported workflow key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


@dataclass(frozen=True)
class CompiledJob:
    script: bytes
    workload_steps: tuple[int, ...]
    native_steps: tuple[int, ...]
    workflow_sha256: str


def _keys(value: dict, allowed: set[str], context: str) -> None:
    if not isinstance(value, dict) or set(value) - allowed:
        raise Refused(f"unsupported {context}")


def compile_job(workflow: bytes, expected_sha256: str, job_id: str) -> CompiledJob:
    """Compile literal shell steps; only exact GH qualification plumbing maps to native evidence."""
    if hashlib.sha256(workflow).hexdigest() != expected_sha256:
        raise Refused("trusted workflow digest mismatch")
    if len(workflow) > 1024 * 1024 or not re.fullmatch(r"[A-Za-z0-9_-]+", job_id):
        raise Refused("workflow size or job identifier")
    try:
        document = yaml.load(workflow, Loader=UniqueLoader)
    except (yaml.YAMLError, RecursionError, TypeError) as error:
        raise Refused("invalid workflow") from error
    if not isinstance(document, dict) or "defaults" in document:
        raise Refused("unsupported workflow defaults")
    global_env = document.get("env", {})
    native_global_env = {"BUZZ_CI_REUSE_EPOCH": "${{ vars.BUZZ_CI_REUSE_EPOCH }}",
                         "CARGO_TERM_COLOR": "always", "BUZZ_TEST_POSTGRES_PASSWORD": "buzz_dev",
                         "PLAYWRIGHT_BROWSERS_PATH": "${{ github.workspace }}/.cache/ms-playwright"}
    if global_env not in ({}, native_global_env):
        raise Refused("unsupported workflow environment")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or job_id not in jobs:
        raise Refused("job missing")
    job = jobs[job_id]
    _keys(job, {"name", "runs-on", "timeout-minutes", "permissions", "steps"}, "job semantics")
    if job.get("runs-on") != "ubuntu-latest" or job.get("permissions", {}) not in ({}, {"contents": "read"}):
        raise Refused("unsupported runner or permissions")
    steps = job.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > 64:
        raise Refused("unsupported steps")
    commands = ["#!/bin/bash", "set -euo pipefail", "cd /workspace"]
    if global_env:
        commands.extend(["export BUZZ_CI_REUSE_EPOCH=", "export CARGO_TERM_COLOR=always",
                         "export BUZZ_TEST_POSTGRES_PASSWORD=buzz_dev",
                         "export PLAYWRIGHT_BROWSERS_PATH=/workspace/.cache/ms-playwright"])
    workload, native = [], []
    checkout_seen = False
    qualification_seen = False
    for index, step in enumerate(steps):
        _keys(step, {"name", "uses", "run", "shell", "env", "working-directory", "with"}, "step semantics")
        if step.get("uses") == CHECKOUT and set(step) <= {"name", "uses"} and index == 0:
            checkout_seen = True
            native.append(index)
            continue
        if (step.get("run") == CAPTURE and step.get("env") == {"QUALIFICATION_JOB": job_id}
                and set(step) <= {"name", "run", "env"} and workload and index == len(steps) - 2):
            qualification_seen = True
            native.append(index)
            continue
        expected_upload = {"name": "qualification-${{ github.run_attempt }}-" + job_id,
                           "path": "protected-ci-qualification.json", "if-no-files-found": "error", "retention-days": 7}
        if (step.get("uses") == UPLOAD and step.get("with") == expected_upload
                and set(step) <= {"name", "uses", "with"} and qualification_seen and index == len(steps) - 1):
            native.append(index)
            continue
        if not checkout_seen or "uses" in step or "with" in step or not isinstance(step.get("run"), str):
            raise Refused("unsupported action or missing checkout")
        if step.get("shell", "bash") != "bash" or "${{" in step["run"]:
            raise Refused("unsupported shell or expression")
        # Subshells preserve Actions step-local shell state, while files persist.
        commands.append("(")
        cwd = step.get("working-directory", ".")
        if not isinstance(cwd, str) or not safe_relative(cwd, allow_dot=True):
            raise Refused("unsafe working directory")
        import shlex
        commands.append("cd -- " + shlex.quote("/workspace/" + cwd))
        environment = step.get("env", {})
        if not isinstance(environment, dict):
            raise Refused("unsupported step environment")
        for key, value in environment.items():
            if (not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                    or key in {"BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH"}
                    or not isinstance(value, str) or "${{" in value or "\x00" in value):
                raise Refused("unsupported environment value")
            commands.append("export " + key + "=" + shlex.quote(value))
        commands.append(step["run"])
        commands.append(")")
        workload.append(index)
    if not workload or not checkout_seen:
        raise Refused("job contains no executable workload")
    return CompiledJob(("\n".join(commands) + "\n").encode(), tuple(workload), tuple(native), expected_sha256)


def safe_relative(path: str, *, allow_dot: bool = False) -> bool:
    if path == ".":
        return allow_dot
    return (bool(path) and not path.startswith("/") and "\\" not in path
            and all(part not in {"", ".", "..", ".git"} for part in path.split("/"))
            and not any(ord(char) < 32 or ord(char) == 127 for char in path))


def _git(repository: pathlib.Path, args: list[str], deadline: float, *, max_bytes: int = MAX_BLOB,
         cancelled: Callable[[], bool] = lambda: False) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Refused("materialization deadline")
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
                   "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1"}
    argv = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
            "-c", "credential.helper=", "-c", "http.followRedirects=false", "-C", str(repository), *args]
    # The caller bounds fetch via the worker cgroup/quota. Blob and tree reads are
    # bounded here before bytes leave the process.
    with subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True) as child:
        import selectors
        output = bytearray()
        selector = selectors.DefaultSelector()
        assert child.stdout is not None
        selector.register(child.stdout, selectors.EVENT_READ)
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or cancelled():
                    raise Refused("materialization deadline or cancellation")
                if not selector.select(min(remaining, 1)):
                    continue
                chunk = os.read(child.stdout.fileno(), 65536)
                if not chunk:
                    selector.unregister(child.stdout)
                    break
                output.extend(chunk)
                if len(output) > max_bytes:
                    raise Refused("Git output exceeds resource bound")
            if child.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                raise Refused("Git operation failed")
            return bytes(output)
        finally:
            selector.close()
            if child.poll() is None:
                import signal
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()


def materialize(job_dir: pathlib.Path, candidate: str, base: str, workflow_path: str,
                expected_workflow_sha256: str, deadline: float,
                cancelled: Callable[[], bool] = lambda: False) -> dict[str, str]:
    """Fetch only fixed public-origin objects and create an exact raw-object source tree."""
    if (not re.fullmatch(r"[0-9a-f]{40}", candidate) or not re.fullmatch(r"[0-9a-f]{40}", base)
            or not safe_relative(workflow_path) or not re.fullmatch(r"[0-9a-f]{64}", expected_workflow_sha256)):
        raise Refused("invalid source pins")
    from functools import partial
    run_git = partial(_git, cancelled=cancelled)
    git_dir = job_dir / "objects"
    source = job_dir / "source"
    git_dir.mkdir(mode=0o700)
    source.mkdir(mode=0o755)
    run_git(git_dir, ["init", "--bare", "--template="], deadline)
    run_git(git_dir, ["-c", "fetch.fsckObjects=true", "fetch", "--no-tags", "--depth=1", ORIGIN, candidate, base], deadline)
    for oid in {candidate, base}:
        if run_git(git_dir, ["cat-file", "-t", oid], deadline).strip() != b"commit":
            raise Refused("source pin is not a commit")
    tree_oid = run_git(git_dir, ["rev-parse", candidate + "^{tree}"], deadline).decode().strip()
    workflow = run_git(git_dir, ["cat-file", "blob", base + ":" + workflow_path], deadline, max_bytes=1024*1024)
    if hashlib.sha256(workflow).hexdigest() != expected_workflow_sha256:
        raise Refused("trusted workflow digest mismatch")
    entries = run_git(git_dir, ["ls-tree", "-rz", "--full-tree", candidate], deadline, max_bytes=32*1024*1024).split(b"\0")
    parsed = []
    paths = set()
    for entry in entries:
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        path = raw_path.decode("utf-8", errors="strict")
        if mode not in {"100644", "100755", "120000"} or kind != "blob" or not safe_relative(path):
            raise Refused("unsupported source entry")
        if path in paths or len(parsed) >= MAX_FILES:
            raise Refused("duplicate path or file limit")
        paths.add(path)
        parsed.append((mode, oid, path))
    links = {path for mode, _, path in parsed if mode == "120000"}
    if any(any(str(parent) in links for parent in pathlib.PurePosixPath(path).parents) for path in paths):
        raise Refused("symlink source ancestor")
    total = 0
    checkout_digest = hashlib.sha256()
    for mode, oid, path in parsed:
        size = int(run_git(git_dir, ["cat-file", "-s", oid], deadline).strip())
        if size > MAX_BLOB or total + size > MAX_TREE:
            raise Refused("source size limit")
        blob = run_git(git_dir, ["cat-file", "blob", oid], deadline, max_bytes=MAX_BLOB)
        if len(blob) != size or hashlib.sha1(b"blob " + str(size).encode() + b"\0" + blob).hexdigest() != oid:
            raise Refused("source object hash mismatch")
        total += size
        checkout_digest.update(mode.encode() + b" " + path.encode() + b"\0" + bytes.fromhex(oid))
        destination = source / path
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        if mode == "120000":
            target = blob.decode("utf-8", errors="strict")
            import posixpath
            normalized = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
            if (not target or target.startswith("/") or "\\" in target or "\x00" in target
                    or normalized == ".." or normalized.startswith("../") or ".git" in normalized.split("/")):
                raise Refused("source symlink escapes checkout")
            destination.symlink_to(target)
        else:
            with destination.open("xb") as output:
                output.write(blob)
            destination.chmod(0o755 if mode == "100755" else 0o644)
    for directory, _, _ in os.walk(source, followlinks=False):
        pathlib.Path(directory).chmod(0o755)
    (job_dir / "trusted-workflow.yml").write_bytes(workflow)
    return {"candidate_sha": candidate, "base_sha": base, "tree_sha": tree_oid,
            "workflow_file_sha256": expected_workflow_sha256, "checkout_sha256": checkout_digest.hexdigest()}
