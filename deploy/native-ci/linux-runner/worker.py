#!/usr/bin/env python3
"""Credential-free native Linux worker behind the installed v2 admission verifier.

Only the Framework broker may turn this worker's receipt into signed CI events.
The container can access a copy of source and the reviewed shell script only.
"""
from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

from container_runtime import ContainerSpec, run_container
from workflow_source import Refused, compile_job, materialize

PROFILE = Path("/etc/buzzci/linux-runner/profile.json")
ADMISSION_POLICY = Path("/etc/buzzci/linux-runner/admission.json")
SEMANTIC_PROFILE = Path("/etc/buzzci/linux-runner/profile.semantic.json")
VERIFIER = Path("/usr/libexec/buzz-ci-admission-verifier")
JOB_ROOT = Path("/var/lib/buzzci/linux-runner/jobs")
_cancelled = False


def _cancel(_signal: int, _frame: object) -> None:
    global _cancelled
    _cancelled = True


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _read_root_file(path: Path, maximum: int, executable: bool = False) -> bytes:
    for ancestor in [*reversed(path.parents), path]:
        metadata = ancestor.lstat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022 or stat.S_ISLNK(metadata.st_mode):
            raise Refused("unsafe installed authority")
        if ancestor != path and not stat.S_ISDIR(metadata.st_mode):
            raise Refused("unsafe authority ancestor")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > maximum
                or (executable and not metadata.st_mode & 0o111)):
            raise Refused("unsafe installed authority file")
        content = handle.read(maximum + 1)
        if len(content) != metadata.st_size:
            raise Refused("installed authority changed")
        return content


def _publish(path: Path, value: object) -> None:
    _publish_bytes(path, _canonical(value))


def _publish_bytes(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _load_profile(*, for_submission: bool = False) -> tuple[dict, str]:
    raw = _read_root_file(PROFILE, 16384)
    profile = json.loads(raw)
    fields = {"schema_version", "runtime_uid", "verifier_sha256", "admission_policy_sha256",
              "workflow_path", "workflow_id", "job_id", "image", "memory_mib", "cpus", "pids_limit", "maximum_wall_seconds",
              "semantic_profile_sha256"}
    if (not isinstance(profile, dict) or set(profile) != fields or profile["schema_version"] != 1
            or type(profile["runtime_uid"]) is not int or profile["runtime_uid"] == 0
            or os.geteuid() != (0 if for_submission else profile["runtime_uid"])
            or type(profile["maximum_wall_seconds"]) is not int
            or not 1 <= profile["maximum_wall_seconds"] <= 2700):
        raise Refused("unsupported installed profile")
    if hashlib.sha256(_read_root_file(ADMISSION_POLICY, 16384)).hexdigest() != profile["admission_policy_sha256"]:
        raise Refused("admission policy changed")
    if hashlib.sha256(_read_root_file(VERIFIER, 64 * 1024 * 1024, executable=True)).hexdigest() != profile["verifier_sha256"]:
        raise Refused("verifier changed")
    semantic_raw = _read_root_file(SEMANTIC_PROFILE, 16384)
    if hashlib.sha256(semantic_raw).hexdigest() != profile["semantic_profile_sha256"]:
        raise Refused("semantic profile changed")
    semantic = json.loads(semantic_raw)
    for key in ("workflow_path", "workflow_id", "job_id", "image", "memory_mib", "cpus", "pids_limit"):
        if semantic.get(key) != profile[key]:
            raise Refused("installed profile differs from signed runtime semantics")
    if semantic.get("wall_timeout_seconds") != profile["maximum_wall_seconds"]:
        raise Refused("installed deadline differs from signed runtime semantics")
    ContainerSpec("0" * 64, profile["image"], profile["maximum_wall_seconds"], profile["memory_mib"],
                  profile["cpus"], profile["pids_limit"]).validate()
    return profile, hashlib.sha256(raw).hexdigest()


def verify_admission(frame: bytes) -> dict:
    if len(frame) != 992:
        raise Refused("exact v2 job registration frame required")
    result = subprocess.run([str(VERIFIER), str(ADMISSION_POLICY), "live"], input=frame,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
                            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"}, check=False)
    if result.returncode != 0 or len(result.stdout) > 16384:
        raise Refused("v2 admission refused")
    verified = json.loads(result.stdout)
    if not isinstance(verified, dict) or verified.get("schema_version") != 2:
        raise Refused("invalid verifier result")
    return verified


def execute_verified(profile: dict, profile_digest: str, admission: dict, job_dir: Path) -> dict:
    """Execute a verified request once. Caller owns the admission and capacity boundary."""
    if (admission.get("job_id") != profile["job_id"]
            or admission.get("workflow_id") != profile["workflow_id"]
            or admission.get("isolation_profile_digest") != profile["semantic_profile_sha256"]
            or admission.get("artifacts") != [{"artifact_id": "result", "name": "result.json",
                                               "media_type": "application/json", "relative_name": "result.json",
                                               "max_bytes": 32768}]):
        raise Refused("verified job differs from installed profile or artifact contract")
    started_at = int(time.time())
    timeout = min(profile["maximum_wall_seconds"], admission["wall_timeout_seconds"],
                  admission["expires_at"] - started_at)
    if timeout <= 0:
        raise Refused("admission expired")
    deadline = time.monotonic() + timeout
    invocation = hashlib.sha256(_canonical({"admission_message_digest": admission["admission_message_digest"],
                                           "profile_sha256": profile_digest})).hexdigest()
    receipt = {"schema_version": "buzz-ci-native-linux-receipt/v1", "admission": admission,
               "profile_sha256": profile_digest, "invocation_digest": invocation,
               "job_id": profile["job_id"], "started_at": started_at,
               "conclusion": "infrastructure_failure", "cleanup_proven": False}
    try:
        source = materialize(job_dir, admission["candidate_sha"], admission["base_sha"],
                             profile["workflow_path"], admission["workflow_file_sha256"], deadline, lambda: _cancelled)
        compiled = compile_job((job_dir / "trusted-workflow.yml").read_bytes(),
                               admission["workflow_file_sha256"], profile["job_id"])
        script = job_dir / "workflow.sh"
        script.write_bytes(compiled.script)
        script.chmod(0o644)
        receipt["materialization"] = source
        receipt["workflow_execution"] = {
            "schema_version": "buzz-ci-native-shell-projection/v1",
            "job_id": profile["job_id"], "trusted_base_sha": admission["base_sha"],
            "workflow_file_sha256": compiled.workflow_sha256,
            "script_sha256": hashlib.sha256(compiled.script).hexdigest(),
            "executed_step_indices": list(compiled.workload_steps),
            "native_step_indices": list(compiled.native_steps),
            "native_step_meaning": "verified source checkout and native provenance/evidence retention",
        }
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            raise Refused("materialization exhausted deadline")
        spec = ContainerSpec(invocation, profile["image"], remaining, profile["memory_mib"],
                             profile["cpus"], profile["pids_limit"])
        outcome = run_container(spec, job_dir / "source", script, job_dir, lambda: _cancelled)
        output = dataclasses.asdict(outcome)
        for field in ("stdout", "stderr"):
            content = output.pop(field)
            # Raw bytes never enter the signed status. The native evidence item
            # retains bounded bytes, their exact digest, and truncation metadata.
            output[field + "_sha256"] = hashlib.sha256(content).hexdigest()
            _publish_bytes(job_dir / (field + ".log"), content)
            output[field + "_relative_path"] = field + ".log"
        receipt["container"] = output
        receipt["cleanup_proven"] = outcome.cleanup_proven
        if outcome.cleanup_proven:
            receipt["conclusion"] = {"success": "success", "job_failed": "failure",
                                     "cancelled": "cancelled", "deadline": "timed_out"}.get(
                                         outcome.reason, "infrastructure_failure")
    except (Refused, OSError, ValueError, subprocess.SubprocessError) as error:
        # Opaque error class only: no remote stderr, local paths or credential data.
        receipt["error"] = type(error).__name__
    finally:
        # These directories are host-created and never writable by the job's
        # subordinate UID. The job itself writes only to its container tmpfs.
        filesystem_clean = True
        for name in ("source", "objects"):
            path = job_dir / name
            try:
                if path.exists():
                    shutil.rmtree(path)
            except OSError:
                filesystem_clean = False
        receipt["source_cleanup_proven"] = filesystem_clean
        if not filesystem_clean:
            receipt["cleanup_proven"] = False
            receipt["conclusion"] = "infrastructure_failure"
        receipt["finished_at"] = int(time.time())
    return receipt


def claim_job(root: Path, admission: dict, job_id: str) -> Path:
    """Create the persistent logical-attempt claim before any materialization."""
    import re
    if (not isinstance(admission.get("run_id"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", admission["run_id"])
            or type(admission.get("attempt")) is not int or admission["attempt"] < 1
            or not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", job_id)):
        raise Refused("invalid logical attempt")
    logical_digest = hashlib.sha256(_canonical({"run_id": admission["run_id"],
                                               "attempt": admission["attempt"],
                                               "job_id": job_id})).hexdigest()
    job_dir = root / logical_digest
    job_dir.mkdir(mode=0o700)
    return job_dir


def main() -> int:
    if sys.argv[1:] != ["run"] or os.geteuid() == 0:
        raise Refused("dedicated rootless worker invocation required")
    os.umask(0o077)
    profile, profile_digest = _load_profile()
    admission = verify_admission(sys.stdin.buffer.read(993))
    if JOB_ROOT.resolve(strict=True) != JOB_ROOT:
        raise Refused("unsafe job root")
    metadata = JOB_ROOT.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise Refused("private job root required")
    lock_fd = os.open(JOB_ROOT / "capacity.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # The admission frame digest binds the exact signed authorization, not a
        # caller-selected nonce or filesystem path. Existing invocation refuses
        # re-execution, including an incomplete attempt after a broker crash.
        request_digest = admission["admission_message_digest"]
        import re
        if not re.fullmatch(r"[0-9a-f]{64}", request_digest):
            raise Refused("invalid admission digest")
        # A renewed signing window does not permit a logical attempt to rerun.
        job_dir = claim_job(JOB_ROOT, admission, profile["job_id"])
        _publish(job_dir / "admission.json", admission)
        signal.signal(signal.SIGTERM, _cancel)
        signal.signal(signal.SIGINT, _cancel)
        receipt = execute_verified(profile, profile_digest, admission, job_dir)
        receipt_bytes = _canonical(receipt)
        if len(receipt_bytes) > 32768:
            raise Refused("native result exceeds declared artifact bound")
        _publish_bytes(job_dir / "result.json", receipt_bytes)
        sys.stdout.buffer.write(receipt_bytes + b"\n")
        return 0 if receipt["conclusion"] == "success" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Refused, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": type(error).__name__}), file=sys.stderr)
        raise SystemExit(2)
