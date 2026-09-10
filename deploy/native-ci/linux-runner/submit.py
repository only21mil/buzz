#!/usr/bin/env python3
"""Root supervisor for one genuinely signed native Linux registration.

The result is local operator evidence. Native CI publication remains the existing
trusted controller/keyholder's job after it checks this exact binding.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import sys
import time

import worker
from workflow_source import Refused

SUPERVISOR_ROOT = Path("/var/lib/buzzci/linux-runner/supervisor")
WORKER = Path("/usr/libexec/buzzci/linux-runner/worker.py")
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_RUN = "/usr/bin/systemd-run"
_cancelled = False


def _cancel(_signal: int, _frame: object) -> None:
    global _cancelled
    _cancelled = True


def _command(argv: list[str], *, timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(argv, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"},
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=timeout, check=False)


def _state(unit: str) -> dict[str, str]:
    properties = "ActiveState,SubState,ExecMainPID,ExecMainCode,ExecMainStatus,InvocationID,ControlGroup,LoadState"
    result = _command([SYSTEMCTL, "show", unit, "--property=" + properties])
    if result.returncode != 0 or len(result.stdout) > 16384:
        raise Refused("unit readback unavailable")
    return dict(line.split("=", 1) for line in result.stdout.decode("utf-8").splitlines() if "=" in line)


def _cgroup(unit: str, state: dict[str, str]) -> tuple[int, Path, tuple[int, int]]:
    relative = state.get("ControlGroup", "")
    if not relative.startswith("/") or ".." in relative.split("/") or Path(relative).name != unit:
        raise Refused("unexpected worker cgroup")
    path = Path("/sys/fs/cgroup") / relative.lstrip("/")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    metadata = os.fstat(descriptor)
    return descriptor, path, (metadata.st_dev, metadata.st_ino)


def _empty_cgroup(descriptor: int) -> bool:
    events = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
    with os.fdopen(events, "rb") as handle:
        content = handle.read(4097)
    return len(content) <= 4096 and b"populated 0" in content.splitlines()


def _container_absent(profile: dict, invocation: str) -> bool:
    account = pwd.getpwuid(profile["runtime_uid"])
    result = _command(["/usr/sbin/runuser", "--user", account.pw_name, "--", "/usr/bin/env", "-i",
                       "PATH=/usr/bin:/bin", "HOME=" + account.pw_dir,
                       "XDG_RUNTIME_DIR=/run/user/" + str(account.pw_uid), "/usr/bin/podman", "--remote=false",
                       "container", "exists", "buzzci-" + invocation], timeout=20)
    return result.returncode == 1


def _launch(unit: str, directory: Path, profile: dict) -> None:
    account = pwd.getpwuid(profile["runtime_uid"])
    if (account.pw_uid == 0 or account.pw_name != "buzzci-linux"
            or account.pw_dir != "/var/lib/buzzci/linux-runner/home"):
        raise Refused("dedicated runtime account required")
    # newuidmap/newgidmap need their installed privilege transition for rootless
    # Podman. NoNewPrivileges is enforced inside the container, not on this host
    # helper service. The job never executes on the host as this account.
    properties = [
        "User=" + str(account.pw_uid), "Group=" + str(account.pw_gid),
        "RemainAfterExit=yes", "SuccessExitStatus=1", "KillMode=control-group", "TimeoutStopSec=45",
        "Delegate=yes", "UMask=0077", "MemoryMax=3221225472", "MemorySwapMax=0", "CPUQuota=200%",
        "TasksMax=512", "LimitCORE=0", "LimitFSIZE=2147483648", "PrivateTmp=yes",
        "ProtectSystem=strict", "ProtectHome=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes", "RestrictRealtime=yes", "RestrictSUIDSGID=yes",
        "ReadWritePaths=" + account.pw_dir + " " + str(worker.JOB_ROOT) + " /run/user/" + str(account.pw_uid),
        "StandardInput=file:" + str(directory / "registration.bin"),
        "StandardOutput=file:" + str(directory / "stdout.json"),
        "StandardError=file:" + str(directory / "stderr.log"),
        "Environment=PYTHONNOUSERSITE=1", "UnsetEnvironment=PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH",
    ]
    argv = [SYSTEMD_RUN, "--quiet", "--unit=" + unit, "--service-type=exec"]
    argv += ["--property=" + value for value in properties]
    argv += ["/usr/bin/python3", str(WORKER), "run"]
    if _command(argv).returncode != 0:
        raise Refused("worker unit start failed")


def validate_result(result: dict, admission: dict, profile: dict, profile_digest: str,
                    invocation: str, state: dict[str, str]) -> None:
    if not isinstance(result, dict):
        raise Refused("worker result must be a record")
    if (result.get("schema_version") != "buzz-ci-native-linux-receipt/v1"
            or result.get("admission") != admission or result.get("profile_sha256") != profile_digest
            or result.get("invocation_digest") != invocation or result.get("job_id") != profile["job_id"]
            or result.get("cleanup_proven") is not True or result.get("source_cleanup_proven") is not True
            or result.get("conclusion") not in {"success", "failure", "cancelled", "timed_out"}
            or state.get("ExecMainCode") != "1"
            or state.get("ExecMainStatus") != ("0" if result["conclusion"] == "success" else "1")):
        raise Refused("worker result or actual exit disagrees with verified admission")
    container = result.get("container", {})
    if not isinstance(container, dict):
        raise Refused("worker container result must be a record")
    if container.get("container_name") != "buzzci-" + invocation or container.get("cleanup_proven") is not True:
        raise Refused("worker container identity or cleanup mismatch")
    import re
    source = result.get("materialization", {})
    execution = result.get("workflow_execution", {})
    if (not isinstance(source, dict) or not isinstance(execution, dict)
            or source.get("candidate_sha") != admission["candidate_sha"]
            or source.get("base_sha") != admission["base_sha"]
            or source.get("workflow_file_sha256") != admission["workflow_file_sha256"]
            or not re.fullmatch(r"[0-9a-f]{40}", source.get("tree_sha", ""))
            or not re.fullmatch(r"[0-9a-f]{64}", source.get("checkout_sha256", ""))
            or execution.get("schema_version") != "buzz-ci-native-shell-projection/v1"
            or execution.get("job_id") != profile["job_id"]
            or execution.get("trusted_base_sha") != admission["base_sha"]
            or execution.get("workflow_file_sha256") != admission["workflow_file_sha256"]
            or not re.fullmatch(r"[0-9a-f]{64}", execution.get("script_sha256", ""))
            or execution.get("executed_step_indices") != [1]
            or execution.get("native_step_indices") != [0, 2, 3]):
        raise Refused("source or workload projection differs from supported job")
    expected_reason = {"success": "success", "failure": "job_failed", "cancelled": "cancelled", "timed_out": "deadline"}
    if (container.get("reason") != expected_reason[result["conclusion"]]
            or (result["conclusion"] == "success" and container.get("exit_code") != 0)
            or (result["conclusion"] == "failure" and
                (type(container.get("exit_code")) is not int or container["exit_code"] == 0))):
        raise Refused("container outcome does not prove declared conclusion")


def supervise(directory: Path, profile: dict, profile_digest: str, admission: dict) -> dict:
    invocation = hashlib.sha256(worker._canonical({"admission_message_digest": admission["admission_message_digest"],
                                                  "profile_sha256": profile_digest})).hexdigest()
    unit = "buzz-ci-linux-" + invocation + ".service"
    deadline = time.monotonic() + min(profile["maximum_wall_seconds"], admission["wall_timeout_seconds"],
                                      admission["expires_at"] - int(time.time()))
    if deadline <= time.monotonic():
        raise Refused("admission expired before unit launch")
    descriptor = None
    launched = False
    state = {}
    stopped = False
    proof = None
    signal_sent = False
    try:
        if _state(unit).get("LoadState") != "not-found":
            raise Refused("invocation unit already exists")
        launched = True
        _launch(unit, directory, profile)
        first = _state(unit)
        identity = first.get("InvocationID", "")
        if len(identity) != 32:
            raise Refused("worker invocation identity unavailable")
        descriptor, cgroup_path, cgroup_identity = _cgroup(unit, first)
        while True:
            state = _state(unit)
            if state.get("InvocationID") != identity:
                raise Refused("worker invocation changed")
            if state.get("SubState") in {"exited", "failed", "dead"}:
                break
            if (_cancelled or time.monotonic() >= deadline) and not signal_sent:
                if _command([SYSTEMCTL, "kill", "--kill-whom=main", "--signal=SIGTERM", unit]).returncode != 0:
                    raise Refused("worker cancellation delivery failed")
                signal_sent = True
                cleanup_deadline = time.monotonic() + 45
            if signal_sent and time.monotonic() >= cleanup_deadline:
                raise Refused("worker cleanup deadline exceeded")
            time.sleep(0.1)
        raw = worker._read_root_file(directory / "stdout.json", 32769)
        result = json.loads(raw)
        validate_result(result, admission, profile, profile_digest, invocation, state)
        if not _container_absent(profile, invocation) or not _empty_cgroup(descriptor):
            raise Refused("container or worker descendants remain")
        proof = {"schema_version": "buzz-ci-native-linux-supervisor/v1", "native_result": result,
                 "unit": unit, "invocation_id": identity,
                 "cgroup_path": str(cgroup_path), "cgroup_device": cgroup_identity[0],
                 "cgroup_inode": cgroup_identity[1], "exec_main_code": int(state["ExecMainCode"]),
                 "exec_main_status": int(state["ExecMainStatus"]), "container_absent": True,
                 "recursive_cgroup_empty": True}
    finally:
        if launched:
            stopped = _command([SYSTEMCTL, "stop", unit], timeout=50).returncode == 0
            after = _state(unit)
            stopped = stopped and after.get("ActiveState") in {"inactive", "failed"}
        if descriptor is not None:
            os.close(descriptor)
    if not stopped or proof is None:
        raise Refused("unit cleanup unproven")
    proof["unit_inactive"] = True
    proof["finished_at"] = int(time.time())
    return proof


def main() -> int:
    if sys.argv[1:] != ["run"] or os.geteuid() != 0:
        raise Refused("root submit invocation required")
    os.umask(0o077)
    profile, profile_digest = worker._load_profile(for_submission=True)
    registration = sys.stdin.buffer.read(993)
    admission = worker.verify_admission(registration)
    root_metadata = SUPERVISOR_ROOT.lstat()
    if (SUPERVISOR_ROOT.resolve(strict=True) != SUPERVISOR_ROOT or root_metadata.st_uid != 0
            or stat.S_IMODE(root_metadata.st_mode) != 0o700):
        raise Refused("private root supervisor directory required")
    lock_fd = os.open(SUPERVISOR_ROOT / "capacity.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory = worker.claim_job(SUPERVISOR_ROOT, admission, profile["job_id"])
        worker._publish_bytes(directory / "registration.bin", registration)
        worker._publish_bytes(directory / "stdout.json", b"")
        worker._publish_bytes(directory / "stderr.log", b"")
        signal.signal(signal.SIGTERM, _cancel)
        signal.signal(signal.SIGINT, _cancel)
        proof = supervise(directory, profile, profile_digest, admission)
        proof["registration_sha256"] = hashlib.sha256(registration).hexdigest()
        worker._publish(directory / "supervisor.json", proof)
        sys.stdout.buffer.write(worker._canonical(proof) + b"\n")
        return 0 if proof["native_result"]["conclusion"] == "success" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Refused, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": type(error).__name__}), file=sys.stderr)
        raise SystemExit(2)
