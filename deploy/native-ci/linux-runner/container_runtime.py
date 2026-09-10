"""Fixed rootless Podman execution for an already-verified shell job.

The invoking service validates source and workflow provenance and owns the job
folder. This module accepts no executable, engine URL, container arguments, or
container environment from a workflow. The supported network profile is none.

Host prerequisites: a dedicated nonroot account with subordinate UID/GID ranges,
a provisioned mode-0700 /run/user/<uid>, delegated cgroup v2 controllers, and the
digest-pinned image already in that account's rootless storage. The image must
provide /bin/bash and cp. Source directories must be traversable and files
readable by container UID 1000, which maps to a subordinate host UID. SELinux
hosts use private container labels on the fresh job-owned source and script.
Shared checkouts cannot be supplied as mounts. These requirements need an
authorized live smoke.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import pwd
import re
import selectors
import stat
import subprocess
import time
from typing import Callable

PODMAN = "/usr/bin/podman"
OUTPUT_LIMIT = 32 * 1024
IMAGE_RE = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ContainerSpec:
    """Policy-bounded values supplied by the trusted invocation parser."""

    invocation_digest: str
    image: str
    timeout_seconds: int = 900
    memory_mib: int = 2048
    cpus: int = 2
    pids_limit: int = 256
    network: str = "none"

    def validate(self) -> None:
        if (
            not DIGEST_RE.fullmatch(self.invocation_digest)
            or not IMAGE_RE.fullmatch(self.image)
            or type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 3600
            or type(self.memory_mib) is not int
            or not 128 <= self.memory_mib <= 8192
            or type(self.cpus) is not int
            or not 1 <= self.cpus <= 8
            or type(self.pids_limit) is not int
            or not 16 <= self.pids_limit <= 1024
            or self.network != "none"
        ):
            raise ValueError("unsupported container policy")


@dataclass(frozen=True)
class ContainerResult:
    """Bounded terminal output and independent container removal evidence."""

    exit_code: int | None
    reason: str
    cleanup_proven: bool
    container_name: str
    stdout: bytes = b""
    stderr: bytes = b""
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class _Capture:
    def __init__(self) -> None:
        self.kept = bytearray()
        self.count = 0

    def append(self, data: bytes) -> None:
        self.count += len(data)
        self.kept.extend(data[: max(0, OUTPUT_LIMIT - len(self.kept))])


def _safe_path(path: Path, *, directory: bool, owner: int) -> Path:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("noncanonical job path")
    if any(char in str(path) for char in (",", ":", "\n", "\r", "\x00")):
        raise ValueError("unsupported job path")
    metadata = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(metadata.st_mode)
        or metadata.st_uid not in (0, owner)
        or metadata.st_mode & 0o022
    ):
        raise ValueError("unsafe job path")
    return path


def _environment(uid: int) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": pwd.getpwuid(uid).pw_dir,
        "XDG_RUNTIME_DIR": f"/run/user/{uid}",
        "LANG": "C.UTF-8",
    }


def _command(spec: ContainerSpec, source: Path, script: Path, job_dir: Path) -> list[str]:
    """Build fixed host argv. The final shell text is constant, never interpolated."""
    return [
        PODMAN, "--remote=false", "run",
        "--name", f"buzzci-{spec.invocation_digest}",
        "--cidfile", str(job_dir / "container.cid"),
        "--pull=never", "--userns=auto:size=65536", "--user=1000:1000",
        "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--read-only", "--read-only-tmpfs=false", "--ipc=private", "--pid=private",
        "--uts=private", "--cgroupns=private", "--hostname=buzz-ci-job",
        "--http-proxy=false", "--unsetenv-all", "--log-driver=none",
        "--memory", f"{spec.memory_mib}m", "--memory-swap", f"{spec.memory_mib}m",
        "--cpus", str(spec.cpus), "--pids-limit", str(spec.pids_limit),
        "--ulimit=nofile=1024:1024", "--ulimit=core=0:0",
        "--mount", f"type=bind,src={source},dst=/source,ro=true,relabel=private",
        "--mount", f"type=bind,src={script},dst=/workflow.sh,ro=true,relabel=private",
        "--tmpfs", f"/workspace:rw,exec,nosuid,nodev,notmpcopyup,size={spec.memory_mib}m,mode=0700,uid=1000,gid=1000",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,notmpcopyup,size=256m,mode=1777",
        "--env=PATH=/usr/local/bin:/usr/bin:/bin", "--env=HOME=/workspace",
        "--env=LANG=C.UTF-8", "--workdir=/workspace", "--entrypoint=/bin/sh",
        spec.image, "-eu", "-c",
        "cp -R /source/. /workspace/; exec /bin/bash --noprofile --norc -e -o pipefail /workflow.sh",
    ]


def _control(arguments: list[str], environment: dict[str, str]) -> int | None:
    try:
        return subprocess.run(
            [PODMAN, "--remote=false", *arguments],
            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=20, check=False,
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return None


def _remove_and_verify(name: str, environment: dict[str, str]) -> bool:
    _control(["rm", "--force", "--time=5", name], environment)
    # Podman's exists command returns exactly 1 for absence. Backend errors,
    # including 125 and a timeout, never constitute removal evidence.
    return _control(["container", "exists", name], environment) == 1


def _stop_client(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run_container(
    spec: ContainerSpec,
    source: Path,
    script: Path,
    job_dir: Path,
    cancelled: Callable[[], bool],
) -> ContainerResult:
    """Execute once, drain bounded output, and require proven removal for success.

    No process is started as root. The caller keeps source, script and the
    private job directory stable for this call, and writes terminal evidence
    only after examining cleanup_proven. Container writes live solely in tmpfs.
    """
    spec.validate()
    uid = os.geteuid()
    if uid == 0:
        raise PermissionError("rootless runtime UID required")
    source = _safe_path(source, directory=True, owner=uid)
    script = _safe_path(script, directory=False, owner=uid)
    job_dir = _safe_path(job_dir, directory=True, owner=uid)
    if job_dir.stat().st_uid != uid or stat.S_IMODE(job_dir.stat().st_mode) != 0o700:
        raise ValueError("private runtime-owned job directory required")
    if (source != job_dir / "source" or script != job_dir / "workflow.sh"
            or source.stat().st_uid != uid or script.stat().st_uid != uid
            or script.stat().st_nlink != 1):
        raise ValueError("private relabel requires fresh job-owned source and script")
    if (job_dir / "container.cid").exists() or (job_dir / "container.cid").is_symlink():
        raise ValueError("invocation already started")
    name = f"buzzci-{spec.invocation_digest}"
    environment = _environment(uid)
    if _control(["container", "exists", name], environment) != 1:
        raise RuntimeError("container absence before launch unproven")
    if cancelled():
        return ContainerResult(None, "cancelled", True, name)
    stdout, stderr = _Capture(), _Capture()
    process = None
    exit_code = None
    reason = "runtime_error"
    cleanup_proven = False
    try:
        process = subprocess.Popen(
            _command(spec, source, script, job_dir), env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, start_new_session=True,
        )
        deadline = time.monotonic() + spec.timeout_seconds
        with selectors.DefaultSelector() as selector:
            if process.stdout is None or process.stderr is None:
                raise RuntimeError("missing runtime output pipes")
            for pipe, capture in ((process.stdout, stdout), (process.stderr, stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, capture)
            while True:
                if cancelled():
                    reason = "cancelled"
                    break
                if time.monotonic() >= deadline:
                    reason = "deadline"
                    break
                for key, _ in selector.select(timeout=0.1):
                    try:
                        data = os.read(key.fileobj.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if data:
                        key.data.append(data)
                    else:
                        selector.unregister(key.fileobj)
                exit_code = process.poll()
                if exit_code is not None and not selector.get_map():
                    reason = "success" if exit_code == 0 else "job_failed"
                    break
    except (OSError, RuntimeError, subprocess.SubprocessError):
        reason = "runtime_error"
    finally:
        if process is not None:
            try:
                _stop_client(process)
            except (OSError, subprocess.SubprocessError):
                # A live client might create the container after removal.
                reason = "client_stop_unproven"
            else:
                cleanup_proven = _remove_and_verify(name, environment)
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
        else:
            cleanup_proven = _remove_and_verify(name, environment)
    if not cleanup_proven:
        reason = "cleanup_unproven"
    return ContainerResult(
        exit_code, reason, cleanup_proven, name, bytes(stdout.kept), bytes(stderr.kept),
        stdout.count, stderr.count, stdout.count > OUTPUT_LIMIT, stderr.count > OUTPUT_LIMIT,
    )
