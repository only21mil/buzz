#!/usr/bin/env python3
"""Freeze an exact, dormant Buzz CI execd installation package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

SCHEMA = "buzz-ci-execd-install-package-v1"
PROVENANCE_SCHEMA = "buzz-ci-binary-provenance-v1"
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RELATIVE = Path("deploy/native-ci/execd")
DEFAULT_STATE = {
    "enabled": False,
    "active": False,
    "provisioned": False,
    "capacity": 0,
}
DAEMON_CONTRACT = {
    "capacity": 0,
    "descriptor_name": "buzz-ci-execd",
    "peer_accounts": ["buzzci-ctl", "buzzci-runner"],
    "service_user": "root",
    "socket_mode": "0666",
    "socket_path": "/run/buzzci/execd.sock",
}

STATIC_ASSETS = (
    ("service", "templates/buzz-ci-execd.service", "buzz-ci-execd.service", "/etc/systemd/system/buzz-ci-execd.service", 0o400, 0o644, 0, 0),
    ("socket", "templates/buzz-ci-execd.socket", "buzz-ci-execd.socket", "/etc/systemd/system/buzz-ci-execd.socket", 0o400, 0o644, 0, 0),
    ("tmpfiles", "templates/buzzci-execd.tmpfiles", "buzzci-execd.conf", "/usr/lib/tmpfiles.d/buzzci-execd.conf", 0o400, 0o644, 0, 0),
    ("documentation", "README.md", "README.md", "/usr/share/doc/buzz-ci-execd/README.md", 0o400, 0o644, 0, 0),
)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_regular(path: Path, mode: int | None = None, max_bytes: int = 128 * 1024 * 1024) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe regular file: {path}")
        if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
            raise ValueError(f"wrong source mode: {path}")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"source is too large: {path}")
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(fd)


def load_provenance(path: Path) -> tuple[dict[str, object], bytes]:
    raw, _ = read_regular(path, 0o600, 64 * 1024)
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"schema", "binary", "source_commit", "profile", "sha256"}:
        raise ValueError("invalid binary provenance fields")
    if value["schema"] != PROVENANCE_SCHEMA or value["binary"] != "buzz-ci-execd" or value["profile"] != "release":
        raise ValueError("invalid binary provenance identity")
    if not isinstance(value["source_commit"], str) or not GIT_OID.fullmatch(value["source_commit"]):
        raise ValueError("invalid binary provenance source commit")
    if not isinstance(value["sha256"], str) or not DIGEST.fullmatch(value["sha256"]):
        raise ValueError("invalid binary provenance digest")
    return value, raw


def git_output(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def verify_source(root: Path, source_commit: str) -> Path:
    if not GIT_OID.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object id")
    root = Path(git_output(root, "rev-parse", "--show-toplevel"))
    if git_output(root, "rev-parse", "HEAD") != source_commit:
        raise ValueError("source checkout HEAD does not match the requested commit")
    if git_output(root, "status", "--porcelain", "--untracked-files=all", "--", str(PACKAGE_RELATIVE)):
        raise ValueError("execd package source path is not clean")
    package_dir = root / PACKAGE_RELATIVE
    if Path(os.path.realpath(package_dir)) != package_dir:
        raise ValueError("execd package source directory must not contain symbolic links")
    subprocess.run(
        ["git", "-C", str(root), "diff", "--quiet", source_commit, "--", str(PACKAGE_RELATIVE)],
        check=True,
    )
    for path in (
        PACKAGE_RELATIVE / "README.md",
        PACKAGE_RELATIVE / "templates/buzz-ci-execd.service",
        PACKAGE_RELATIVE / "templates/buzz-ci-execd.socket",
        PACKAGE_RELATIVE / "templates/buzzci-execd.tmpfiles",
    ):
        subprocess.run(
            ["git", "-C", str(root), "ls-files", "--error-unmatch", str(path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return root


def write_asset(path: Path, payload: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)


def entry(role: str, source: str, target: str, source_mode: int, install_mode: int, uid: int, gid: int, payload: bytes) -> dict[str, object]:
    return {
        "role": role,
        "source": f"assets/{source}",
        "target": target,
        "source_mode": f"{source_mode:04o}",
        "install_mode": f"{install_mode:04o}",
        "uid": uid,
        "gid": gid,
        "sha256": sha256(payload),
    }


def freeze_package(
    source_root: Path,
    source_commit: str,
    binary: Path,
    provenance_path: Path,
    output: Path,
) -> dict[str, object]:
    source_root = verify_source(source_root, source_commit)
    provenance, provenance_raw = load_provenance(provenance_path)
    if provenance["source_commit"] != source_commit:
        raise ValueError("binary provenance is bound to another source commit")
    binary_payload, binary_metadata = read_regular(binary, 0o755)
    if binary_metadata.st_uid != provenance_path.lstat().st_uid or binary_metadata.st_gid != provenance_path.lstat().st_gid:
        raise ValueError("binary and provenance ownership differ")
    if sha256(binary_payload) != provenance["sha256"]:
        raise ValueError("binary digest does not match its provenance")

    output = Path(os.path.abspath(output))
    parent = output.parent
    if Path(os.path.realpath(parent)) != parent or parent.lstat().st_mode & 0o022:
        raise ValueError("package output parent must be a private real directory")
    if output.exists() or output.is_symlink():
        raise ValueError("package output must not already exist")
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    stage.chmod(0o700)
    assets = stage / "assets"
    assets.mkdir(mode=0o700)
    try:
        entries: list[dict[str, object]] = []
        write_asset(assets / "buzz-ci-execd", binary_payload, 0o500)
        entries.append(entry("binary", "buzz-ci-execd", "/usr/libexec/buzz-ci-execd", 0o500, 0o755, 0, 0, binary_payload))

        package_dir = source_root / PACKAGE_RELATIVE
        for role, source_name, asset_name, target, source_mode, install_mode, uid, gid in STATIC_ASSETS:
            payload, _ = read_regular(package_dir / source_name, 0o644)
            write_asset(assets / asset_name, payload, source_mode)
            entries.append(entry(role, asset_name, target, source_mode, install_mode, uid, gid, payload))

        entries.sort(key=lambda item: str(item["target"]).encode())
        manifest: dict[str, object] = {
            "schema": SCHEMA,
            "package_id": f"buzz-ci-execd-{source_commit[:12]}-{str(provenance['sha256'])[:12]}",
            "source_commit": source_commit,
            "binary_provenance_sha256": sha256(provenance_raw),
            "default_state": DEFAULT_STATE,
            "daemon_contract": DAEMON_CONTRACT,
            "package_uid": 0,
            "package_gid": 0,
            "directories": [
                {"target": "/usr/share/doc/buzz-ci-execd", "mode": "0755", "uid": 0, "gid": 0},
            ],
            "entries": entries,
        }
        manifest["package_digest"] = sha256(canonical_json(manifest))
        write_asset(stage / "binary-provenance.json", provenance_raw, 0o600)
        write_asset(stage / "package-manifest.json", canonical_json(manifest), 0o600)
        os.replace(stage, output)
        return manifest
    except BaseException:
        shutil.rmtree(stage)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    manifest = freeze_package(
        arguments.source_root,
        arguments.source_commit,
        arguments.binary,
        arguments.binary_provenance,
        arguments.output,
    )
    print(json.dumps({"status": "frozen", "package_id": manifest["package_id"], "package_digest": manifest["package_digest"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
