#!/usr/bin/env python3
"""Freeze the exact credential-free bytes consumed by both installers."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
INSTALLER_PATH = SCRIPT_DIR / "install-static-system.py"
SPEC = importlib.util.spec_from_file_location("install_static_system", INSTALLER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load install package schema")
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)
DESKTOP_APP_SHA256_TOKEN = b"__BUZZ_APPIMAGE_SHA256__"


def hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def open_source(
    path: Path,
    modes: tuple[int, ...] | None = None,
    *,
    allow_hardlinks: bool = False,
) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_gid != os.getgid()
            or (metadata.st_nlink != 1 and not allow_hardlinks)
        ):
            raise ValueError(f"unsafe freeze source: {path}")
        if modes is not None and stat.S_IMODE(metadata.st_mode) not in modes:
            raise ValueError(f"wrong freeze source mode: {path}")
        return fd
    except Exception:
        os.close(fd)
        raise


def write_payload(destination: Path, payload: bytes, mode: int) -> str:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    try:
        digest = hashlib.sha256()
        view = memoryview(payload)
        while view:
            written = os.write(destination_fd, view)
            digest.update(view[:written])
            view = view[written:]
        os.fchmod(destination_fd, mode)
        os.fsync(destination_fd)
        return digest.hexdigest()
    finally:
        os.close(destination_fd)


def copy_source(
    source: Path,
    destination: Path,
    mode: int,
    *,
    built_binary: bool = False,
    source_modes: tuple[int, ...] | None = None,
) -> str:
    source_fd = open_source(
        source,
        (0o700, 0o755) if built_binary else (source_modes or (mode,)),
        allow_hardlinks=built_binary,
    )
    try:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            mode,
        )
        try:
            digest = hashlib.sha256()
            while chunk := os.read(source_fd, 1024 * 1024):
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    view = view[written:]
            os.fchmod(destination_fd, mode)
            os.fsync(destination_fd)
            return digest.hexdigest()
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


def render_desktop_launcher(template: Path, app_sha256: str) -> bytes:
    source_fd = open_source(template, (0o700, 0o755))
    try:
        chunks: list[bytes] = []
        while chunk := os.read(source_fd, 1024 * 1024):
            chunks.append(chunk)
    finally:
        os.close(source_fd)
    payload = b"".join(chunks)
    if payload.count(DESKTOP_APP_SHA256_TOKEN) != 1:
        raise ValueError("desktop launcher template must contain one AppImage hash token")
    rendered = payload.replace(DESKTOP_APP_SHA256_TOKEN, app_sha256.encode())
    if DESKTOP_APP_SHA256_TOKEN in rendered:
        raise ValueError("desktop launcher AppImage hash token was not fully replaced")
    return rendered


def source_for_entry(
    source_name: str,
    repo_root: Path,
    binary_dir: Path,
    desktop_app: Path,
) -> Path:
    if source_name.startswith("bin/"):
        return binary_dir / Path(source_name).name
    if source_name.startswith("system/"):
        return repo_root / "scripts/mempool-genesis" / Path(source_name).name
    if source_name == "desktop/Buzz_0.5.8_amd64.AppImage":
        return desktop_app
    if source_name == "desktop/launch-buzz-desktop":
        return repo_root / "scripts/mempool-genesis/launch-buzz-desktop"
    raise ValueError(f"unrecognized package source: {source_name}")


def repository_source_modes(source_name: str, package_mode: int) -> tuple[int, ...]:
    if source_name.startswith("system/") and not package_mode & 0o111:
        return (0o400, 0o440, 0o600, 0o640, 0o644)
    if package_mode & 0o111:
        return (0o700, 0o755)
    return (package_mode,)


def entry_contracts() -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for target, (source, mode) in INSTALLER.TARGETS.items():
        entries.append(
            {
                "owner": "static",
                "role": "static",
                "source": source,
                "target": target,
                "source_mode": f"{mode:04o}",
                "install_mode": f"{mode:04o}",
                "status": "A",
            }
        )
    for target, (source, role, source_mode, install_mode) in INSTALLER.DESKTOP_TARGETS.items():
        entries.append(
            {
                "owner": "desktop",
                "role": role,
                "source": source,
                "target": target,
                "source_mode": f"{source_mode:04o}",
                "install_mode": f"{install_mode:04o}",
                "status": "A",
            }
        )
    return sorted(entries, key=lambda entry: str(entry["target"]).encode())


def require_clean_worktree(repo_root: Path) -> None:
    top_level = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if Path(top_level).resolve(strict=True) != repo_root:
        raise ValueError("repo root is not the Git worktree root")
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout
    if status:
        raise ValueError("install package source worktree is not clean")


def build_release_binaries(repo_root: Path) -> Path:
    subprocess.run(
        ["cargo", "build", "--release", "-p", "buzz-agent-key-handoff"],
        cwd=repo_root,
        check=True,
    )
    require_clean_worktree(repo_root)
    return repo_root / "target/release"


def freeze_package(
    package: Path,
    package_id: str,
    repo_root: Path,
    binary_dir: Path,
    desktop_app: Path,
    previous_launcher: Path,
) -> dict[str, object]:
    if not INSTALLER.PACKAGE_ID.fullmatch(package_id):
        raise ValueError("invalid package id")
    if package.exists() or package.is_symlink():
        raise ValueError("package path already exists")
    previous_launcher_fd = open_source(previous_launcher)
    try:
        previous_launcher_hash = hash_fd(previous_launcher_fd)
    finally:
        os.close(previous_launcher_fd)

    package.mkdir(mode=0o700)
    try:
        entries = entry_contracts()
        desktop_app_entry = next(
            entry for entry in entries if entry["role"] == "desktop_app"
        )
        desktop_app_mode = int(str(desktop_app_entry["source_mode"]), 8)
        desktop_app_entry["sha256"] = copy_source(
            desktop_app,
            package / str(desktop_app_entry["source"]),
            desktop_app_mode,
            source_modes=repository_source_modes(
                str(desktop_app_entry["source"]), desktop_app_mode
            ),
        )
        launcher = next(
            entry for entry in entries if entry["role"] == "desktop_launcher"
        )
        launcher_mode = int(str(launcher["source_mode"]), 8)
        launcher_template = source_for_entry(
            str(launcher["source"]), repo_root, binary_dir, desktop_app
        )
        launcher["sha256"] = write_payload(
            package / str(launcher["source"]),
            render_desktop_launcher(
                launcher_template, str(desktop_app_entry["sha256"])
            ),
            launcher_mode,
        )
        for entry in entries:
            if entry["role"] in {"desktop_app", "desktop_launcher"}:
                continue
            source_mode = int(str(entry["source_mode"]), 8)
            source = source_for_entry(
                str(entry["source"]), repo_root, binary_dir, desktop_app
            )
            entry["sha256"] = copy_source(
                source,
                package / str(entry["source"]),
                source_mode,
                built_binary=str(entry["source"]).startswith("bin/"),
                source_modes=repository_source_modes(str(entry["source"]), source_mode),
            )
        manifest: dict[str, object] = {
            "schema": INSTALLER.SCHEMA,
            "package_id": package_id,
            "entries": entries,
            "desktop_launcher_sha256": launcher["sha256"],
            "desktop_previous_launcher_sha256": previous_launcher_hash,
            "package_fingerprint": INSTALLER.package_fingerprint(entries),
        }
        payload = (
            json.dumps(manifest, indent=2, sort_keys=True, separators=(",", ": "))
            + "\n"
        )
        manifest_path = package / INSTALLER.MANIFEST_NAME
        manifest_path.write_text(payload)
        manifest_path.chmod(0o600)
        INSTALLER.exact_manifest(package)
        return manifest
    except Exception:
        shutil.rmtree(package)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--package-id", required=True)
    parser.add_argument("--desktop-app", required=True)
    parser.add_argument("--repo-root", default=str(SCRIPT_DIR.parents[1]))
    parser.add_argument(
        "--previous-launcher",
        default="/home/victor/projects/buzz/scripts/launch_buzz_desktop.sh",
    )
    args = parser.parse_args()

    package = Path(args.package).resolve(strict=False)
    repo_root = Path(args.repo_root).resolve(strict=True)
    require_clean_worktree(repo_root)
    binary_dir = build_release_binaries(repo_root)
    desktop_app = Path(args.desktop_app).resolve(strict=True)
    previous_launcher = Path(args.previous_launcher).resolve(strict=True)
    manifest = freeze_package(
        package,
        args.package_id,
        repo_root,
        binary_dir,
        desktop_app,
        previous_launcher,
    )
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
