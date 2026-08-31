#!/usr/bin/env python3
"""Validate clean Git package sources without depending on checkout umask."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess

GIT_OID = re.compile(r"^[0-9a-f]{40}$")
GIT_REGULAR_MODES = {0o100644: {0o600, 0o644}, 0o100755: {0o700, 0o755}}
SHARED_HELPER = Path("deploy/native-ci/package_source.py")


def git_output(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _relative_path(value: Path) -> Path:
    if value.is_absolute() or not value.parts or any(part in {"", ".", ".."} for part in value.parts):
        raise ValueError(f"package source path must be normalized and relative: {value}")
    return value


def _git_file_mode(root: Path, relative: Path) -> int:
    output = git_output(root, "ls-files", "--stage", "--", str(relative))
    lines = output.splitlines()
    if len(lines) != 1:
        raise ValueError(f"tracked source is missing or ambiguous: {relative}")
    fields = lines[0].split(maxsplit=3)
    if len(fields) != 4 or fields[2] != "0" or fields[3] != str(relative):
        raise ValueError(f"tracked source index entry differs: {relative}")
    try:
        git_mode = int(fields[0], 8)
    except ValueError as error:
        raise ValueError(f"tracked source Git mode is invalid: {relative}") from error
    if git_mode not in GIT_REGULAR_MODES:
        raise ValueError(f"tracked source is not a regular file: {relative}")
    return git_mode


def validate_metadata(metadata: os.stat_result, git_mode: int, expected_uid: int, where: str) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"tracked source is not a single regular file: {where}")
    if metadata.st_uid != expected_uid or not metadata.st_mode & stat.S_IRUSR:
        raise ValueError(f"tracked source owner access differs: {where}")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in GIT_REGULAR_MODES.get(git_mode, set()):
        if mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            raise ValueError(f"tracked source has unsafe permissions: {where}")
        raise ValueError(f"tracked source executable class or materialized mode differs: {where}")


def tracked_payload(
    source_root: Path,
    relative: Path,
    expected_git_mode: int | None = None,
    max_bytes: int = 128 * 1024 * 1024,
) -> tuple[bytes, os.stat_result]:
    source_root = Path(os.path.abspath(source_root))
    relative = _relative_path(relative)
    path = source_root / relative
    if Path(os.path.realpath(path)) != path:
        raise ValueError(f"tracked source must not contain symbolic links: {relative}")
    git_mode = _git_file_mode(source_root, relative)
    if expected_git_mode is not None and git_mode != expected_git_mode:
        raise ValueError(f"tracked source Git mode differs: {relative}")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError(f"tracked source cannot be opened safely: {relative}") from error
    try:
        metadata = os.fstat(descriptor)
        validate_metadata(metadata, git_mode, source_root.lstat().st_uid, str(relative))
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"tracked source is too large: {relative}")
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def tracked_files(source_root: Path, package_relative: Path) -> list[Path]:
    package_relative = _relative_path(package_relative)
    output = git_output(source_root, "ls-files", "--stage", "--", str(package_relative))
    paths: list[Path] = []
    for line in output.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) != 4 or fields[2] != "0":
            raise ValueError(f"tracked package index entry differs: {package_relative}")
        relative = Path(fields[3])
        _relative_path(relative)
        if relative != package_relative and package_relative not in relative.parents:
            raise ValueError(f"tracked package source escaped its path: {relative}")
        paths.append(relative)
    if not paths:
        raise ValueError(f"package source has no tracked files: {package_relative}")
    return paths


def verify_checkout(source_root: Path, source_commit: str, package_relative: Path) -> Path:
    if not GIT_OID.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object id")
    package_relative = _relative_path(package_relative)
    source_root = Path(os.path.abspath(source_root))
    if Path(os.path.realpath(source_root)) != source_root or not source_root.is_dir():
        raise ValueError("source root must be a real directory")
    if Path(git_output(source_root, "rev-parse", "--show-toplevel")) != source_root:
        raise ValueError("source root must be the Git checkout root")
    if git_output(source_root, "rev-parse", "HEAD") != source_commit:
        raise ValueError("source checkout HEAD does not match the requested commit")
    for relative in tracked_files(source_root, package_relative):
        tracked_payload(source_root, relative)
    if package_relative != SHARED_HELPER:
        tracked_payload(source_root, SHARED_HELPER, 0o100644, 1024 * 1024)
    bound_paths = sorted({str(package_relative), str(SHARED_HELPER)})
    if git_output(source_root, "status", "--porcelain", "--untracked-files=all", "--", *bound_paths):
        raise ValueError("package source path is not clean")
    subprocess.run(
        ["git", "-C", str(source_root), "diff", "--quiet", source_commit, "--", *bound_paths],
        check=True,
    )
    return source_root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--package-path", type=Path, action="append", required=True)
    arguments = parser.parse_args()
    for package_path in arguments.package_path:
        verify_checkout(arguments.source_root, arguments.source_commit, package_path)
    print(json.dumps({"package_paths": [str(path) for path in arguments.package_path], "status": "checked"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
