#!/usr/bin/env python3
"""Render the closed Buzz CI runner configuration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import tempfile

MAX_UID = (1 << 32) - 1


def config_bytes(controld_uid: int) -> bytes:
    if not 1 <= controld_uid <= MAX_UID:
        raise ValueError("controld UID must be a nonzero u32")
    # Host is deliberately absent. The runner therefore returns
    # backend_unavailable and exposes no execution capacity.
    value = {"schema_version": 1, "controld_uid": controld_uid}
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def require_safe_parent(path: Path) -> Path:
    parent = path.parent
    lexical = Path(os.path.abspath(parent))
    resolved = Path(os.path.realpath(parent))
    if lexical != resolved:
        raise ValueError("output parent must not contain symbolic links")
    metadata = resolved.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
        raise ValueError("output parent must be a private real directory")
    return resolved


def render(path: Path, controld_uid: int) -> None:
    parent = require_safe_parent(path)
    if path.exists() or path.is_symlink():
        raise ValueError("output must not already exist")
    payload = config_bytes(controld_uid)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def check(path: Path, controld_uid: int, expected_uid: int | None = None) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (expected_uid is not None and metadata.st_uid != expected_uid)
        ):
            raise ValueError("runner configuration metadata is unsafe")
        raw = b""
        while chunk := os.read(fd, 16 * 1024 + 1 - len(raw)):
            raw += chunk
            if len(raw) > 16 * 1024:
                raise ValueError("runner configuration is too large")
        if raw != config_bytes(controld_uid):
            raise ValueError("runner configuration is not the closed canonical form")
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controld-uid", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--expected-uid", type=int)
    arguments = parser.parse_args()
    if arguments.check:
        check(arguments.output, arguments.controld_uid, arguments.expected_uid)
    else:
        render(arguments.output, arguments.controld_uid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
