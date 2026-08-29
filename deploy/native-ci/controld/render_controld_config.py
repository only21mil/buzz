#!/usr/bin/env python3
"""Render the capacity-zero Buzz CI controld configuration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import tempfile

CAPACITY = 0
STORE_ROOT = "/var/lib/buzzci/controld"
MAX_CONFIG_BYTES = 16 * 1024


def validate_store_root(store_root: str) -> None:
    path = Path(store_root)
    if (
        not path.is_absolute()
        or path != Path(os.path.abspath(path))
        or any(component in {".", ".."} for component in path.parts)
    ):
        raise ValueError("controld store root must be an absolute normalized path")


def config_bytes(store_root: str = STORE_ROOT, capacity: int = CAPACITY) -> bytes:
    validate_store_root(store_root)
    if isinstance(capacity, bool) or capacity != CAPACITY:
        raise ValueError("controld package supports capacity exactly zero")
    value = {"schema_version": 1, "capacity": capacity, "store_root": store_root}
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


def render(path: Path, store_root: str = STORE_ROOT) -> None:
    parent = require_safe_parent(path)
    if path.exists() or path.is_symlink():
        raise ValueError("output must not already exist")
    payload = config_bytes(store_root)
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


def check(path: Path, store_root: str = STORE_ROOT, expected_uid: int | None = None) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (expected_uid is not None and metadata.st_uid != expected_uid)
        ):
            raise ValueError("controld configuration metadata is unsafe")
        raw = b""
        while chunk := os.read(fd, MAX_CONFIG_BYTES + 1 - len(raw)):
            raw += chunk
            if len(raw) > MAX_CONFIG_BYTES:
                raise ValueError("controld configuration is too large")
        if raw != config_bytes(store_root):
            raise ValueError("controld configuration is not canonical capacity zero")
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--store-root", default=STORE_ROOT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--expected-uid", type=int)
    arguments = parser.parse_args()
    if arguments.check:
        check(arguments.output, arguments.store_root, arguments.expected_uid)
    else:
        render(arguments.output, arguments.store_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
