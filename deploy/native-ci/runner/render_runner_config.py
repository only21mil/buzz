#!/usr/bin/env python3
"""Render strict dormant or broker-v2 Buzz CI runner configuration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile

MAX_UID = (1 << 32) - 1
BROKER_SOCKET = "/run/buzzci/execd.sock"
BROKER_UID = 0
BROKER_GID = 0
REPLAY_JOURNAL = "/var/lib/buzzci/runner/v2-replay.json"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
PROXY_FIELDS = frozenset({
    "connect_timeout_millis", "io_timeout_millis", "transport_attempts",
    "retry_delay_millis", "lane_manifest_digest", "lane_epoch",
    "admission_key_generation", "isolation_profile_digest", "audience_digest",
    "acceptance_time_reference",
})


def config_bytes(controld_uid: int, controld_gid: int, proxy: dict[str, object] | None = None) -> bytes:
    if not 1 <= controld_uid <= MAX_UID or not 1 <= controld_gid <= MAX_UID:
        raise ValueError("controld UID and GID must be nonzero u32 values")
    value: dict[str, object] = {
        "schema_version": 2,
        "controld_uid": controld_uid,
        "controld_gid": controld_gid,
        "mode": "dormant" if proxy is None else "v2_proxy",
    }
    if proxy is not None:
        if not isinstance(proxy, dict) or set(proxy) != PROXY_FIELDS:
            raise ValueError("v2 proxy fields are incomplete or unknown")
        for field in ("lane_manifest_digest", "isolation_profile_digest", "audience_digest"):
            digest = proxy[field]
            if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or digest == "0" * 64:
                raise ValueError(f"invalid {field}")
        if not 1 <= int(proxy["connect_timeout_millis"]) <= 30_000:
            raise ValueError("invalid connect timeout")
        if not 1 <= int(proxy["io_timeout_millis"]) <= 30_000:
            raise ValueError("invalid I/O timeout")
        if not 1 <= int(proxy["transport_attempts"]) <= 5:
            raise ValueError("invalid transport attempt count")
        if not 0 <= int(proxy["retry_delay_millis"]) <= 5_000:
            raise ValueError("invalid retry delay")
        if int(proxy["lane_epoch"]) <= 0 or int(proxy["admission_key_generation"]) <= 0:
            raise ValueError("lane epoch and key generation must be positive")
        if int(proxy["acceptance_time_reference"]) <= 0:
            raise ValueError("acceptance time reference must be positive")
        value.update({
            "execd_socket": BROKER_SOCKET,
            "execd_uid": BROKER_UID,
            "execd_gid": BROKER_GID,
            "replay_journal": REPLAY_JOURNAL,
            **proxy,
        })
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


def render(path: Path, controld_uid: int, controld_gid: int, proxy: dict[str, object] | None = None) -> None:
    parent = require_safe_parent(path)
    if path.exists() or path.is_symlink():
        raise ValueError("output must not already exist")
    payload = config_bytes(controld_uid, controld_gid, proxy)
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


def check(path: Path, controld_uid: int, controld_gid: int, expected_uid: int | None = None, proxy: dict[str, object] | None = None) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or (expected_uid is not None and metadata.st_uid != expected_uid)):
            raise ValueError("runner configuration metadata is unsafe")
        raw = b""
        while chunk := os.read(fd, 16 * 1024 + 1 - len(raw)):
            raw += chunk
            if len(raw) > 16 * 1024:
                raise ValueError("runner configuration is too large")
        if raw != config_bytes(controld_uid, controld_gid, proxy):
            raise ValueError("runner configuration is not canonical")
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controld-uid", type=int, required=True)
    parser.add_argument("--controld-gid", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--expected-uid", type=int)
    arguments = parser.parse_args()
    if arguments.check:
        check(arguments.output, arguments.controld_uid, arguments.controld_gid, arguments.expected_uid)
    else:
        render(arguments.output, arguments.controld_uid, arguments.controld_gid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
