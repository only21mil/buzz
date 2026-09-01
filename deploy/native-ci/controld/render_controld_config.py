#!/usr/bin/env python3
"""Render or verify strict dormant and capacity-one controld configuration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import tempfile
from urllib.parse import urlsplit

CAPACITY = 0
STORE_ROOT = "/var/lib/buzzci/controld"
MAX_CONFIG_BYTES = 16 * 1024
RUNNER_SOCKET = "/run/buzzci/runner-control.sock"
KEYHOLDER_SOCKET = "/run/buzzci/keyholder.sock"
ACCEPTANCE_BINDING = "/var/lib/buzzci/activation-controller/controld-acceptance-v2.json"
ACTIVE_FIELDS = {
    "relay_url", "relay_http_origin", "channel_id", "poll_interval_millis",
    "runner_socket", "runner_uid", "runner_gid", "runner_connect_timeout_millis",
    "runner_io_timeout_millis", "runner_transport_attempts",
    "lane_manifest_digest", "lane_epoch", "audience_digest", "isolation_profile_digest",
    "workflow_id", "workflow_digest", "jobs", "keyholder_socket", "keyholder_uid",
    "keyholder_gid", "keyholder_selectors", "keyholder_timeout_millis",
    "keyholder_transport_attempts",
}


def validate_store_root(store_root: str) -> None:
    path = Path(store_root)
    if (
        not path.is_absolute()
        or path != Path(os.path.abspath(path))
        or any(component in {".", ".."} for component in path.parts)
    ):
        raise ValueError("controld store root must be an absolute normalized path")


def config_bytes(
    store_root: str = STORE_ROOT,
    capacity: int = CAPACITY,
    active: dict[str, object] | None = None,
    acceptance_binding: str = ACCEPTANCE_BINDING,
) -> bytes:
    validate_store_root(store_root)
    if isinstance(capacity, bool) or capacity not in {0, 1}:
        raise ValueError("controld capacity must be exactly zero or one")
    if capacity == 0 and active is not None:
        raise ValueError("capacity zero cannot contain provider bindings")
    if acceptance_binding != ACCEPTANCE_BINDING:
        raise ValueError("acceptance binding differs from the fixed receipt")
    if capacity == 1:
        validate_active(active)
    value = {
        "schema_version": 2,
        "capacity": capacity,
        "store_root": store_root,
        "acceptance_binding": acceptance_binding,
    }
    if active is not None:
        value.update(active)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def validate_active(active: dict[str, object] | None) -> None:
    if not isinstance(active, dict) or set(active) != ACTIVE_FIELDS:
        raise ValueError("capacity one requires the exact provider field set")
    relay = urlsplit(str(active["relay_url"]))
    origin = urlsplit(str(active["relay_http_origin"]))
    if (
        relay.scheme != "wss" or not relay.hostname or relay.path not in {"", "/"}
        or relay.username is not None or relay.password is not None or relay.query or relay.fragment
        or origin.scheme != "https" or origin.hostname != relay.hostname
        or origin.port != relay.port or origin.path not in {"", "/"}
        or origin.username is not None or origin.password is not None or origin.query or origin.fragment
    ):
        raise ValueError("relay URL and HTTP origin are not one exact secure authority")
    if active["runner_socket"] != RUNNER_SOCKET:
        raise ValueError("runner socket differs from the fixed interface")
    if active["keyholder_socket"] != KEYHOLDER_SOCKET:
        raise ValueError("keyholder socket differs from the fixed interface")
    for field in ("runner_uid", "runner_gid", "keyholder_uid", "keyholder_gid"):
        value = active[field]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 0xFFFFFFFF:
            raise ValueError(f"invalid identity field: {field}")
    for field, maximum in (
        ("poll_interval_millis", 60_000),
        ("runner_connect_timeout_millis", 5_000),
        ("runner_io_timeout_millis", 30_000),
        ("runner_transport_attempts", 8),
        ("keyholder_timeout_millis", 5_000),
        ("keyholder_transport_attempts", 8),
    ):
        value = active[field]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise ValueError(f"invalid bounded field: {field}")
    for field in ("lane_manifest_digest", "audience_digest", "isolation_profile_digest", "workflow_digest"):
        value = active[field]
        if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise ValueError(f"invalid digest field: {field}")
    if not isinstance(active["lane_epoch"], int) or isinstance(active["lane_epoch"], bool) or active["lane_epoch"] < 1:
        raise ValueError("invalid lane epoch")
    if not isinstance(active["channel_id"], str) or not isinstance(active["workflow_id"], str):
        raise ValueError("invalid channel or workflow identity")
    jobs = active["jobs"]
    if not isinstance(jobs, list) or len(jobs) != 1:
        raise ValueError("capacity-one static job source must contain exactly one job")
    artifacts = jobs[0].get("artifacts") if isinstance(jobs[0], dict) else None
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise ValueError("capacity-one static job must declare exactly one artifact")
    artifact = artifacts[0]
    if not isinstance(artifact, dict) or set(artifact) != {
        "artifact_id", "name", "media_type", "relative_name", "max_bytes"
    }:
        raise ValueError("capacity-one artifact declaration is incomplete")
    for field in ("artifact_id", "name", "relative_name"):
        value = artifact[field]
        if (
            not isinstance(value, str) or not 1 <= len(value) <= 64
            or value in {".", ".."}
            or any(not (ch.isascii() and (ch.isalnum() or ch in "._-")) for ch in value)
        ):
            raise ValueError(f"invalid artifact field: {field}")
    media_type = artifact["media_type"]
    if (
        not isinstance(media_type, str) or not 1 <= len(media_type) <= 64
        or "/" not in media_type
        or any(not (ch.isascii() and (ch.isalnum() or ch in "/+.-")) for ch in media_type)
    ):
        raise ValueError("invalid artifact media type")
    maximum = artifact["max_bytes"]
    if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 32768:
        raise ValueError("invalid artifact byte bound")
    selectors = active["keyholder_selectors"]
    if not isinstance(selectors, dict) or set(selectors) != {"ci_event", "nip98", "manifest"}:
        raise ValueError("keyholder selectors are incomplete")
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
