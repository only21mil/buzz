"""Shared filesystem checks for native CI installers.

Component-specific read policies and package schemas stay in each installer.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat


def canonical_json(value: object) -> bytes:
    """Encode deterministic JSON with one trailing newline."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256(payload: bytes) -> str:
    """Return the hexadecimal SHA-256 digest of a payload."""
    return hashlib.sha256(payload).hexdigest()


def mapped_id(value: int, root: Path, *, group: bool = False) -> int:
    """Map root ownership to the invoking identity for a fake root."""
    if value != 0 or root == Path("/"):
        return value
    metadata = root.lstat()
    return metadata.st_gid if group else metadata.st_uid


def require_directory(path: Path, uid: int, gid: int, mode_value: int) -> None:
    """Reject a directory with unexpected type, owner, group, or mode."""
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode_value
    ):
        raise ValueError(f"unsafe directory metadata: {path}")


def require_package_tree(package: Path, root: Path) -> tuple[int, int]:
    """Validate the private package and assets directories."""
    package = Path(os.path.abspath(package))
    if Path(os.path.realpath(package)) != package:
        raise ValueError("package root must not be a symbolic path")
    root_uid = mapped_id(0, root)
    root_gid = mapped_id(0, root, group=True)
    require_directory(package, root_uid, root_gid, 0o700)
    require_directory(package / "assets", root_uid, root_gid, 0o700)
    return root_uid, root_gid


def rooted(root: Path, target: str) -> Path:
    """Resolve an absolute installation target beneath the supplied root."""
    if not target.startswith("/") or ".." in Path(target).parts:
        raise ValueError("unsafe target path")
    return root / target.removeprefix("/")


def validate_parent_chain(root: Path, parent: Path) -> None:
    """Reject symbolic or writable installation parent directories."""
    root = Path(os.path.abspath(root))
    if Path(os.path.realpath(root)) != root:
        raise ValueError("install root must not be a symbolic path")
    root_uid = mapped_id(0, root)
    root_gid = mapped_id(0, root, group=True)
    current = root
    require_directory(
        current, root_uid, root_gid, stat.S_IMODE(current.lstat().st_mode)
    )
    for component in parent.relative_to(root).parts:
        current /= component
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != root_uid
            or metadata.st_gid != root_gid
            or metadata.st_mode & 0o022
        ):
            raise ValueError(f"unsafe target directory chain: {current}")
