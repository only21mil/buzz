"""Shared filesystem and serialization helpers for native CI packages.

Component-specific read policies and package schemas stay in each installer.
"""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
import os
from pathlib import Path
import stat
import re
import subprocess


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


def git_output(root: Path, *arguments: str) -> str:
    """Run Git in the supplied checkout and return stripped text output."""
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def entry(role: str, source: str, target: str, source_mode: int, install_mode: int, uid: int, gid: int, payload: bytes) -> dict[str, object]:
    """Describe a frozen asset with its target metadata and digest."""
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


def write_asset(path: Path, payload: bytes, mode: int) -> None:
    """Create and sync a new asset without following or replacing links."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)


def parse_mode(value: object) -> int:
    """Parse the package file-mode format."""
    if not isinstance(value, str) or not re.fullmatch(r"0[4567][0-7]{2}", value):
        raise ValueError("invalid mode")
    return int(value, 8)


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject repeated keys while decoding a JSON object."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def u32(value: object, *, nonzero: bool = False) -> int:
    """Validate an unsigned 32-bit identity, excluding booleans."""
    minimum = 1 if nonzero else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= (1 << 32) - 1:
        raise ValueError("invalid numeric identity")
    return value


def backup_root_path(root: Path, backup_root: Path) -> Path:
    """Map an absolute backup root into the installation root."""
    if root == Path("/"):
        return backup_root
    return rooted(root, str(backup_root))


def validate_target_parent(root: Path, parent: Path, expected_directories: set[str]) -> None:
    """Validate an existing parent or an explicitly allowed new directory."""
    if parent.exists():
        validate_parent_chain(root, parent)
        return
    logical = "/" + str(parent.relative_to(root))
    if logical not in expected_directories or parent.is_symlink():
        raise ValueError(f"target parent is unavailable: {parent}")
    validate_parent_chain(root, parent.parent)


def ensure_private_tree(root: Path, path: Path, default_backup_root: Path, shared_state_root: Path, install_backups_root: Path, fsync_directory: Callable[[Path], None]) -> None:
    """Create and validate a private backup tree using caller directory policy."""
    root_uid = mapped_id(0, root)
    root_gid = mapped_id(0, root, group=True)
    default_path = backup_root_path(root, default_backup_root)
    exact_modes = {
        rooted(root, str(shared_state_root)): 0o711,
        rooted(root, str(install_backups_root)): 0o700,
        default_path: 0o700,
    } if path == default_path else {path: 0o700}
    current = root
    for component in path.relative_to(root).parts:
        current /= component
        created = not current.exists() and not current.is_symlink()
        if created:
            parent = current.parent
            current.mkdir(mode=0o700)
            descriptor = os.open(
                current, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                os.fchown(descriptor, root_uid, root_gid)
                os.fchmod(descriptor, exact_modes.get(current, 0o700))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            fsync_directory(parent)
        metadata = current.lstat()
        expected_mode = exact_modes.get(current)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != root_uid
            or metadata.st_gid != root_gid
            or (expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode)
            or (expected_mode is None and metadata.st_mode & 0o022)
        ):
            raise ValueError(f"unsafe backup directory chain: {current}")
    require_directory(path, root_uid, root_gid, 0o700)
