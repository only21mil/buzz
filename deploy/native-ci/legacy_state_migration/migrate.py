#!/usr/bin/env python3
"""Archive or restore the one known legacy Buzz CI host layout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any


PLAN_SCHEMA = "buzz-ci-legacy-state-migration-plan-v1"
CHECK_SCHEMA = "buzz-ci-legacy-state-migration-check-v1"
TX_SCHEMA = "buzz-ci-legacy-state-migration-transaction-v1"
RECEIPT_SCHEMA = "buzz-ci-legacy-state-migration-receipt-v1"
ROLLBACK_SCHEMA = "buzz-ci-legacy-state-migration-rollback-v1"
DEFAULT_ARCHIVE = "/var/lib/buzzci-legacy-archive/f7b2abdb-v1"
SHARED = "/var/lib/buzzci"
ARCHIVE_PATHS = (
    "/var/lib/buzzci/activation",
    "/var/lib/buzzci/fixtures",
    "/var/lib/buzzci/lease01",
    "/var/lib/buzzci/lease01.img",
    "/var/lib/buzzci/leases",
    "/etc/buzzci/authority",
    "/etc/buzzci/harness.env",
    "/etc/buzzci/qualification-cases",
    "/etc/systemd/system/sockets.target.wants/buzz-ci-execd.socket",
    "/etc/systemd/system/buzz-ci-execd.service",
    "/etc/systemd/system/buzz-ci-execd.socket",
    "/etc/systemd/system/buzz-ci-execd.service.d",
    "/usr/lib/tmpfiles.d/buzzci-control.conf",
)
ALLOWED_SYMLINKS = {
    "/etc/systemd/system/sockets.target.wants/buzz-ci-execd.socket": "/etc/systemd/system/buzz-ci-execd.socket",
}
RETAINED_DIRECT = {"principals", "seccomp"}
# Principal home directories are owned by their principal on the live host.
# Only the shared root and its normalized directories must be root-owned.
PRINCIPAL_OWNERS = {"/var/lib/buzzci/principals/ctl": (961, 961)}
NORMALIZED_DIRS = (
    "/var/lib/buzzci",
    "/var/lib/buzzci/seccomp",
    "/var/lib/buzzci/seccomp/v1",
    "/var/lib/buzzci/seccomp/v1/sha256",
)
UNITS = ("buzz-ci-execd.socket", "buzz-ci-execd.service")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
LIVE_REGULAR_EXPECTATIONS = {
    "/etc/systemd/system/buzz-ci-execd.service": ("0644", 341, "681adfc8ef9756f20909b34c6acd959558455e44bc1f1a6c14c937328f39eda8"),
    "/etc/systemd/system/buzz-ci-execd.socket": ("0644", 306, "afa9e9eef2dba23689410788914ce5baa91a8bcfbe9b1dcf7d1ada4f00fabae5"),
    "/etc/systemd/system/buzz-ci-execd.service.d/10-host-adapters.conf": ("0644", 519, "2b9497c8f942156e3ef54167380dbaccf9ddba7ebc4982ab1932fd3bb8c79e04"),
    "/usr/lib/tmpfiles.d/buzzci-control.conf": ("0644", 611, "fd5d9c4472f6fe1f4ad34d76446cbb308964587e05ae4346876e6a2f27034d42"),
}


class Refusal(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("duplicate JSON key")
        result[key] = value
    return result


def mapped(root: Path, logical: str) -> Path:
    path = PurePosixPath(logical)
    if not logical.startswith("/") or ".." in path.parts:
        raise Refusal(f"unsafe logical path: {logical}")
    return root / logical.removeprefix("/")


def logical_from(root: Path, path: Path) -> str:
    return "/" + path.relative_to(root).as_posix()


def root_ids(root: Path) -> tuple[int, int]:
    if root == Path("/"):
        return (0, 0)
    metadata = root.lstat()
    return (metadata.st_uid, metadata.st_gid)


def principal_owner(root: Path, logical: str) -> tuple[int, int]:
    if root == Path("/"):
        return PRINCIPAL_OWNERS[logical]
    return root_ids(root)


def safe_root(value: str) -> Path:
    root = Path(os.path.abspath(value))
    if Path(os.path.realpath(root)) != root:
        raise Refusal("root must not contain symbolic links")
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
        raise Refusal("root directory metadata is unsafe")
    if root == Path("/") and (metadata.st_uid, metadata.st_gid) != (0, 0):
        raise Refusal("live root is not root-owned")
    return root


def file_digest(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise Refusal(f"unsafe regular file: {path}")
        digest = hashlib.sha256()
        while block := os.read(descriptor, 4 * 1024 * 1024):
            digest.update(block)
        after = os.fstat(descriptor)
        if identity(metadata) != identity(after):
            raise Refusal(f"file changed while hashing: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def metadata_record(
    path: Path,
    *,
    root: Path,
    base: Path,
    allow_symlink: bool = False,
    require_root_owned: bool = True,
) -> dict[str, object]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) and not allow_symlink:
        raise Refusal(f"symbolic links are forbidden in archived trees: {path}")
    if metadata.st_nlink != 1 and stat.S_ISREG(metadata.st_mode):
        raise Refusal(f"hard-linked files are forbidden: {path}")
    if require_root_owned and (metadata.st_uid != root_ids(root)[0] or metadata.st_gid != root_ids(root)[1]):
        raise Refusal(f"legacy archive item is not root-owned: {path}")
    if metadata.st_mode & 0o022 and not stat.S_ISLNK(metadata.st_mode):
        raise Refusal(f"legacy archive item is group/world writable: {path}")
    record: dict[str, object] = {
        "relative_path": "." if path == base else path.relative_to(base).as_posix(),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "links": metadata.st_nlink,
        "size": metadata.st_size,
    }
    if stat.S_ISLNK(metadata.st_mode):
        record["type"] = "symlink"
        record["target"] = os.readlink(path)
    elif stat.S_ISREG(metadata.st_mode):
        record["type"] = "file"
        record["sha256"] = file_digest(path)
    elif stat.S_ISDIR(metadata.st_mode):
        record["type"] = "directory"
    else:
        raise Refusal(f"special files are forbidden in archived trees: {path}")
    return record


def scan_tree(
    path: Path,
    *,
    root: Path,
    allow_symlink: bool = False,
    require_root_owned: bool = True,
) -> dict[str, object]:
    if not path.exists() and not path.is_symlink():
        raise Refusal(f"required legacy path is absent: {path}")
    entries = [
        metadata_record(
            path,
            root=root,
            base=path,
            allow_symlink=allow_symlink,
            require_root_owned=require_root_owned,
        )
    ]
    if entries[0]["type"] == "directory":
        for directory, names, files in os.walk(path, topdown=True, followlinks=False):
            names.sort()
            files.sort()
            parent = Path(directory)
            for name in names + files:
                entries.append(
                    metadata_record(
                        parent / name,
                        root=root,
                        base=path,
                        require_root_owned=require_root_owned,
                    )
                )
    tree_digest = sha256(canonical(entries))
    return {"path": logical_from(root, path), "entries": entries, "tree_sha256": tree_digest}


def scan_retained(root: Path) -> list[dict[str, object]]:
    shared = mapped(root, SHARED)
    metadata = shared.lstat()
    expected_ids = root_ids(root)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != expected_ids
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise Refusal("legacy shared root must be root-owned mode 0700")
    names = {entry.name for entry in os.scandir(shared)}
    expected = {PurePosixPath(path).name for path in ARCHIVE_PATHS if path.startswith(SHARED + "/")}
    if names != expected | RETAINED_DIRECT:
        raise Refusal(f"unknown direct shared-root entries: {sorted(names ^ (expected | RETAINED_DIRECT))}")
    retained = []
    for name in sorted(RETAINED_DIRECT):
        tree = scan_tree(shared / name, root=root, require_root_owned=name != "principals")
        if tree["entries"][0]["type"] != "directory":
            raise Refusal(f"retained shared entry is not a directory: {name}")
        retained.append(tree)
    seccomp_entries = {item["relative_path"]: item for item in retained[1]["entries"]}
    if set(seccomp_entries) != {".", "v1", "v1/sha256"}:
        raise Refusal("legacy seccomp tree has unknown or missing entries")
    if any(item["type"] != "directory" for item in seccomp_entries.values()):
        raise Refusal("legacy seccomp tree contains a non-directory")
    principals_entries = {item["relative_path"]: item for item in retained[0]["entries"]}
    if set(principals_entries) != {".", "ctl"} or any(
        item["type"] != "directory" for item in principals_entries.values()
    ):
        raise Refusal("legacy principals tree has unknown or missing entries")
    if principals_entries["."]["mode"] != "0711" or principals_entries["ctl"]["mode"] != "0700":
        raise Refusal("legacy principals directory modes differ")
    expected_root = root_ids(root)
    expected_ctl = principal_owner(root, SHARED + "/principals/ctl")
    if (principals_entries["."]["uid"], principals_entries["."]["gid"]) != expected_root or (
        principals_entries["ctl"]["uid"], principals_entries["ctl"]["gid"]
    ) != expected_ctl:
        raise Refusal("legacy principals ownership differs")
    return retained


def require_exact_etc_buzzci(root: Path, expected: set[str]) -> None:
    directory = mapped(root, "/etc/buzzci")
    metadata = directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != root_ids(root)
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        raise Refusal("/etc/buzzci metadata differs")
    observed = {entry.name for entry in os.scandir(directory)}
    if observed != expected:
        raise Refusal(f"unknown or missing /etc/buzzci entries: {sorted(observed ^ expected)}")


def validate_live_expectations(root: Path, items: list[dict[str, object]]) -> None:
    if root != Path("/"):
        return
    flattened: dict[str, dict[str, object]] = {}
    for tree in items:
        base = str(tree["path"])
        for entry in tree["entries"]:  # type: ignore[index]
            relative = str(entry["relative_path"])
            full_path = base if relative == "." else base.rstrip("/") + "/" + relative
            flattened[full_path] = entry
    for path, (mode, size, expected_digest) in LIVE_REGULAR_EXPECTATIONS.items():
        entry = flattened.get(path)
        if entry is None or (entry.get("type"), entry.get("mode"), entry.get("size"), entry.get("sha256")) != (
            "file",
            mode,
            size,
            expected_digest,
        ):
            raise Refusal(f"known legacy fragment differs: {path}")
    lease = flattened.get("/var/lib/buzzci/lease01.img")
    if lease is None or (lease.get("type"), lease.get("mode"), lease.get("size"), lease.get("links")) != (
        "file",
        "0600",
        20 * 1024 * 1024 * 1024,
        1,
    ):
        raise Refusal("known legacy lease image metadata differs")


def decode_mount(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def proc_files(proc_root: Path, name: str) -> list[str]:
    path = proc_root / name
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise Refusal(f"cannot read {path}: {error}") from error


def path_contains(parent: str, candidate: str) -> bool:
    parent_path = PurePosixPath(parent)
    candidate_path = PurePosixPath(candidate)
    return candidate_path == parent_path or parent_path in candidate_path.parents


def prove_unused(root: Path, proc_root: Path, sys_root: Path, trees: list[dict[str, object]]) -> dict[str, object]:
    logical_paths = [str(item["path"]) for item in trees]
    logical_paths.extend(str(item["archive_path"]) for item in trees if "archive_path" in item)
    identities = {
        (int(entry["device"]), int(entry["inode"]))
        for tree in trees
        for entry in tree["entries"]
    }
    for line in proc_files(proc_root, "self/mountinfo"):
        fields = line.split()
        if "-" not in fields or len(fields) < 10:
            raise Refusal("malformed /proc/self/mountinfo")
        separator = fields.index("-")
        mountpoint = decode_mount(fields[4])
        source = decode_mount(fields[separator + 2])
        if any(path_contains(path, mountpoint) or source == path for path in logical_paths):
            raise Refusal(f"legacy path is mounted or used as a mount source: {mountpoint} {source}")
    swaps = proc_files(proc_root, "swaps")
    for line in swaps[1:]:
        fields = line.split()
        if fields and any(path_contains(path, decode_mount(fields[0])) for path in logical_paths):
            raise Refusal("legacy path is active swap")
    for line in proc_files(proc_root, "locks"):
        match = re.search(r"\s([0-9a-fA-F]+):([0-9a-fA-F]+):(\d+)\s", line)
        if match:
            dev = os.makedev(int(match.group(1), 16), int(match.group(2), 16))
            if (dev, int(match.group(3))) in identities:
                raise Refusal("legacy inode has an active kernel lock")
    for process in proc_root.iterdir():
        if not process.name.isdigit():
            continue
        for collection in ("fd", "map_files"):
            directory = process / collection
            try:
                entries = list(directory.iterdir())
            except FileNotFoundError:
                continue
            except PermissionError as error:
                raise Refusal(f"cannot inspect {directory}") from error
            for entry in entries:
                try:
                    target = os.readlink(entry)
                    metadata = entry.stat()
                except FileNotFoundError:
                    continue
                except OSError as error:
                    raise Refusal(f"cannot inspect process reference {entry}: {error}") from error
                target = target.removesuffix(" (deleted)")
                if (metadata.st_dev, metadata.st_ino) in identities or any(
                    path_contains(path, target) for path in logical_paths if target.startswith("/")
                ):
                    raise Refusal(f"legacy path is open by process {process.name}")
    loop_root = sys_root / "class/block"
    if not loop_root.is_dir():
        raise Refusal(f"cannot inspect loop devices under {loop_root}")
    for loop in loop_root.glob("loop*/loop/backing_file"):
        try:
            backing = loop.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            continue
        if backing and not backing.startswith("/"):
            backing = "/" + backing
        if any(path_contains(path, backing) for path in logical_paths):
            raise Refusal(f"legacy path is attached to loop device {loop}")
    return {"mountinfo": "clear", "swaps": "clear", "locks": "clear", "process_references": "clear", "loop_devices": "clear"}


def systemctl(systemctl_path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(systemctl_path), *arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )


def unit_state(systemctl_path: Path, unit: str, *, allow_absent: bool = False) -> dict[str, str]:
    result = systemctl(
        systemctl_path,
        "show",
        unit,
        "--property=LoadState",
        "--property=ActiveState",
        "--property=SubState",
        "--property=UnitFileState",
        "--property=FragmentPath",
        "--property=DropInPaths",
    )
    if result.returncode != 0:
        raise Refusal(f"systemctl show failed for {unit}: {result.stderr.strip()}")
    fields: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise Refusal(f"malformed systemctl output for {unit}")
        fields[key] = value
    if set(fields) != {"LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths"}:
        raise Refusal(f"incomplete systemctl output for {unit}")
    if allow_absent and fields == {
        "LoadState": "not-found",
        "ActiveState": "inactive",
        "SubState": "dead",
        "UnitFileState": "",
        "FragmentPath": "",
        "DropInPaths": "",
    }:
        return {"unit": unit, **fields}
    if fields["LoadState"] != "loaded" or fields["ActiveState"] not in {"active", "inactive"}:
        raise Refusal(f"unsupported unit state for {unit}: {fields}")
    if fields["UnitFileState"] not in {"enabled", "disabled", "static"}:
        raise Refusal(f"unsupported unit-file state for {unit}: {fields}")
    return {"unit": unit, **fields}


def validate_tool_path(root: Path, systemctl_path: Path) -> None:
    if root == Path("/") and systemctl_path != Path("/usr/bin/systemctl"):
        raise Refusal("live migration requires /usr/bin/systemctl")
    metadata = systemctl_path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
        raise Refusal("systemctl executable metadata is unsafe")
    if root == Path("/") and (metadata.st_uid, metadata.st_gid) != (0, 0):
        raise Refusal("systemctl executable is not root-owned")


def archive_destination(archive_root: str, logical: str) -> str:
    return archive_root.rstrip("/") + "/items/rootfs" + logical


def validate_archive_location(root: Path, archive: str) -> None:
    archive_path = PurePosixPath(archive)
    if not archive.startswith("/") or ".." in archive_path.parts:
        raise Refusal("archive root must be absolute and canonical")
    protected = ("/var/lib/buzzci", "/etc/buzzci", "/etc/systemd", "/usr/lib/tmpfiles.d")
    if any(path_contains(item, archive) or path_contains(archive, item) for item in protected):
        raise Refusal("archive root overlaps a managed or legacy root")
    target = mapped(root, archive)
    existing = target
    while not existing.exists():
        if existing == root:
            raise Refusal("archive root has no existing parent")
        existing = existing.parent
    if Path(os.path.realpath(existing)) != existing:
        raise Refusal("archive root has a symbolic ancestor")
    metadata = existing.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
        raise Refusal("archive parent is unsafe")
    shared_device = mapped(root, SHARED).lstat().st_dev
    if metadata.st_dev != shared_device:
        raise Refusal("archive root is not on the shared-state filesystem")


def normalized_directory_mode(root: Path, logical: str) -> str:
    # Only the directory itself must be root-owned. Its children were already
    # scanned as archive items or retained trees, where principal homes keep
    # their principal's ownership.
    path = mapped(root, logical)
    if not path.exists() and not path.is_symlink():
        raise Refusal(f"required legacy path is absent: {path}")
    record = metadata_record(path, root=root, base=path)
    if record["type"] != "directory":
        raise Refusal(f"normalized path is not a directory: {logical}")
    return str(record["mode"])


def build_plan(root: Path, proc_root: Path, sys_root: Path, archive: str, systemctl_path: Path) -> dict[str, object]:
    validate_archive_location(root, archive)
    validate_tool_path(root, systemctl_path)
    retained = scan_retained(root)
    require_exact_etc_buzzci(root, {"authority", "harness.env", "qualification-cases"})
    items = []
    for path in ARCHIVE_PATHS:
        item = scan_tree(mapped(root, path), root=root, allow_symlink=path in ALLOWED_SYMLINKS)
        if path in ALLOWED_SYMLINKS and item["entries"][0].get("target") != ALLOWED_SYMLINKS[path]:
            raise Refusal(f"legacy enablement link target differs: {path}")
        items.append(item)
    validate_live_expectations(root, items)
    proof = prove_unused(root, proc_root, sys_root, items)
    states = [unit_state(systemctl_path, unit) for unit in UNITS]
    if (
        states[0]["ActiveState"] != "active"
        or states[0]["SubState"] != "listening"
        or states[0]["UnitFileState"] != "enabled"
    ):
        raise Refusal("legacy execd socket is not in the expected active/enabled state")
    if (
        states[1]["ActiveState"] != "inactive"
        or states[1]["SubState"] != "dead"
        or states[1]["UnitFileState"] != "static"
    ):
        raise Refusal("legacy execd service is not in the expected inactive/static state")
    expected_fragments = {
        "buzz-ci-execd.socket": "/etc/systemd/system/buzz-ci-execd.socket",
        "buzz-ci-execd.service": "/etc/systemd/system/buzz-ci-execd.service",
    }
    for state in states:
        if state["FragmentPath"] != expected_fragments[state["unit"]]:
            raise Refusal(f"legacy unit fragment path differs: {state['unit']}")
    service_dropins = states[1]["DropInPaths"].split()
    if set(service_dropins) != {
        "/etc/systemd/system/buzz-ci-execd.service.d/10-host-adapters.conf",
        "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
    } or len(service_dropins) != 2 or states[0]["DropInPaths"]:
        raise Refusal("legacy unit drop-in inventory differs")
    plan: dict[str, object] = {
        "schema": PLAN_SCHEMA,
        "root": str(root),
        "archive_root": archive,
        "shared_root_before": {"mode": "0700", "uid": root_ids(root)[0], "gid": root_ids(root)[1]},
        "shared_root_after": {"mode": "0711", "uid": root_ids(root)[0], "gid": root_ids(root)[1]},
        "archive_items": [
            {**item, "archive_path": archive_destination(archive, str(item["path"]))}
            for item in items
        ],
        "retained_items": retained,
        "normalized_directories": [
            {"path": path, "before_mode": normalized_directory_mode(root, path), "after_mode": "0711"}
            for path in NORMALIZED_DIRS
        ],
        "unused_proof": proof,
        "unit_states": states,
    }
    return plan


def read_canonical_json(path: Path, *, expected_schema: str, root: Path) -> tuple[dict[str, Any], bytes]:
    path = Path(os.path.abspath(path))
    if Path(os.path.realpath(path)) != path:
        raise Refusal(f"JSON input path contains a symbolic link: {path}")
    parent_metadata = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or (parent_metadata.st_uid, parent_metadata.st_gid) != root_ids(root)
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
    ):
        raise Refusal(f"JSON input parent must be root-owned mode 0700: {path.parent}")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_uid, metadata.st_gid) != root_ids(root)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise Refusal(f"input must be a one-link mode-0600 regular file: {path}")
        if metadata.st_size > 16 * 1024 * 1024:
            raise Refusal("JSON input exceeds size limit")
        raw = b""
        while block := os.read(descriptor, 1024 * 1024):
            raw += block
    finally:
        os.close(descriptor)
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict) or value.get("schema") != expected_schema or canonical(value) != raw:
        raise Refusal("JSON input is not the expected canonical document")
    return value, raw


def mkdir_private(path: Path, root: Path) -> None:
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    if Path(os.path.realpath(current)) != current:
        raise Refusal("archive parent contains a symbolic link")
    for item in reversed(missing):
        item.mkdir(mode=0o700)
        descriptor = os.open(item, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(item.parent)
    expected = root_ids(root)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_uid, metadata.st_gid) != expected or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise Refusal(f"private directory metadata differs: {path}")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    parent = path.parent
    descriptor_parent = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    temporary = f".{path.name}.{os.getpid()}.new"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
            dir_fd=descriptor_parent,
        )
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path.name, src_dir_fd=descriptor_parent, dst_dir_fd=descriptor_parent)
        os.fsync(descriptor_parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=descriptor_parent)
        except FileNotFoundError:
            pass
        os.close(descriptor_parent)


def tree_matches(path: Path, root: Path, expected: dict[str, Any]) -> bool:
    try:
        observed = scan_tree(
            path,
            root=root,
            allow_symlink=bool(expected.get("entries")) and expected["entries"][0].get("type") == "symlink",
            require_root_owned=not str(expected.get("path", "")).endswith("/principals"),
        )
    except (FileNotFoundError, Refusal):
        return False
    comparable = {"entries": observed["entries"], "tree_sha256": observed["tree_sha256"]}
    wanted = {"entries": expected["entries"], "tree_sha256": expected["tree_sha256"]}
    return comparable == wanted


def move_exact(root: Path, source: str, destination: str, expected: dict[str, Any]) -> None:
    src = mapped(root, source)
    dst = mapped(root, destination)
    if dst.parent.exists():
        metadata = dst.parent.lstat()
        required_mode = 0o700 if "/items/rootfs/" in destination else None
        if (
            Path(os.path.realpath(dst.parent)) != dst.parent
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != root_ids(root)
            or metadata.st_mode & 0o022
            or (required_mode is not None and stat.S_IMODE(metadata.st_mode) != required_mode)
        ):
            raise Refusal(f"destination parent metadata is unsafe: {dst.parent}")
    else:
        mkdir_private(dst.parent, root)
    source_exists = src.exists() or src.is_symlink()
    destination_exists = dst.exists() or dst.is_symlink()
    if source_exists and destination_exists:
        raise Refusal(f"both migration locations exist: {source}")
    if not source_exists:
        if tree_matches(dst, root, expected):
            return
        raise Refusal(f"source is absent and archive differs: {source}")
    if destination_exists or not tree_matches(src, root, expected):
        raise Refusal(f"source drift before rename: {source}")
    src_parent_fd = os.open(src.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    dst_parent_fd = os.open(dst.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        src_meta = os.stat(src.name, dir_fd=src_parent_fd, follow_symlinks=False)
        dst_parent_meta = os.fstat(dst_parent_fd)
        if src_meta.st_dev != dst_parent_meta.st_dev:
            raise Refusal(f"cross-filesystem archive rename refused: {source}")
        os.rename(src.name, dst.name, src_dir_fd=src_parent_fd, dst_dir_fd=dst_parent_fd)
        os.fsync(src_parent_fd)
        os.fsync(dst_parent_fd)
    finally:
        os.close(src_parent_fd)
        os.close(dst_parent_fd)
    if not tree_matches(dst, root, expected):
        raise Refusal(f"archive drift after rename: {source}")


def chmod_directory(path: Path, mode: int) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise Refusal(f"normalization target is not a directory: {path}")
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)


def run_systemctl(systemctl_path: Path, *arguments: str) -> None:
    result = systemctl(systemctl_path, *arguments)
    if result.returncode != 0:
        raise Refusal(f"systemctl {' '.join(arguments)} failed: {result.stderr.strip()}")


def quiesce(systemctl_path: Path) -> None:
    run_systemctl(systemctl_path, "stop", "buzz-ci-execd.socket")
    run_systemctl(systemctl_path, "stop", "buzz-ci-execd.service")
    for unit in UNITS:
        state = unit_state(systemctl_path, unit)
        if state["ActiveState"] != "inactive":
            raise Refusal(f"unit did not quiesce: {unit}")
    if unit_state(systemctl_path, UNITS[0])["UnitFileState"] != "enabled":
        raise Refusal("legacy socket enablement drifted before archival")


def restore_units(systemctl_path: Path, states: list[dict[str, str]]) -> None:
    run_systemctl(systemctl_path, "daemon-reload")
    by_unit = {item["unit"]: item for item in states}
    for unit in reversed(UNITS):
        desired = by_unit[unit]
        if desired["UnitFileState"] == "enabled":
            run_systemctl(systemctl_path, "enable", unit)
        elif desired["UnitFileState"] == "disabled":
            run_systemctl(systemctl_path, "disable", unit)
    for unit in reversed(UNITS):
        if by_unit[unit]["ActiveState"] == "active":
            run_systemctl(systemctl_path, "start", unit)
        else:
            run_systemctl(systemctl_path, "stop", unit)
    for unit, expected in by_unit.items():
        observed = unit_state(systemctl_path, unit)
        for field in ("LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths"):
            if observed[field] != expected[field]:
                raise Refusal(f"unit state did not restore for {unit}: {field}")


def current_archive_state(root: Path, plan: dict[str, Any]) -> str:
    live = 0
    archived = 0
    for item in plan["archive_items"]:
        source = mapped(root, item["path"])
        destination = mapped(root, item["archive_path"])
        if tree_matches(source, root, item):
            live += 1
        elif tree_matches(destination, root, item):
            archived += 1
        else:
            raise Refusal(f"migration item is absent or drifted: {item['path']}")
    if live == len(plan["archive_items"]):
        return "legacy"
    if archived == len(plan["archive_items"]):
        return "archived"
    return "partial"


def validate_plan_shape(plan: dict[str, Any], root: Path, archive: str) -> None:
    if root == Path("/") and archive != DEFAULT_ARCHIVE:
        raise Refusal("live migration requires the fixed archive root")
    if plan.get("root") != str(root) or plan.get("archive_root") != archive:
        raise Refusal("plan root or archive binding differs")
    archive_items = plan.get("archive_items")
    if not isinstance(archive_items, list) or any(not isinstance(item, dict) for item in archive_items):
        raise Refusal("plan archive inventory is malformed")
    paths = [item.get("path") for item in archive_items]
    if paths != list(ARCHIVE_PATHS):
        raise Refusal("plan archive inventory differs from the fixed allowlist")
    for item in archive_items:
        if item.get("archive_path") != archive_destination(archive, str(item.get("path"))):
            raise Refusal("plan archive destination differs")
    normalized = plan.get("normalized_directories")
    if not isinstance(normalized, list) or any(not isinstance(item, dict) for item in normalized):
        raise Refusal("plan normalization inventory is malformed")
    if [item.get("path") for item in normalized] != list(NORMALIZED_DIRS):
        raise Refusal("plan normalization inventory differs")
    if any(
        set(item) != {"path", "before_mode", "after_mode"}
        or item["before_mode"] != "0700"
        or item["after_mode"] != "0711"
        for item in normalized
    ):
        raise Refusal("plan normalization modes differ")
    unit_states = plan.get("unit_states")
    if not isinstance(unit_states, list) or any(not isinstance(item, dict) for item in unit_states):
        raise Refusal("plan unit inventory is malformed")
    if [item.get("unit") for item in unit_states] != list(UNITS):
        raise Refusal("plan unit inventory differs")
    expected_unit_fields = {
        "unit", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths"
    }
    if any(
        set(item) != expected_unit_fields or any(not isinstance(value, str) for value in item.values())
        for item in unit_states
    ):
        raise Refusal("plan unit-state fields differ")
    retained = plan.get("retained_items")
    if (
        not isinstance(retained, list)
        or any(not isinstance(item, dict) for item in retained)
        or [item.get("path") for item in retained]
        != ["/var/lib/buzzci/principals", "/var/lib/buzzci/seccomp"]
    ):
        raise Refusal("plan retained inventory differs")
    socket, service = unit_states
    if socket != {
        "unit": "buzz-ci-execd.socket",
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "listening",
        "UnitFileState": "enabled",
        "FragmentPath": "/etc/systemd/system/buzz-ci-execd.socket",
        "DropInPaths": "",
    }:
        raise Refusal("plan socket state differs")
    if (
        {key: service[key] for key in expected_unit_fields - {"DropInPaths"}}
        != {
            "unit": "buzz-ci-execd.service",
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "UnitFileState": "static",
            "FragmentPath": "/etc/systemd/system/buzz-ci-execd.service",
        }
        or set(service["DropInPaths"].split())
        != {
            "/etc/systemd/system/buzz-ci-execd.service.d/10-host-adapters.conf",
            "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
        }
        or len(service["DropInPaths"].split()) != 2
    ):
        raise Refusal("plan service state differs")


def validate_receipt(receipt: dict[str, Any], root: Path, receipt_input: Path) -> tuple[str, dict[str, Any]]:
    expected_fields = {
        "schema",
        "result",
        "plan_sha256",
        "archive_root",
        "transaction_sha256",
        "archive_items",
        "retained_items",
        "normalized_directories",
        "unit_states_before",
        "unit_states_after",
    }
    if set(receipt) != expected_fields or receipt.get("result") != "PASS":
        raise Refusal("migration receipt fields or result differ")
    if any(not isinstance(receipt.get(field), str) or not DIGEST.fullmatch(receipt[field]) for field in ("plan_sha256", "transaction_sha256")):
        raise Refusal("migration receipt digest differs")
    archive = receipt.get("archive_root")
    if not isinstance(archive, str):
        raise Refusal("migration receipt archive root differs")
    expected_receipt = receipt_path(root, archive)
    if Path(os.path.abspath(receipt_input)) != expected_receipt:
        raise Refusal("migration receipt must be read from its fixed archive path")
    plan = {
        "root": str(root),
        "archive_root": archive,
        "archive_items": receipt["archive_items"],
        "retained_items": receipt["retained_items"],
        "normalized_directories": receipt["normalized_directories"],
        "unit_states": receipt["unit_states_before"],
    }
    validate_plan_shape(plan, root, archive)
    after = receipt.get("unit_states_after")
    if (
        not isinstance(after, list)
        or any(not isinstance(item, dict) for item in after)
        or [item.get("unit") for item in after] != list(UNITS)
    ):
        raise Refusal("migration receipt terminal unit inventory differs")
    for item in after:
        if not isinstance(item, dict) or item != {
            "unit": item.get("unit"),
            "LoadState": "not-found",
            "ActiveState": "inactive",
            "SubState": "dead",
            "UnitFileState": "",
            "FragmentPath": "",
            "DropInPaths": "",
        }:
            raise Refusal("migration receipt terminal unit state differs")
    transaction, transaction_raw = read_canonical_json(
        transaction_path(root, archive),
        expected_schema=TX_SCHEMA,
        root=root,
    )
    if (
        set(transaction) != {"schema", "plan_sha256", "phase", "completed_moves"}
        or transaction.get("plan_sha256") != receipt["plan_sha256"]
        or transaction.get("phase") != "migrated"
        or transaction.get("completed_moves") != len(ARCHIVE_PATHS)
        or sha256(transaction_raw) != receipt["transaction_sha256"]
    ):
        raise Refusal("migration transaction does not bind the receipt")
    return archive, plan


def transaction_path(root: Path, archive: str) -> Path:
    return mapped(root, archive) / "transaction-v1.json"


def receipt_path(root: Path, archive: str) -> Path:
    return mapped(root, archive) / "receipt-v1.json"


def migrate(args: argparse.Namespace, root: Path, proc_root: Path, sys_root: Path, systemctl_path: Path) -> dict[str, object]:
    if root == Path("/") and os.geteuid() != 0:
        raise Refusal("live migration requires root")
    plan, plan_raw = read_canonical_json(Path(args.plan), expected_schema=PLAN_SCHEMA, root=root)
    plan_digest = sha256(plan_raw)
    if args.approve_migration != plan_digest:
        raise Refusal(f"migration approval must equal plan SHA-256 {plan_digest}")
    archive = str(plan["archive_root"])
    validate_plan_shape(plan, root, archive)
    validate_archive_location(root, archive)
    validate_tool_path(root, systemctl_path)
    tx_path = transaction_path(root, archive)
    if not tx_path.exists():
        observed = build_plan(root, proc_root, sys_root, archive, systemctl_path)
        if canonical(observed) != plan_raw:
            raise Refusal("live state differs from the approved plan")
        mkdir_private(mapped(root, archive), root)
        transaction: dict[str, object] = {
            "schema": TX_SCHEMA,
            "plan_sha256": plan_digest,
            "phase": "prepared",
            "completed_moves": 0,
        }
        atomic_write(tx_path, canonical(transaction))
    else:
        transaction, _ = read_canonical_json(tx_path, expected_schema=TX_SCHEMA, root=root)
        if transaction.get("plan_sha256") != plan_digest:
            raise Refusal("existing transaction belongs to another plan")
    state = current_archive_state(root, plan)
    if state == "legacy":
        quiesce(systemctl_path)
        transaction["phase"] = "quiesced"
        atomic_write(tx_path, canonical(transaction))
    elif state == "partial":
        for unit in UNITS:
            if unit_state(systemctl_path, unit, allow_absent=True)["ActiveState"] != "inactive":
                raise Refusal("a unit became active during partial migration")
    moves = int(transaction.get("completed_moves", 0))
    for index, item in enumerate(plan["archive_items"], start=1):
        move_exact(root, item["path"], item["archive_path"], item)
        moves = max(moves, index)
        transaction["completed_moves"] = moves
        transaction["phase"] = "archiving"
        atomic_write(tx_path, canonical(transaction))
        if args.fail_after_moves == index:
            raise Refusal("injected crash after archive move")
    prove_unused(root, proc_root, sys_root, plan["archive_items"])
    shared_names = {entry.name for entry in os.scandir(mapped(root, SHARED))}
    if shared_names != RETAINED_DIRECT:
        raise Refusal("shared root gained unknown entries during migration")
    require_exact_etc_buzzci(root, set())
    for item in plan["normalized_directories"]:
        chmod_directory(mapped(root, item["path"]), int(item["after_mode"], 8))
    run_systemctl(systemctl_path, "daemon-reload")
    absent_states = [unit_state(systemctl_path, unit, allow_absent=True) for unit in UNITS]
    if any(state["LoadState"] != "not-found" for state in absent_states):
        raise Refusal("legacy unit remains loadable after archive and daemon-reload")
    if {entry.name for entry in os.scandir(mapped(root, SHARED))} != RETAINED_DIRECT:
        raise Refusal("shared root changed during final migration readback")
    require_exact_etc_buzzci(root, set())
    for item in plan["normalized_directories"]:
        metadata = mapped(root, item["path"]).lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != int(item["after_mode"], 8):
            raise Refusal(f"normalized directory readback differs: {item['path']}")
    transaction["phase"] = "migrated"
    atomic_write(tx_path, canonical(transaction))
    receipt: dict[str, object] = {
        "schema": RECEIPT_SCHEMA,
        "result": "PASS",
        "plan_sha256": plan_digest,
        "archive_root": archive,
        "transaction_sha256": sha256(canonical(transaction)),
        "archive_items": plan["archive_items"],
        "retained_items": plan["retained_items"],
        "normalized_directories": plan["normalized_directories"],
        "unit_states_before": plan["unit_states"],
        "unit_states_after": absent_states,
    }
    receipt_raw = canonical(receipt)
    final_receipt_path = receipt_path(root, archive)
    if final_receipt_path.exists():
        existing, existing_raw = read_canonical_json(
            final_receipt_path,
            expected_schema=RECEIPT_SCHEMA,
            root=root,
        )
        if existing != receipt:
            raise Refusal("existing migration receipt differs")
        receipt_raw = existing_raw
    else:
        atomic_write(final_receipt_path, receipt_raw)
    return {
        "result": "PASS",
        "state": "migrated",
        "receipt": str(final_receipt_path),
        "receipt_sha256": sha256(receipt_raw),
    }


def rollback(args: argparse.Namespace, root: Path, systemctl_path: Path) -> dict[str, object]:
    if root == Path("/") and os.geteuid() != 0:
        raise Refusal("live rollback requires root")
    receipt, receipt_raw = read_canonical_json(Path(args.receipt), expected_schema=RECEIPT_SCHEMA, root=root)
    receipt_digest = sha256(receipt_raw)
    if args.approve_rollback != receipt_digest:
        raise Refusal(f"rollback approval must equal receipt SHA-256 {receipt_digest}")
    archive, plan = validate_receipt(receipt, root, Path(args.receipt))
    validate_archive_location(root, archive)
    validate_tool_path(root, systemctl_path)
    archive_state = current_archive_state(root, plan)
    rollback_file = mapped(root, archive) / "rollback-v1.json"
    if archive_state != "legacy":
        for unit in UNITS:
            if unit_state(systemctl_path, unit, allow_absent=True)["ActiveState"] != "inactive":
                raise Refusal("rollback requires both legacy units inactive")
    names = {entry.name for entry in os.scandir(mapped(root, SHARED))}
    restored_direct = {
        PurePosixPath(item["path"]).name
        for item in plan["archive_items"]
        if str(item["path"]).startswith(SHARED + "/") and tree_matches(mapped(root, item["path"]), root, item)
    }
    if names != RETAINED_DIRECT | restored_direct:
        raise Refusal("rollback refuses while new or unknown shared state exists")
    restored_etc = {
        PurePosixPath(item["path"]).name
        for item in plan["archive_items"]
        if str(item["path"]).startswith("/etc/buzzci/") and tree_matches(mapped(root, item["path"]), root, item)
    }
    require_exact_etc_buzzci(root, restored_etc)
    for retained in plan["retained_items"]:
        current = scan_tree(
            mapped(root, retained["path"]),
            root=root,
            require_root_owned=not str(retained["path"]).endswith("/principals"),
        )
        before = retained
        # The migration changes only the seccomp directory modes.
        if retained["path"].endswith("/seccomp"):
            for entry in current["entries"]:
                entry["mode"] = next(old["mode"] for old in before["entries"] if old["relative_path"] == entry["relative_path"])
            current["tree_sha256"] = sha256(canonical(current["entries"]))
        if {"entries": current["entries"], "tree_sha256": current["tree_sha256"]} != {"entries": before["entries"], "tree_sha256": before["tree_sha256"]}:
            raise Refusal(f"retained state drift blocks rollback: {retained['path']}")
    for item in reversed(plan["normalized_directories"]):
        chmod_directory(mapped(root, item["path"]), int(item["before_mode"], 8))
    for index, item in enumerate(reversed(plan["archive_items"]), start=1):
        move_exact(root, item["archive_path"], item["path"], {**item, "path": item["archive_path"]})
        if args.fail_after_moves == index:
            raise Refusal("injected crash after rollback move")
    restore_units(systemctl_path, plan["unit_states"])
    expected_shared = RETAINED_DIRECT | {
        PurePosixPath(item["path"]).name
        for item in plan["archive_items"]
        if str(item["path"]).startswith(SHARED + "/")
    }
    if {entry.name for entry in os.scandir(mapped(root, SHARED))} != expected_shared:
        raise Refusal("shared root differs after rollback")
    require_exact_etc_buzzci(root, {"authority", "harness.env", "qualification-cases"})
    for item in plan["normalized_directories"]:
        metadata = mapped(root, item["path"]).lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != int(item["before_mode"], 8):
            raise Refusal(f"restored directory mode differs: {item['path']}")
    result: dict[str, object] = {
        "schema": ROLLBACK_SCHEMA,
        "result": "PASS",
        "migration_receipt_sha256": receipt_digest,
        "restored_items": [item["path"] for item in plan["archive_items"]],
        "restored_unit_states": plan["unit_states"],
    }
    result_raw = canonical(result)
    if rollback_file.exists():
        existing, existing_raw = read_canonical_json(rollback_file, expected_schema=ROLLBACK_SCHEMA, root=root)
        if existing != result:
            raise Refusal("existing rollback receipt differs")
        result_raw = existing_raw
    else:
        atomic_write(rollback_file, result_raw)
    return {"result": "PASS", "state": "rolled_back", "receipt": str(rollback_file), "receipt_sha256": sha256(result_raw)}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--root", default="/")
    result.add_argument("--proc-root", default="/proc")
    result.add_argument("--sys-root", default="/sys")
    result.add_argument("--archive-root", default=DEFAULT_ARCHIVE)
    result.add_argument("--systemctl", default="/usr/bin/systemctl")
    subparsers = result.add_subparsers(dest="action", required=True)
    subparsers.add_parser("check")
    subparsers.add_parser("plan")
    migrate_parser = subparsers.add_parser("migrate")
    migrate_parser.add_argument("--plan", required=True)
    migrate_parser.add_argument("--approve-migration", required=True)
    migrate_parser.add_argument("--fail-after-moves", type=int, default=-1, help=argparse.SUPPRESS)
    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument("--receipt", required=True)
    rollback_parser.add_argument("--approve-rollback", required=True)
    rollback_parser.add_argument("--fail-after-moves", type=int, default=-1, help=argparse.SUPPRESS)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        root = safe_root(args.root)
        proc_root = Path(os.path.abspath(args.proc_root))
        sys_root = Path(os.path.abspath(args.sys_root))
        systemctl_path = Path(os.path.abspath(args.systemctl))
        if root == Path("/") and (proc_root != Path("/proc") or sys_root != Path("/sys")):
            raise Refusal("live operation requires the real /proc and /sys")
        if args.action in {"check", "plan"}:
            plan = build_plan(root, proc_root, sys_root, args.archive_root, systemctl_path)
            if args.action == "plan":
                sys.stdout.buffer.write(canonical(plan))
            else:
                payload = {"schema": CHECK_SCHEMA, "result": "PASS", "plan_sha256": sha256(canonical(plan)), "plan": plan}
                sys.stdout.buffer.write(canonical(payload))
        elif args.action == "migrate":
            sys.stdout.buffer.write(canonical(migrate(args, root, proc_root, sys_root, systemctl_path)))
        else:
            sys.stdout.buffer.write(canonical(rollback(args, root, systemctl_path)))
        return 0
    except (OSError, Refusal, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
