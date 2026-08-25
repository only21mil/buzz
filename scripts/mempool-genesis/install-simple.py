#!/usr/bin/env python3
"""Install a frozen, credential-free package onto an empty target tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import NamedTuple


MANIFEST_NAME = "install-package.manifest.json"
SCHEMA = "buzz-agent-install-package-v2"
ENTRY_COUNT = 9
EXPECTED_PACKAGE_ID = "mempool-genesis-static-9faf30181"
EXPECTED_MANIFEST_SHA256 = "fc706e3b41dfe038ceb4e856ce8469e32a55d40acd367c736f4b6dfcfad5c92e"
EXPECTED_PACKAGE_FINGERPRINT = "b38fcf16c830003a4fe768500c5590db2c545a4cff72a4304343c8b275f15383"
REQUIRED_MANIFEST_FIELDS = {
    "schema",
    "package_id",
    "entries",
    "desktop_launcher_sha256",
    "desktop_previous_launcher_sha256",
    "package_fingerprint",
}
REQUIRED_ENTRY_FIELDS = {
    "owner",
    "role",
    "source",
    "target",
    "source_mode",
    "install_mode",
    "status",
    "sha256",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MODE = re.compile(r"^0[0-7]{3}$")
PACKAGE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{7,95}$")
EXPECTED_ENTRIES = {
    "/usr/local/libexec/buzz/verify-installed-agent": (
        "system/verify-installed-agent", "static", "static", "0755", "0755"
    ),
    "/usr/local/libexec/buzz/buzz-agent-key-handoff": (
        "bin/buzz-agent-key-handoff", "static", "static", "0755", "0755"
    ),
    "/usr/local/libexec/buzz/export-managed-agent-key": (
        "bin/export-managed-agent-key", "static", "static", "0755", "0755"
    ),
    "/usr/local/sbin/buzz-install-agent-key": (
        "bin/buzz-install-agent-key", "static", "static", "0755", "0755"
    ),
    "/usr/local/sbin/install-enrollment-map": (
        "system/install-enrollment-map", "static", "static", "0755", "0755"
    ),
    "/etc/sudoers.d/buzz-agent-key-handoff": (
        "system/buzz-agent-key-handoff.sudoers", "static", "static", "0440", "0440"
    ),
    "/etc/systemd/system/buzz-agent@.service": (
        "system/buzz-agent@.service", "static", "static", "0644", "0644"
    ),
    "/home/victor/work/buzz-client/Buzz_0.5.8-fixed-050ac722_amd64.AppImage": (
        "desktop/Buzz_0.5.8_amd64.AppImage",
        "desktop",
        "desktop_app",
        "0755",
        "0755",
    ),
    "/home/victor/projects/buzz/scripts/launch_buzz_desktop.sh": (
        "desktop/launch-buzz-desktop",
        "desktop",
        "desktop_launcher",
        "0755",
        "0700",
    ),
}


class TargetReport(NamedTuple):
    entry: dict[str, object]
    target_text: str
    lexical_target: Path
    resolved_parent: Path
    resolved_target: Path
    target_status: str
    parent_status: str
    parent_uid: int | None
    parent_gid: int | None
    parent_mode: int | None
    world_writable: bool | None
    owner_expectation: str
    owner_met: bool
    symlink_resolved: bool
    elevation_needed: bool
    target_uid: int | None
    target_gid: int | None
    blockers: tuple[str, ...]


class PreflightResult(NamedTuple):
    entries: list[dict[str, object]]
    planned: list[tuple[dict[str, object], Path, int, int]]
    target_reports: list[TargetReport]
    credential_dir: Path
    credential_dir_status: str
    identity_error: str | None
    blockers: list[str]


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def package_fingerprint(entries: list[dict[str, object]]) -> str:
    ordered = sorted(entries, key=lambda entry: str(entry["target"]).encode())
    payload = "".join(
        f'{entry["status"]}\t{entry["sha256"]}\t{entry["target"]}\n'
        for entry in ordered
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def load_and_verify_manifest(
    package: Path, manifest_path: Path
) -> list[dict[str, object]]:
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read manifest: {error}") from error
    if hashlib.sha256(manifest_bytes).hexdigest() != EXPECTED_MANIFEST_SHA256:
        raise ValueError("manifest SHA-256 mismatch")
    try:
        manifest = json.loads(manifest_bytes, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise ValueError("manifest root is not an object")
    missing_manifest_fields = REQUIRED_MANIFEST_FIELDS - manifest.keys()
    if missing_manifest_fields:
        raise ValueError(
            "manifest is missing: " + ", ".join(sorted(missing_manifest_fields))
        )
    unexpected_manifest_fields = manifest.keys() - REQUIRED_MANIFEST_FIELDS
    if unexpected_manifest_fields:
        raise ValueError(
            "manifest has unexpected fields: "
            + ", ".join(sorted(unexpected_manifest_fields))
        )
    if manifest["package_id"] != EXPECTED_PACKAGE_ID:
        raise ValueError("package ID mismatch")
    if (
        manifest["schema"] != SCHEMA
        or not isinstance(manifest["package_id"], str)
        or not PACKAGE_ID.fullmatch(manifest["package_id"])
    ):
        raise ValueError("invalid manifest identity")
    entries = manifest["entries"]
    fingerprint = manifest["package_fingerprint"]
    if not isinstance(entries, list) or len(entries) != ENTRY_COUNT:
        raise ValueError(f"manifest must contain exactly {ENTRY_COUNT} entries")
    for number, raw_entry in enumerate(entries, start=1):
        if not isinstance(raw_entry, dict):
            raise ValueError(f"entry {number} is not an object")
        missing = REQUIRED_ENTRY_FIELDS - raw_entry.keys()
        if missing:
            raise ValueError(f"entry {number} is missing: {', '.join(sorted(missing))}")
        unexpected = raw_entry.keys() - REQUIRED_ENTRY_FIELDS
        if unexpected:
            raise ValueError(
                f"entry {number} has unexpected fields: {', '.join(sorted(unexpected))}"
            )
    actual_fingerprint = package_fingerprint(entries)
    if actual_fingerprint != EXPECTED_PACKAGE_FINGERPRINT:
        raise ValueError("reviewed package fingerprint mismatch")
    if not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint):
        raise ValueError("invalid package_fingerprint")
    if actual_fingerprint != fingerprint:
        raise ValueError("package fingerprint mismatch")
    for field in ("desktop_launcher_sha256", "desktop_previous_launcher_sha256"):
        value = manifest[field]
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            raise ValueError(f"invalid manifest field: {field}")

    seen_sources: set[str] = set()
    seen_targets: set[str] = set()
    verified: list[dict[str, object]] = []
    for number, raw_entry in enumerate(entries, start=1):
        source_text = raw_entry["source"]
        target_text = raw_entry["target"]
        status = raw_entry["status"]
        digest = raw_entry["sha256"]
        install_mode = raw_entry["install_mode"]
        if not isinstance(source_text, str) or not source_text:
            raise ValueError(f"entry {number} has an invalid source")
        source_relative = Path(source_text)
        if source_relative.is_absolute() or ".." in source_relative.parts:
            raise ValueError(f"entry {number} source escapes the package")
        if source_text in seen_sources:
            raise ValueError(f"duplicate package source: {source_text}")
        seen_sources.add(source_text)
        if not isinstance(target_text, str) or not Path(target_text).is_absolute():
            raise ValueError(f"entry {number} has a non-absolute target")
        if target_text in seen_targets:
            raise ValueError(f"duplicate target: {target_text}")
        seen_targets.add(target_text)
        expected = EXPECTED_ENTRIES.get(target_text)
        contract = (
            source_text,
            raw_entry["owner"],
            raw_entry["role"],
            raw_entry["source_mode"],
            install_mode,
        )
        if expected is None or contract != expected:
            raise ValueError(f"entry {number} does not match the install contract")
        if not isinstance(status, str) or status != "A":
            raise ValueError(f"entry {number} has an invalid status")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValueError(f"entry {number} has an invalid sha256")
        if not isinstance(install_mode, str) or not MODE.fullmatch(install_mode):
            raise ValueError(f"entry {number} has an invalid install_mode")

        verified.append(dict(raw_entry))

    if seen_targets != set(EXPECTED_ENTRIES):
        raise ValueError("manifest target set mismatch")
    launchers = [entry for entry in verified if entry["role"] == "desktop_launcher"]
    if (
        len(launchers) != 1
        or manifest["desktop_launcher_sha256"] != launchers[0]["sha256"]
    ):
        raise ValueError("desktop launcher hash mismatch")
    package_root = package.resolve(strict=True)
    for entry in verified:
        source_text = str(entry["source"])
        source_relative = Path(source_text)
        try:
            source = (package_root / source_relative).resolve(strict=True)
            source.relative_to(package_root)
        except (OSError, ValueError) as error:
            raise ValueError(f"invalid package source: {source_text}") from error
        if not source.is_file():
            raise ValueError(f"package source is not a regular file: {source_text}")
        if sha256_file(source) != entry["sha256"]:
            raise ValueError(f"package source hash mismatch: {source_text}")
    return verified


def rooted_path(root: Path, absolute_path: str) -> Path:
    return root / absolute_path.lstrip("/")


def target_exists(path: Path) -> bool:
    return os.path.lexists(path)


def _path_status(path: Path) -> tuple[str, OSError | None]:
    try:
        path.lstat()
    except FileNotFoundError:
        return "absent", None
    except OSError as error:
        return "unreadable", error
    return "EXISTS", None


def _inspect_targets(
    entries: list[dict[str, object]],
    root: Path,
) -> tuple[
    list[TargetReport],
    list[tuple[dict[str, object], Path, int, int]],
    list[str],
]:
    reports: list[TargetReport] = []
    planned: list[tuple[dict[str, object], Path, int, int]] = []
    blockers: list[str] = []
    resolved_targets: set[Path] = set()
    for entry in entries:
        target_text = str(entry["target"])
        lexical_target = rooted_path(root, target_text)
        target_status, target_error = _path_status(lexical_target)
        target_blockers: list[str] = []
        elevation_needed = isinstance(target_error, PermissionError)
        if target_status == "EXISTS":
            target_blockers.append(f"target already exists: {target_text}")
        elif target_status == "unreadable":
            target_blockers.append(
                f"target unreadable: {target_text} "
                f"(elevation needed: {'yes' if elevation_needed else 'unknown'})"
            )

        lexical_parent = lexical_target.parent
        resolved_parent = Path(os.path.realpath(lexical_parent))
        resolved_target = resolved_parent / lexical_target.name
        symlink_resolved = resolved_parent != Path(os.path.abspath(lexical_parent))
        parent_status = "present"
        parent_uid: int | None = None
        parent_gid: int | None = None
        parent_mode: int | None = None
        world_writable: bool | None = None
        try:
            parent_metadata = resolved_parent.stat()
        except FileNotFoundError:
            parent_status = "absent"
            target_blockers.append(f"target parent does not exist: {lexical_parent}")
        except OSError as error:
            parent_status = "unreadable"
            elevation_needed = elevation_needed or isinstance(error, PermissionError)
            target_blockers.append(
                f"target parent unreadable: {lexical_parent} "
                f"(elevation needed: "
                f"{'yes' if isinstance(error, PermissionError) else 'unknown'})"
            )
        else:
            parent_uid = parent_metadata.st_uid
            parent_gid = parent_metadata.st_gid
            parent_mode = stat.S_IMODE(parent_metadata.st_mode)
            world_writable = bool(parent_metadata.st_mode & stat.S_IWOTH)
            if not stat.S_ISDIR(parent_metadata.st_mode):
                target_blockers.append(
                    f"target parent is not a directory: {lexical_parent}"
                )
            if world_writable:
                target_blockers.append(
                    f"target parent is world-writable: {lexical_parent}"
                )

        owner = entry["owner"]
        if owner == "static":
            owner_expectation = "static->root parent"
            owner_met = parent_uid == 0
            if parent_status == "present" and not owner_met:
                target_blockers.append(
                    f"target parent is not root-owned: {lexical_parent}"
                )
            target_uid = 0
            target_gid = 0
        elif owner == "desktop":
            owner_expectation = "desktop->non-root parent"
            owner_met = parent_uid is not None and parent_uid != 0
            if parent_status == "present" and not owner_met:
                target_blockers.append(
                    f"desktop target parent is root-owned: {lexical_parent}"
                )
            target_uid = parent_uid
            target_gid = parent_gid
        else:
            owner_expectation = f"{owner}->unsupported parent"
            owner_met = False
            target_uid = None
            target_gid = None
            target_blockers.append(f"unsupported target owner: {owner}")

        declared_basename = Path(target_text).name
        if (
            not resolved_target.is_absolute()
            or not declared_basename
            or resolved_target.name != declared_basename
        ):
            target_blockers.append(f"resolved target basename mismatch: {target_text}")
        if resolved_target in resolved_targets:
            target_blockers.append(f"resolved target collision: {target_text}")
        resolved_targets.add(resolved_target)
        if not target_blockers and target_uid is not None and target_gid is not None:
            planned.append((entry, resolved_target, target_uid, target_gid))
        blockers.extend(target_blockers)
        reports.append(
            TargetReport(
                entry=entry,
                target_text=target_text,
                lexical_target=lexical_target,
                resolved_parent=resolved_parent,
                resolved_target=resolved_target,
                target_status=target_status,
                parent_status=parent_status,
                parent_uid=parent_uid,
                parent_gid=parent_gid,
                parent_mode=parent_mode,
                world_writable=world_writable,
                owner_expectation=owner_expectation,
                owner_met=owner_met,
                symlink_resolved=symlink_resolved,
                elevation_needed=elevation_needed,
                target_uid=target_uid,
                target_gid=target_gid,
                blockers=tuple(target_blockers),
            )
        )
    return reports, planned, blockers


def preflight_targets(
    entries: list[dict[str, object]], root: Path
) -> list[tuple[dict[str, object], Path, int, int]]:
    _, planned, blockers = _inspect_targets(entries, root)
    if blockers:
        raise ValueError(blockers[0])
    return planned


def _expected_target_entries() -> list[dict[str, object]]:
    return [
        {"target": target, "owner": contract[1]}
        for target, contract in EXPECTED_ENTRIES.items()
    ]


def preflight(
    package: Path,
    manifest_path: Path,
    *,
    root: Path = Path("/"),
) -> PreflightResult:
    blockers: list[str] = []
    identity_error: str | None = None
    try:
        entries = load_and_verify_manifest(package, manifest_path)
    except Exception as error:
        identity_error = str(error)
        blockers.append(identity_error)
        entries = _expected_target_entries()

    target_reports, planned, target_blockers = _inspect_targets(entries, root)
    blockers.extend(target_blockers)

    credential_dir = rooted_path(root, "/etc/buzz-agents/credentials")
    credential_status, credential_error = _path_status(credential_dir)
    if credential_status == "unreadable":
        blockers.append(
            "credential directory unreadable: "
            f"{credential_dir} (elevation needed: "
            f"{'yes' if isinstance(credential_error, PermissionError) else 'unknown'})"
        )
    elif credential_status == "EXISTS":
        try:
            metadata = credential_dir.stat()
        except OSError as error:
            blockers.append(
                "credential directory unreadable: "
                f"{credential_dir} (elevation needed: "
                f"{'yes' if isinstance(error, PermissionError) else 'unknown'})"
            )
        else:
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                blockers.append(
                    "existing credential directory is not root-owned mode 0700"
                )
    else:
        credential_parent = credential_dir.parent
        resolved_parent = Path(os.path.realpath(credential_parent))
        try:
            parent_metadata = resolved_parent.stat()
        except FileNotFoundError:
            blockers.append(
                f"credential directory parent does not exist: {credential_parent}"
            )
        except OSError as error:
            blockers.append(
                "credential directory parent unreadable: "
                f"{credential_parent} (elevation needed: "
                f"{'yes' if isinstance(error, PermissionError) else 'unknown'})"
            )
        else:
            if not stat.S_ISDIR(parent_metadata.st_mode):
                blockers.append(
                    f"credential directory parent is not a directory: {credential_parent}"
                )
            if parent_metadata.st_mode & stat.S_IWOTH:
                blockers.append(
                    f"credential directory parent is world-writable: {credential_parent}"
                )
            if parent_metadata.st_uid != 0:
                blockers.append(
                    "credential directory parent is not root-owned: "
                    f"{credential_parent}"
                )

    return PreflightResult(
        entries=entries,
        planned=planned,
        target_reports=target_reports,
        credential_dir=credential_dir,
        credential_dir_status=credential_status,
        identity_error=identity_error,
        blockers=blockers,
    )


def install_one(
    source: Path,
    target: Path,
    mode: int,
    owner_uid: int,
    owner_gid: int,
) -> None:
    temporary_fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.install.", dir=target.parent
    )
    try:
        with os.fdopen(temporary_fd, "wb", closefd=True) as temporary:
            with source.open("rb") as package_source:
                while chunk := package_source.read(1024 * 1024):
                    temporary.write(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())
            os.fchmod(temporary.fileno(), mode)
            try:
                os.fchown(temporary.fileno(), owner_uid, owner_gid)
            except PermissionError:
                # MG_INSTALL_TEST=1 lets a non-root test process exercise static
                # installs in a fixture tree. With the shipped default (unset),
                # every chown is mandatory and a failure aborts the install.
                if not (
                    owner_uid == 0
                    and os.getuid() != 0
                    and os.environ.get("MG_INSTALL_TEST") == "1"
                ):
                    raise
        os.rename(temporary_name, target)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def cleanup(
    created_targets: list[Path], credential_dir: Path, credential_dir_created: bool
) -> tuple[list[str], list[str]]:
    removed: list[str] = []
    left: list[str] = []
    for target in reversed(created_targets):
        try:
            target.unlink()
            removed.append(str(target))
        except FileNotFoundError:
            removed.append(f"{target} (already absent)")
        except OSError:
            left.append(str(target))
    if credential_dir_created:
        try:
            credential_dir.rmdir()
            removed.append(str(credential_dir))
        except OSError:
            left.append(str(credential_dir))
    return removed, left


def install(
    package: Path,
    manifest_path: Path,
    *,
    root: Path = Path("/"),
) -> int:
    result = preflight(package, manifest_path, root=root)
    if result.blockers:
        print(f"INSTALL REFUSED: {result.blockers[0]}")
        return 1

    credential_dir = result.credential_dir
    if result.credential_dir_status == "absent":
        print(f"PLAN CREATE DIRECTORY {credential_dir} mode=0700 owner=0:0")
    for entry, target, target_uid, target_gid in result.planned:
        print(
            f"PLAN INSTALL {package / str(entry['source'])} -> {target} "
            f"mode={entry['install_mode']} owner={target_uid}:{target_gid}"
        )

    created_targets: list[Path] = []
    credential_dir_created = False
    try:
        if not target_exists(credential_dir):
            credential_dir.mkdir(mode=0o700)
            credential_dir_created = True
            os.chown(credential_dir, 0, 0)
            os.chmod(credential_dir, 0o700)
        for entry, target, target_uid, target_gid in result.planned:
            install_one(
                package.resolve(strict=True) / str(entry["source"]),
                target,
                int(str(entry["install_mode"]), 8),
                target_uid,
                target_gid,
            )
            created_targets.append(target)
    except Exception as error:
        removed, left = cleanup(
            created_targets, credential_dir, credential_dir_created
        )
        print(f"ROLLBACK CLEANUP removed={removed or ['none']} left={left or ['none']}")
        print(f"INSTALL ROLLED BACK: {error}")
        return 1

    print("INSTALL OK")
    return 0


def _display_value(value: object | None) -> str:
    return "unreadable" if value is None else str(value)


def check(
    package: Path,
    manifest_path: Path,
    *,
    root: Path = Path("/"),
) -> int:
    result = preflight(package, manifest_path, root=root)
    if result.identity_error is None:
        print("PINNED IDENTITY: MET")
    else:
        print(f"PINNED IDENTITY: UNMET ({result.identity_error})")

    for report in result.target_reports:
        mode = (
            "unreadable"
            if report.parent_mode is None
            else f"0{report.parent_mode:03o}"
        )
        world_writable = (
            "unreadable"
            if report.world_writable is None
            else "yes" if report.world_writable else "no"
        )
        print(
            f"TARGET {report.target_text}; {report.target_status}; "
            f"resolved-parent={report.resolved_parent}; "
            f"parent={report.parent_status}; "
            f"owner-uid={_display_value(report.parent_uid)}; mode={mode}; "
            f"world-writable={world_writable}; "
            f"owner-expectation={report.owner_expectation} "
            f"{'MET' if report.owner_met else 'UNMET'}; "
            f"symlink-resolved={'yes' if report.symlink_resolved else 'no'}; "
            f"elevation-needed={'yes' if report.elevation_needed else 'no'}"
        )

    print(
        f"CREDENTIAL DIRECTORY {result.credential_dir}; "
        f"{result.credential_dir_status}"
    )
    if result.blockers:
        print("PREFLIGHT BLOCKERS:")
        for blocker in result.blockers:
            print(f"- {blocker}")
        return 1
    print("PREFLIGHT OK: real install would proceed")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--package", required=True)
    parser.add_argument("--manifest")
    args = parser.parse_args()

    package = Path(args.package).resolve(strict=False)
    manifest_path = (
        Path(args.manifest).resolve(strict=False)
        if args.manifest
        else package / MANIFEST_NAME
    )
    action = check if args.check else install
    sys.exit(action(package, manifest_path))


if __name__ == "__main__":
    main()
