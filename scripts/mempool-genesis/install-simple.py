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


def require_safe_directory(path: Path, owner_uid: int) -> Path:
    resolved = Path(os.path.realpath(path))
    try:
        metadata = resolved.stat()
    except OSError as error:
        raise ValueError(f"target parent does not exist: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"target parent is not a directory: {path}")
    if metadata.st_uid != owner_uid:
        raise ValueError(f"target parent is not root-owned: {path}")
    if metadata.st_mode & stat.S_IWOTH:
        raise ValueError(f"target parent is world-writable: {path}")
    return resolved


def target_exists(path: Path) -> bool:
    return os.path.lexists(path)


def preflight_targets(
    entries: list[dict[str, object]], root: Path, owner_uid: int
) -> list[tuple[dict[str, object], Path]]:
    planned: list[tuple[dict[str, object], Path]] = []
    for entry in entries:
        target_text = str(entry["target"])
        lexical_target = rooted_path(root, target_text)
        if target_exists(lexical_target):
            raise ValueError(f"target already exists: {target_text}")
        resolved_parent = require_safe_directory(lexical_target.parent, owner_uid)
        resolved_target = resolved_parent / lexical_target.name
        if target_exists(resolved_target):
            raise ValueError(f"resolved target already exists: {target_text}")
        planned.append((entry, resolved_target))
    return planned


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
            os.fchown(temporary.fileno(), owner_uid, owner_gid)
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
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> int:
    try:
        entries = load_and_verify_manifest(package, manifest_path)
        planned = preflight_targets(entries, root, owner_uid)
        credential_dir = rooted_path(root, "/etc/buzz-agents/credentials")
        if target_exists(credential_dir):
            metadata = credential_dir.stat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != owner_uid
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ValueError(
                    "existing credential directory is not root-owned mode 0700"
                )
        else:
            require_safe_directory(credential_dir.parent, owner_uid)
    except Exception as error:
        print(f"INSTALL REFUSED: {error}")
        return 1

    if not target_exists(credential_dir):
        print(f"PLAN CREATE DIRECTORY {credential_dir} mode=0700 owner={owner_uid}:{owner_gid}")
    for entry, target in planned:
        print(
            f"PLAN INSTALL {package / str(entry['source'])} -> {target} "
            f"mode={entry['install_mode']} owner={owner_uid}:{owner_gid}"
        )

    created_targets: list[Path] = []
    credential_dir_created = False
    try:
        if not target_exists(credential_dir):
            credential_dir.mkdir(mode=0o700)
            credential_dir_created = True
            os.chown(credential_dir, owner_uid, owner_gid)
            os.chmod(credential_dir, 0o700)
        for entry, target in planned:
            install_one(
                package.resolve(strict=True) / str(entry["source"]),
                target,
                int(str(entry["install_mode"]), 8),
                owner_uid,
                owner_gid,
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--manifest")
    args = parser.parse_args()

    package = Path(args.package).resolve(strict=False)
    manifest_path = (
        Path(args.manifest).resolve(strict=False)
        if args.manifest
        else package / MANIFEST_NAME
    )
    sys.exit(install(package, manifest_path))


if __name__ == "__main__":
    main()
