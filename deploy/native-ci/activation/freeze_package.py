#!/usr/bin/env python3
"""Freeze a dormant Buzz CI capacity-one activation package."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

import package as activation_package

PACKAGE_RELATIVE = Path("deploy/native-ci/activation")
STATIC_SOURCES = {
    "sysusers": ("buzzci-activation.sysusers.in", "assets/buzzci-activation.conf"),
    "tmpfiles": ("buzzci-activation.tmpfiles", "assets/buzzci-activation.tmpfiles"),
    "capacity_target": ("buzz-ci-capacity-one.target", "assets/buzz-ci-capacity-one.target"),
    "execd_socket_dropin": ("20-execd-capacity-one.conf", "assets/20-execd-capacity-one.conf"),
    "runner_service_dropin": ("20-runner-capacity-one.conf", "assets/20-runner-capacity-one.conf"),
    "controld_service_dropin": ("20-controld-capacity-one.conf", "assets/20-controld-capacity-one.conf"),
    "keyholder_socket_dropin": ("20-keyholder-capacity-one.conf", "assets/20-keyholder-capacity-one.conf"),
}
TRACKED_EXECUTABLES = (
    "controller.py",
    "freeze_package.py",
    "package.py",
)


def _git(source_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source_root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    return result.stdout.strip()


def _safe_input_directory(path: Path, where: str) -> Path:
    absolute = Path(os.path.abspath(path))
    metadata = absolute.lstat()
    if Path(os.path.realpath(absolute)) != absolute or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{where} must be a real directory")
    if metadata.st_mode & 0o022:
        raise ValueError(f"{where} must not be group or world writable")
    return absolute


def _git_file_mode(source_root: Path, relative: Path) -> int:
    output = _git(source_root, "ls-files", "--stage", "--", str(relative))
    lines = output.splitlines()
    if len(lines) != 1:
        raise ValueError(f"tracked source is missing or ambiguous: {relative}")
    fields = lines[0].split(maxsplit=3)
    if len(fields) != 4 or fields[2] != "0" or fields[3] != str(relative):
        raise ValueError(f"tracked source index entry differs: {relative}")
    if fields[0] not in {"100644", "100755"}:
        raise ValueError(f"tracked source is not a regular file: {relative}")
    return int(fields[0], 8)


def _validate_checkout_metadata(
    metadata: os.stat_result,
    git_mode: int,
    expected_uid: int,
    where: str,
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != expected_uid or not mode & stat.S_IRUSR:
        raise ValueError(f"tracked source owner access differs: {where}")
    if mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise ValueError(f"tracked source has unsafe permissions: {where}")
    if git_mode == 0o100644:
        if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise ValueError(f"tracked source executable class differs: {where}")
    elif git_mode == 0o100755:
        if not mode & stat.S_IXUSR:
            raise ValueError(f"tracked source executable class differs: {where}")
    else:
        raise ValueError(f"tracked source Git mode is unsupported: {where}")


def _tracked_payload(
    source_root: Path,
    relative: Path,
    expected_git_mode: int,
    limit: int = 64 * 1024,
) -> bytes:
    path = source_root / relative
    absolute = Path(os.path.abspath(path))
    if Path(os.path.realpath(absolute)) != absolute:
        raise ValueError(f"tracked source must not contain symbolic links: {relative}")
    git_mode = _git_file_mode(source_root, relative)
    if git_mode != expected_git_mode:
        raise ValueError(f"tracked source Git mode differs: {relative}")
    payload, metadata = activation_package.read_fd(absolute, limit)
    _validate_checkout_metadata(metadata, git_mode, source_root.lstat().st_uid, str(relative))
    return payload


def _render_sysusers(template: bytes, identities: dict[str, object]) -> bytes:
    text = template.decode("utf-8")
    replacements = {
        "@RUNNER_UID@": str(identities["runner"]["uid"]),
        "@RUNNER_GID@": str(identities["runner"]["gid"]),
        "@CONTROLD_UID@": str(identities["controld"]["uid"]),
        "@CONTROLD_GID@": str(identities["controld"]["gid"]),
        "@KEYHOLDER_UID@": str(identities["keyholder"]["uid"]),
        "@KEYHOLDER_GID@": str(identities["keyholder"]["gid"]),
    }
    for token, value in replacements.items():
        text = text.replace(token, value)
    if "@" in text:
        raise ValueError("unresolved sysusers template token")
    return text.encode()


def _static_payload(source_root: Path, role: str, identities: dict[str, object]) -> tuple[bytes, str]:
    template_name, asset_name = STATIC_SOURCES[role]
    payload = _tracked_payload(
        source_root,
        PACKAGE_RELATIVE / "templates" / template_name,
        0o100644,
    )
    if role == "sysusers":
        payload = _render_sysusers(payload, identities)
    return payload, asset_name


def _external_payload(asset_root: Path, source: str, expected_mode: int) -> bytes:
    path = asset_root / Path(source).name
    payload, metadata = activation_package.read_fd(path)
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise ValueError(f"source mode differs from draft: {source}")
    if metadata.st_uid != asset_root.lstat().st_uid:
        raise ValueError(f"source ownership differs from asset root: {source}")
    return payload


def _write_asset(path: Path, payload: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        if stat.S_IMODE(os.fstat(fd).st_mode) != mode:
            raise OSError(f"could not materialize exact asset mode: {path}")
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def freeze_package(
    source_root: Path,
    source_commit: str,
    draft_path: Path,
    asset_root: Path,
    output: Path,
) -> dict[str, object]:
    source_root = _safe_input_directory(source_root, "source root")
    asset_root = _safe_input_directory(asset_root, "asset root")
    if not activation_package.GIT_OID.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object ID")
    if _git(source_root, "rev-parse", "HEAD") != source_commit:
        raise ValueError("source checkout does not match the requested commit")
    if _git(source_root, "status", "--porcelain", "--", str(PACKAGE_RELATIVE)):
        raise ValueError("activation package source is dirty")
    for name in TRACKED_EXECUTABLES:
        _tracked_payload(source_root, PACKAGE_RELATIVE / name, 0o100755, 1024 * 1024)

    draft, _draft_raw, draft_metadata = activation_package.parse_json(draft_path)
    if stat.S_IMODE(draft_metadata.st_mode) & 0o077:
        raise ValueError("activation draft must be private")
    activation_package.validate_manifest(draft, require_digest=False)
    if draft["source_commit"] != source_commit:
        raise ValueError("draft source commit differs from checkout")

    payloads: dict[str, tuple[bytes, int]] = {}
    for entry in draft["entries"]:
        role = entry["role"]
        if role in STATIC_SOURCES:
            payload, expected_source = _static_payload(source_root, role, draft["identities"])
            if entry["source"] != expected_source:
                raise ValueError(f"static asset name differs for {role}")
            expected_mode = activation_package.parse_mode(entry["source_mode"])
            if expected_mode != 0o400:
                raise ValueError(f"static source mode must be 0400: {role}")
        else:
            expected_mode = activation_package.parse_mode(entry["source_mode"])
            payload = _external_payload(asset_root, entry["source"], expected_mode)
        if activation_package.digest(payload) != entry["sha256"]:
            raise ValueError(f"staged asset digest differs for {role}")
        payloads[entry["source"]] = (payload, expected_mode)
        if "active_source" in entry:
            active_mode = activation_package.parse_mode(entry["active_source_mode"])
            active_payload = _external_payload(asset_root, entry["active_source"], active_mode)
            if activation_package.digest(active_payload) != entry["active_sha256"]:
                raise ValueError(f"active asset digest differs for {role}")
            payloads[entry["active_source"]] = (active_payload, active_mode)

    for component in draft["components"]:
        source = component["provenance_source"]
        raw = _external_payload(asset_root, source, 0o400)
        provenance = json.loads(raw, object_pairs_hook=activation_package.reject_duplicates)
        if provenance != {
            "binary": Path(component["binary_path"]).name,
            "profile": "release",
            "schema": activation_package.PROVENANCE_SCHEMA,
            "sha256": component["binary_sha256"],
            "source_commit": component["source_commit"],
        }:
            raise ValueError(f"component provenance does not match: {component['name']}")
        if activation_package.digest(raw) != component["provenance_sha256"]:
            raise ValueError(f"component provenance digest differs: {component['name']}")
        payloads[source] = (raw, 0o400)

    qualification = draft["qualification"]
    request = _external_payload(asset_root, qualification["request_source"], 0o400)
    if activation_package.digest(request) != qualification["request_sha256"]:
        raise ValueError("qualification request digest differs")
    payloads[qualification["request_source"]] = (request, 0o400)

    activation_package.validate_payloads(
        draft,
        {source: payload for source, (payload, _mode) in payloads.items()},
    )

    referenced_sources = {
        entry["source"] for entry in draft["entries"]
    } | {
        entry["active_source"] for entry in draft["entries"] if "active_source" in entry
    } | {
        component["provenance_source"] for component in draft["components"]
    } | {qualification["request_source"]}
    if set(payloads) != referenced_sources:
        raise ValueError("package assets collide")

    unsigned = dict(draft)
    package_digest = activation_package.digest(activation_package.canonical_json(unsigned))
    manifest = dict(unsigned)
    manifest["schema"] = activation_package.MANIFEST_SCHEMA
    manifest["package_digest"] = package_digest
    manifest["activation_id"] = f"buzz-ci-capacity-one-{source_commit[:12]}-{package_digest[:12]}"
    activation_package.validate_manifest(manifest)

    output = Path(os.path.abspath(output))
    parent = _safe_input_directory(output.parent, "output parent")
    if output.exists() or output.is_symlink():
        raise ValueError("output must not already exist")
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    stage.chmod(0o700)
    assets = stage / "assets"
    assets.mkdir(mode=0o700)
    try:
        for source, (payload, source_mode) in sorted(payloads.items()):
            _write_asset(assets / Path(source).name, payload, source_mode)
        _write_asset(stage / "activation-manifest.json", activation_package.canonical_json(manifest), 0o600)
        os.replace(stage, output)
        return manifest
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--draft", type=Path, required=True)
    parser.add_argument("--asset-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    manifest = freeze_package(
        arguments.source_root,
        arguments.source_commit,
        arguments.draft,
        arguments.asset_root,
        arguments.output,
    )
    print(activation_package.canonical_json(manifest).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
