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
    "acceptance_control_socket": ("buzz-ci-acceptance-control.socket", "assets/buzz-ci-acceptance-control.socket"),
    "acceptance_control_service": ("buzz-ci-acceptance-control.service", "assets/buzz-ci-acceptance-control.service"),
    "acceptance_tmpfiles": ("buzzci-acceptance.tmpfiles", "assets/buzzci-acceptance.tmpfiles"),
    "execd_socket_dropin": ("20-execd-capacity-one.conf", "assets/20-execd-capacity-one.conf"),
    "runner_service_dropin": ("20-runner-capacity-one.conf", "assets/20-runner-capacity-one.conf"),
    "controld_service_dropin": ("20-controld-capacity-one.conf", "assets/20-controld-capacity-one.conf"),
    "keyholder_socket_dropin": ("20-keyholder-capacity-one.conf", "assets/20-keyholder-capacity-one.conf"),
}
TRACKED_ROOT_SOURCES = {
    "activation_controller": ("controller.py", "assets/buzz-ci-activation-controller", 0o100755, 0o500),
    "activation_package_module": ("package.py", "assets/buzz_ci_activation_package.py", 0o100755, 0o500),
}
TRACKED_REPO_SOURCES = {
    "receipt_verifier_binary": (
        Path("deploy/native-ci/acceptance/verify-receipt.py"),
        "assets/buzz-ci-verify-acceptance-receipt",
        0o100755,
        0o500,
    ),
    "receipt_verifier_expected_stages": (
        Path("deploy/native-ci/acceptance/expected-stages.json"),
        "assets/buzz-ci-acceptance-expected-stages.json",
        0o100644,
        0o400,
    ),
    "fixture_manifest": (
        Path("deploy/native-ci/acceptance/fixtures/fixture-manifest.json"),
        "assets/buzz-ci-capacity-one-fixture-manifest.json",
        0o100644,
        0o400,
    ),
    "fixture_input": (
        Path("deploy/native-ci/acceptance/fixtures/input.txt"),
        "assets/buzz-ci-capacity-one-fixture-input.txt",
        0o100644,
        0o400,
    ),
    "fixture_script": (
        Path("deploy/native-ci/acceptance/fixtures/run-fixture.sh"),
        "assets/buzz-ci-capacity-one-fixture",
        0o100755,
        0o500,
    ),
    "execd_service": (
        Path("deploy/native-ci/execd/templates/buzz-ci-execd.service"),
        "assets/buzz-ci-execd.service",
        0o100644,
        0o400,
    ),
    "execd_socket": (
        Path("deploy/native-ci/execd/templates/buzz-ci-execd.socket"),
        "assets/buzz-ci-execd.socket",
        0o100644,
        0o400,
    ),
    "executor_service": (
        Path("deploy/native-ci/execd/templates/buzz-ci-executor.service"),
        "assets/buzz-ci-executor.service",
        0o100644,
        0o400,
    ),
    "executor_socket": (
        Path("deploy/native-ci/execd/templates/buzz-ci-executor.socket"),
        "assets/buzz-ci-executor.socket",
        0o100644,
        0o400,
    ),
}
TRACKED_COMPONENT_PROVENANCE = {
    "receipt_verifier": "assets/receipt-verifier-provenance.json",
}
TRACKED_EXECUTABLES = (
    "controller.py",
    "freeze_package.py",
    "package.py",
)

SYSTEMD_SOURCE_PATHS = {
    "/usr/lib/systemd/system/service.d/10-timeout-abort.conf": Path("deploy/native-ci/activation/platform/fedora-44-systemd-259/10-timeout-abort.conf"),
    "/etc/systemd/system/buzz-ci-capacity-one.target": Path("deploy/native-ci/activation/templates/buzz-ci-capacity-one.target"),
    "/etc/systemd/system/buzz-ci-controld-acceptance.socket": Path("deploy/native-ci/controld/templates/buzz-ci-controld-acceptance.socket"),
    "/etc/systemd/system/buzz-ci-acceptance-control.socket": Path("deploy/native-ci/activation/templates/buzz-ci-acceptance-control.socket"),
    "/etc/systemd/system/buzz-ci-acceptance-control.service": Path("deploy/native-ci/activation/templates/buzz-ci-acceptance-control.service"),
    "/etc/systemd/system/buzz-ci-runner.service": Path("deploy/native-ci/runner/templates/buzz-ci-runner.service"),
    "/etc/systemd/system/buzz-ci-runner.service.d/20-capacity-one.conf": Path("deploy/native-ci/activation/templates/20-runner-capacity-one.conf"),
    "/etc/systemd/system/buzz-ci-runner.socket": Path("deploy/native-ci/runner/templates/buzz-ci-runner.socket"),
    "/etc/systemd/system/buzz-ci-controld.service": Path("deploy/native-ci/controld/templates/buzz-ci-controld.service"),
    "/etc/systemd/system/buzz-ci-controld.service.d/20-capacity-one.conf": Path("deploy/native-ci/activation/templates/20-controld-capacity-one.conf"),
    "/etc/systemd/system/buzz-ci-keyholder.service": Path("deploy/native-ci/keyholder/templates/buzz-ci-keyholder.service"),
    "/etc/systemd/system/buzz-ci-keyholder.service.d/20-acceptance-actor.conf": Path("deploy/native-ci/keyholder/templates/20-acceptance-actor.conf"),
    "/etc/systemd/system/buzz-ci-keyholder.socket": Path("deploy/native-ci/keyholder/templates/buzz-ci-keyholder.socket"),
    "/etc/systemd/system/buzz-ci-keyholder.socket.d/20-capacity-one.conf": Path("deploy/native-ci/activation/templates/20-keyholder-capacity-one.conf"),
    "/usr/lib/systemd/system/buzz-ci-execd.service": Path("deploy/native-ci/execd/templates/buzz-ci-execd.service"),
    "/usr/lib/systemd/system/buzz-ci-execd.socket": Path("deploy/native-ci/execd/templates/buzz-ci-execd.socket"),
    "/etc/systemd/system/buzz-ci-execd.socket.d/20-capacity-one.conf": Path("deploy/native-ci/activation/templates/20-execd-capacity-one.conf"),
    "/usr/lib/systemd/system/buzz-ci-executor.service": Path("deploy/native-ci/execd/templates/buzz-ci-executor.service"),
    "/usr/lib/systemd/system/buzz-ci-executor.socket": Path("deploy/native-ci/execd/templates/buzz-ci-executor.socket"),
}


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


def _git_blob(source_root: Path, revision: str, relative: Path) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(source_root), "show", f"{revision}:{relative}"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    return result.stdout


def _shared_repository_root(path: Path, metadata: os.stat_result, where: str) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != os.geteuid() or metadata.st_gid not in {os.getegid(), *os.getgroups()}:
        raise ValueError(f"{where} shared repository ownership differs")
    if mode != 0o2775:
        raise ValueError(f"{where} shared repository mode must be 2775")
    if _git(path, "config", "--get", "core.sharedRepository") != "all":
        raise ValueError(f"{where} group write requires core.sharedRepository=all")
    if _git(path, "rev-parse", "--is-inside-work-tree") != "true":
        raise ValueError(f"{where} is not a Git worktree")
    top_level = Path(_git(path, "rev-parse", "--show-toplevel"))
    if Path(os.path.realpath(top_level)) != path:
        raise ValueError(f"{where} does not match the Git worktree root")
    git_directory = Path(_git(path, "rev-parse", "--absolute-git-dir"))
    git_metadata = git_directory.lstat()
    if (
        Path(os.path.realpath(git_directory)) != git_directory
        or not stat.S_ISDIR(git_metadata.st_mode)
        or git_metadata.st_uid != metadata.st_uid
        or git_metadata.st_mode & (stat.S_IWOTH | stat.S_ISVTX)
    ):
        raise ValueError(f"{where} Git directory identity is unsafe")
    if git_metadata.st_mode & stat.S_IWGRP and (
        git_metadata.st_gid != metadata.st_gid or not git_metadata.st_mode & stat.S_ISGID
    ):
        raise ValueError(f"{where} Git directory shared access differs")


def _safe_input_directory(
    path: Path, where: str, *, allow_shared_repository: bool = False,
) -> Path:
    absolute = Path(os.path.abspath(path))
    metadata = absolute.lstat()
    if Path(os.path.realpath(absolute)) != absolute or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{where} must be a real directory")
    if metadata.st_uid != os.geteuid():
        raise ValueError(f"{where} ownership differs")
    if metadata.st_mode & stat.S_IWOTH:
        raise ValueError(f"{where} must not be group or world writable")
    if metadata.st_mode & stat.S_IWGRP:
        if not allow_shared_repository:
            raise ValueError(f"{where} must not be group or world writable")
        _shared_repository_root(absolute, metadata, where)
    return absolute


def _validate_tracked_parents(source_root: Path, relative: Path) -> None:
    if relative.is_absolute() or relative != Path(*relative.parts) or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"tracked source path is not normalized: {relative}")
    root_metadata = source_root.lstat()
    shared = bool(root_metadata.st_mode & stat.S_IWGRP)
    current = source_root
    for part in relative.parts[:-1]:
        current /= part
        metadata = current.lstat()
        if Path(os.path.realpath(current)) != current or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"tracked source parent is not a real directory: {relative}")
        if metadata.st_uid != root_metadata.st_uid or metadata.st_mode & (stat.S_IWOTH | stat.S_ISVTX):
            raise ValueError(f"tracked source parent access differs: {relative}")
        if metadata.st_mode & stat.S_IWGRP and (
            not shared
            or metadata.st_gid != root_metadata.st_gid
            or not metadata.st_mode & stat.S_ISGID
            or stat.S_IMODE(metadata.st_mode) & 0o050 != 0o050
        ):
            raise ValueError(f"tracked source parent shared access differs: {relative}")


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
    _validate_tracked_parents(source_root, relative)
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


def _render_sysusers(template: bytes, identities: dict[str, object], access_group: dict[str, object]) -> bytes:
    text = template.decode("utf-8")
    replacements = {
        "@RUNNER_UID@": str(identities["runner"]["uid"]),
        "@RUNNER_GID@": str(identities["runner"]["gid"]),
        "@CONTROLD_UID@": str(identities["controld"]["uid"]),
        "@CONTROLD_GID@": str(identities["controld"]["gid"]),
        "@KEYHOLDER_UID@": str(identities["keyholder"]["uid"]),
        "@KEYHOLDER_GID@": str(identities["keyholder"]["gid"]),
        "@QUALIFICATION_UID@": str(identities["qualification"]["uid"]),
        "@QUALIFICATION_GID@": str(identities["qualification"]["gid"]),
        "@JOB_UID@": str(identities["job"]["uid"]),
        "@JOB_GID@": str(identities["job"]["gid"]),
        "@EXECD_ACCESS_GID@": str(access_group["gid"]),
    }
    for token, value in replacements.items():
        text = text.replace(token, value)
    if "@" in text:
        raise ValueError("unresolved sysusers template token")
    return text.encode()


def _static_payload(
    source_root: Path,
    role: str,
    identities: dict[str, object],
    access_group: dict[str, object],
) -> tuple[bytes, str]:
    if role in TRACKED_ROOT_SOURCES:
        source_name, asset_name, git_mode, _source_mode = TRACKED_ROOT_SOURCES[role]
        payload = _tracked_payload(source_root, PACKAGE_RELATIVE / source_name, git_mode, 1024 * 1024)
        return payload, asset_name
    if role in TRACKED_REPO_SOURCES:
        relative, asset_name, git_mode, _source_mode = TRACKED_REPO_SOURCES[role]
        payload = _tracked_payload(source_root, relative, git_mode, 1024 * 1024)
        return payload, asset_name
    template_name, asset_name = STATIC_SOURCES[role]
    payload = _tracked_payload(
        source_root,
        PACKAGE_RELATIVE / "templates" / template_name,
        0o100644,
    )
    if role == "sysusers":
        payload = _render_sysusers(payload, identities, access_group)
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
    source_root = _safe_input_directory(source_root, "source root", allow_shared_repository=True)
    asset_root = _safe_input_directory(asset_root, "asset root")
    if not activation_package.GIT_OID.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object ID")
    if _git(source_root, "rev-parse", "HEAD") != source_commit:
        raise ValueError("source checkout does not match the requested commit")
    tracked_roots = [str(PACKAGE_RELATIVE), *(str(item[0]) for item in TRACKED_REPO_SOURCES.values())]
    if _git(source_root, "status", "--porcelain", "--", *tracked_roots):
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
        if role in STATIC_SOURCES or role in TRACKED_ROOT_SOURCES or role in TRACKED_REPO_SOURCES:
            payload, expected_source = _static_payload(
                source_root,
                role,
                draft["identities"],
                draft["access_group"],
            )
            if entry["source"] != expected_source:
                raise ValueError(f"static asset name differs for {role}")
            expected_mode = activation_package.parse_mode(entry["source_mode"])
            wanted_mode = TRACKED_ROOT_SOURCES.get(
                role, TRACKED_REPO_SOURCES.get(role, (None, None, None, 0o400)),
            )[3]
            if expected_mode != wanted_mode:
                raise ValueError(f"tracked source mode differs for {role}")
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
        tracked_source = TRACKED_COMPONENT_PROVENANCE.get(component["name"])
        if tracked_source is not None:
            relative = TRACKED_REPO_SOURCES["receipt_verifier_binary"][0]
            source_blob = _git(source_root, "rev-parse", f"{component['source_commit']}:{relative}")
            checkout_blob = _git(source_root, "rev-parse", f"HEAD:{relative}")
            if source != tracked_source or source_blob != checkout_blob:
                raise ValueError(f"tracked component provenance differs: {component['name']}")
            raw = activation_package.canonical_json({
                "binary": Path(component["binary_path"]).name,
                "profile": "release",
                "schema": activation_package.PROVENANCE_SCHEMA,
                "sha256": component["binary_sha256"],
                "source_commit": component["source_commit"],
            })
        else:
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
        if "package_manifest_source" in component:
            package_source = component["package_manifest_source"]
            package_raw = _external_payload(asset_root, package_source, 0o400)
            if activation_package.digest(package_raw) != component["package_manifest_sha256"]:
                raise ValueError(f"{component['name']} package manifest digest differs")
            payloads[package_source] = (package_raw, 0o400)

    component_commits = {item["name"]: item["source_commit"] for item in draft["components"]}
    for unit in draft["effective_systemd"]:
        for record in (unit["fragment"], *unit["drop_ins"]):
            source_path = SYSTEMD_SOURCE_PATHS.get(record["path"])
            if source_path is None:
                raise ValueError(f"effective systemd source is unknown: {record['path']}")
            revision = (
                source_commit
                if record["owner"] in {"activation", "platform"}
                else component_commits[record["owner"]]
            )
            if activation_package.digest(_git_blob(source_root, revision, source_path)) != record["sha256"]:
                raise ValueError(f"effective systemd source digest differs: {record['path']}")

    activation_package.validate_payloads(
        draft,
        {source: payload for source, (payload, _mode) in payloads.items()},
    )
    tmpfiles_sources = {
        "runner": Path("deploy/native-ci/runner/templates/buzzci-runner.tmpfiles"),
        "controld": Path("deploy/native-ci/controld/templates/buzzci-controld.tmpfiles"),
    }
    tmpfiles_plan = {
        item["component"]: item
        for item in activation_package.component_tmpfiles_plan(
            draft, {source: payload for source, (payload, _mode) in payloads.items()},
        )
    }
    component_commits = {item["name"]: item["source_commit"] for item in draft["components"]}
    for name, relative in tmpfiles_sources.items():
        if activation_package.digest(
            _git_blob(source_root, component_commits[name], relative)
        ) != tmpfiles_plan[name]["sha256"]:
            raise ValueError(f"{name} package tmpfiles source binding differs")
    components_by_name = {item["name"]: item for item in draft["components"]}
    for name in activation_package.COMPONENT_PACKAGE_NAMES:
        component = components_by_name[name]
        package = json.loads(payloads[component["package_manifest_source"]][0])
        documentation = next(item for item in package["entries"] if item["role"] == "documentation")
        if activation_package.digest(
            _git_blob(source_root, component_commits[name], Path(f"deploy/native-ci/{name}/README.md"))
        ) != documentation["sha256"]:
            raise ValueError(f"{name} package documentation source binding differs")

    referenced_sources = {
        entry["source"] for entry in draft["entries"]
    } | {
        entry["active_source"] for entry in draft["entries"] if "active_source" in entry
    } | {
        component["provenance_source"] for component in draft["components"]
    }
    referenced_sources.update(
        component["package_manifest_source"]
        for component in draft["components"]
        if "package_manifest_source" in component
    )
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
