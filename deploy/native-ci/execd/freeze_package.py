#!/usr/bin/env python3
"""Freeze the non-overlapping production execd binary package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

SCHEMA = "buzz-ci-execd-install-package-v1"
PREACTIVATION_SCHEMA = "buzz-ci-execd-preactivation-input-v1"
PROVENANCE_SCHEMA = "buzz-ci-binary-provenance-v1"
PACKAGE_RELATIVE = Path("deploy/native-ci/execd")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_STATE = {"enabled": False, "active": False, "capacity": 0}
RUNTIME_CONTRACT = {
    "binary": "/usr/libexec/buzz-ci-execd",
    "uid": 0,
    "gid": 0,
    "mode": "0755",
}
ACTIVATION_OWNED_TARGETS = [
    "/usr/lib/systemd/system/buzz-ci-execd.service",
    "/usr/lib/systemd/system/buzz-ci-execd.socket",
    "/usr/lib/systemd/system/buzz-ci-executor.service",
    "/usr/lib/systemd/system/buzz-ci-executor.socket",
    "/usr/libexec/buzz-ci-capacity-one-fixture",
    "/usr/libexec/buzz-ci-executor",
    "/usr/share/buzzci/execd-v2/fixture/fixture-manifest.json",
    "/usr/share/buzzci/execd-v2/fixture/input.txt",
]
ACTIVATION_SCHEMA = "buzz-ci-capacity-one-activation-package-v1"
ACTIVATION_DRAFT_SCHEMA = "buzz-ci-capacity-one-activation-draft-v1"
SECCOMP_CONTRACT = {
    "source_path": "/usr/share/containers/seccomp.json",
    "source_sha256": "2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4",
    "source_mode": "0644",
    "installed_path": "/var/lib/buzzci/seccomp/v1/sha256/2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4.json",
    "installed_mode": "0444",
    "runtime_receipt": "/var/lib/buzzci/activation/receipts/seccomp.json",
    "packaged_bytes": False,
}
INSTALL_RECEIPT = {
    "schema": "buzz-ci-execd-install-receipt-v1",
    "path": "/var/lib/buzzci/execd-v2/package/receipt-v1.json",
    "mode": "0600",
    "uid": 0,
    "gid": 0,
}
DIRECTORIES = [{"target": "/usr/libexec", "mode": "0755", "uid": 0, "gid": 0}]


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def read_regular(
    path: Path,
    expected_mode: int | None = None,
    maximum: int = 128 * 1024 * 1024,
) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe regular file: {path}")
        if expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise ValueError(f"wrong source mode: {path}")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > maximum:
                raise ValueError(f"source exceeds byte limit: {path}")
            chunks.append(chunk)
        if size == 0:
            raise ValueError(f"empty source: {path}")
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def _json(path: Path) -> tuple[dict[str, object], bytes, os.stat_result]:
    raw, metadata = read_regular(path, 0o600, 64 * 1024)
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ValueError("binary provenance must be a JSON object")
    return value, raw, metadata


def load_provenance(path: Path) -> tuple[dict[str, object], bytes, os.stat_result]:
    value, raw, metadata = _json(path)
    if set(value) != {"schema", "binary", "source_commit", "profile", "sha256"}:
        raise ValueError("binary provenance fields differ")
    if (
        value["schema"] != PROVENANCE_SCHEMA
        or value["binary"] != "buzz-ci-execd"
        or value["profile"] != "release"
        or not isinstance(value["source_commit"], str)
        or not GIT_OID.fullmatch(value["source_commit"])
        or not isinstance(value["sha256"], str)
        or not DIGEST.fullmatch(value["sha256"])
    ):
        raise ValueError("binary provenance identity differs")
    return value, raw, metadata


def parse_preactivation_input(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("pre-activation execd input is not valid JSON") from error
    expected = {"schema", "source_commit", "binary_sha256", "provenance_sha256"}
    if not isinstance(value, dict) or set(value) != expected or canonical_json(value) != raw:
        raise ValueError("pre-activation execd input fields or canonical bytes differ")
    if (
        value["schema"] != PREACTIVATION_SCHEMA
        or not isinstance(value["source_commit"], str)
        or not GIT_OID.fullmatch(value["source_commit"])
        or any(
            not isinstance(value[field], str) or not DIGEST.fullmatch(value[field])
            or value[field] == "0" * 64
            for field in ("binary_sha256", "provenance_sha256")
        )
        or value["source_commit"] == "0" * 40
    ):
        raise ValueError("pre-activation execd input identity differs")
    return value


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def verify_source(root: Path, source_commit: str) -> Path:
    if not GIT_OID.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object id")
    root = Path(_git(root, "rev-parse", "--show-toplevel"))
    if _git(root, "rev-parse", "HEAD") != source_commit:
        raise ValueError("source checkout HEAD differs from source commit")
    if _git(root, "status", "--porcelain", "--untracked-files=all", "--", str(PACKAGE_RELATIVE)):
        raise ValueError("execd package source is not clean")
    package = root / PACKAGE_RELATIVE
    if Path(os.path.realpath(package)) != package:
        raise ValueError("execd package source contains a symbolic path")
    return root


def _validated_binary_input(
    source_root: Path,
    source_commit: str,
    binary: Path,
    provenance_path: Path,
) -> tuple[bytes, dict[str, object], bytes]:
    verify_source(source_root, source_commit)
    for source in (binary, provenance_path):
        absolute = Path(os.path.abspath(source))
        if Path(os.path.realpath(absolute)) != absolute:
            raise ValueError("binary input path must not contain symbolic links")
    provenance, provenance_raw, provenance_metadata = load_provenance(provenance_path)
    if provenance["source_commit"] != source_commit:
        raise ValueError("binary provenance is bound to another source commit")
    payload, binary_metadata = read_regular(binary, 0o755)
    if (
        (binary_metadata.st_uid, binary_metadata.st_gid)
        != (provenance_metadata.st_uid, provenance_metadata.st_gid)
        or sha256(payload) != provenance["sha256"]
    ):
        raise ValueError("binary bytes or ownership differ from provenance")
    return payload, provenance, provenance_raw


def _private_output(path: Path) -> Path:
    output = Path(os.path.abspath(path))
    parent = output.parent
    parent_metadata = parent.lstat()
    if (
        Path(os.path.realpath(parent)) != parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_mode & 0o022
    ):
        raise ValueError("output parent must be a private real directory")
    if output.exists() or output.is_symlink():
        raise ValueError("output must not already exist")
    return output


def prepare_preactivation_input(
    source_root: Path,
    source_commit: str,
    binary: Path,
    provenance_path: Path,
    output: Path,
) -> dict[str, object]:
    payload, _provenance, provenance_raw = _validated_binary_input(
        source_root, source_commit, binary, provenance_path,
    )
    value: dict[str, object] = {
        "schema": PREACTIVATION_SCHEMA,
        "source_commit": source_commit,
        "binary_sha256": sha256(payload),
        "provenance_sha256": sha256(provenance_raw),
    }
    output = _private_output(output)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    stage.chmod(0o700)
    staged = stage / "preactivation-input.json"
    try:
        _write(staged, canonical_json(value), 0o600)
        os.link(staged, output, follow_symlinks=False)
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return value


def load_preactivation_input(
    path: Path,
    source_commit: str,
    binary_sha256: str,
    provenance_sha256: str,
) -> tuple[dict[str, object], bytes]:
    path = Path(os.path.abspath(path))
    if Path(os.path.realpath(path)) != path:
        raise ValueError("pre-activation execd input path contains a symbolic link")
    raw, metadata = read_regular(path, 0o600, 64 * 1024)
    if metadata.st_nlink != 1:
        raise ValueError("pre-activation execd input must have one link")
    value = parse_preactivation_input(raw)
    expected = {
        "source_commit": source_commit,
        "binary_sha256": binary_sha256,
        "provenance_sha256": provenance_sha256,
    }
    if any(value[field] != wanted for field, wanted in expected.items()):
        raise ValueError("pre-activation execd input tuple differs from final inputs")
    return value, raw


def activation_binding(
    package: Path,
    source_commit: str,
    binary_sha256: str,
    provenance_sha256: str,
    preactivation_sha256: str,
) -> dict[str, object]:
    package = Path(os.path.abspath(package))
    package_metadata = package.lstat()
    if (
        Path(os.path.realpath(package)) != package
        or not stat.S_ISDIR(package_metadata.st_mode)
        or stat.S_IMODE(package_metadata.st_mode) != 0o700
    ):
        raise ValueError("activation package root is unsafe")
    manifest_path = package / "activation-manifest.json"
    raw, _ = read_regular(manifest_path, 0o600, 1024 * 1024)
    manifest = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(manifest, dict) or canonical_json(manifest) != raw:
        raise ValueError("activation manifest must be a JSON object")
    required = {"schema", "activation_id", "source_commit", "components", "entries", "package_digest"}
    if not required <= set(manifest) or manifest["schema"] != ACTIVATION_SCHEMA:
        raise ValueError("activation manifest identity differs")
    unsigned = dict(manifest)
    package_digest = unsigned.pop("package_digest")
    unsigned.pop("activation_id", None)
    unsigned["schema"] = ACTIVATION_DRAFT_SCHEMA
    if (
        not isinstance(package_digest, str)
        or not DIGEST.fullmatch(package_digest)
        or sha256(canonical_json(unsigned)) != package_digest
        or manifest["source_commit"] != source_commit
        or manifest["activation_id"]
        != f"buzz-ci-capacity-one-{source_commit[:12]}-{package_digest[:12]}"
    ):
        raise ValueError("activation manifest digest or source binding differs")
    components = manifest["components"]
    if not isinstance(components, list):
        raise ValueError("activation component inventory differs")
    execd = [item for item in components if isinstance(item, dict) and item.get("name") == "execd"]
    if len(execd) != 1:
        raise ValueError("activation execd component is absent or ambiguous")
    component = execd[0]
    if (
        component.get("binary_path") != RUNTIME_CONTRACT["binary"]
        or component.get("binary_sha256") != binary_sha256
        or component.get("source_commit") != source_commit
        or component.get("uid") != 0
        or component.get("gid") != 0
        or component.get("mode") != "0755"
        or component.get("provenance_sha256") != provenance_sha256
    ):
        raise ValueError("activation execd component differs")
    entries = manifest["entries"]
    if not isinstance(entries, list):
        raise ValueError("activation managed entry inventory differs")
    selected = [
        item
        for item in entries
        if isinstance(item, dict) and item.get("target") in ACTIVATION_OWNED_TARGETS
    ]
    if sorted(str(item.get("target")) for item in selected) != ACTIVATION_OWNED_TARGETS:
        raise ValueError("activation-owned execd targets differ")
    selected.sort(key=lambda item: str(item["target"]).encode())
    return {
        "activation_id": manifest["activation_id"],
        "package_digest": package_digest,
        "manifest_sha256": sha256(raw),
        "source_commit": source_commit,
        "execd_binary_sha256": binary_sha256,
        "execd_provenance_sha256": provenance_sha256,
        "preactivation_input_sha256": preactivation_sha256,
        "owned_entries_sha256": sha256(canonical_json(selected)),
        "owned_target_sha256": [
            {"target": item["target"], "sha256": item["sha256"]} for item in selected
        ],
        "receipt_path": "/var/lib/buzzci/activation-controller/receipt-v1.json",
        "receipt_schema": "buzz-ci-capacity-one-activation-receipt-v1",
    }


def _write(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def freeze_package(
    source_root: Path,
    source_commit: str,
    binary: Path,
    provenance_path: Path,
    preactivation_path: Path,
    activation_package: Path,
    output: Path,
) -> dict[str, object]:
    payload, _provenance, provenance_raw = _validated_binary_input(
        source_root, source_commit, binary, provenance_path,
    )
    _preactivation, preactivation_raw = load_preactivation_input(
        preactivation_path, source_commit, sha256(payload), sha256(provenance_raw),
    )
    binding = activation_binding(
        activation_package,
        source_commit,
        sha256(payload),
        sha256(provenance_raw),
        sha256(preactivation_raw),
    )

    output = _private_output(output)
    parent = output.parent
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    stage.chmod(0o700)
    assets = stage / "assets"
    assets.mkdir(mode=0o700)
    try:
        _write(assets / "buzz-ci-execd", payload, 0o500)
        entry = {
            "role": "binary",
            "source": "assets/buzz-ci-execd",
            "target": RUNTIME_CONTRACT["binary"],
            "source_mode": "0500",
            "install_mode": RUNTIME_CONTRACT["mode"],
            "uid": 0,
            "gid": 0,
            "sha256": sha256(payload),
        }
        manifest: dict[str, object] = {
            "schema": SCHEMA,
            "package_id": f"buzz-ci-execd-{source_commit[:12]}-{sha256(payload)[:12]}",
            "source_commit": source_commit,
            "binary_provenance_sha256": sha256(provenance_raw),
            "default_state": DEFAULT_STATE,
            "runtime_contract": RUNTIME_CONTRACT,
            "activation_owned_targets": ACTIVATION_OWNED_TARGETS,
            "activation_binding": binding,
            "seccomp_contract": SECCOMP_CONTRACT,
            "install_receipt": INSTALL_RECEIPT,
            "package_uid": 0,
            "package_gid": 0,
            "directories": DIRECTORIES,
            "entries": [entry],
        }
        manifest["package_digest"] = sha256(canonical_json(manifest))
        _write(stage / "binary-provenance.json", provenance_raw, 0o600)
        _write(stage / "package-manifest.json", canonical_json(manifest), 0o600)
        os.replace(stage, output)
        return manifest
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    prepare = actions.add_parser("prepare-input")
    freeze = actions.add_parser("freeze-package")
    for action in (prepare, freeze):
        action.add_argument("--source-root", type=Path, required=True)
        action.add_argument("--source-commit", required=True)
        action.add_argument("--binary", type=Path, required=True)
        action.add_argument("--binary-provenance", type=Path, required=True)
        action.add_argument("--output", type=Path, required=True)
    freeze.add_argument("--preactivation-input", type=Path, required=True)
    freeze.add_argument("--activation-package", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.action == "prepare-input":
        value = prepare_preactivation_input(
            arguments.source_root,
            arguments.source_commit,
            arguments.binary,
            arguments.binary_provenance,
            arguments.output,
        )
        print(json.dumps({"status": "prepared", **value}, sort_keys=True))
        return 0
    manifest = freeze_package(
        arguments.source_root,
        arguments.source_commit,
        arguments.binary,
        arguments.binary_provenance,
        arguments.preactivation_input,
        arguments.activation_package,
        arguments.output,
    )
    print(
        json.dumps(
            {
                "status": "frozen",
                "package_id": manifest["package_id"],
                "package_digest": manifest["package_digest"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
