#!/usr/bin/env python3
"""Freeze public acceptance policy and keyholder systemd wiring without a credential."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

NATIVE_CI_DIR = Path(__file__).resolve().parents[1]
if str(NATIVE_CI_DIR) not in sys.path:
    sys.path.insert(0, str(NATIVE_CI_DIR))
KEYHOLDER_DIR = Path(__file__).resolve().parent
if str(KEYHOLDER_DIR) not in sys.path:
    sys.path.insert(0, str(KEYHOLDER_DIR))

import package_source
import render_keyholder_config

SCHEMA = "buzz-ci-keyholder-acceptance-package-v1"
PROVENANCE_SCHEMA = "buzz-ci-binary-provenance-v1"
PACKAGE_RELATIVE = Path("deploy/native-ci/keyholder")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_CONTRACT = {
    "socket_path": "/run/buzzci/keyholder.sock",
    "fd_name": "buzz-ci-keyholder-control",
    "config_path": "/etc/buzzci/keyholder-v1.json",
    "enabled": False,
    "active": False,
}
CREDENTIAL_CONTRACT = {
    "runtime_name": "acceptance-actor.key",
    "encrypted_source": "/etc/credstore.encrypted/buzzci-keyholder/acceptance-actor.key",
    "source_mode": "0400",
    "source_uid": 0,
    "source_gid": 0,
    "plaintext_bytes": 32,
    "packaged": False,
}
DIRECTORIES = (
    "/etc/buzzci",
    "/etc/systemd/system/buzz-ci-keyholder.service.d",
    "/usr/libexec",
    "/usr/lib/tmpfiles.d",
    "/usr/share/doc/buzz-ci-keyholder",
)
STATIC_ASSETS = (
    ("service", "templates/buzz-ci-keyholder.service", "buzz-ci-keyholder.service", "/etc/systemd/system/buzz-ci-keyholder.service"),
    ("socket", "templates/buzz-ci-keyholder.socket", "buzz-ci-keyholder.socket", "/etc/systemd/system/buzz-ci-keyholder.socket"),
    ("tmpfiles", "templates/buzzci-keyholder.tmpfiles", "buzzci-keyholder.conf", "/usr/lib/tmpfiles.d/buzzci-keyholder.conf"),
    ("acceptance_credential_dropin", "templates/20-acceptance-actor.conf", "20-acceptance-actor.conf", "/etc/systemd/system/buzz-ci-keyholder.service.d/20-acceptance-actor.conf"),
    ("documentation", "README.md", "README.md", "/usr/share/doc/buzz-ci-keyholder/README.md"),
)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != mode:
            raise OSError(f"could not materialize exact asset mode: {path}")
    finally:
        os.close(descriptor)


def _entry(
    role: str,
    source: str,
    target: str,
    uid: int,
    gid: int,
    payload: bytes,
    *,
    source_mode: str = "0400",
    install_mode: str | None = None,
) -> dict[str, object]:
    if install_mode is None:
        install_mode = "0600" if role == "config" else "0644"
    return {
        "role": role,
        "source": f"assets/{source}",
        "target": target,
        "source_mode": source_mode,
        "install_mode": install_mode,
        "uid": uid,
        "gid": gid,
        "sha256": digest(payload),
        "size": len(payload),
    }


def _load_provenance(path: Path) -> tuple[dict[str, object], bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > 64 * 1024
        ):
            raise ValueError("binary provenance metadata is unsafe")
        raw = b""
        while chunk := os.read(descriptor, 64 * 1024):
            raw += chunk
    finally:
        os.close(descriptor)
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "binary", "source_commit", "profile", "sha256"}
        or value.get("schema") != PROVENANCE_SCHEMA
        or value.get("binary") != "buzz-ci-keyholder"
        or value.get("profile") != "release"
        or not isinstance(value.get("source_commit"), str)
        or not GIT_OID.fullmatch(str(value["source_commit"]))
        or not isinstance(value.get("sha256"), str)
        or not DIGEST.fullmatch(str(value["sha256"]))
        or canonical_json(value) != raw
    ):
        raise ValueError("binary provenance is not canonical or has invalid fields")
    return value, raw, metadata


def _read_binary(path: Path) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o755
        ):
            raise ValueError("release binary metadata is unsafe")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > 128 * 1024 * 1024:
                raise ValueError("release binary exceeds byte limit")
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def _validate_units(payloads: dict[str, bytes]) -> None:
    service = payloads["service"].decode()
    socket = payloads["socket"].decode()
    dropin = payloads["acceptance_credential_dropin"].decode()
    existing = {
        "LoadCredentialEncrypted=ci-event.key:/etc/credstore.encrypted/buzzci-keyholder/ci-event.key",
        "LoadCredentialEncrypted=nip98.key:/etc/credstore.encrypted/buzzci-keyholder/nip98.key",
        "LoadCredentialEncrypted=manifest.key:/etc/credstore.encrypted/buzzci-keyholder/manifest.key",
    }
    actual_existing = {line for line in service.splitlines() if line.startswith("LoadCredentialEncrypted=")}
    if actual_existing != existing or "acceptance-actor.key" in service:
        raise ValueError("base credential domains differ")
    expected_dropin = "[Service]\nLoadCredentialEncrypted=acceptance-actor.key:/etc/credstore.encrypted/buzzci-keyholder/acceptance-actor.key\n"
    if dropin != expected_dropin or any(name in dropin for name in ("ci-event.key", "nip98.key", "manifest.key")):
        raise ValueError("acceptance credential drop-in differs")
    required_socket = {
        "ListenStream=/run/buzzci/keyholder.sock",
        "FileDescriptorName=buzz-ci-keyholder-control",
        "Accept=no",
        "SocketUser=buzzci-keyholder",
        "SocketGroup=buzzci-controld",
        "SocketMode=0620",
        "Service=buzz-ci-keyholder.service",
    }
    if not required_socket.issubset(set(socket.splitlines())):
        raise ValueError("keyholder socket/FD contract differs")
    if "LimitCORE=0" not in service or "ExecStart=/usr/libexec/buzz-ci-keyholder --config /etc/buzzci/keyholder-v1.json" not in service:
        raise ValueError("keyholder service contract differs")
    expected_read_only = (
        "ReadOnlyPaths=/etc/buzzci/keyholder-v1.json /run/buzzci "
        "/var/lib/buzzci/activation-controller/controld-acceptance-v1.json"
    )
    if expected_read_only not in service.splitlines():
        raise ValueError("acceptance binding receipt mount contract differs")


def freeze_package(
    source_root: Path,
    source_commit: str,
    binary: Path,
    provenance_path: Path,
    public_spec: Path,
    output: Path,
    keyholder_uid: int,
    keyholder_gid: int,
    controld_uid: int,
    controld_gid: int,
) -> dict[str, object]:
    if not GIT_OID.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object id")
    source_root = package_source.verify_checkout(source_root, source_commit, PACKAGE_RELATIVE)
    provenance, provenance_raw, provenance_metadata = _load_provenance(provenance_path)
    binary_payload, binary_metadata = _read_binary(binary)
    if provenance["source_commit"] != source_commit:
        raise ValueError("binary provenance is bound to another source commit")
    if (binary_metadata.st_uid, binary_metadata.st_gid) != (
        provenance_metadata.st_uid,
        provenance_metadata.st_gid,
    ):
        raise ValueError("release binary and provenance ownership differ")
    if digest(binary_payload) != provenance["sha256"]:
        raise ValueError("release binary digest differs from provenance")
    for identity in (keyholder_uid, keyholder_gid, controld_uid, controld_gid):
        if isinstance(identity, bool) or not 1 <= identity <= 0xFFFF_FFFF:
            raise ValueError("service identities must use nonzero u32 values")
    if keyholder_uid == controld_uid or keyholder_gid == controld_gid:
        raise ValueError("keyholder and controld identities must be distinct")
    config = render_keyholder_config.config_bytes(public_spec)
    config_value = json.loads(config)
    if (config_value["peer"]["uid"], config_value["peer"]["gid"]) != (controld_uid, controld_gid):
        raise ValueError("public spec peer identity differs from controld identity")

    output = Path(os.path.abspath(output))
    parent = output.parent
    if Path(os.path.realpath(parent)) != parent or parent.lstat().st_mode & 0o022:
        raise ValueError("package output parent must be a private real directory")
    if output.exists() or output.is_symlink():
        raise ValueError("package output must not already exist")
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    stage.chmod(0o700)
    assets = stage / "assets"
    assets.mkdir(mode=0o700)
    try:
        entries = []
        payloads: dict[str, bytes] = {}
        _write(assets / "buzz-ci-keyholder", binary_payload, 0o500)
        entries.append(
            _entry(
                "binary",
                "buzz-ci-keyholder",
                "/usr/libexec/buzz-ci-keyholder",
                0,
                0,
                binary_payload,
                source_mode="0500",
                install_mode="0755",
            )
        )
        _write(assets / "keyholder-v1.json", config, 0o400)
        entries.append(_entry("config", "keyholder-v1.json", RUNTIME_CONTRACT["config_path"], keyholder_uid, keyholder_gid, config))
        for role, source, name, target in STATIC_ASSETS:
            payload, _ = package_source.tracked_payload(source_root, PACKAGE_RELATIVE / source, 0o100644)
            payloads[role] = payload
            _write(assets / name, payload, 0o400)
            entries.append(_entry(role, name, target, 0, 0, payload))
        _validate_units(payloads)
        entries.sort(key=lambda item: str(item["target"]).encode())
        manifest: dict[str, object] = {
            "schema": SCHEMA,
            "package_id": f"buzz-ci-keyholder-acceptance-{source_commit[:12]}-{digest(binary_payload + config)[:12]}",
            "source_commit": source_commit,
            "binary_provenance_sha256": digest(provenance_raw),
            "package_uid": 0,
            "package_gid": 0,
            "identities": {
                "keyholder_uid": keyholder_uid,
                "keyholder_gid": keyholder_gid,
                "controld_uid": controld_uid,
                "controld_gid": controld_gid,
            },
            "runtime_contract": RUNTIME_CONTRACT,
            "credential_contract": CREDENTIAL_CONTRACT,
            "directories": [
                {"target": target, "mode": "0755", "uid": 0, "gid": 0}
                for target in DIRECTORIES
            ],
            "entries": entries,
        }
        manifest["package_digest"] = digest(canonical_json(manifest))
        _write(stage / "binary-provenance.json", provenance_raw, 0o600)
        _write(stage / "package-manifest.json", canonical_json(manifest), 0o600)
        os.replace(stage, output)
        if stat.S_IMODE(output.lstat().st_mode) != 0o700:
            raise OSError("could not materialize exact package mode")
        return manifest
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-provenance", dest="provenance_path", type=Path, required=True)
    parser.add_argument("--public-spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keyholder-uid", type=int, required=True)
    parser.add_argument("--keyholder-gid", type=int, required=True)
    parser.add_argument("--controld-uid", type=int, required=True)
    parser.add_argument("--controld-gid", type=int, required=True)
    arguments = parser.parse_args()
    result = freeze_package(**vars(arguments))
    print(json.dumps({"package_id": result["package_id"], "package_digest": result["package_digest"], "status": "frozen"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
