#!/usr/bin/env python3
"""Build a source-bound dormant Buzz CI evidence maintenance package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path

PACKAGE_RELATIVE = Path("deploy/native-ci/evidence-maintenance")
SCHEMA = "buzz-ci-evidence-maintenance-install-package-v1"
IDENTITY = "buzzci-evidence-maintenance"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def read_regular(path: Path, mode: int) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"source is not a single regular file: {path.name}")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"source mode mismatch: {path.name}")
    return path.read_bytes()


def write_asset(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchmod(descriptor, mode)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def entry(role: str, source: str, target: str, source_mode: int, install_mode: int, uid: int, gid: int, payload: bytes) -> dict[str, object]:
    return {
        "role": role,
        "source": f"assets/{source}",
        "target": target,
        "source_mode": f"0{source_mode:o}",
        "install_mode": f"0{install_mode:o}",
        "uid": uid,
        "gid": gid,
        "sha256": sha256(payload),
    }


def freeze_package(source_root: Path, source_commit: str, binary: Path, output: Path, service_uid: int, service_gid: int) -> dict[str, object]:
    if len(source_commit) != 40 or any(character not in "0123456789abcdef" for character in source_commit):
        raise ValueError("source commit must be 40 lowercase hex characters")
    if not 1 <= service_uid <= (1 << 32) - 1 or not 1 <= service_gid <= (1 << 32) - 1:
        raise ValueError("service identity must use nonzero u32 values")
    source_root = Path(os.path.realpath(source_root))
    binary_payload = read_regular(binary, 0o755)
    output = Path(os.path.abspath(output))
    if output.exists() or output.is_symlink():
        raise ValueError("package output must not already exist")
    parent = output.parent
    if Path(os.path.realpath(parent)) != parent or parent.lstat().st_mode & 0o022:
        raise ValueError("package output parent must be a private real directory")

    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    stage.chmod(0o700)
    assets = stage / "assets"
    assets.mkdir(mode=0o700)
    package_dir = source_root / PACKAGE_RELATIVE
    try:
        entries: list[dict[str, object]] = []
        files = [
            ("binary", binary, "buzz-ci-evidence-maintenance", "/usr/libexec/buzz-ci-evidence-maintenance", 0o755, 0o500, 0, 0, binary_payload),
            ("config", package_dir / "templates/evidence-maintenance-v1.json", "evidence-maintenance-v1.json", "/etc/buzzci/evidence-maintenance-v1.json", 0o644, 0o440, 0, service_gid, None),
            ("service", package_dir / "templates/buzz-ci-evidence-maintenance.service", "buzz-ci-evidence-maintenance.service", "/usr/lib/systemd/system/buzz-ci-evidence-maintenance.service", 0o644, 0o644, 0, 0, None),
            ("timer", package_dir / "templates/buzz-ci-evidence-maintenance.timer", "buzz-ci-evidence-maintenance.timer", "/usr/lib/systemd/system/buzz-ci-evidence-maintenance.timer", 0o644, 0o644, 0, 0, None),
            ("tmpfiles", package_dir / "templates/buzzci-evidence-maintenance.tmpfiles", "buzzci-evidence-maintenance.conf", "/usr/lib/tmpfiles.d/buzzci-evidence-maintenance.conf", 0o644, 0o644, 0, 0, None),
            ("documentation", package_dir / "README.md", "README.md", "/usr/share/doc/buzz-ci-evidence-maintenance/README.md", 0o644, 0o644, 0, 0, None),
        ]
        for role, source, asset_name, target, source_mode, install_mode, uid, gid, known_payload in files:
            payload = known_payload if known_payload is not None else read_regular(source, source_mode)
            write_asset(assets / asset_name, payload, source_mode)
            entries.append(entry(role, asset_name, target, source_mode, install_mode, uid, gid, payload))

        sysusers = read_regular(package_dir / "templates/buzzci-evidence-maintenance.sysusers.in", 0o644)
        sysusers = sysusers.replace(b"@UID@", str(service_uid).encode()).replace(b"@GID@", str(service_gid).encode())
        write_asset(assets / "buzzci-evidence-maintenance.sysusers", sysusers, 0o644)
        entries.append(entry("sysusers", "buzzci-evidence-maintenance.sysusers", "/usr/lib/sysusers.d/buzzci-evidence-maintenance.conf", 0o644, 0o644, 0, 0, sysusers))
        entries.sort(key=lambda item: str(item["target"]).encode())
        manifest: dict[str, object] = {
            "schema": SCHEMA,
            "package_id": f"buzz-ci-evidence-maintenance-{source_commit[:12]}-{sha256(binary_payload)[:12]}",
            "source_commit": source_commit,
            "default_state": {"enabled": False, "active": False, "credentials_installed": False},
            "identity": {"user": IDENTITY, "group": IDENTITY, "uid": service_uid, "gid": service_gid},
            "entries": entries,
        }
        manifest["package_digest"] = sha256(canonical_json(manifest))
        write_asset(stage / "package-manifest.json", canonical_json(manifest), 0o600)
        os.replace(stage, output)
        return manifest
    except BaseException:
        shutil.rmtree(stage)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--service-uid", type=int, required=True)
    parser.add_argument("--service-gid", type=int, required=True)
    args = parser.parse_args()
    manifest = freeze_package(args.source_root, args.source_commit, args.binary, args.output, args.service_uid, args.service_gid)
    print(json.dumps({"status": "frozen", "package_id": manifest["package_id"], "package_digest": manifest["package_digest"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
