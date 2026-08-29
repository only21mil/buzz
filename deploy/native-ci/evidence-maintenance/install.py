#!/usr/bin/env python3
"""Install a verified evidence maintenance package without activating it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def install_package(package: Path, root: Path) -> dict[str, object]:
    package = Path(os.path.realpath(package))
    root = Path(os.path.realpath(root))
    manifest_path = package / "package-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("package manifest must be a regular file")
    manifest = json.loads(manifest_path.read_bytes())
    claimed_digest = manifest.pop("package_digest", None)
    if claimed_digest != sha256(canonical_json(manifest)):
        raise ValueError("package digest mismatch")
    manifest["package_digest"] = claimed_digest
    if manifest.get("schema") != "buzz-ci-evidence-maintenance-install-package-v1":
        raise ValueError("unsupported package schema")

    prepared: list[tuple[dict[str, object], bytes, Path]] = []
    for item in manifest.get("entries", []):
        source = package / str(item["source"])
        metadata = source.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("package asset is not a single regular file")
        payload = source.read_bytes()
        if sha256(payload) != item["sha256"] or stat.S_IMODE(metadata.st_mode) != int(str(item["source_mode"]), 8):
            raise ValueError("package asset integrity mismatch")
        relative = Path(str(item["target"]).lstrip("/"))
        target = root / relative
        if any(part in {"", ".", ".."} for part in relative.parts):
            raise ValueError("invalid package target")
        prepared.append((item, payload, target))

    for item, payload, target in prepared:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.is_symlink():
            raise ValueError("refusing symlink install target")
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, int(str(item["install_mode"]), 8))
        try:
            install_mode = int(str(item["install_mode"]), 8)
            os.fchmod(descriptor, install_mode)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != install_mode:
                raise OSError(f"could not materialize exact install mode: {target}")
            view = memoryview(payload)
            while view:
                view = view[os.write(descriptor, view):]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if stat.S_IMODE(target.lstat().st_mode) != install_mode:
            raise OSError(f"installed target mode readback differs: {target}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("/"))
    args = parser.parse_args()
    manifest = install_package(args.package, args.root)
    print(json.dumps({"status": "installed_dormant", "package_id": manifest["package_id"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
