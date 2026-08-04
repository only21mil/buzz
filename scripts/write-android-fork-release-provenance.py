#!/usr/bin/env python3
"""Write the canonical nonsecret provenance receipt for a verified fork APK."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, text=True, capture_output=True
    ).stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--certificate-sha256", required=True)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--dependencies", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    cert = args.certificate_sha256.lower().replace(":", "")
    if len(cert) != 64 or any(character not in "0123456789abcdef" for character in cert):
        parser.error("certificate fingerprint must be 64 hex characters")
    if args.version_code <= 0:
        parser.error("version code must be positive")
    if not args.apk.is_file() or not args.dependencies.is_file():
        parser.error("verified APK and dependency manifest must exist")

    commit = git("rev-parse", f"{args.commit}^{{commit}}")
    if commit != args.commit:
        parser.error("commit must be an exact full commit SHA")
    tag_object = git("rev-parse", f"refs/tags/{args.tag}")
    if git("cat-file", "-t", tag_object) != "tag":
        parser.error("source tag must be annotated")
    if git("rev-parse", f"refs/tags/{args.tag}^{{commit}}") != commit:
        parser.error("source tag does not resolve to the requested commit")

    lockfiles = {}
    for relative in ("mobile/pubspec.lock", "mobile/android/gradle/wrapper/gradle-wrapper.properties"):
        path = Path(relative)
        if path.is_file():
            lockfiles[relative] = digest(path)

    receipt = {
        "schema": "buzz-android-direct-release-provenance-v1",
        "source": {
            "repository": os.environ.get("GITHUB_REPOSITORY", ""),
            "tag": args.tag,
            "tag_object_sha": tag_object,
            "commit_sha": commit,
            "tree_sha": git("rev-parse", f"{commit}^{{tree}}"),
        },
        "build": {
            "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", ""),
            "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "runner_image": os.environ.get("ImageOS", ""),
            "runner_image_version": os.environ.get("ImageVersion", ""),
            "lockfiles": lockfiles,
        },
        "artifact": {
            "filename": args.apk.name,
            "size": args.apk.stat().st_size,
            "sha256": digest(args.apk),
            "dependency_manifest_filename": args.dependencies.name,
            "dependency_manifest_sha256": digest(args.dependencies),
            "package_id": "xyz.block.buzz.mobile",
            "version_name": args.version_name,
            "version_code": args.version_code,
        },
        "signing": {
            "certificate_sha256": cert,
            "signer_count": 1,
        },
        "verification": {
            "android_google_free": True,
            "apk_signature": True,
            "debuggable": False,
            "post_notifications_permission": True,
        },
    }
    args.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
