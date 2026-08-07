#!/usr/bin/env python3
"""Validate and derive immutable only21mil Android release metadata."""

from __future__ import annotations

import argparse
import json
import re
import sys


TAG_RE = re.compile(
    r"^only21mil-android-v(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)-rc\."
    r"(?P<rc>[1-9][0-9]*)$"
)
ANDROID_MAX_VERSION_CODE = 2_100_000_000


class MetadataError(ValueError):
    pass


def metadata(tag: str) -> dict[str, str | int]:
    match = TAG_RE.fullmatch(tag)
    if match is None:
        raise MetadataError(
            "tag must match only21mil-android-vX.Y.Z-rc.N with canonical integers"
        )
    major, minor, patch, rc = (
        int(match.group(name)) for name in ("major", "minor", "patch", "rc")
    )
    if any(component > 99 for component in (major, minor, patch)):
        raise MetadataError("each marketing-version component must be between 0 and 99")
    if rc > 999:
        raise MetadataError("release-candidate number must be between 1 and 999")

    version_code = 1_000_000_000 + major * 10_000_000 + minor * 100_000 + patch * 1_000 + rc
    if version_code >= ANDROID_MAX_VERSION_CODE:
        raise MetadataError("derived Android version code exceeds the platform limit")

    version = f"{major}.{minor}.{patch}"
    return {
        "tag": tag,
        "version": version,
        "version_name": f"{version}-only21mil.rc.{rc}",
        "version_code": version_code,
        "candidate_number": rc,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument(
        "--format", choices=("json", "github-output"), default="json"
    )
    args = parser.parse_args()
    try:
        values = metadata(args.tag)
    except MetadataError as error:
        print(f"android-fork-release-metadata: {error}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(values, sort_keys=True, separators=(",", ":")))
    else:
        for key in ("tag", "version", "version_name", "version_code", "candidate_number"):
            print(f"{key}={values[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
