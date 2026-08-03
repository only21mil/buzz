#!/usr/bin/env python3
"""Fail closed when an Android app packages Google SDK dependencies or code."""

from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path


EXPECTED_CONFIGURATIONS = {
    "debugRuntimeClasspath",
    "profileRuntimeClasspath",
    "releaseRuntimeClasspath",
}
FORBIDDEN_DEPENDENCY_GROUPS = (
    "com.google.android.gms",
    "com.google.firebase",
    "com.google.mlkit",
)
FORBIDDEN_PACKAGE_MARKERS = (
    b"com/google/android/gms/",
    b"com/google/firebase/",
    b"com/google/mlkit/",
    b"com.google.android.gms",
    b"com.google.firebase",
    b"com.google.mlkit",
)
FORBIDDEN_ENTRY_NAME_MARKERS = FORBIDDEN_PACKAGE_MARKERS + (
    b"assets/firebase",
    b"assets/google-play-services",
    b"assets/google_play_services",
    b"assets/mlkit",
)
MAX_ENTRY_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
MARKER_OVERLAP_BYTES = max(map(len, FORBIDDEN_PACKAGE_MARKERS)) - 1
COORDINATE_RE = re.compile(r"^([^:\s]+):([^:\s]+):([^:\s]+)$")


class CheckFailure(RuntimeError):
    """A deterministic policy or input validation failure."""


def parse_dependency_manifest(path: Path) -> tuple[set[str], list[tuple[str, str]]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CheckFailure(f"cannot read dependency manifest {path}: {error}") from error

    configurations: set[str] = set()
    components: list[tuple[str, str]] = []
    previous_line = ""
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line:
            raise CheckFailure(f"dependency manifest has a blank line at {line_number}")
        if previous_line and line <= previous_line:
            raise CheckFailure("dependency manifest must be strictly sorted with no duplicates")
        previous_line = line

        fields = line.split("\t")
        if len(fields) == 2 and fields[0] == "configuration":
            configuration = fields[1]
            if configuration not in EXPECTED_CONFIGURATIONS:
                raise CheckFailure(f"unexpected runtime configuration: {configuration}")
            configurations.add(configuration)
            continue
        if len(fields) == 3 and fields[0] == "component":
            configuration, coordinate = fields[1:]
            if configuration not in EXPECTED_CONFIGURATIONS:
                raise CheckFailure(f"component uses unexpected configuration: {configuration}")
            if COORDINATE_RE.fullmatch(coordinate) is None:
                raise CheckFailure(
                    f"malformed dependency coordinate at line {line_number}: {coordinate}"
                )
            components.append((configuration, coordinate))
            continue
        raise CheckFailure(f"malformed dependency manifest line {line_number}")

    if configurations != EXPECTED_CONFIGURATIONS:
        missing = sorted(EXPECTED_CONFIGURATIONS - configurations)
        raise CheckFailure("dependency manifest is missing configurations: " + ", ".join(missing))
    component_configurations = {configuration for configuration, _ in components}
    missing_components = sorted(EXPECTED_CONFIGURATIONS - component_configurations)
    if missing_components:
        raise CheckFailure(
            "dependency manifest has no resolved components for: " + ", ".join(missing_components)
        )
    return configurations, components


def check_dependencies(components: list[tuple[str, str]]) -> None:
    forbidden: list[str] = []
    for configuration, coordinate in components:
        group = coordinate.split(":", maxsplit=1)[0]
        if any(
            group == banned or group.startswith(f"{banned}.")
            for banned in FORBIDDEN_DEPENDENCY_GROUPS
        ):
            forbidden.append(f"{configuration}: {coordinate}")
    if forbidden:
        raise CheckFailure("forbidden Google SDK dependencies:\n  " + "\n  ".join(forbidden))


def entry_contains_marker(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes | None:
    tail = b""
    try:
        with archive.open(info, "r") as entry:
            while chunk := entry.read(READ_CHUNK_BYTES):
                searchable = tail + chunk
                for marker in FORBIDDEN_PACKAGE_MARKERS:
                    if marker in searchable:
                        return marker
                tail = searchable[-MARKER_OVERLAP_BYTES:]
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise CheckFailure(f"cannot read APK entry {info.filename}: {error}") from error
    return None


def check_apk(path: Path) -> tuple[int, int]:
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as error:
        raise CheckFailure(f"cannot open APK {path}: {error}") from error

    with archive:
        infos = archive.infolist()
        if not infos:
            raise CheckFailure("APK archive is empty")
        names: set[str] = set()
        total_bytes = 0
        for info in infos:
            if info.filename in names:
                raise CheckFailure(f"APK contains a duplicate entry: {info.filename}")
            names.add(info.filename)
            if info.file_size < 0 or info.file_size > MAX_ENTRY_BYTES:
                raise CheckFailure(f"APK entry exceeds scan limit: {info.filename}")
            total_bytes += info.file_size
            if total_bytes > MAX_ARCHIVE_BYTES:
                raise CheckFailure("APK uncompressed size exceeds scan limit")

            normalized_name = info.filename.replace("\\", "/").lower().encode("utf-8")
            marker = next(
                (
                    candidate
                    for candidate in FORBIDDEN_ENTRY_NAME_MARKERS
                    if candidate.lower() in normalized_name
                ),
                None,
            )
            if marker is not None:
                raise CheckFailure(
                    f"forbidden Google SDK marker {marker.decode()} in APK entry name {info.filename}"
                )
            if info.is_dir():
                continue
            marker = entry_contains_marker(archive, info)
            if marker is not None:
                raise CheckFailure(
                    f"forbidden Google SDK marker {marker.decode()} in APK entry {info.filename}"
                )
        return len(infos), total_bytes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--dependency-manifest", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        _, components = parse_dependency_manifest(args.dependency_manifest)
        check_dependencies(components)
        entry_count, unpacked_bytes = check_apk(args.apk)
    except CheckFailure as error:
        print(f"Android Google SDK-free check failed: {error}", file=sys.stderr)
        return 1

    print(
        "Android Google SDK-free check passed: "
        f"{len(EXPECTED_CONFIGURATIONS)} runtime configurations, "
        f"{len(components)} resolved components, {entry_count} APK entries, "
        f"{unpacked_bytes} uncompressed bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
