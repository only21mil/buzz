#!/usr/bin/env python3
"""Fail closed on unsafe mobile/pubspec.yaml manifest content.

A raw merge once inserted duplicate ``image`` keys and a
``google_mlkit_selfie_segmentation`` dependency into mobile/pubspec.yaml
without leaving a conflict marker, and YAML parsers resolve duplicate keys
with silent last-wins semantics. This guard runs before dependency
resolution and rejects:

- duplicate mapping keys at the same level (the silent-merge hazard),
- tab indentation (invalid YAML that some parsers accept),
- direct ML Kit / Firebase dependencies (the app stays Google-free and
  keeps the reviewed ZXing substitution).

Standard library only, so CI and hooks run it with no extra installs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


BANNED_DEPENDENCY_SUBSTRINGS = ("mlkit", "firebase")
DEPENDENCY_SECTIONS = ("dependencies", "dev_dependencies")
MAX_MANIFEST_BYTES = 1024 * 1024


class CheckFailure(RuntimeError):
    """A deterministic policy or input validation failure."""


def strip_comment(content: str) -> str:
    """Remove a trailing ``#`` comment, ignoring ``#`` inside quotes."""
    quote: str | None = None
    index = 0
    while index < len(content):
        char = content[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "#":
            return content[:index]
        index += 1
    return content


def check_pubspec(path: Path) -> int:
    """Validate the manifest. Returns the dependency count on success."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CheckFailure(f"cannot read pubspec {path}: {error}") from error
    if len(raw) > MAX_MANIFEST_BYTES:
        raise CheckFailure(f"pubspec {path} exceeds scan limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CheckFailure(f"pubspec {path} is not valid UTF-8: {error}") from error

    # Stack of (indent, keys) for the open mapping at each level.
    stack: list[tuple[int, set[str]]] = [(-1, set())]
    section: str | None = None
    section_indent = -1
    dependency_count = 0

    for line_number, line in enumerate(text.splitlines(), start=1):
        if "\t" in line:
            raise CheckFailure(f"{path}:{line_number}: tab indentation is not valid YAML")
        content = strip_comment(line)
        if not content.strip():
            continue
        indent = len(content) - len(content.lstrip(" "))
        stripped = content.strip()

        # A mapping key at column C closes every open block at column >= C.
        # A sequence item's inline map sits strictly between the dash column
        # and its content, so sibling items (``- asset:`` under ``fonts:``)
        # each get a fresh scope instead of reading as duplicates, while a
        # continuation key at the content column (``style:`` after
        # ``- asset:``) still lands in the same item.
        scope_indent = indent
        if stripped.startswith("- ") or stripped == "-":
            stripped = stripped[1:].lstrip()
            scope_indent = indent + 1
            while stack and stack[-1][0] >= scope_indent:
                stack.pop()
            stack.append((scope_indent, set()))
            if not stripped or ":" not in stripped:
                continue
        else:
            while stack and stack[-1][0] >= scope_indent:
                stack.pop()

        if ":" not in stripped:
            continue
        key, _, _ = stripped.partition(":")
        key = key.strip()
        if not key or key.startswith("-") or " " in key.strip("'\""):
            continue
        key = key.strip("'\"")
        if not key:
            continue

        if not stack:
            raise CheckFailure(f"{path}:{line_number}: mapping is nested inconsistently")
        keys = stack[-1][1]
        if key in keys:
            raise CheckFailure(f"{path}:{line_number}: duplicate key {key!r}")
        keys.add(key)
        # A nested mapping opens when the value after the colon is empty.
        _, _, value = stripped.partition(":")
        if not value.strip():
            stack.append((scope_indent, set()))

        if indent <= section_indent:
            section = None
            section_indent = -1
        if scope_indent == 0:
            section = key
            section_indent = 0

        if section in DEPENDENCY_SECTIONS and indent == 2:
            dependency_count += 1
            lowered = key.lower()
            banned = next(
                (marker for marker in BANNED_DEPENDENCY_SUBSTRINGS if marker in lowered),
                None,
            )
            if banned is not None:
                raise CheckFailure(
                    f"{path}:{line_number}: prohibited {banned} dependency {key!r}; "
                    "keep the reviewed Google-free substitution"
                )

    if dependency_count == 0:
        raise CheckFailure(f"{path} declares no dependencies; refusing an empty manifest")
    return dependency_count


def parse_args() -> argparse.Namespace:
    default = Path(__file__).resolve().parent.parent / "mobile" / "pubspec.yaml"
    parser = argparse.ArgumentParser()
    parser.add_argument("--pubspec", type=Path, default=default)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        dependency_count = check_pubspec(args.pubspec)
    except CheckFailure as error:
        print(f"Pubspec manifest check failed: {error}", file=sys.stderr)
        return 1
    print(f"Pubspec manifest check passed: {dependency_count} direct dependencies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
