#!/usr/bin/env python3
"""Rust attribute lexer adapted from block/buzz bd73490418266f267d9bb3bdf13e64582adc8e80."""

from __future__ import annotations

import re

IGNORE_ATTRIBUTE = re.compile(r"#\s*\[\s*ignore\s*=")
BARE_IGNORE_ATTRIBUTE = re.compile(r"#\s*\[\s*ignore\s*\]")
FUNCTION = re.compile(r"\b(?:async\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
MODULE = re.compile(r"\bmod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{")
RAW_STRING = re.compile(r'(?:b?r)(?P<hashes>#{0,255})"')
CHAR_LITERAL = re.compile(r"(?:b)?'(?:\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|.)|[^\\'\n])'")

def sanitize_rust(source: str) -> str:
    """Blank comments and literals while preserving byte offsets and braces."""
    chars = list(source)
    index = 0
    length = len(source)
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end == -1 else end
            for offset in range(index, end):
                chars[offset] = " "
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            for offset in range(start, index):
                if chars[offset] != "\n":
                    chars[offset] = " "
            continue

        character = CHAR_LITERAL.match(source, index)
        if character:
            start = index
            index = character.end()
            for offset in range(start, index):
                chars[offset] = " "
            continue

        raw = RAW_STRING.match(source, index)
        if raw:
            start = index
            terminator = '"' + raw.group("hashes")
            index = raw.end()
            end = source.find(terminator, index)
            index = length if end == -1 else end + len(terminator)
            for offset in range(start, index):
                if chars[offset] != "\n":
                    chars[offset] = " "
            continue

        quote_start = index
        if source.startswith('b"', index):
            index += 1
        if source[index] == '"':
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            for offset in range(quote_start, min(index, length)):
                if chars[offset] != "\n":
                    chars[offset] = " "
            continue
        index += 1
    return "".join(chars)


def parse_rust_string_literal(source: str, start: int) -> tuple[str, int] | None:
    """Parse an ordinary or raw Rust string literal at or after start."""
    index = start
    while index < len(source) and source[index].isspace():
        index += 1

    raw = RAW_STRING.match(source, index)
    if raw:
        content_start = raw.end()
        terminator = '"' + raw.group("hashes")
        content_end = source.find(terminator, content_start)
        if content_end == -1:
            return None
        return source[content_start:content_end], content_end + len(terminator)

    if index >= len(source) or source[index] != '"':
        return None
    index += 1
    content = []
    while index < len(source):
        if source[index] == "\\":
            if index + 1 >= len(source):
                return None
            content.append(source[index + 1])
            index += 2
        elif source[index] == '"':
            return "".join(content), index + 1
        else:
            content.append(source[index])
            index += 1
    return None


def ignore_attributes(source: str, sanitized: str) -> list[tuple[int, int, str]]:
    """Return real ignore attributes and reasons, excluding comments."""
    attributes = []
    for match in IGNORE_ATTRIBUTE.finditer(sanitized):
        parsed = parse_rust_string_literal(source, match.end())
        if parsed is None:
            continue
        reason, literal_end = parsed
        attribute_end = literal_end
        while attribute_end < len(source) and source[attribute_end].isspace():
            attribute_end += 1
        if attribute_end >= len(source) or source[attribute_end] != "]":
            continue
        attributes.append((match.start(), attribute_end + 1, reason))
    return attributes


def module_ranges(source: str) -> list[tuple[int, int, str]]:
    sanitized = sanitize_rust(source)
    brace_pairs: dict[int, int] = {}
    stack: list[int] = []
    for index, char in enumerate(sanitized):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            brace_pairs[stack.pop()] = index

    ranges = []
    for match in MODULE.finditer(sanitized):
        open_brace = sanitized.find("{", match.start(), match.end())
        close_brace = brace_pairs.get(open_brace)
        if close_brace is not None:
            ranges.append((open_brace, close_brace, match.group("name")))
    return ranges


