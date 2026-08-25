#!/usr/bin/env python3
"""Freeze a dirty Git candidate into a Tier 2 v3 source manifest."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


MANIFEST_KIND = "git-source-manifest-v1"
GIT_MODES = {"100644", "100755", "120000"}
OID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA40_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
INVISIBLE = frozenset(
    list(range(0x200B, 0x2010))
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
    + [0x00AD, 0x061C, 0x180E, 0xFEFF]
)


class FreezeError(RuntimeError):
    """A fail-closed freeze or verification error."""


def git(repo: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        {
            "GIT_ALLOW_PROTOCOL": "none",
            "GIT_CONFIG_COUNT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    command = [
        "git",
        "--no-optional-locks",
        "--no-replace-objects",
        "-C",
        str(repo),
        "-c",
        "core.quotepath=off",
        *args,
    ]
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=120,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FreezeError(f"git {' '.join(args)} could not run: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise FreezeError(f"git {' '.join(args)} exited {result.returncode}: {detail}")
    return result.stdout


def resolve_repo(value: str) -> Path:
    repo = Path(value).resolve()
    if not repo.is_dir():
        raise FreezeError(f"repo root is not a directory: {repo}")
    top = Path(git(repo, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if top != repo:
        raise FreezeError(f"repo must name the worktree root: {repo} (found {top})")
    return repo


def resolve_oid(repo: Path, ref: str) -> str:
    oid = git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()
    if not OID_RE.fullmatch(oid):
        raise FreezeError(f"ref did not resolve to a full Git object id: {ref}")
    return oid


def checked_path(raw: bytes) -> str:
    try:
        path = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise FreezeError("git reported a non-UTF-8 path") from exc
    if not path or path.startswith("/") or "\\" in path or path != path.strip():
        raise FreezeError(f"unsafe repository path: {path!r}")
    for char in path:
        if ord(char) < 0x20 or ord(char) == 0x7F or ord(char) in INVISIBLE:
            raise FreezeError(f"unsafe control or invisible character in path: {path!r}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} or part.casefold() == ".git" for part in parts):
        raise FreezeError(f"unsafe repository path: {path!r}")
    if any(part != part.strip() for part in parts):
        raise FreezeError(f"unsafe repository path whitespace: {path!r}")
    return path


def split_nul(data: bytes) -> list[bytes]:
    parts = data.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    return parts


def inventory(repo: Path) -> list[dict[str, object]]:
    entries: dict[str, dict[str, object]] = {}
    for record in split_nul(git(repo, "ls-files", "-s", "-z")):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            raw_mode, raw_oid, raw_stage = metadata.split(b" ")
        except ValueError as exc:
            raise FreezeError("git ls-files -s returned an invalid record") from exc
        mode = raw_mode.decode("ascii", "strict")
        oid = raw_oid.decode("ascii", "strict")
        stage = raw_stage.decode("ascii", "strict")
        path = checked_path(raw_path)
        if stage != "0":
            raise FreezeError(f"unmerged index entry at stage {stage}: {path}")
        if mode == "160000":
            raise FreezeError(f"submodules are not reviewable: {path}")
        if mode not in GIT_MODES or not OID_RE.fullmatch(oid):
            raise FreezeError(f"unsupported index entry {mode} {oid}: {path}")
        if path in entries:
            raise FreezeError(f"duplicate index path: {path}")
        entries[path] = {"path": path, "source": "index", "mode": mode}

    for raw_path in split_nul(
        git(repo, "ls-files", "--others", "--exclude-standard", "-z")
    ):
        path = checked_path(raw_path)
        if path in entries:
            raise FreezeError(f"path is both tracked and untracked: {path}")
        entries[path] = {"path": path, "source": "untracked", "mode": None}

    ordered: list[dict[str, object]] = []
    for path in sorted(entries, key=lambda value: value.encode("utf-8")):
        item = entries[path]
        absolute = repo / path
        try:
            file_stat = absolute.lstat()
        except FileNotFoundError:
            if item["source"] != "index":
                raise FreezeError(f"untracked path disappeared: {path}")
            item.update(
                {"state": "deleted", "size": 0, "sha256": None, "blob": None}
            )
            ordered.append(item)
            continue

        if stat.S_ISLNK(file_stat.st_mode):
            if item["source"] != "index" or item["mode"] != "120000":
                raise FreezeError(f"unreviewable symlink: {path}")
            target = os.readlink(absolute).encode("utf-8", "surrogateescape")
            blob = git(repo, "hash-object", "--stdin", input_bytes=target).decode().strip()
            item.update(
                {
                    "state": "present",
                    "size": len(target),
                    "sha256": hashlib.sha256(target).hexdigest(),
                    "blob": blob,
                }
            )
            ordered.append(item)
            continue
        if not stat.S_ISREG(file_stat.st_mode):
            raise FreezeError(f"candidate path is not a regular file: {path}")

        if item["source"] == "untracked":
            item["mode"] = "100755" if file_stat.st_mode & 0o111 else "100644"
        data_hash = hashlib.sha256()
        size = 0
        file_descriptor = os.open(absolute, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            while chunk := os.read(file_descriptor, 1024 * 1024):
                data_hash.update(chunk)
                size += len(chunk)
        finally:
            os.close(file_descriptor)
        blob = git(repo, "hash-object", "--", path).decode().strip()
        if not OID_RE.fullmatch(blob):
            raise FreezeError(f"git returned an invalid blob id for {path}")
        item.update(
            {
                "state": "present",
                "size": size,
                "sha256": data_hash.hexdigest(),
                "blob": blob,
            }
        )
        ordered.append(item)
    if not ordered:
        raise FreezeError("manifest requires at least one index or untracked entry")
    return ordered


def fingerprint(lines: list[str]) -> str:
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def manifest_bytes(repo: Path, head: str) -> tuple[bytes, dict[str, object]]:
    entries = inventory(repo)
    present = [entry for entry in entries if entry["state"] == "present"]
    dirty_fingerprint = fingerprint(
        [
            f"{entry['state']}\t{entry['source']}\t{entry['mode']}\t"
            f"{entry['sha256'] or '-'}\t{entry['path']}\n"
            for entry in entries
        ]
    )
    tree_fingerprint = fingerprint(
        [
            f"{entry['mode']}\t{entry['blob']}\t{entry['path']}\n"
            for entry in present
        ]
    )
    root_stat = repo.stat()
    object_format = git(repo, "rev-parse", "--show-object-format").decode().strip()
    if object_format not in {"sha1", "sha256"}:
        raise FreezeError(f"unsupported Git object format: {object_format}")
    header = {
        "manifest": MANIFEST_KIND,
        "root": str(repo),
        "root_identity": f"{root_stat.st_dev}:{root_stat.st_ino}",
        "base_head": head,
        "object_format": object_format,
        "entry_count": len(entries),
        "dirty_fingerprint": dirty_fingerprint,
        "tree_fingerprint": tree_fingerprint,
    }
    lines = [header, *entries]
    payload = b"".join(
        (json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for line in lines
    )
    return payload, header


def write_private(path: Path, payload: bytes) -> None:
    if not path.parent.is_dir():
        raise FreezeError(f"manifest parent does not exist: {path.parent}")
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        raise FreezeError(f"manifest target is not a regular file: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def first_parent_summary(repo: Path, base: str, head: str) -> dict[str, object]:
    ancestry = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", base, head],
        check=False,
        capture_output=True,
    )
    if ancestry.returncode != 0:
        raise FreezeError(f"base is not an ancestor of HEAD: {base}")
    commits = [
        value
        for value in git(repo, "rev-list", "--first-parent", f"{base}..{head}")
        .decode()
        .splitlines()
        if value
    ]
    merge_count = 0
    merged_tips: list[str] = []
    for commit in commits:
        parents = git(repo, "show", "-s", "--format=%P", commit).decode().split()
        if len(parents) > 1:
            merge_count += 1
            merged_tips.extend(parents[1:])
    merged_tips = list(dict.fromkeys(merged_tips))
    return {
        "total": len(commits),
        "merge": merge_count,
        "direct": len(commits) - merge_count,
        "merged_tips": merged_tips,
    }


def name_status_count(repo: Path, base: str, head: str) -> int:
    records = split_nul(git(repo, "diff", "--name-status", "-z", base, head))
    count = 0
    index = 0
    while index < len(records):
        status_code = records[index].decode("ascii", "strict")
        index += 1
        path_count = 2 if status_code.startswith(("R", "C")) else 1
        if index + path_count > len(records):
            raise FreezeError("git diff --name-status returned an invalid record")
        for raw_path in records[index : index + path_count]:
            checked_path(raw_path)
        index += path_count
        count += 1
    return count


def freeze(repo: Path, base_ref: str, manifest_path: Path) -> dict[str, object]:
    requested_manifest = manifest_path.absolute()
    if requested_manifest.is_symlink():
        raise FreezeError(f"manifest path is a symlink: {requested_manifest}")
    real_manifest = requested_manifest.resolve()
    if real_manifest.parent == repo or repo in real_manifest.parents:
        raise FreezeError("manifest must be written outside the reviewed repository")
    head = resolve_oid(repo, "HEAD")
    base = resolve_oid(repo, base_ref)
    summary = first_parent_summary(repo, base, head)
    payload, header = manifest_bytes(repo, head)
    if resolve_oid(repo, "HEAD") != head:
        raise FreezeError("HEAD moved while the candidate was being frozen")
    write_private(real_manifest, payload)
    manifest_sha256 = hashlib.sha256(payload).hexdigest()
    created_utc = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    diffstat = git(repo, "diff", "--stat", "--no-color", base, head).decode(
        "utf-8", "strict"
    )
    return {
        "schema": "tier2-evidence-v3",
        "review_id": "TODO",
        "revision": 1,
        "producer_provider": "gpt",
        "producer_identity": "TODO",
        "purpose": "TODO",
        "created_utc": created_utc,
        "candidate": {"mode": "repo", "root": str(repo), "base_head": head},
        "invariants": ["TODO: replace with exact review invariants."],
        "commands": [],
        "known_limits": ["Complete the evidence skeleton before review authorization."],
        "artifact_fingerprint": manifest_sha256,
        "artifact_target": {
            "type": MANIFEST_KIND,
            "manifest_path": str(real_manifest),
            "manifest_sha256": manifest_sha256,
            "entry_count": header["entry_count"],
            "root": str(repo),
            "root_identity": header["root_identity"],
            "base_head": head,
            "object_format": header["object_format"],
            "dirty_fingerprint": header["dirty_fingerprint"],
            "tree_fingerprint": header["tree_fingerprint"],
        },
        "git_summary": {
            "head": head,
            "base": base,
            "first_parent_total": summary["total"],
            "first_parent_merge": summary["merge"],
            "first_parent_direct": summary["direct"],
            "merged_tips": summary["merged_tips"],
            "diffstat": diffstat,
            "name_status_count": name_status_count(repo, base, head),
        },
    }


def walk_sha40(value: object, location: str = "$") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            found.extend(
                (match.group(0).lower(), f"{location}.<key>")
                for match in SHA40_RE.finditer(str(key))
            )
            found.extend(walk_sha40(child, f"{location}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(walk_sha40(child, f"{location}[{index}]"))
    elif isinstance(value, str):
        found.extend((match.group(0).lower(), location) for match in SHA40_RE.finditer(value))
    return found


def merged_tip_shas(bundle: object) -> set[str]:
    allowed: set[str] = set()
    if isinstance(bundle, dict):
        for key, value in bundle.items():
            normalized = key.replace("-", "_").casefold()
            if normalized in {"merged_tip", "merged_tips", "merged_tip_sha", "merged_tip_shas"}:
                values = value if isinstance(value, list) else [value]
                for candidate in values:
                    if isinstance(candidate, str) and re.fullmatch(r"[0-9a-fA-F]{40}", candidate):
                        allowed.add(candidate.lower())
            else:
                allowed.update(merged_tip_shas(value))
    elif isinstance(bundle, list):
        for value in bundle:
            allowed.update(merged_tip_shas(value))
    return allowed


def verify(repo: Path, base_ref: str, bundle_path: Path) -> None:
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FreezeError(f"bundle is not readable JSON: {bundle_path}: {exc}") from exc
    head = resolve_oid(repo, "HEAD").lower()
    base = resolve_oid(repo, base_ref).lower()
    allowed = {head, base, *merged_tip_shas(bundle)}
    stale = [(sha, location) for sha, location in walk_sha40(bundle) if sha not in allowed]
    if stale:
        lines = ["stale 40-hex SHA values:"]
        lines.extend(f"{sha} at {location}" for sha, location in stale)
        raise FreezeError("\n".join(lines))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", help="absolute or relative Git worktree root")
    parser.add_argument("base", help="base ref for lineage and diff metadata")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--manifest", type=Path, help="output JSONL path outside the repo")
    mode.add_argument("--verify", type=Path, metavar="BUNDLE", help="scan a bundle for stale SHAs")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        repo = resolve_repo(args.repo)
        if args.verify is not None:
            verify(repo, args.base, args.verify)
        else:
            bundle = freeze(repo, args.base, args.manifest)
            json.dump(bundle, sys.stdout, sort_keys=True, indent=2)
            sys.stdout.write("\n")
    except FreezeError as exc:
        print(f"tier2-freeze: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
