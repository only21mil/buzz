#!/usr/bin/env python3
"""Verify the saved-prompt patch in a temporary copy; never install or restart."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


PACKAGE = Path(__file__).resolve().parent
SEATS = (
    "sats-codex", "sats-codex-2", "sats-codex-r", "sats-dsv4f",
    "sats-glm", "sats-glm52", "sats-hermes", "sats-claude-code",
    "sats-claude-code-r", "alpheus-codex", "alpheus-claude-code",
    "archimedes-codex", "archimedes-hermes",
)
ACTIVE = SEATS[:7] + SEATS[9:11]
LAUNCHER = "scripts/launch_buzz_agent.sh"
EXPECTED = {f"config/{seat}-system.md" for seat in SEATS} | {LAUNCHER}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def verify(source):
    manifest = json.loads((PACKAGE / "manifest.json").read_text())
    patch = PACKAGE / "saved-prompts.patch"
    rows = manifest["files"]
    check(len(rows) == len(EXPECTED), "Wrong file count")
    check({row["path"] for row in rows} == EXPECTED, "Unexpected source paths")
    check(digest(patch) == manifest["patch_sha256"], "Patch digest mismatch")
    with tempfile.TemporaryDirectory(prefix="buzz-prompt-check-") as temporary:
        staged = Path(temporary)
        for row in rows:
            path = source / row["path"]
            check(path.is_file() and not path.is_symlink(), f"Invalid source: {path}")
            check(digest(path) == row["before_sha256"], f"Source drift: {path}")
            destination = staged / row["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
        subprocess.run(["git", "apply", "--check", str(patch)], cwd=staged, check=True)
        subprocess.run(["git", "apply", str(patch)], cwd=staged, check=True)
        for row in rows:
            check(digest(staged / row["path"]) == row["after_sha256"],
                  f"Candidate mismatch: {row['path']}")
            check(digest(source / row["path"]) == row["before_sha256"],
                  f"Source changed during verification: {row['path']}")
        original = (source / LAUNCHER).read_text()
        candidate = (staged / LAUNCHER).read_text()
        pattern = r"system_prompt_sha256=[0-9a-f]{64}"
        check(re.sub(pattern, "PIN", original) == re.sub(pattern, "PIN", candidate),
              "Launcher change beyond pins")
        for seat in ACTIVE:
            path = f"config/{seat}-system.md"
            check(f"system_prompt={manifest['source_owner']}/{path}\n"
                  f"    system_prompt_sha256={digest(staged / path)}" in candidate,
                  f"Missing matching pin: {seat}")
        check("fail 'Sats Claude Code and Sats Claude Code-R are retired" in candidate,
              "Retired-seat rejection missing")
        subprocess.run(["bash", "-n", str(staged / LAUNCHER)], check=True)
    print("PASS: fourteen exact sources, patch, nine pins, preserved launcher, shell syntax; no installation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.source_root.resolve(strict=True))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FAIL: {error}\n")
