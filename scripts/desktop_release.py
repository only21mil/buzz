#!/usr/bin/env python3
"""Generate and validate immutable desktop release candidates."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(os.environ.get("DESKTOP_RELEASE_ROOT", Path(__file__).resolve().parent.parent))
CHANGELOG = ROOT / "CHANGELOG.md"
METADATA = ROOT / ".release" / "desktop-candidate.json"
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
STABLE_TAG = re.compile(r"desktop-v([0-9]+)\.([0-9]+)\.([0-9]+)$")
DESKTOP_PATHS = (
    "desktop/",
    "crates/buzz-core/",
    "crates/buzz-persona/",
    "crates/buzz-sdk/",
    "crates/buzz-agent/",
    "crates/buzz-media/",
)
CANDIDATE_FILES = {
    ".release/desktop-candidate.json",
    "CHANGELOG.md",
    "desktop/package.json",
    "desktop/src-tauri/tauri.conf.json",
    "desktop/src-tauri/Cargo.toml",
    "desktop/src-tauri/Cargo.lock",
    "pnpm-lock.yaml",
}
REQUIRED_CANDIDATE_FILES = {
    ".release/desktop-candidate.json",
    "CHANGELOG.md",
    "desktop/package.json",
    "desktop/src-tauri/tauri.conf.json",
    "desktop/src-tauri/Cargo.toml",
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def tree_text(commit: str, path: str) -> str:
    try:
        return subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=ROOT, text=True)
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"{commit} has no {path}") from error


def manifest_versions(commit: str) -> dict[str, str]:
    versions = {
        "desktop/package.json": json.loads(tree_text(commit, "desktop/package.json"))["version"],
        "desktop/src-tauri/tauri.conf.json": json.loads(tree_text(commit, "desktop/src-tauri/tauri.conf.json"))["version"],
    }
    cargo = re.search(r'(?m)^version = "([^"]+)"', tree_text(commit, "desktop/src-tauri/Cargo.toml"))
    versions["desktop/src-tauri/Cargo.toml"] = cargo.group(1) if cargo else ""
    return versions


def candidate_identity(commit: str) -> dict[str, str] | None:
    # The identity is the exact metadata blob plus the three manifest version
    # fields. Manifest bytes outside the version field change in ordinary
    # dependency work and do not make a commit a release candidate. A commit
    # without candidate metadata has no identity.
    entry = git("ls-tree", commit, "--", ".release/desktop-candidate.json")
    if not entry:
        return None
    identity = {"metadata_blob": entry.split()[2]}
    identity.update(manifest_versions(commit))
    return identity


def commit_list(range_spec: str, paths: tuple[str, ...] | None = None) -> list[dict[str, str]]:
    args = ["log", range_spec, "--no-merges", "--format=%H%x00%s"]
    if paths:
        args += ["--", *paths]
    out = git(*args)
    if not out:
        return []
    return [dict(zip(("sha", "subject"), line.split("\0", 1))) for line in out.splitlines()]


def gh_json(endpoint: str) -> object:
    try:
        return json.loads(subprocess.check_output(
            ["gh", "api", endpoint], cwd=ROOT, text=True
        ))
    except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot verify prior desktop release via GitHub: {error}") from error


def stable_tags() -> list[tuple[tuple[int, int, int], str, str]]:
    tags: list[tuple[tuple[int, int, int], str, str]] = []
    aliases: dict[tuple[int, int, int], list[tuple[str, str]]] = {}
    for tag in git("tag", "--list", "desktop-v*").splitlines():
        match = STABLE_TAG.fullmatch(tag)
        if not match:
            continue
        version = tuple(map(int, match.groups()))
        sha = git("rev-list", "-n", "1", tag)
        aliases.setdefault(version, []).append((tag, sha))
    for version, refs in aliases.items():
        if len(refs) != 1:
            detail = ", ".join(f"{tag}@{sha}" for tag, sha in refs)
            raise SystemExit(f"ambiguous desktop release version {version}: {detail}")
        tag, sha = refs[0]
        tags.append((version, tag, sha))
    return tags


def previous_release(
    version: str, repo: str, *, allow_target_sha: str | None = None
) -> dict[str, str] | None:
    target = tuple(map(int, version.split("-", 1)[0].split(".")))
    target_tag = f"desktop-v{version}"
    target_refs = git("tag", "--list", target_tag).splitlines()
    target_ref = (
        (target_tag, git("rev-list", "-n", "1", target_tag))
        if target_refs
        else None
    )
    target_collision = target_ref is not None and (
        allow_target_sha is None or target_ref[1] != allow_target_sha
    )
    tags = stable_tags()
    newer = [item for item in tags if item[0] > target]
    equal = [item for item in tags if item[0] == target]
    allowed_stable_retry = (
        "-" not in version
        and len(equal) == 1
        and allow_target_sha is not None
        and equal[0][1] == target_tag
        and equal[0][2] == allow_target_sha
    )
    if target_collision or newer or (equal and not allowed_stable_retry):
        blocked = [item[1] for item in newer + equal]
        if target_collision and target_tag not in blocked:
            blocked.append(target_tag)
        detail = ", ".join(blocked)
        raise SystemExit(f"desktop release version must increase beyond existing tags: {detail}")
    eligible = [item for item in tags if item[0] < target]
    if not eligible:
        return None
    prior_version, tag, candidate_sha = max(eligible)
    try:
        metadata = json.loads(git("show", f"{tag}:.release/desktop-candidate.json"))
    except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
        raise SystemExit(f"prior release {tag} has invalid candidate metadata") from error
    expected = {
        "version": ".".join(map(str, prior_version)),
        "tag": tag,
    }
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise SystemExit(f"prior release {tag} metadata does not match its tag")
    base_sha = metadata.get("base_sha")
    if not isinstance(base_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise SystemExit(f"prior release {tag} has invalid base_sha")
    pulls = gh_json(f"repos/{repo}/commits/{candidate_sha}/pulls")
    matches = [pr for pr in pulls if pr.get("merged_at") and (
        pr.get("head", {}).get("sha") == candidate_sha
        or pr.get("merge_commit_sha") == candidate_sha
    )]
    if len(matches) != 1 or not matches[0].get("merge_commit_sha"):
        raise SystemExit(f"prior release {tag} does not identify exactly one merged release PR")
    return {
        "tag": tag,
        "candidate_sha": candidate_sha,
        "base_sha": base_sha,
        "merge_sha": matches[0]["merge_commit_sha"],
    }


def bullet(commit: dict[str, str], repo: str) -> str:
    sha, subject = commit["sha"], commit["subject"]
    short = sha[:12]
    pr_match = re.search(r" \(#([0-9]+)\)$", subject)
    if pr_match:
        pr = pr_match.group(1)
        subject = subject[: pr_match.start()]
        return f"- {subject} ([#{pr}](https://github.com/{repo}/pull/{pr})) ([`{sha}`](https://github.com/{repo}/commit/{sha}))"
    return f"- {subject} ([`{sha}`](https://github.com/{repo}/commit/{sha}))"


def expected(base_sha: str, previous_base: str, previous_merge: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    # Immutable candidate tags may live on side history after squash merge. The
    # prior candidate metadata is the ledger boundary; exclude only its known
    # squash commit so unrelated commits around that merge remain accounted for.
    range_spec = f"{previous_base}..{base_sha}" if previous_base else base_sha
    all_commits = [c for c in commit_list(range_spec) if c["sha"] != previous_merge]
    relevant_shas = {c["sha"] for c in commit_list(range_spec, DESKTOP_PATHS)} - {previous_merge}
    relevant = [c for c in all_commits if c["sha"] in relevant_shas]
    other = [c for c in all_commits if c["sha"] not in relevant_shas]
    return relevant, other


def render(version: str, base_sha: str, previous: dict[str, str] | None, repo: str) -> tuple[str, list[str]]:
    relevant, other = expected(
        base_sha, previous["base_sha"] if previous else "", previous["merge_sha"] if previous else ""
    )
    lines = [f"## v{version}", "", "### Desktop and shared changes", ""]
    lines += [bullet(c, repo) for c in relevant] or ["- None"]
    lines += ["", "### Other repository changes", ""]
    lines += [bullet(c, repo) for c in other] or ["- None"]
    compare_start = previous["tag"] if previous else git("rev-list", "--max-parents=0", base_sha).splitlines()[0]
    lines += ["", f"[Compare {compare_start}...desktop-v{version}](https://github.com/{repo}/compare/{compare_start}...desktop-v{version})"]
    return "\n".join(lines) + "\n", [c["sha"] for c in relevant + other]


def generate(args: argparse.Namespace) -> None:
    if not SEMVER.fullmatch(args.version):
        raise SystemExit(f"invalid semver: {args.version}")
    base_sha = git("rev-parse", args.base)
    repo = args.repo or re.sub(r".*github\.com[:/]", "", git("remote", "get-url", "origin")).removesuffix(".git")
    previous = previous_release(args.version, repo)
    block, commits = render(args.version, base_sha, previous, repo)
    old = CHANGELOG.read_text() if CHANGELOG.exists() else "# Changelog\n"
    if not old.startswith("# Changelog"):
        raise SystemExit("CHANGELOG.md must begin with '# Changelog'")
    remainder = old.split("\n", 1)[1].lstrip("\n") if "\n" in old else ""
    CHANGELOG.write_text(f"# Changelog\n\n{block}\n{remainder}")
    METADATA.parent.mkdir(parents=True, exist_ok=True)
    METADATA.write_text(json.dumps({
        "schema": 2,
        "version": args.version,
        "base_sha": base_sha,
        "previous_tag": previous["tag"] if previous else None,
        "previous_base_sha": previous["base_sha"] if previous else None,
        "previous_merge_sha": previous["merge_sha"] if previous else None,
        "tag": f"desktop-v{args.version}",
        "commit_count": len(commits),
    }, indent=2) + "\n")


def validate(args: argparse.Namespace) -> None:
    data = json.loads(METADATA.read_text())
    version = args.version or data["version"]
    if data != {**data, "version": version}:
        raise SystemExit("candidate version does not match metadata")
    if data["tag"] != f"desktop-v{version}":
        raise SystemExit("candidate tag does not match version")
    candidate = git("rev-parse", args.candidate)
    parents = git("show", "-s", "--format=%P", candidate).split()
    if len(parents) != 1 or parents[0] != data["base_sha"]:
        raise SystemExit("candidate must be one commit directly above recorded base_sha")
    changed = set(git("diff-tree", "--no-commit-id", "--name-only", "-r", candidate).splitlines())
    unexpected = changed - CANDIDATE_FILES
    missing = REQUIRED_CANDIDATE_FILES - changed
    if unexpected or missing:
        detail = []
        if unexpected:
            detail.append(f"unexpected files: {', '.join(sorted(unexpected))}")
        if missing:
            detail.append(f"missing required files: {', '.join(sorted(missing))}")
        raise SystemExit("candidate is not version-only (" + "; ".join(detail) + ")")
    repo = args.repo or "block/buzz"
    previous = previous_release(version, repo, allow_target_sha=candidate)
    recorded_previous = {
        "tag": data.get("previous_tag"),
        "base_sha": data.get("previous_base_sha"),
        "merge_sha": data.get("previous_merge_sha"),
    } if data.get("previous_tag") else None
    expected_previous = {key: previous[key] for key in ("tag", "base_sha", "merge_sha")} if previous else None
    if recorded_previous != expected_previous:
        raise SystemExit("recorded previous release ledger does not match immutable prior release")
    expected_block, shas = render(version, data["base_sha"], previous, repo)
    text = CHANGELOG.read_text()
    blocks = re.findall(rf"(?ms)^## v{re.escape(version)}\n.*?(?=^## v|\Z)", text)
    if len(blocks) != 1:
        raise SystemExit(f"expected exactly one changelog block for v{version}")
    if blocks[0].rstrip() != expected_block.rstrip():
        raise SystemExit("changelog block is not deterministic for recorded candidate base")
    found = re.findall(r"\[`([0-9a-f]{40})`\]", blocks[0])
    if len(found) != len(set(found)) or set(found) != set(shas) or len(found) != data["commit_count"]:
        raise SystemExit("changelog does not account for every expected non-merge commit exactly once")
    manifests = {
        ROOT / "desktop/package.json": json.loads((ROOT / "desktop/package.json").read_text())["version"],
        ROOT / "desktop/src-tauri/tauri.conf.json": json.loads((ROOT / "desktop/src-tauri/tauri.conf.json").read_text())["version"],
    }
    cargo = re.search(r'(?m)^version = "([^"]+)"', (ROOT / "desktop/src-tauri/Cargo.toml").read_text())
    manifests[ROOT / "desktop/src-tauri/Cargo.toml"] = cargo.group(1) if cargo else ""
    bad = [str(path.relative_to(ROOT)) for path, value in manifests.items() if value != version]
    if bad:
        raise SystemExit(f"version mismatch in: {', '.join(bad)}")
    author = git("show", "-s", "--format=%an <%ae>", candidate)
    body = git("show", "-s", "--format=%B", candidate)
    if author != "Wes <wesbillman@users.noreply.github.com>":
        raise SystemExit(f"unexpected candidate author: {author}")
    if "Signed-off-by: Wes <wesbillman@users.noreply.github.com>" not in body:
        raise SystemExit("candidate is missing Wes Signed-off-by trailer")
    if not re.search(r"(?m)^Co-authored-by: .+ <.+>$", body):
        raise SystemExit("candidate is missing automation Co-authored-by trailer")
    print(f"validated immutable desktop candidate {candidate} for desktop-v{version}")


def verify_main(args: argparse.Namespace) -> None:
    """Verify the desktop candidate carried by an exact commit on main.

    Unchanged mode: the candidate identity is byte-equal to the first parent
    and the tree is self-consistent. Release mode: the identity changed, so the
    commit must be the merge of one internal version-bump/<version> pull
    request, carry that pull request's candidate files byte-for-byte, and the
    pull request head must pass the immutable candidate validation.
    """
    commit = git("rev-parse", f"{args.commit}^{{commit}}")
    parents = git("show", "-s", "--format=%P", commit).split()
    if not parents:
        raise SystemExit(f"{commit} has no parent to compare the desktop candidate against")
    parent = parents[0]
    metadata = json.loads(tree_text(commit, ".release/desktop-candidate.json"))
    version = metadata.get("version")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise SystemExit(f"{commit} records an invalid desktop candidate version: {version!r}")
    if metadata.get("tag") != f"desktop-v{version}":
        raise SystemExit(f"{commit} records a candidate tag that does not match desktop-v{version}")
    current = candidate_identity(commit)
    assert current is not None
    bad = [path for path, value in current.items() if path != "metadata_blob" and value != version]
    if bad:
        raise SystemExit(f"{commit} version mismatch in: {', '.join(bad)}")
    blocks = re.findall(rf"(?ms)^## v{re.escape(version)}\n.*?(?=^## v|\Z)", tree_text(commit, "CHANGELOG.md"))
    if len(blocks) != 1:
        raise SystemExit(f"{commit} must carry exactly one changelog block for v{version}")
    previous = candidate_identity(parent)
    if current == previous:
        print(
            f"desktop candidate unchanged on main: {commit} matches parent {parent} "
            f"for desktop-v{version} (metadata blob {current['metadata_blob']})"
        )
        return

    repo = args.repo or "block/buzz"
    pulls = gh_json(f"repos/{repo}/commits/{commit}/pulls")
    matches = [pr for pr in pulls if pr.get("merged_at") and pr.get("merge_commit_sha") == commit]
    if len(matches) != 1:
        raise SystemExit(f"desktop candidate changed at {commit}, which is not the merge of exactly one pull request")
    pr = matches[0]
    head_sha = pr.get("head", {}).get("sha", "")
    head_ref = pr.get("head", {}).get("ref", "")
    head_repo = pr.get("head", {}).get("repo", {}).get("full_name", "")
    number = pr.get("number")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise SystemExit(f"pull request #{number} has no resolvable head commit")
    if head_ref != f"version-bump/{version}":
        raise SystemExit(
            f"desktop candidate changed at {commit} outside a version-bump/{version} release "
            f"(pull request #{number} from {head_ref or '?'})"
        )
    if head_repo != repo:
        raise SystemExit(f"desktop release pull request #{number} must be internal, not from {head_repo or '?'}")
    if subprocess.run(["git", "cat-file", "-e", f"{head_sha}^{{commit}}"], cwd=ROOT).returncode != 0:
        git("fetch", "origin", head_sha, "--no-tags")
    differs = git("diff", "--name-only", head_sha, commit, "--", *sorted(CANDIDATE_FILES))
    if differs:
        raise SystemExit(
            f"{commit} does not carry reviewed candidate {head_sha} byte-for-byte: "
            + ", ".join(differs.splitlines())
        )
    worktree = tempfile.mkdtemp(prefix="desktop-candidate.")
    try:
        git("worktree", "add", "--detach", worktree, head_sha)
        result = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "validate",
             "--candidate", head_sha, "--version", version, "--repo", repo],
            cwd=worktree, env={**os.environ, "DESKTOP_RELEASE_ROOT": worktree},
        )
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", worktree], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(worktree, ignore_errors=True)
    if result.returncode != 0:
        raise SystemExit(f"immutable candidate {head_sha} carried by {commit} failed validation")
    print(
        f"desktop candidate released on main: {commit} carries validated immutable candidate "
        f"{head_sha} for desktop-v{version} (pull request #{number})"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("version")
    gen.add_argument("--base", required=True)
    gen.add_argument("--repo")
    val = sub.add_parser("validate")
    val.add_argument("--candidate", default="HEAD")
    val.add_argument("--version")
    val.add_argument("--repo")
    main_check = sub.add_parser("verify-main")
    main_check.add_argument("--commit", default="HEAD")
    main_check.add_argument("--repo")
    args = parser.parse_args()
    {"generate": generate, "validate": validate, "verify-main": verify_main}[args.command](args)


if __name__ == "__main__":
    main()
