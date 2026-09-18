#!/usr/bin/env bash
# Pre-push guard: CI checks the PR merged with main, so local runs on a
# skewed branch can pass while CI fails. Block the push only when
# the canonical main has changed files this branch also touches.
#
# The canonical main is resolved from configured remotes in priority order
# (origin, then the known upstream mirrors buzz, github, upstream). Earlier
# versions assumed origin/main and exited silently when that ref was missing,
# so a checkout whose canonical history lived on another remote skipped the
# check entirely. Every configured candidate is now consulted before the hook
# gives up, and giving up says so on stderr instead of passing quietly.
set -euo pipefail

branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$branch" = "main" ] || [ "$branch" = "HEAD" ]; then
  exit 0
fi

main_ref=""
for remote in origin buzz github upstream; do
  git remote get-url "$remote" >/dev/null 2>&1 || continue
  git fetch --quiet "$remote" main 2>/dev/null || true
  if git rev-parse --verify --quiet "$remote/main" >/dev/null; then
    main_ref="$remote/main"
    break
  fi
done

if [ -z "$main_ref" ]; then
  echo "check-branch-skew: no configured remote has a main ref; skipping skew check." >&2
  exit 0
fi

base=$(git merge-base HEAD "$main_ref")
if [ "$base" = "$(git rev-parse "$main_ref")" ]; then
  exit 0
fi

overlap=$(comm -12 \
  <(git diff --name-only "$base" "$main_ref" -- | sort) \
  <(git diff --name-only "$base" HEAD -- | sort))

if [ -z "$overlap" ]; then
  exit 0
fi

{
  echo "Branch is behind $main_ref, and main changed files this branch also touches:"
  echo "$overlap" | sed 's/^/  /'
  echo "Local checks ran on a tree CI will never test. Run 'git merge $main_ref',"
  echo "resolve, re-run checks, then push."
} >&2
exit 1
