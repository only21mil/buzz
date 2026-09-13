#!/usr/bin/env bash
# Contract for scripts/check-branch-skew.sh (CD-12): the hook must resolve the
# canonical main from configured remotes instead of assuming origin/main, and
# must still block on overlapping skew when the canonical history lives on a
# fallback remote. Uses local file-path remotes only, so it runs infra-free.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
hook="$repo_root/scripts/check-branch-skew.sh"

fail() {
  echo "branch-skew contract failed: $*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git_commit() {
  git -c user.email=contract@test -c user.name=contract commit -qm "$1"
}

# Fresh upstream repo with a main branch.
git init -qb main "$work/upstream"
(
  cd "$work/upstream"
  echo base >a.txt
  echo base >b.txt
  git add .
  git_commit "base"
)

# Overlapping skew: feature and main both touch a.txt.
git -c protocol.file.allow=always clone -qb main "$work/upstream" "$work/overlap" 2>/dev/null
(
  cd "$work/overlap"
  git checkout -qb feature
  echo feature >a.txt
  git add a.txt
  git_commit "feature touches a"
)
(
  cd "$work/upstream"
  echo main >a.txt
  git add a.txt
  git_commit "main touches a"
)
(cd "$work/overlap" && bash "$hook" >/dev/null 2>&1) \
  && fail "overlapping skew on origin/main must block the push"
echo "overlap blocks: ok"

# Disjoint skew: main touches b.txt only, feature is clean relative to it.
git -c protocol.file.allow=always clone -qb main "$work/upstream" "$work/disjoint" 2>/dev/null
(
  cd "$work/disjoint"
  git checkout -qb feature
  echo feature >c.txt
  git add c.txt
  git_commit "feature adds c"
)
(cd "$work/disjoint" && bash "$hook" >/dev/null 2>&1) \
  || fail "disjoint skew must not block the push"
echo "disjoint passes: ok"

# CD-12 regression: no origin remote; canonical history lives on buzz.
# The old script checked origin/main only and exited 0 here without checking.
git -c protocol.file.allow=always clone -qb main "$work/upstream" "$work/fallback" 2>/dev/null
(
  cd "$work/fallback"
  git checkout -qb feature
  echo feature >a.txt
  git add a.txt
  git_commit "feature touches a"
  git remote remove origin
  git remote add buzz "$work/upstream"
)
(
  cd "$work/upstream"
  echo main-again >a.txt
  git add a.txt
  git_commit "main touches a again"
)
(cd "$work/fallback" && bash "$hook" >/dev/null 2>&1) \
  && fail "overlapping skew on the buzz fallback remote must block the push"
echo "fallback remote blocks: ok"

# No remotes at all: nothing to compare against, so the hook skips loudly.
git init -qb feature "$work/noremote"
(
  cd "$work/noremote"
  echo lone >a.txt
  git add .
  git_commit "lone"
)
output=$(cd "$work/noremote" && bash "$hook" 2>&1) \
  || fail "a repo with no remotes must exit 0"
grep -Fq "skipping skew check" <<<"$output" \
  || fail "skipping the check must say so on stderr"
echo "no-remote skips loudly: ok"

echo "branch-skew contract passed"
