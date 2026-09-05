#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
mode="${2:-publish}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
  echo "usage: $0 <semver> [publish|validate-only]" >&2
  exit 1
}

[[ "$mode" == publish || "$mode" == validate-only ]] || { echo "unknown mode: $mode" >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo "working tree is dirty" >&2; exit 1; }
remote="${RELEASE_REMOTE:-origin}"
repository="${RELEASE_REPOSITORY:-${GITHUB_REPOSITORY:-}}"
if [[ -z "$repository" ]]; then
  remote_url="$(git remote get-url "$remote")"
  case "$remote_url" in
    https://github.com/*) repository="${remote_url#https://github.com/}" ;;
    git@github.com:*) repository="${remote_url#git@github.com:}" ;;
    *) echo "set RELEASE_REPOSITORY=owner/repo for a non-GitHub release remote" >&2; exit 1 ;;
  esac
  repository="${repository%.git}"
fi
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "invalid release repository" >&2; exit 1; }
# Use a dedicated fetched ref; the authoritative relay must not overwrite an
# unrelated upstream origin/main tracking ref.
base_ref=refs/release-preparation/main
git fetch "$remote" "refs/heads/main:$base_ref" --no-tags
git fetch "$remote" 'refs/tags/desktop-v*:refs/tags/desktop-v*'
remote_tags="$(git ls-remote --refs "$remote" 'refs/tags/desktop-v*' | sort)"
local_tags="$(git for-each-ref --format='%(objectname)%09%(refname)' 'refs/tags/desktop-v*' | sort)"
[[ "$local_tags" == "$remote_tags" ]] || {
  echo "desktop tags differ from release remote; use a fresh --no-tags clone of that remote" >&2
  exit 1
}
base_sha="$(git rev-parse "$base_ref")"
branch="version-bump/$version"

remote_branch="refs/heads/$branch"
remote_oid=""
if remote_oid="$(git ls-remote "$remote" "$remote_branch" | awk '{print $1}')" && [[ -n "$remote_oid" ]]; then
  git fetch "$remote" "$remote_branch" --no-tags
fi

git checkout -B "$branch" "$base_sha"
just bump-desktop-version "$version"
scripts/desktop_release.py generate "$version" --base "$base_sha" --repo "$repository"

git add \
  .release/desktop-candidate.json \
  CHANGELOG.md \
  desktop/package.json \
  desktop/src-tauri/tauri.conf.json \
  desktop/src-tauri/Cargo.toml \
  desktop/src-tauri/Cargo.lock \
  pnpm-lock.yaml

agent_name="${RELEASE_AUTOMATION_NAME:-${AGENT_NAME:-Release Automation}}"
agent_email="${RELEASE_AUTOMATION_EMAIL:-${AGENT_EMAIL:-release-automation@users.noreply.github.com}}"
msg="$(mktemp)"
trap 'rm -f "$msg"' EXIT
cat >"$msg" <<EOF
chore(release): release Buzz Desktop version $version

Co-authored-by: $agent_name <$agent_email>
EOF
git -c user.name='Wes' -c user.email='wesbillman@users.noreply.github.com' \
  commit -s -F "$msg"
scripts/desktop_release.py validate --candidate HEAD --version "$version" --repo "$repository"

candidate_sha="$(git rev-parse HEAD)"
previous_tag="$(python3 -c 'import json; print(json.load(open(".release/desktop-candidate.json"))["previous_tag"] or "initial")')"
printf 'base_sha=%s\ncandidate_sha=%s\nprevious_tag=%s\ntag=desktop-v%s\n' \
  "$base_sha" "$candidate_sha" "$previous_tag" "$version"

if [[ "$mode" == validate-only ]]; then
  exit 0
fi
[[ "$mode" == publish ]] || { echo "unknown mode: $mode" >&2; exit 1; }
if [[ -n "$remote_oid" ]]; then
  git push --force-with-lease="$remote_branch:$remote_oid" "$remote" "HEAD:$remote_branch"
else
  git push --force-with-lease="$remote_branch:" "$remote" "HEAD:$remote_branch"
fi

body="$(mktemp)"
trap 'rm -f "$msg" "$body"' EXIT
cat >"$body" <<EOF
## Buzz Desktop release v$version

- **Frozen main:** \`$base_sha\`
- **Reviewed candidate:** \`$candidate_sha\`
- **Previous desktop release:** \`$previous_tag\`
- **Proposed immutable tag:** \`desktop-v$version\`

This PR may be **squash merged** after the Desktop Release Candidate check and all protected-branch checks pass. Merging authorizes publication of the exact reviewed candidate; later or unrelated changes on \`main\` cannot alter it.

The checked-in changelog accounts for every non-merge commit in the release range. The Desktop tag points to the reviewed candidate commit, not the later squash commit. Publication remains bound to that immutable candidate tag.
EOF
if existing="$(gh pr list --repo "$repository" --head "$branch" --state open --json number --jq '.[0].number')" && [[ -n "$existing" ]]; then
  gh pr edit "$existing" --repo "$repository" --title "chore(release): release Buzz Desktop version $version" --body-file "$body"
else
  gh pr create --repo "$repository" --base main --head "$branch" \
    --title "chore(release): release Buzz Desktop version $version" --body-file "$body"
fi
