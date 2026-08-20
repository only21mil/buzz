#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "publish-android-fork-release-candidate: $*" >&2
  exit 1
}

[[ "$#" -eq 2 ]] || fail "usage: $0 <source-tag> <target-commit-sha>"
readonly tag="$1"
readonly target_sha="$2"
readonly repo="${GITHUB_REPOSITORY:-}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repo_root
readonly metadata_tool="$repo_root/scripts/android-fork-release-metadata.py"

[[ "$repo" == "only21mil/buzz" ]] || fail "tag publication is restricted to only21mil/buzz"
[[ "$target_sha" =~ ^[0-9a-f]{40}$ ]] || fail "target commit must be a full lowercase SHA"
command -v gh >/dev/null 2>&1 || fail "gh is required"
metadata="$(python3 "$metadata_tool" "$tag")" || fail "invalid source tag"
version="$(printf '%s' "$metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
candidate="$(printf '%s' "$metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["candidate_number"])')"
version_code="$(printf '%s' "$metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version_code"])')"

main_sha="$(gh api "repos/$repo/git/ref/heads/main" --jq .object.sha)" || \
  fail "could not resolve fork main"
[[ "$main_sha" == "$target_sha" ]] || \
  fail "fork main moved from requested commit $target_sha to $main_sha"
[[ "$(gh api "repos/$repo/commits/$target_sha" --jq .sha)" == "$target_sha" ]] || \
  fail "$target_sha is not an exact commit in $repo"

if gh api "repos/$repo/git/ref/tags/$tag" --silent >/dev/null 2>&1; then
  fail "$tag already exists; tags and version codes are immutable"
fi

latest_code=0
next_candidate=1
refs_tsv="$(
  gh api --paginate "repos/$repo/git/matching-refs/tags/only21mil-android-v" \
    --jq '.[] | [.ref, .object.type, .object.sha] | @tsv'
)" || fail "could not list existing fork Android tags"
while IFS=$'\t' read -r ref object_type object_sha; do
  [[ -n "$ref" ]] || continue
  remote_tag="${ref#refs/tags/}"
  remote_metadata="$(python3 "$metadata_tool" "$remote_tag")" || \
    fail "remote tag $remote_tag violates the fork release namespace"
  remote_code="$(printf '%s' "$remote_metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version_code"])')"
  remote_version="$(printf '%s' "$remote_metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
  remote_candidate="$(printf '%s' "$remote_metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["candidate_number"])')"
  [[ "$object_type" == "tag" && "$object_sha" =~ ^[0-9a-f]{40}$ ]] || \
    fail "$remote_tag must be an annotated tag"
  (( remote_code > latest_code )) && latest_code="$remote_code"
  if [[ "$remote_version" == "$version" ]] && (( remote_candidate >= next_candidate )); then
    next_candidate=$((remote_candidate + 1))
  fi
done <<< "$refs_tsv"

[[ "$candidate" -eq "$next_candidate" ]] || \
  fail "$version candidate sequence changed; expected rc.$next_candidate, got rc.$candidate"
(( version_code > latest_code )) || \
  fail "version code $version_code must be greater than existing maximum $latest_code"

readonly message="Buzz only21mil Android $version release candidate $candidate (vc$version_code)"
tag_object_sha="$(
  gh api --method POST "repos/$repo/git/tags" \
    -f tag="$tag" \
    -f message="$message" \
    -f object="$target_sha" \
    -f type=commit \
    --jq .sha
)" || fail "could not create annotated tag object for $tag"
[[ "$tag_object_sha" =~ ^[0-9a-f]{40}$ ]] || fail "GitHub returned an invalid tag object SHA"

gh api --method POST "repos/$repo/git/refs" \
  -f ref="refs/tags/$tag" \
  -f sha="$tag_object_sha" \
  --silent || fail "could not publish $tag"

published_type="$(gh api "repos/$repo/git/ref/tags/$tag" --jq .object.type)" || \
  fail "could not verify $tag"
published_object="$(gh api "repos/$repo/git/ref/tags/$tag" --jq .object.sha)" || \
  fail "could not verify $tag object"
direct_sha="$(gh api "repos/$repo/git/tags/$tag_object_sha" --jq .object.sha)" || \
  fail "could not verify annotated tag target"
[[ "$published_type" == "tag" && "$published_object" == "$tag_object_sha" ]] || \
  fail "$tag does not reference the expected annotated object"
[[ "$direct_sha" == "$target_sha" ]] || fail "$tag does not target $target_sha"

printf 'Published %s at %s (version-code %s).\n' "$tag" "$target_sha" "$version_code"
