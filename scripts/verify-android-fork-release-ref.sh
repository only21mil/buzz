#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "verify-android-fork-release-ref: $*" >&2
  exit 1
}

[[ "$#" -eq 2 ]] || fail "usage: $0 <source-tag> <expected-commit-sha>"
readonly tag="$1"
readonly expected_commit="$2"
readonly repository="${GITHUB_REPOSITORY:-}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repo_root
readonly metadata_tool="$repo_root/scripts/android-fork-release-metadata.py"

[[ "$repository" == "only21mil/buzz" ]] || fail "release builds are restricted to only21mil/buzz"
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || fail "expected commit must be a full lowercase SHA"
python3 "$metadata_tool" "$tag" >/dev/null || fail "invalid source tag"

git -C "$repo_root" fetch --quiet --no-tags origin \
  +refs/heads/main:refs/remotes/origin/main || fail "could not refresh fork main"
git -C "$repo_root" fetch --quiet --force origin \
  "refs/tags/$tag:refs/tags/$tag" || fail "could not refresh source tag"

[[ "$(git -C "$repo_root" cat-file -t "refs/tags/$tag")" == "tag" ]] || \
  fail "$tag must be an annotated tag"
tag_object="$(git -C "$repo_root" rev-parse "refs/tags/$tag")"
readonly tag_object
commit="$(git -C "$repo_root" rev-parse "refs/tags/$tag^{commit}")"
readonly commit
[[ "$commit" == "$expected_commit" ]] || \
  fail "$tag resolves to $commit, not requested commit $expected_commit"
git -C "$repo_root" merge-base --is-ancestor "$commit" refs/remotes/origin/main || \
  fail "$commit is not reachable from only21mil/buzz main"

remote_object="$(
  git -C "$repo_root" ls-remote --refs origin "refs/tags/$tag" | awk 'NR == 1 {print $1}'
)"
readonly remote_object
[[ "$remote_object" == "$tag_object" ]] || \
  fail "remote $tag moved or does not reference local tag object $tag_object"

declare -A seen_codes=()
selected_code="$(
  python3 "$metadata_tool" "$tag" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["version_code"])'
)"
latest_code=0
while IFS= read -r remote_tag; do
  [[ -n "$remote_tag" ]] || continue
  metadata="$(python3 "$metadata_tool" "$remote_tag")" || \
    fail "remote tag $remote_tag violates the fork release namespace"
  code="$(printf '%s' "$metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version_code"])')"
  [[ -z "${seen_codes[$code]:-}" ]] || \
    fail "remote tags $remote_tag and ${seen_codes[$code]} reuse Android version code $code"
  seen_codes[$code]="$remote_tag"
  (( code > latest_code )) && latest_code="$code"
done < <(
  git -C "$repo_root" ls-remote --refs origin 'refs/tags/only21mil-android-v*' |
    sed 's#^[^[:space:]]*[[:space:]]refs/tags/##' | sort
)
[[ "$selected_code" -eq "$latest_code" ]] || \
  fail "$tag uses version code $selected_code, but latest remote code is $latest_code"

printf 'Verified %s: tag-object=%s commit=%s tree=%s version-code=%s\n' \
  "$tag" "$tag_object" "$commit" \
  "$(git -C "$repo_root" rev-parse "$commit^{tree}")" "$selected_code"
