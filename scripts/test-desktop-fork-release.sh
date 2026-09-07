#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
filter="$repo_root/scripts/desktop-release-required-checks.jq"
policy='[[{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true,"required_status_checks":[{"context":"Desktop Release Candidate","integration_id":15368},{"context":"relay_e2e_canary","integration_id":15368}]}}]]'
result=$(jq -er -f "$filter" <<<"$policy")
[[ "$result" == $'Desktop Release Candidate:15368\nrelay_e2e_canary:15368' ]]
for mutation in \
  '[]' \
  '.[0][0].parameters.strict_required_status_checks_policy = false' \
  '.[0][0].parameters.required_status_checks = []' \
  '.[0][0].parameters.required_status_checks[0].integration_id = null' \
  '.[0][0].parameters.required_status_checks[0].integration_id = 9' \
  '.[0][0].parameters.required_status_checks[1].context = "bad\nname"' \
  '.[0][0].parameters.required_status_checks += [{"context":"relay_e2e_canary","integration_id":99}]'; do
  if jq "$mutation" <<<"$policy" | jq -er -f "$filter" >"$tmp/refusal.log" 2>&1; then
    echo "accepted invalid release policy: $mutation" >&2; exit 1
  fi
done

# A real Git fixture proves the non-GitHub relay remote selects fork links,
# preserves upstream origin/main, and receives the candidate before PR creation.
git init -q --bare "$tmp/relay.git"
git init -q "$tmp/source"
cd "$tmp/source"
git config user.name test
git config user.email test@example.com
git config commit.gpgSign false
git config core.hooksPath /dev/null
mkdir -p scripts desktop/src-tauri .release
cp "$repo_root/scripts/desktop_release.py" scripts/
cp "$repo_root/scripts/prepare-desktop-release.sh" scripts/
printf '{"version":"0.0.0"}\n' > desktop/package.json
printf '{"version":"0.0.0"}\n' > desktop/src-tauri/tauri.conf.json
printf '[package]\nversion = "0.0.0"\n' > desktop/src-tauri/Cargo.toml
printf '# lock\n' > desktop/src-tauri/Cargo.lock
printf '# lock\n' > pnpm-lock.yaml
printf '# Changelog\n' > CHANGELOG.md
git add .
git commit -qm initial
git branch -M main
base=$(git rev-parse HEAD)
git remote add buzz "$tmp/relay.git"
git push -q buzz main
git update-ref refs/remotes/origin/main "$base"
mkdir "$tmp/bin"
cat > "$tmp/bin/just" <<'JUST'
#!/usr/bin/env bash
[[ "$1" == bump-desktop-version ]] || exit 91
python3 - "$2" <<'PY'
import json, sys
from pathlib import Path
for name in ('desktop/package.json', 'desktop/src-tauri/tauri.conf.json'):
 p=Path(name); obj=json.loads(p.read_text()); obj['version']=sys.argv[1]; p.write_text(json.dumps(obj)+'\n')
Path('desktop/src-tauri/Cargo.toml').write_text('[package]\nversion = "'+sys.argv[1]+'"\n')
PY
JUST
cat > "$tmp/bin/gh" <<'GH'
#!/usr/bin/env bash
[[ "$1" == pr ]] || exit 92
printf '%s\n' "$*" >> "$CALL_LOG"
case "$2" in
  list) [[ "$3" == --repo && "$4" == only21mil/buzz ]] || exit 93 ;;
  create)
    [[ "$3" == --repo && "$4" == only21mil/buzz ]] || exit 94
    [[ "$(git ls-remote buzz refs/heads/version-bump/0.1.0 | cut -f1)" == "$(git rev-parse HEAD)" ]] || exit 95 ;;
  *) exit 96 ;;
esac
GH
chmod +x "$tmp/bin/just" "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" CALL_LOG="$tmp/gh.log" RELEASE_REMOTE=buzz
unset RELEASE_REPOSITORY GITHUB_REPOSITORY
if scripts/prepare-desktop-release.sh 0.1.0 validate-only >"$tmp/missing-repo.log" 2>&1; then
  echo 'non-GitHub remote accepted without repository binding' >&2; exit 1
fi
[[ "$(git rev-parse HEAD)" == "$base" ]]
export RELEASE_REPOSITORY=only21mil/buzz
if scripts/prepare-desktop-release.sh 0.1.0 validate-only >"$tmp/wrong-identity.log" 2>&1; then
  echo 'fork preparation accepted a noncanonical identity' >&2; exit 1
fi
grep -Fq 'GIT_AUTHOR_IDENT must use Victor Vogel' "$tmp/wrong-identity.log"
[[ "$(git rev-parse HEAD)" == "$base" ]]
[[ -z "$(git for-each-ref refs/release-preparation/)" ]]
git config user.name 'Victor Vogel'
git config user.email '263261067+only21mil@users.noreply.github.com'
if GIT_COMMITTER_NAME=Wrong scripts/prepare-desktop-release.sh 0.1.0 validate-only >"$tmp/wrong-committer.log" 2>&1; then
  echo 'fork preparation accepted an overridden committer' >&2; exit 1
fi
grep -Fq 'GIT_COMMITTER_IDENT must use Victor Vogel' "$tmp/wrong-committer.log"
if GIT_AUTHOR_EMAIL=wrong@example.com scripts/prepare-desktop-release.sh 0.1.0 validate-only >"$tmp/wrong-author.log" 2>&1; then
  echo 'fork preparation accepted an overridden author' >&2; exit 1
fi
grep -Fq 'GIT_AUTHOR_IDENT must use Victor Vogel' "$tmp/wrong-author.log"
git -c tag.gpgSign=false tag desktop-v0.0.1
if scripts/prepare-desktop-release.sh 0.1.0 validate-only >"$tmp/foreign-tag.log" 2>&1; then
  echo 'accepted an upstream-only desktop tag as fork release history' >&2; exit 1
fi
git tag -d desktop-v0.0.1 >/dev/null
scripts/prepare-desktop-release.sh 0.1.0 validate-only
victor='Victor Vogel <263261067+only21mil@users.noreply.github.com>'
wes='Wes <wesbillman@users.noreply.github.com>'
[[ "$(git show -s --format='%an <%ae>')" == "$victor" ]]
[[ "$(git show -s --format='%cn <%ce>')" == "$victor" ]]
git show -s --format='%(trailers:only,unfold)' | grep -Fxq "Signed-off-by: $victor"
[[ ! -e "$CALL_LOG" ]]
[[ -z "$(git ls-remote buzz refs/heads/version-bump/0.1.0)" ]]
grep -Fq 'https://github.com/only21mil/buzz/' CHANGELOG.md
! grep -Fq 'https://github.com/block/buzz/' CHANGELOG.md
[[ "$(git rev-parse refs/remotes/origin/main)" == "$base" ]]

# Rebuild only commit provenance around the exact valid candidate tree. Each
# refusal must reach the identity check, not fail earlier on release content.
candidate=$(git rev-parse HEAD)
tree=$(git rev-parse HEAD^{tree})
assert_provenance_refused() {
  local author_name="$1" author_email="$2" message="$3" expected="$4" rejected
  rejected=$(GIT_AUTHOR_NAME="$author_name" GIT_AUTHOR_EMAIL="$author_email" \
    git -c commit.gpgSign=false commit-tree "$tree" -p "$base" -m "$message")
  if scripts/desktop_release.py validate --candidate "$rejected" --version 0.1.0 --repo only21mil/buzz >"$tmp/provenance.log" 2>&1; then
    echo "accepted invalid fork provenance: $expected" >&2; exit 1
  fi
  grep -Fq "$expected" "$tmp/provenance.log"
}
automation='Co-authored-by: Release Automation <release-automation@users.noreply.github.com>'
assert_provenance_refused Wes wesbillman@users.noreply.github.com \
  "Release"$'\n\n'"Signed-off-by: $wes"$'\n'"$automation" 'unexpected candidate author'
assert_provenance_refused 'Victor Vogel' '263261067+only21mil@users.noreply.github.com' \
  "Release"$'\n\n'"Signed-off-by: $wes"$'\n'"$automation" 'candidate is missing Signed-off-by trailer'
assert_provenance_refused 'Victor Vogel' '263261067+only21mil@users.noreply.github.com' \
  "Release"$'\n\n'"Signed-off-by: $victor"$'\n\nThis is body text, not a signoff trailer.\n\n'"$automation" \
  'candidate is missing Signed-off-by trailer'
assert_provenance_refused 'Victor Vogel' '263261067+only21mil@users.noreply.github.com' \
  "Release"$'\n\n'"Signed-off-by: $victor" 'candidate is missing automation Co-authored-by trailer'
[[ "$(git rev-parse HEAD)" == "$candidate" ]]
scripts/prepare-desktop-release.sh 0.1.0 publish
grep -Fq 'pr create --repo only21mil/buzz' "$CALL_LOG"
[[ -z "$(git status --porcelain)" ]]
# The same generator still emits and validates the upstream release identity.
RELEASE_REPOSITORY=block/buzz scripts/prepare-desktop-release.sh 0.1.0 validate-only
[[ "$(git show -s --format='%an <%ae>')" == "$wes" ]]
git show -s --format='%(trailers:only,unfold)' | grep -Fxq "Signed-off-by: $wes"
git commit -q --amend --no-edit --author="$victor"
if scripts/desktop_release.py validate --version 0.1.0 --repo block/buzz >"$tmp/upstream-author.log" 2>&1; then
  echo 'upstream validator accepted fork author' >&2; exit 1
fi
grep -Fq 'unexpected candidate author' "$tmp/upstream-author.log"
echo 'desktop fork release policy and repository routing passed'
