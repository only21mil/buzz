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
git -c tag.gpgSign=false tag desktop-v0.0.1
if scripts/prepare-desktop-release.sh 0.1.0 validate-only >"$tmp/foreign-tag.log" 2>&1; then
  echo 'accepted an upstream-only desktop tag as fork release history' >&2; exit 1
fi
git tag -d desktop-v0.0.1 >/dev/null
scripts/prepare-desktop-release.sh 0.1.0 validate-only
[[ ! -e "$CALL_LOG" ]]
[[ -z "$(git ls-remote buzz refs/heads/version-bump/0.1.0)" ]]
grep -Fq 'https://github.com/only21mil/buzz/' CHANGELOG.md
! grep -Fq 'https://github.com/block/buzz/' CHANGELOG.md
[[ "$(git rev-parse refs/remotes/origin/main)" == "$base" ]]
scripts/prepare-desktop-release.sh 0.1.0 publish
grep -Fq 'pr create --repo only21mil/buzz' "$CALL_LOG"
[[ -z "$(git status --porcelain)" ]]
echo 'desktop fork release policy and repository routing passed'
