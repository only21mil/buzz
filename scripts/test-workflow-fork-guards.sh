#!/usr/bin/env bash
# Contract for CD-15: upstream security/staging workflows must not execute
# under fork credentials unguarded. codex-security-review.yml and
# staging-dev-relay-image.yml arrive via upstream reconciliation (P08), so
# this contract lands first (P09 prep): it passes vacuously while they are
# absent and constrains them the moment they appear. A general sweep also
# covers any workflow that uses pull_request_target, whose base-run context
# is the trust boundary the audit calls out.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflows="$repo_root/.github/workflows"

fail() {
  echo "workflow fork-guard contract failed: $*" >&2
  exit 1
}

# File-level check applied to workflows that must never run unscoped.
require_fork_guard() {
  local file=$1
  local name
  name="$(basename "$file")"
  [[ -f "$file" ]] || return 0
  grep -Fq "github.repository" "$file" \
    || fail "$name exists without a github.repository guard"
  if grep -Fq "pull_request_target" "$file"; then
    grep -Fq "github.repository" "$file" \
      || fail "$name uses pull_request_target without a repository guard"
  fi
  if grep -Eq '^[[:space:]]*permissions:[[:space:]]*write-all' "$file"; then
    fail "$name grants write-all permissions"
  fi
  echo "guarded: $name"
}

require_fork_guard "$workflows/codex-security-review.yml"
require_fork_guard "$workflows/staging-dev-relay-image.yml"

# Sweep: no workflow may pair pull_request_target with fork credentials.
while IFS= read -r file; do
  grep -Fq "pull_request_target" "$file" || continue
  grep -Fq "github.repository" "$file" \
    || fail "$(basename "$file") uses pull_request_target without a repository guard"
done < <(find "$workflows" -maxdepth 1 -name '*.yml')

echo "workflow fork-guard contract passed"
