#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ci_workflow=${1:-"$repo_root/.github/workflows/ci.yml"}

fail() {
  echo "CI path filter contract failed: $*" >&2
  exit 1
}

filter_block() {
  local filter_name=$1
  local next_filter=$2
  sed -n "/^            ${filter_name}:$/,/^            ${next_filter}:$/p" "$ci_workflow"
}

require_ci_path() {
  local filter_name=$1
  local block=$2
  local path=$3
  local count
  count=$(grep -Fxc "              - '$path'" <<<"$block" || true)
  [[ $count -eq 1 ]] || fail "$filter_name must contain exactly one $path entry"
}

rust_block=$(filter_block rust desktop)
desktop_block=$(filter_block desktop desktop-rust)
web_block=$(filter_block web mobile)

for path in \
  'deploy/compose/**' \
  '.github/workflows/ci.yml' \
  '.github/workflows/relay_e2e_canary.yml' \
  'docs/ci/**' \
  'docs/delivery-lifecycle.md' \
  'scripts/ci-promotion-readiness.py' \
  'scripts/protected-ci-receipt.py' \
  'scripts/run-tests.sh' \
  'scripts/test-ci-promotion-readiness.py' \
  scripts/test-ci-path-filter-contract.sh \
  'scripts/test-protected-ci-receipt.py' \
  'scripts/test-relay-e2e-canary-contract.sh' \
  Justfile; do
  require_ci_path rust "$rust_block" "$path"
done

for path in admin-web/package.json package.json pnpm-lock.yaml pnpm-workspace.yaml 'patches/**'; do
  require_ci_path desktop "$desktop_block" "$path"
  require_ci_path web "$web_block" "$path"
done
require_ci_path web "$web_block" .github/workflows/ci.yml
require_ci_path web "$web_block" Justfile

contract_step_count=$(grep -Fxc '        run: scripts/test-ci-path-filter-contract.sh' "$ci_workflow" || true)
[[ $contract_step_count -eq 1 ]] || fail "CI must run this contract exactly once"

unit_block=$(sed -n '/^  unit-tests:$/,/^  desktop-tests:$/p' "$ci_workflow")
grep -Fq "needs.changes.outputs.rust == 'true'" <<<"$unit_block" || \
  fail "Unit Tests must activate from the rust path filter"
if grep -Eq '^[[:space:]]*if:[[:space:]]*(false|\$\{\{[[:space:]]*false[[:space:]]*\}\})[[:space:]]*$' \
  <<<"$unit_block"; then
  fail "Unit Tests must not be disabled with an always-false condition"
fi

echo "CI path filter contract passed"
