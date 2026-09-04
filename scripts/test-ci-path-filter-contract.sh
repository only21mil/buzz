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

# A skipped protected check cannot produce the canonical success receipt. Exercise
# the actual job expressions for unchanged main PRs and the existing path routes.
python3 - "$ci_workflow" <<'PY'
import ast
from pathlib import Path
import re
import sys

workflow = Path(sys.argv[1]).read_text()


def evaluate(node, values):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in values:
        return values[node.id]
    if isinstance(node, ast.BoolOp):
        operands = [evaluate(value, values) for value in node.values]
        if isinstance(node.op, ast.And):
            return all(operands)
        if isinstance(node.op, ast.Or):
            return any(operands)
    if (isinstance(node, ast.Compare) and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)):
        return evaluate(node.left, values) == evaluate(node.comparators[0], values)
    raise SystemExit("unsupported protected-job condition syntax")


cases = (
    ("push", "", "false", True),
    ("pull_request", "main", "false", True),
    ("pull_request", "main", "true", True),
    ("pull_request", "release", "false", False),
    ("pull_request", "release", "true", True),
    ("workflow_dispatch", "", "false", False),
    ("workflow_dispatch", "", "true", True),
)
for job in ("web", "mobile"):
    block = re.search(rf"(?ms)^  {job}:\n(.*?)(?=^  [a-z0-9-]+:|\Z)", workflow)
    if block is None:
        raise SystemExit(f"required job missing: {job}")
    condition = re.search(r"(?m)^    if: (.+)$", block.group(1))
    if condition is None:
        raise SystemExit(f"required job condition missing: {job}")
    expression = condition.group(1)
    for original, variable in (
        ("github.event_name", "event"),
        ("github.base_ref", "base"),
        (f"needs.changes.outputs.{job}", "changed"),
    ):
        expression = expression.replace(original, variable)
    tree = ast.parse(expression.replace("&&", " and ").replace("||", " or "), mode="eval")
    for event, base, changed, expected in cases:
        actual = evaluate(tree.body, {"event": event, "base": base, "changed": changed})
        if actual is not expected:
            raise SystemExit(
                f"{job} condition for event={event}, base={base}, changed={changed}: "
                f"expected {expected}, got {actual}"
            )
print("Protected Web/Mobile job condition contract passed: 14 cases")
PY

echo "CI path filter contract passed"
