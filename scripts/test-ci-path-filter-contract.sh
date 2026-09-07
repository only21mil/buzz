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
  'scripts/postgres-test-*.py' \
  'scripts/postgres-test-*.sh' \
  'scripts/postgres_test_*.py' \
  'scripts/postgres-tests.tsv' \
  'scripts/test-postgres-test-*.py' \
  'scripts/test-postgres-test-*.sh' \
  'scripts/check-postgres-test-discovery.py' \
  'scripts/test-native-ci-python.sh' \
  'scripts/pre-freeze.sh' \
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
# every required CI job and dependency using the actual expressions and scripts.
python3 - "$ci_workflow" <<'PY'
import ast
import itertools
from pathlib import Path
import re
import subprocess
import sys
import textwrap

workflow = Path(sys.argv[1]).read_text()
blocks = dict(re.findall(r"(?ms)^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:|\Z)", workflow))
filters = ("rust", "desktop", "desktop-rust", "web", "mobile")
desktop_paths = ("desktop", "desktop-rust", "rust")
# Include the actual work behind the protected Desktop aggregate contexts.
routes = {
    "changes": None,
    "dead-token-guard": None,
    "rust-lint": ("rust", "desktop-rust"),
    "unit-tests": ("rust",),
    "security": ("rust",),
    "backend-integration": ("rust",),
    "relay-e2e": ("rust",),
    "desktop-core": desktop_paths,
    "desktop-smoke-e2e": desktop_paths,
    "desktop": desktop_paths,
    "desktop-e2e-relay": desktop_paths,
    "desktop-e2e-integration-shard": desktop_paths,
    "desktop-e2e-integration": desktop_paths,
    "desktop-build-macos": desktop_paths,
    "web": ("web",),
    "mobile": ("mobile",),
}


def evaluate(node, values):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in values:
        return values[node.id]
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "always" and not node.args and not node.keywords):
        return True
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


cases = 0
for job, paths in routes.items():
    if job not in blocks:
        raise SystemExit(f"required job missing: {job}")
    block = blocks[job]
    condition = re.search(r"(?m)^    if: (.+)$", block)
    if paths is None:
        if condition is not None:
            raise SystemExit(f"{job} must run without a job condition")
    elif condition is None:
        raise SystemExit(f"required job condition missing: {job}")
    else:
        expression = condition.group(1)
        # Replace desktop-rust before desktop to avoid partial matches.
        for original, variable in sorted(
            [("github.event_name", "event"), ("github.base_ref", "base")]
            + [(f"needs.changes.outputs.{name}", f"changed_{i}")
               for i, name in enumerate(filters)], key=lambda pair: -len(pair[0])
        ):
            expression = expression.replace(original, variable)
        tree = ast.parse(expression.replace("&&", " and ").replace("||", " or "), mode="eval")
    needs = re.search(r"(?m)^    needs: \[(.+)\]$", block)
    if needs:
        dependencies = {name.strip() for name in needs.group(1).split(",")}
        if not dependencies <= routes.keys():
            raise SystemExit(f"{job} has unchecked dependencies: {dependencies - routes.keys()}")
    for event, base in (("push", ""), ("pull_request", "main"),
                        ("pull_request", "release"), ("pull_request", "topic"),
                        ("workflow_dispatch", "")):
        for changed in itertools.product(("false", "true"), repeat=len(filters)):
            values = {"event": event, "base": base}
            values.update({f"changed_{i}": value for i, value in enumerate(changed)})
            expected = (paths is None or event in ("push", "workflow_dispatch")
                        or (event == "pull_request" and base == "main")
                        or any(changed[filters.index(path)] == "true" for path in paths))
            actual = True if paths is None else evaluate(tree.body, values)
            if actual is not expected:
                raise SystemExit(
                    f"{job} condition for event={event}, base={base}, changed={changed}: "
                    f"expected {expected}, got {actual}"
                )
            cases += 1
print(f"Protected CI job condition contract passed: {cases} cases")

# Run the aggregate's own shell for every dependency outcome. The aggregate must
# execute even after a failed dependency, and only all-success may pass.
aggregate_cases = 0
for job, dependencies in {
    "desktop": ("desktop-core", "desktop-smoke-e2e"),
    "desktop-e2e-integration": ("desktop-e2e-integration-shard",),
}.items():
    block = blocks[job]
    if not re.search(r"(?m)^    if: always\(\) && ", block):
        raise SystemExit(f"{job} must report dependency failures with always()")
    declared = re.search(r"(?m)^    needs: \[(.+)\]$", block)
    if declared is None or {part.strip() for part in declared.group(1).split(",")} != {"changes", *dependencies}:
        raise SystemExit(f"{job} aggregate dependencies changed")
    if re.search(r"(?m)^        if:", block) or "continue-on-error:" in block:
        raise SystemExit(f"{job} must not skip or tolerate its result check")
    run = re.search(r"(?m)^        run: \|\n((?:          .*\n|\n)+)", block)
    if run is None:
        raise SystemExit(f"{job} aggregate script missing")
    for outcomes in itertools.product(("success", "failure", "skipped", "cancelled"), repeat=len(dependencies)):
        script = textwrap.dedent(run.group(1))
        for dependency, outcome in zip(dependencies, outcomes):
            script = script.replace("${{ needs." + dependency + ".result }}", outcome)
        result = subprocess.run(["bash", "-e", "-c", script], capture_output=True, text=True)
        expected = all(outcome == "success" for outcome in outcomes)
        if (result.returncode == 0) is not expected:
            raise SystemExit(f"{job} aggregate accepted wrong outcome {outcomes}: {result.stdout}{result.stderr}")
        aggregate_cases += 1
print(f"Protected Desktop aggregate contract passed: {aggregate_cases} cases")
PY

echo "CI path filter contract passed"
