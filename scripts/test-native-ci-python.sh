#!/usr/bin/env bash
# Native-CI Python suites shared by `just test-unit` and pre-freeze (issue #160).
# Suites are discovered, not listed: every directory under deploy/native-ci or
# scripts/ that holds a test_*.py file runs. The fleet-bundle suites below are
# excluded by name because they bind framework-desktop paths; each exclusion
# must still exist so the list cannot go stale.
set -euo pipefail
test "$(check-jsonschema --version)" = "check-jsonschema, version 0.38.0"

excluded_suites=(
  scripts/mempool-genesis/activation/tests
  scripts/mempool-genesis/tests
  scripts/roster-migration/tests
)
for suite in "${excluded_suites[@]}"; do
  [[ -d "$suite" ]] || {
    printf 'stale suite exclusion, directory is gone: %s\n' "$suite" >&2
    exit 1
  }
done

mapfile -t discovered < <(
  find deploy/native-ci scripts -name 'test_*.py' -not -path '*/node_modules/*' -printf '%h\n' | sort -u
)
suites=()
for suite in "${discovered[@]}"; do
  skip=0
  for excluded in "${excluded_suites[@]}"; do
    [[ "$suite" == "$excluded" ]] && skip=1
  done
  ((skip == 1)) || suites+=("$suite")
done
((${#suites[@]} > 0)) || {
  printf 'no unittest suites discovered\n' >&2
  exit 1
}
printf 'discovered %d unittest suites\n' "${#suites[@]}"
for suite in "${suites[@]}"; do
  python3 -m unittest discover "$suite" -p "test_*.py"
done
python3 scripts/test-ci-promotion-readiness.py
python3 scripts/test-protected-ci-receipt.py
python3 scripts/test-protected-ci-reuse.py
python3 scripts/test-ci-apt-retry.py
bash scripts/test-ci-path-filter-contract.sh
bash scripts/test-relay-e2e-canary-contract.sh
python3 scripts/test-populate-ci-promotion-relay-origin.py
python3 scripts/test-ci-workflow-inventory.py
python3 scripts/ci-workflow-inventory.py --offline --check
