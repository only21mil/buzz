#!/usr/bin/env bash
# Existing native-CI suites shared by unit tests and pre-freeze (issue #160).
set -euo pipefail
test "$(check-jsonschema --version)" = "check-jsonschema, version 0.38.0"
for suite in \
  deploy/native-ci/acceptance/tests \
  deploy/native-ci/activation/render_inputs/tests \
  deploy/native-ci/activation/tests \
  deploy/native-ci/activation/tests/clean_host_e2e \
  deploy/native-ci/controld/tests \
  deploy/native-ci/execd/tests \
  deploy/native-ci/keyholder/tests \
  deploy/native-ci/legacy_state_migration/tests \
  deploy/native-ci/runner/tests \
  deploy/native-ci/tests; do
  python3 -m unittest discover "$suite" -p "test_*.py"
done
python3 scripts/test-ci-promotion-readiness.py
python3 scripts/test-protected-ci-receipt.py
python3 scripts/test-protected-ci-reuse.py
bash scripts/test-ci-path-filter-contract.sh
bash scripts/test-relay-e2e-canary-contract.sh
python3 scripts/test-populate-ci-promotion-relay-origin.py
python3 scripts/test-ci-workflow-inventory.py
python3 scripts/ci-workflow-inventory.py --offline --check
