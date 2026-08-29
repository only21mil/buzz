#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch_root=${TEST_TMP_ROOT:-"${TMPDIR:-/var/tmp}/buzz-promotion-readiness-tests"}
mkdir -p -- "$scratch_root"

PYTHONPYCACHEPREFIX="$scratch_root/pycache" python3 -m py_compile \
  "$repo_root/scripts/ci-promotion-readiness.py" \
  "$repo_root/scripts/populate-ci-promotion-relay-origin.py" \
  "$repo_root/scripts/test-ci-promotion-readiness.py"
TMPDIR="$scratch_root" PYTHONPYCACHEPREFIX="$scratch_root/pycache" \
  python3 "$repo_root/scripts/test-ci-promotion-readiness.py"
