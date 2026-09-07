#!/usr/bin/env bash
set -euo pipefail
scripts_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
python3 "$scripts_dir/test-postgres-test-local.py"
python3 "$scripts_dir/test-postgres-test-discovery.py"
python3 "$scripts_dir/check-postgres-test-discovery.py"
