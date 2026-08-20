#!/usr/bin/env bash
set -euo pipefail
export SUITE_FIXTURE_TEST_ID=TM-01
exec "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/stub_runner.sh" "$@"
