#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if env -u BUZZ_RELAY_PRIVATE_KEY bash "${SCRIPT_DIR}/require-relay-key.sh" >/dev/null 2>&1; then
    echo "missing identity unexpectedly accepted" >&2
    exit 1
fi
if BUZZ_RELAY_PRIVATE_KEY='' bash "${SCRIPT_DIR}/require-relay-key.sh" >/dev/null 2>&1; then
    echo "empty identity unexpectedly accepted" >&2
    exit 1
fi
# Public synthetic fixture, only in this process environment. No key file.
printf -v BUZZ_RELAY_PRIVATE_KEY '%064d' 2
export BUZZ_RELAY_PRIVATE_KEY
fixture_identity="$BUZZ_RELAY_PRIVATE_KEY"
for _ in 1 2; do
    output="$(bash "${SCRIPT_DIR}/require-relay-key.sh" 2>&1)"
    [[ -z "$output" ]]
    [[ "$BUZZ_RELAY_PRIVATE_KEY" == "$fixture_identity" ]]
done
echo "relay identity environment checks passed"
