#!/usr/bin/env bash
# Validate presence only. Rust validates the key before connecting to services.
# The caller supplies its stable identity through the protected environment.
# This helper never generates, prints, or writes key material.
set -euo pipefail
if [[ -z "${BUZZ_RELAY_PRIVATE_KEY:-}" ]]; then
    echo "BUZZ_RELAY_PRIVATE_KEY must be exported from the protected environment before starting a relay." >&2
    exit 1
fi
