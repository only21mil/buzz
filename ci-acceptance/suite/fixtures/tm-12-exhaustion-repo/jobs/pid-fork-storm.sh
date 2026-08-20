#!/usr/bin/env bash
set -euo pipefail

timeout 20 bash -c '
  trap "kill 0 2>/dev/null || true" EXIT
  while :; do
    sleep 20 &
  done
'
