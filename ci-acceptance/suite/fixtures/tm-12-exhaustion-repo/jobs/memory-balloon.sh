#!/usr/bin/env bash
set -euo pipefail

timeout 20 bash -c '
  chunks=()
  while :; do
    chunks+=("$(head -c 16777216 /dev/zero | tr "\0" x)")
  done
'
