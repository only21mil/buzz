#!/usr/bin/env bash
set -euo pipefail

timeout 20 bash -c '
  file=${BUZZ_CI_WORKSPACE_DIR:-$PWD}/disk-fill.bin
  while dd if=/dev/zero of="$file" bs=1048576 count=64 oflag=append conv=notrunc status=none; do :; done
'
