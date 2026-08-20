#!/usr/bin/env bash
set -euo pipefail

timeout 20 bash -c '
  artifact_dir=${BUZZ_CI_ARTIFACT_DIR:-$PWD/artifacts}
  mkdir -p "$artifact_dir"
  i=0
  while :; do
    dd if=/dev/zero of="$artifact_dir/artifact-$i.bin" bs=1048576 count=1 status=none
    i=$((i + 1))
  done
'
