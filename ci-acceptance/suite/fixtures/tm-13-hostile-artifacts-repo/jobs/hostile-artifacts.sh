#!/usr/bin/env bash
set -euo pipefail

timeout 30 bash -c '
  artifact_dir=${BUZZ_CI_ARTIFACT_DIR:-$PWD/artifacts}
  mkdir -p "$artifact_dir/payload" "$artifact_dir/bomb"

  outside_marker=$PWD/outside-target.txt
  printf "escape target\n" >"$outside_marker"
  ln -s ../outside-target.txt "$artifact_dir/payload/symlink-escape"
  ln "$outside_marker" "$artifact_dir/payload/hardlink-escape"
  mkfifo "$artifact_dir/payload/fifo-entry"
  timeout 5 python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.close()" "$artifact_dir/payload/socket-entry"

  printf "device-node request: character 1:3\n" >"$artifact_dir/payload/device-node.request"
  tar -cf "$artifact_dir/device-entry.tar" --transform="s#^dev/null$#device-entry#" -C / dev/null

  printf "traversal\n" >"$artifact_dir/traversal-source"
  tar -cf "$artifact_dir/traversal-entry.tar" --transform="s#^traversal-source#../escape#" -C "$artifact_dir" traversal-source

  head -c 1048576 /dev/zero >"$artifact_dir/bomb/level-0.bin"
  gzip -9 "$artifact_dir/bomb/level-0.bin"
  level=$artifact_dir/bomb/level-0.bin.gz
  for depth in 1 2 3; do
    next=$artifact_dir/bomb/level-$depth.tar
    tar -cf "$next" -C "$(dirname "$level")" "$(basename "$level")"
    gzip -9 "$next"
    level=$next.gz
  done
  size=$(wc -c <"$level")
  test "$size" -le 2097152

  printf "\033[31mansi-red\033[0m\n"
  printf "\033]0;tm13-osc-title\007osc-end\n"
  printf "fake token ghp_%036d\n" 0
  printf "fake key AKIA%016d\n" 0
  printf "ghp_%036d" 0 | base64
  printf "AKIA%016d" 0 | base64

  cache_parent=${BUZZ_CI_WORKSPACE_DIR:-$PWD}/../tm13-cache-poison-attempt
  if printf "poison attempt\n" >"$cache_parent" 2>/dev/null; then
    printf "cache poison write escaped workspace\n" >&2
  else
    printf "cache poison write refused\n"
  fi
'
