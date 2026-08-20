#!/usr/bin/env bash
set -euo pipefail

timeout 20 bash -c '
  line=tm12-log-flood-0123456789abcdef0123456789abcdef
  while :; do printf "%s\n" "$line"; done
'
