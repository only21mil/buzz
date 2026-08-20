#!/usr/bin/env bash
set -euo pipefail

attempt="${BUZZ_CI_ATTEMPT:?runner must inject BUZZ_CI_ATTEMPT}"
if [[ "$attempt" == 1 ]]; then
  printf 'flaky attempt 1 failure: BUZZ_CI_ATTEMPT=1\n' >&2
  exit 1
fi
if [[ "$attempt" =~ ^[2-9][0-9]*$ ]]; then
  printf 'flaky attempt %s success: BUZZ_CI_ATTEMPT=%s\n' "$attempt" "$attempt"
  exit 0
fi
printf 'invalid BUZZ_CI_ATTEMPT=%s\n' "$attempt" >&2
exit 2

