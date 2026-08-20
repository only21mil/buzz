#!/usr/bin/env bash
set -euo pipefail

printf 'ok completed: BUZZ_CI_ATTEMPT=%s\n' "${BUZZ_CI_ATTEMPT:?runner must inject BUZZ_CI_ATTEMPT}"

