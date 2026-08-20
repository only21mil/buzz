#!/usr/bin/env bash
set -euo pipefail

# workflow.yml gives this job a one-minute timeout; the default sleep is
# deliberately longer. The runner, rather than this script, owns timed_out.
sleep "${BUZZ_CI_SLOWPOKE_SECONDS:-65}"
printf 'slowpoke unexpectedly completed\n'

