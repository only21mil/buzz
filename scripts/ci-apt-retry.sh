#!/usr/bin/env bash
# Retry an apt-backed install command with backoff.
#
# Usage: scripts/ci-apt-retry.sh <command> [args...]
#
# Each attempt refreshes the package lists, then runs the command. A transient
# mirror or lock failure retries after 20s, then 40s. The third failure fails
# the step. APT_RETRY_ATTEMPTS overrides the attempt count.

set -u -o pipefail

if [[ $# -eq 0 ]]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

attempts="${APT_RETRY_ATTEMPTS:-3}"
apt_options=(
    -o Acquire::Retries=3
    -o Acquire::http::Timeout=30
    -o Acquire::https::Timeout=30
)

for ((attempt = 1; attempt <= attempts; attempt++)); do
    if sudo apt-get update "${apt_options[@]}" && "$@"; then
        exit 0
    fi
    if (( attempt == attempts )); then
        echo "::error::apt install failed after ${attempts} attempts: $*" >&2
        exit 1
    fi
    delay=$((attempt * 20))
    echo "apt attempt ${attempt} of ${attempts} failed; retrying in ${delay}s" >&2
    sleep "${delay}"
done
