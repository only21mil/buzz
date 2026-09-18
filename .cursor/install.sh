#!/usr/bin/env bash
# Cloud-agent and fresh-clone toolchain setup. Safe to run repeatedly.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${ROOT}/bin:${PATH}"

if [[ ! -x "${ROOT}/bin/hermit" ]]; then
  echo "Error: Hermit not found at ${ROOT}/bin/hermit" >&2
  exit 1
fi

if "${ROOT}/bin/hermit" noop >/dev/null 2>&1; then
  eval "$("${ROOT}/bin/hermit" activate "${ROOT}")"
fi

# True when $1 >= $2 (numeric semver components; portable, no GNU sort -V).
version_ge() {
  local actual="$1"
  local minimum="$2"
  local IFS=.
  local -a a=($actual) b=($minimum)
  local max=${#a[@]}
  if (( ${#b[@]} > max )); then
    max=${#b[@]}
  fi
  local i av bv
  for ((i = 0; i < max; i++)); do
    av=${a[i]:-0}
    bv=${b[i]:-0}
    av=${av%%[^0-9]*}
    bv=${bv%%[^0-9]*}
    if ((10#$av > 10#$bv)); then
      return 0
    fi
    if ((10#$av < 10#$bv)); then
      return 1
    fi
  done
  return 0
}

# rustc/cargo print "tool X.Y.Z (...)"; node prints "vX.Y.Z"; pnpm prints "X.Y.Z".
extract_version() {
  local raw="$1"
  if [[ "$raw" == *" "* ]]; then
    echo "$raw" | awk '{print $2}'
  else
    echo "${raw#v}"
  fi
}

require_min_version() {
  local label="$1"
  local actual="$2"
  local minimum="$3"
  if ! version_ge "$actual" "$minimum"; then
    echo "Error: ${label} ${actual} is below the required minimum (${minimum}+)." >&2
    exit 1
  fi
}

echo "Ensuring toolchain via Hermit..."
cargo --version &
node --version &
pnpm --version &
wait

RUST_VERSION="$(extract_version "$(rustc --version)")"
NODE_VERSION="$(extract_version "$(node --version)")"
PNPM_VERSION="$(extract_version "$(pnpm --version)")"

require_min_version "rustc" "$RUST_VERSION" "1.88"
require_min_version "node" "$NODE_VERSION" "24"
require_min_version "pnpm" "$PNPM_VERSION" "10"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example. Review it before running just dev."
  echo "Relay startup also needs BUZZ_RELAY_PRIVATE_KEY from your protected environment."
fi

if ! command -v docker &>/dev/null; then
  echo ""
  echo "Docker is not installed. Toolchain setup finished; just setup still needs Docker"
  echo "for Postgres, Redis, and other dev services."
  echo "Install from https://docs.docker.com/get-docker/ then run: just setup"
elif ! docker info &>/dev/null 2>&1; then
  echo ""
  echo "Docker is installed but the daemon is not running. Start Docker, then run: just setup"
else
  echo "Docker is available. Run just setup to start dev services and apply migrations."
fi
