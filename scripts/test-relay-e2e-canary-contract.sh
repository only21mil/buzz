#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
contract_script="$repo_root/scripts/test-relay-e2e-canary-contract.sh"
workflow=${RELAY_E2E_CANARY_WORKFLOW:-"$repo_root/.github/workflows/relay_e2e_canary.yml"}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT

fail() {
  echo "relay_e2e_canary contract failed: $*" >&2
  exit 1
}

expected="$scratch/expected.yml"
cat >"$expected" <<'YAML'
name: relay_e2e_canary

on:
  workflow_dispatch:

permissions: {}

jobs:
  relay_e2e_canary:
    name: relay_e2e_canary
    runs-on: ubuntu-24.04
    timeout-minutes: 2
    steps:
      - name: Exercise protected rerun semantics
        env:
          RUN_ATTEMPT: ${{ github.run_attempt }}
        run: |
          set -euo pipefail
          case "$RUN_ATTEMPT" in
            1)
              echo "expected attempt 1 failure" >&2
              exit 1
              ;;
            2)
              echo "expected attempt 2 success"
              ;;
            *)
              echo "unexpected run attempt: $RUN_ATTEMPT" >&2
              exit 1
              ;;
          esac
YAML

[[ -f "$workflow" && ! -L "$workflow" ]] || fail "workflow must be a regular file"
cmp -s -- "$expected" "$workflow" || fail "workflow bytes differ from the closed fixture"

# The closed fixture contains no action, credential, publication, artifact,
# checkout, or declared network operation. Keep this explicit so a future
# extension must change both the workflow and its reviewed contract.
if grep -Eiq \
  '(^|[^[:alnum:]_])(secrets\.|uses:|actions/checkout|https?://|curl|wget|\bgh[[:space:]]|\bgit[[:space:]]|\bssh\b|\bnc\b|socat|docker|artifact|upload|download|packages:[[:space:]]*write|contents:[[:space:]]*write)' \
  "$workflow"; then
  fail "workflow gained a forbidden credential, action, network operation, artifact, or write operation"
fi

[[ "$(grep -Fxc 'name: relay_e2e_canary' "$workflow")" -eq 1 ]] || \
  fail "workflow name must be exactly relay_e2e_canary"
[[ "$(grep -Fxc '  relay_e2e_canary:' "$workflow")" -eq 1 ]] || \
  fail "job id must be exactly relay_e2e_canary"
[[ "$(grep -Fxc '    name: relay_e2e_canary' "$workflow")" -eq 1 ]] || \
  fail "job display name must be exactly relay_e2e_canary"
[[ "$(grep -Fxc '  workflow_dispatch:' "$workflow")" -eq 1 ]] || \
  fail "workflow_dispatch must be the sole trigger"
[[ "$(grep -Ec '^  (push|pull_request|schedule|repository_dispatch|workflow_call):' "$workflow" || true)" -eq 0 ]] || \
  fail "workflow gained a non-manual trigger"
[[ "$(grep -Fxc 'permissions: {}' "$workflow")" -eq 1 ]] || \
  fail "workflow must declare an empty permission set"
[[ "$(grep -Ec '^  [a-z-]+: (read|write)$' "$workflow" || true)" -eq 0 ]] || \
  fail "workflow gained a token permission"
[[ "$(grep -Fxc '    runs-on: ubuntu-24.04' "$workflow")" -eq 1 ]] || \
  fail "runner must be ubuntu-24.04"
[[ "$(grep -Fxc '    timeout-minutes: 2' "$workflow")" -eq 1 ]] || \
  fail "timeout must be two minutes"
# shellcheck disable=SC2016 # Match the literal GitHub expression; do not expand it in Bash.
[[ "$(grep -Fxc '          RUN_ATTEMPT: ${{ github.run_attempt }}' "$workflow")" -eq 1 ]] || \
  fail "run attempt must come only from github.run_attempt"

attempt_script="$scratch/attempt.sh"
sed -n '/^        run: |$/,$p' "$workflow" | tail -n +2 | sed 's/^          //' >"$attempt_script"
chmod 0700 "$attempt_script"

run_attempt() {
  local attempt=$1
  local expected_status=$2
  local actual_status

  set +e
  RUN_ATTEMPT="$attempt" bash "$attempt_script" >"$scratch/attempt-$attempt.stdout" 2>"$scratch/attempt-$attempt.stderr"
  actual_status=$?
  set -e
  [[ "$actual_status" -eq "$expected_status" ]] || \
    fail "attempt $attempt exited $actual_status, expected $expected_status"
}

run_attempt 1 1
run_attempt 2 0
run_attempt 3 1

if [[ ${RELAY_E2E_CANARY_SKIP_MUTATION_PROBES:-0} != 1 ]]; then
  mutated="$scratch/mutated.yml"
  removed="$scratch/removed.yml"
  sed 's/name: relay_e2e_canary/name: relay-e2e-canary/' "$workflow" >"$mutated"
  sed '/^  workflow_dispatch:$/d' "$workflow" >"$removed"

  if RELAY_E2E_CANARY_WORKFLOW="$mutated" RELAY_E2E_CANARY_SKIP_MUTATION_PROBES=1 \
    bash "$contract_script" >"$scratch/mutated.log" 2>&1; then
    fail "contract accepted a mutated workflow name"
  fi
  if RELAY_E2E_CANARY_WORKFLOW="$removed" RELAY_E2E_CANARY_SKIP_MUTATION_PROBES=1 \
    bash "$contract_script" >"$scratch/removed.log" 2>&1; then
    fail "contract accepted a removed workflow_dispatch trigger"
  fi
fi

echo "relay_e2e_canary workflow contract passed"
