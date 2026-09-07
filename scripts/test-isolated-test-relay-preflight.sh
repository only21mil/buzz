#!/usr/bin/env bash
# Exercise only preflight paths, with no real service or schema commands.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
fixture="$test_root/repo"
mock_bin="$test_root/bin"
mkdir -p "$fixture/scripts" "$mock_bin"
cp "$repo_root/scripts/start-isolated-test-relay.sh" \
  "$repo_root/scripts/require-relay-key.sh" "$fixture/scripts/"

# A closed PATH prevents the fixture from invoking any host service tools.
ln -s "$(command -v bash)" "$mock_bin/bash"
ln -s "$(command -v dirname)" "$mock_bin/dirname"
cat > "$mock_bin/lsof" <<'SH'
#!/usr/bin/env bash
printf 'lsof %s\n' "$*" >> "$ACTION_LOG"
exit "$LSOF_STATUS"
SH
cat > "$mock_bin/docker" <<'SH'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >> "$ACTION_LOG"
# Stop at the first backing-service action even when preflight succeeds.
exit 97
SH
chmod +x "$mock_bin/lsof" "$mock_bin/docker"

run_launcher() {
  : > "$test_root/actions"
  status=0
  env -i PATH="$mock_bin" ACTION_LOG="$test_root/actions" \
    LSOF_STATUS="$lsof_status" "$@" \
    bash "$fixture/scripts/start-isolated-test-relay.sh" \
    > "$test_root/output" 2>&1 || status=$?
}

assert_status() {
  if [[ "$status" -ne "$1" ]]; then
    printf 'Expected status %s, got %s\n' "$1" "$status" >&2
    cat "$test_root/output" >&2
    exit 1
  fi
}

lsof_status=0
run_launcher BUZZ_RELAY_PRIVATE_KEY=fixture-presence-value
assert_status 1
grep -Fq 'Port 3030 is already in use' "$test_root/output"
grep -Fq "exact 'Stop relay:' command printed by that launch" "$test_root/output"
printf '%s\n' 'lsof -nP -iTCP:3030 -sTCP:LISTEN' \
  'lsof -nP -iTCP:3030 -sTCP:LISTEN' > "$test_root/expected"
cmp "$test_root/expected" "$test_root/actions"
echo 'Occupied port: refused before any Docker or schema action'

lsof_status=1
run_launcher BUZZ_RELAY_PRIVATE_KEY=fixture-presence-value
assert_status 97
printf '%s\n' 'lsof -nP -iTCP:3030 -sTCP:LISTEN' \
  'docker compose -p buzz-harness -f docker-compose.harness.yml up -d' \
  > "$test_root/expected"
cmp "$test_root/expected" "$test_root/actions"
echo 'Free port: checked before the first mocked backing-service action'

rm "$mock_bin/lsof"
run_launcher BUZZ_RELAY_PRIVATE_KEY=fixture-presence-value
assert_status 1
grep -Fq 'lsof is required' "$test_root/output"
[[ ! -s "$test_root/actions" ]]
echo 'Missing lsof: refused before any Docker or schema action'

run_launcher
assert_status 1
grep -Fq 'BUZZ_RELAY_PRIVATE_KEY must be exported' "$test_root/output"
[[ ! -s "$test_root/actions" ]]
run_launcher BUZZ_RELAY_PRIVATE_KEY=
assert_status 1
grep -Fq 'BUZZ_RELAY_PRIVATE_KEY must be exported' "$test_root/output"
[[ ! -s "$test_root/actions" ]]
echo 'Missing and empty identity: refused before service preflight'

# The child shell expands the helper path and supplied identity.
# shellcheck disable=SC2016
env -i PATH="$mock_bin" BUZZ_RELAY_PRIVATE_KEY=fixture-presence-value \
  bash -c 'source "$1"; [[ "$BUZZ_RELAY_PRIVATE_KEY" == fixture-presence-value ]]' \
  bash "$fixture/scripts/require-relay-key.sh" > "$test_root/helper-output" 2>&1
[[ ! -s "$test_root/helper-output" ]]
echo 'Identity helper: supplied value preserved with no output'
