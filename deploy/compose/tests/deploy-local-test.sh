#!/usr/bin/env bash
set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
compose_dir=$(cd "${test_dir}/.." && pwd)
deploy_script=${compose_dir}/deploy-local.sh
test_commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
scratch_root=${TEST_TMP_ROOT:-${HOME}/work/buzz-relay-deploy-tests}
mkdir -p "${scratch_root}"
scratch=$(mktemp -d "${scratch_root}/stubbed.XXXXXX")
trap 'rm -rf "${scratch}"' EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local file=$1 pattern=$2
  grep -Eq "${pattern}" "${file}" || fail "${file} does not contain /${pattern}/"
}

assert_not_contains() {
  local file=$1 pattern=$2
  if grep -Eq "${pattern}" "${file}"; then
    fail "${file} unexpectedly contains /${pattern}/"
  fi
}

make_stubs() {
  local bin_dir=$1
  mkdir -p "${bin_dir}"

  cat >"${bin_dir}/sudo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
while [[ ${1:-} == --preserve-env=* ]]; do
  shift
done
exec "$@"
STUB

  cat >"${bin_dir}/git" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'git %s\n' "$*" >>"${TEST_COMMAND_LOG}"
args=" $* "
case "${args}" in
  *" rev-parse --show-toplevel "*) printf '%s\n' "${TEST_REPO_ROOT}" ;;
  *" cat-file -e "*) exit 0 ;;
  *" rev-parse --verify "*|*" rev-parse HEAD "*) printf '%s\n' "${TEST_COMMIT}" ;;
  *" status --porcelain "*) exit 0 ;;
  *" worktree add --detach "*)
    previous=
    for arg in "$@"; do
      if [[ ${previous} == --detach ]]; then
        mkdir -p "${arg}/migrations"
        : >"${arg}/migrations/0031_workflow_approval_foundations.sql"
        : >"${arg}/Dockerfile"
        exit 0
      fi
      previous=${arg}
    done
    exit 2
    ;;
  *" worktree remove --force "*) exit 0 ;;
  *) printf 'unexpected git invocation: %s\n' "$*" >&2; exit 90 ;;
esac
STUB

  cat >"${bin_dir}/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'docker BUZZ_IMAGE=%s %s\n' "${BUZZ_IMAGE:-}" "$*" >>"${TEST_COMMAND_LOG}"
args=" $* "
state=$(cat "${TEST_CONTAINER_STATE}")

case "${args}" in
  *" build "*) exit 0 ;;
  *" image inspect "*) printf 'sha256:2222222222222222222222222222222222222222222222222222222222222222\n' ;;
  *" image tag "*) exit 0 ;;
  *"org.block.buzz.required-migration"*) printf '%s\n' "${TEST_PRIOR_REQUIRED_MIGRATION}" ;;
  *" inspect --format {{.Image}} "*)
    case "${state}" in
      old|rollback) printf 'sha256:1111111111111111111111111111111111111111111111111111111111111111\n' ;;
      new) printf 'sha256:2222222222222222222222222222222222222222222222222222222222222222\n' ;;
    esac
    ;;
  *" inspect --format {{.Config.Image}} "*) printf 'localhost/buzz-relay:old\n' ;;
  *" exec "*" sha256sum /usr/local/bin/buzz-relay "*)
    case "${state}" in
      old|rollback) printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /usr/local/bin/buzz-relay\n' ;;
      new) printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /usr/local/bin/buzz-relay\n' ;;
    esac
    ;;
  *" exec "*" bash -ec "*)
    if [[ ${TEST_SCENARIO} == post_swap_failure* && ${state} == new ]]; then
      exit 1
    fi
    if [[ ${TEST_SCENARIO} == stalled_probe && ${state} == new ]]; then
      sleep 60
    fi
    exit 0
    ;;
  *" compose "*" ps -q relay "*)
    case "${state}" in
      old) printf 'relay-old\n' ;;
      new) printf 'relay-new\n' ;;
      rollback) printf 'relay-rollback\n' ;;
    esac
    ;;
  *" compose "*" exec -T postgres sh -euc "*"pg_dump"*) printf 'stub custom dump\n' ;;
  *" compose "*" exec -T postgres sh -euc "*"psql"*)
    if [[ ${args} == *"to_regclass"* ]]; then
      printf 't\n'
    else
      case "${TEST_SCENARIO}" in
        rollback_refusal) printf '32|t\n' ;;
        *) printf '%s|t\n' "$(cat "${TEST_DB_STATE}")" ;;
      esac
    fi
    ;;
  *" compose "*" run --rm --no-deps "*)
    if [[ ${TEST_SCENARIO} == migration_fail ]]; then
      exit 17
    fi
    printf '31\n' >"${TEST_DB_STATE}"
    exit 0
    ;;
  *" compose "*" up -d --no-deps --force-recreate relay "*)
    if [[ ${BUZZ_IMAGE:-} == *":rollback-"* ]]; then
      printf 'rollback\n' >"${TEST_CONTAINER_STATE}"
    else
      printf 'new\n' >"${TEST_CONTAINER_STATE}"
    fi
    exit 0
    ;;
  *) printf 'unexpected docker invocation: %s\n' "$*" >&2; exit 91 ;;
esac
STUB

  chmod 755 "${bin_dir}/sudo" "${bin_dir}/git" "${bin_dir}/docker"
}

run_case() {
  local scenario=$1 expected=$2
  local case_dir=${scratch}/${scenario}
  local initial_db=28 prior_required_migration=28
  if [[ ${scenario} == post_swap_failure_unadvanced || ${scenario} == stalled_probe ]]; then
    initial_db=31
    prior_required_migration=31
  fi
  mkdir -p "${case_dir}/bin" "${case_dir}/logs" "${case_dir}/build"
  chmod 700 "${case_dir}"
  make_stubs "${case_dir}/bin"
  printf 'old\n' >"${case_dir}/container-state"
  printf '%d\n' "${initial_db}" >"${case_dir}/db-state"
  : >"${case_dir}/commands.log"
  : >"${case_dir}/compose.env"
  cat >"${case_dir}/secrets.env" <<'ENV'
BUZZ_RELAY_PRIVATE_KEY=test-relay-key
BUZZ_GIT_HOOK_HMAC_SECRET=test-hook-secret
BUZZ_POSTGRES_PASSWORD=test-postgres-password
BUZZ_REDIS_PASSWORD=test-redis-password
BUZZ_S3_ACCESS_KEY=test-s3-access
BUZZ_S3_SECRET_KEY=test-s3-secret
BUZZ_RELAY_OWNER_PUBKEY=test-owner-pubkey
ENV
  chmod 600 "${case_dir}/secrets.env"

  set +e
  PATH="${case_dir}/bin:${PATH}" \
    TEST_SCENARIO=${scenario} \
    TEST_COMMAND_LOG="${case_dir}/commands.log" \
    TEST_CONTAINER_STATE="${case_dir}/container-state" \
    TEST_DB_STATE="${case_dir}/db-state" \
    TEST_PRIOR_REQUIRED_MIGRATION="${prior_required_migration}" \
    TEST_REPO_ROOT="${case_dir}/repo" \
    TEST_COMMIT=${test_commit} \
    BUZZ_SECRET_ENV_FILE="${case_dir}/secrets.env" \
    BUZZ_COMPOSE_ENV_FILE="${case_dir}/compose.env" \
    BUZZ_DEPLOY_LOG_ROOT="${case_dir}/logs" \
    BUZZ_DEPLOY_BUILD_ROOT="${case_dir}/build" \
    BUZZ_DEPLOY_HEALTH_ATTEMPTS=1 \
    BUZZ_DEPLOY_HEALTH_INTERVAL=0 \
    BUZZ_DEPLOY_PROBE_TIMEOUT=0.1 \
    "${deploy_script}" "${test_commit}" >"${case_dir}/output" 2>&1
  rc=$?
  set -e

  if [[ ${expected} == success && ${rc} -ne 0 ]]; then
    sed -n '1,240p' "${case_dir}/output" >&2
    fail "${scenario} returned ${rc}, expected success"
  fi
  if [[ ${expected} == failure && ${rc} -eq 0 ]]; then
    fail "${scenario} succeeded, expected failure"
  fi
}

run_case migration_fail failure
assert_contains "${scratch}/migration_fail/output" 'migration command failed'
assert_not_contains "${scratch}/migration_fail/commands.log" ' up -d --no-deps --force-recreate relay'

run_case rollback_refusal failure
assert_contains "${scratch}/rollback_refusal/output" 'database migration 32 is newer than image requirement 31'
assert_not_contains "${scratch}/rollback_refusal/commands.log" ' run --rm --no-deps '
assert_not_contains "${scratch}/rollback_refusal/commands.log" ' up -d --no-deps --force-recreate relay'

run_case healthy success
healthy_log=${scratch}/healthy/commands.log
dump_line=$(grep -n 'exec -T postgres sh -euc.*pg_dump' "${healthy_log}" | head -1 | cut -d: -f1)
migrate_line=$(grep -n 'run --rm --no-deps.*buzz-admin relay migrate' "${healthy_log}" | head -1 | cut -d: -f1)
swap_line=$(grep -n 'up -d --no-deps --force-recreate relay' "${healthy_log}" | head -1 | cut -d: -f1)
[[ -n ${dump_line} && -n ${migrate_line} && -n ${swap_line} ]] || fail 'healthy path did not run dump, migrate, and swap'
((dump_line < migrate_line && migrate_line < swap_line)) || fail 'healthy ordering is not dump before migrate before swap'
assert_contains "${scratch}/healthy/output" 'DEPLOY SUCCEEDED'

run_case post_swap_failure failure
assert_contains "${scratch}/post_swap_failure/output" 'AUTOMATIC ROLLBACK REFUSED: database migration 31 exceeds prior image requirement 28'
assert_contains "${scratch}/post_swap_failure/output" 'Database dump: .*/buzz-prod-before-.*[.]dump'
assert_contains "${scratch}/post_swap_failure/output" 'LOUD STOP: do not restore the prior image'
swap_count=$(grep -c 'up -d --no-deps --force-recreate relay' "${scratch}/post_swap_failure/commands.log")
[[ ${swap_count} -eq 1 ]] || fail "post-swap failure made ${swap_count} recreate calls, expected 1"
assert_not_contains "${scratch}/post_swap_failure/commands.log" 'BUZZ_IMAGE=localhost/buzz-relay:rollback-'

run_case post_swap_failure_unadvanced failure
assert_contains "${scratch}/post_swap_failure_unadvanced/output" 'ROLLBACK SUCCEEDED'
assert_contains "${scratch}/post_swap_failure_unadvanced/output" 'prior service was restored'
unadvanced_swap_count=$(grep -c 'up -d --no-deps --force-recreate relay' "${scratch}/post_swap_failure_unadvanced/commands.log")
[[ ${unadvanced_swap_count} -eq 2 ]] || fail "unadvanced post-swap failure made ${unadvanced_swap_count} recreate calls, expected 2"
assert_contains "${scratch}/post_swap_failure_unadvanced/commands.log" 'BUZZ_IMAGE=localhost/buzz-relay:rollback-'

run_case stalled_probe failure
assert_contains "${scratch}/stalled_probe/output" 'ROLLBACK SUCCEEDED'
assert_contains "${scratch}/stalled_probe/output" 'prior service was restored'
stalled_swap_count=$(grep -c 'up -d --no-deps --force-recreate relay' "${scratch}/stalled_probe/commands.log")
[[ ${stalled_swap_count} -eq 2 ]] || fail "stalled probe made ${stalled_swap_count} recreate calls, expected 2"
assert_contains "${scratch}/stalled_probe/commands.log" 'BUZZ_IMAGE=localhost/buzz-relay:rollback-'

printf 'PASS: deploy-local stubbed scenarios\n'
