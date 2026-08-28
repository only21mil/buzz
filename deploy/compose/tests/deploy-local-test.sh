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
printf 'sudo %s\n' "$*" >>"${TEST_COMMAND_LOG}"
while [[ ${1:-} == --preserve-env=* ]]; do
  shift
done
unset BUZZ_IMAGE BUZZ_EXPECTED_IMAGE
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
  *" rev-parse --verify refs/remotes/origin/main"*) printf '%s\n' "${TEST_SOURCE_HEAD}" ;;
  *" rev-parse --verify HEAD"*) printf '%s\n' "${TEST_CHECKOUT_HEAD}" ;;
  *" rev-parse --verify "*|*" rev-parse HEAD "*) printf '%s\n' "${TEST_COMMIT}" ;;
  *" merge-base --is-ancestor "*) exit 0 ;;
  *" status --porcelain "*)
    [[ ${TEST_DIRTY_CHECKOUT} == 1 ]] && printf ' M deploy/compose/deploy-local.sh\n'
    exit 0
    ;;
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
  *" image inspect "*)
    if [[ ${TEST_SCENARIO} == manifest_list ]]; then
      printf 'sha256:3333333333333333333333333333333333333333333333333333333333333333\n'
    fi
    printf 'sha256:2222222222222222222222222222222222222222222222222222222222222222\n'
    ;;
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
  *" compose "*" config --images "*)
    if [[ ${TEST_SCENARIO} == wrong_resolved_image ]]; then
      printf 'ghcr.io/block/buzz:main\n'
    else
      printf 'postgres:16-alpine\n%s\nredis:7-alpine\n' "${BUZZ_IMAGE:-ghcr.io/block/buzz:main}"
    fi
    ;;
  *" compose "*" exec -T postgres sh -euc "*"pg_dump"*) printf 'stub custom dump\n' ;;
  *" compose "*" exec -T postgres sh -euc "*"psql"*)
    if [[ ${args} == *"to_regclass"* ]]; then
      if [[ ${TEST_SCENARIO} == boolean_true ]]; then
        printf '  true  \n'
      else
        printf 't\n'
      fi
    else
      case "${TEST_SCENARIO}" in
        rollback_refusal) printf '32|t\n' ;;
        boolean_false) printf '%s|false\n' "$(cat "${TEST_DB_STATE}")" ;;
        boolean_true) printf '%s|true\n' "$(cat "${TEST_DB_STATE}")" ;;
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
  local checkout_head=${test_commit} source_head=${test_commit} dirty_checkout=0
  local pre_freeze_head=${test_commit} protected_ci_head=${test_commit}
  local receipt_timestamp prior_migration_override=
  if [[ ${scenario} == post_swap_failure_unadvanced || ${scenario} == stalled_probe ]]; then
    initial_db=31
    prior_required_migration=31
  fi
  if [[ ${scenario} == manifest_list || ${scenario} == prior_override_required || \
    ${scenario} == prior_override_success || ${scenario} == prior_override_mismatch ]]; then
    initial_db=31
    prior_required_migration=31
  fi
  case "${scenario}" in
    stale_checkout) checkout_head=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    stale_source) source_head=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    dirty_checkout) dirty_checkout=1 ;;
    short_receipt) pre_freeze_head=aaaaaaaaaaaa ;;
    mismatched_receipt) protected_ci_head=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    prior_override_required) prior_required_migration=invalid ;;
    prior_override_success)
      prior_required_migration=invalid
      prior_migration_override=sha256:1111111111111111111111111111111111111111111111111111111111111111@31
      ;;
    prior_override_mismatch)
      prior_required_migration=invalid
      prior_migration_override=sha256:1111111111111111111111111111111111111111111111111111111111111111@30
      ;;
  esac
  receipt_timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  [[ ${scenario} == stale_receipt ]] && receipt_timestamp=2000-01-01T00:00:00Z

  mkdir -p "${case_dir}/bin" "${case_dir}/logs" "${case_dir}/build" "${case_dir}/repo"
  chmod 700 "${case_dir}"
  make_stubs "${case_dir}/bin"
  printf 'old\n' >"${case_dir}/container-state"
  printf '%d\n' "${initial_db}" >"${case_dir}/db-state"
  : >"${case_dir}/commands.log"
  : >"${case_dir}/compose.env"
  cat >"${case_dir}/pre-freeze-receipt.json" <<JSON
{
  "schema_version": 1,
  "source": "pre-freeze",
  "repository": "only21mil/buzz",
  "head_sha": "${pre_freeze_head}",
  "base_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "timestamp": "${receipt_timestamp}",
  "overall": "PASS",
  "checks": [{"name": "targeted", "status": "PASS"}]
}
JSON
  cat >"${case_dir}/protected-ci-receipt.json" <<JSON
{
  "schema_version": 1,
  "source": "protected-ci",
  "repository": "only21mil/buzz",
  "head_sha": "${protected_ci_head}",
  "timestamp": "${receipt_timestamp}",
  "overall": "PASS",
  "protected": true,
  "full_exact_head": true,
  "checks": [{"name": "full-exact-head", "status": "PASS"}]
}
JSON
  if [[ ${scenario} == dirty_receipt ]]; then
    chmod 666 "${case_dir}/protected-ci-receipt.json"
  fi
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
    TEST_CHECKOUT_HEAD="${checkout_head}" \
    TEST_SOURCE_HEAD="${source_head}" \
    TEST_DIRTY_CHECKOUT="${dirty_checkout}" \
    BUZZ_SECRET_ENV_FILE="${case_dir}/secrets.env" \
    BUZZ_COMPOSE_ENV_FILE="${case_dir}/compose.env" \
    BUZZ_PRE_FREEZE_RECEIPT="${case_dir}/pre-freeze-receipt.json" \
    BUZZ_PROTECTED_CI_RECEIPT="${case_dir}/protected-ci-receipt.json" \
    BUZZ_PRIOR_MIGRATION_OVERRIDE="${prior_migration_override}" \
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

run_local_image_case() {
  local scenario=$1 image=$2 expected_image=$3 expected=$4
  local case_dir=${scratch}/run-local-${scenario}
  mkdir -p "${case_dir}/bin"
  chmod 700 "${case_dir}"
  make_stubs "${case_dir}/bin"
  printf 'old\n' >"${case_dir}/container-state"
  printf '31\n' >"${case_dir}/db-state"
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
  if [[ ${image} == __unset__ ]]; then
    env -u BUZZ_IMAGE \
      PATH="${case_dir}/bin:${PATH}" \
      TEST_SCENARIO="${scenario}" \
      TEST_COMMAND_LOG="${case_dir}/commands.log" \
      TEST_CONTAINER_STATE="${case_dir}/container-state" \
      TEST_DB_STATE="${case_dir}/db-state" \
      TEST_PRIOR_REQUIRED_MIGRATION=31 \
      BUZZ_SECRET_ENV_FILE="${case_dir}/secrets.env" \
      BUZZ_COMPOSE_ENV_FILE="${case_dir}/compose.env" \
      BUZZ_EXPECTED_IMAGE="${expected_image}" \
      "${compose_dir}/run-local.sh" ps -q relay >"${case_dir}/output" 2>&1
  else
    PATH="${case_dir}/bin:${PATH}" \
      TEST_SCENARIO="${scenario}" \
      TEST_COMMAND_LOG="${case_dir}/commands.log" \
      TEST_CONTAINER_STATE="${case_dir}/container-state" \
      TEST_DB_STATE="${case_dir}/db-state" \
      TEST_PRIOR_REQUIRED_MIGRATION=31 \
      BUZZ_SECRET_ENV_FILE="${case_dir}/secrets.env" \
      BUZZ_COMPOSE_ENV_FILE="${case_dir}/compose.env" \
      BUZZ_IMAGE="${image}" \
      BUZZ_EXPECTED_IMAGE="${expected_image}" \
      "${compose_dir}/run-local.sh" ps -q relay >"${case_dir}/output" 2>&1
  fi
  local rc=$?
  set -e
  if [[ ${expected} == success && ${rc} -ne 0 ]]; then
    sed -n '1,160p' "${case_dir}/output" >&2
    fail "run-local ${scenario} returned ${rc}, expected success"
  fi
  if [[ ${expected} == failure && ${rc} -eq 0 ]]; then
    fail "run-local ${scenario} succeeded, expected failure"
  fi
}

for early_failure in stale_checkout stale_source dirty_checkout dirty_receipt \
  short_receipt mismatched_receipt stale_receipt; do
  run_case "${early_failure}" failure
  assert_not_contains "${scratch}/${early_failure}/commands.log" '^docker '
done
assert_contains "${scratch}/stale_checkout/output" 'source checkout is at'
assert_contains "${scratch}/stale_source/output" 'source ref .* expected'
assert_contains "${scratch}/dirty_checkout/output" 'source checkout is dirty'
assert_contains "${scratch}/dirty_receipt/output" 'group- or world-writable'
assert_contains "${scratch}/short_receipt/output" 'head_sha must be a full 40-character'
assert_contains "${scratch}/mismatched_receipt/output" 'does not match the requested commit'
assert_contains "${scratch}/stale_receipt/output" 'receipt is stale'

run_local_image_case missing __unset__ localhost/buzz-relay:${test_commit} failure
assert_contains "${scratch}/run-local-missing/output" 'BUZZ_IMAGE is required'
assert_not_contains "${scratch}/run-local-missing/commands.log" '^docker '

run_local_image_case default ghcr.io/block/buzz:main ghcr.io/block/buzz:main failure
assert_contains "${scratch}/run-local-default/output" 'deployment image must be pinned'
assert_not_contains "${scratch}/run-local-default/commands.log" '^docker '

run_local_image_case wrong_resolved_image localhost/buzz-relay:${test_commit} \
  localhost/buzz-relay:${test_commit} failure
assert_contains "${scratch}/run-local-wrong_resolved_image/output" \
  'Compose did not resolve the expected deployment image'
assert_not_contains "${scratch}/run-local-wrong_resolved_image/commands.log" ' ps -q relay'

run_local_image_case pinned localhost/buzz-relay:${test_commit} \
  localhost/buzz-relay:${test_commit} success
assert_contains "${scratch}/run-local-pinned/commands.log" \
  'sudo .*env BUZZ_IMAGE=localhost/buzz-relay:'
assert_contains "${scratch}/run-local-pinned/commands.log" \
  'docker BUZZ_IMAGE=localhost/buzz-relay:.* ps -q relay'

run_case migration_fail failure
assert_contains "${scratch}/migration_fail/output" 'migration command failed'
assert_not_contains "${scratch}/migration_fail/commands.log" ' up -d --no-deps --force-recreate relay'

run_case rollback_refusal failure
assert_contains "${scratch}/rollback_refusal/output" 'database migration 32 is newer than image requirement 31'
assert_not_contains "${scratch}/rollback_refusal/commands.log" ' run --rm --no-deps '
assert_not_contains "${scratch}/rollback_refusal/commands.log" ' up -d --no-deps --force-recreate relay'

run_case boolean_false failure
assert_contains "${scratch}/boolean_false/output" 'success=false'
assert_not_contains "${scratch}/boolean_false/commands.log" ' up -d --no-deps --force-recreate relay'

run_case boolean_true success
assert_contains "${scratch}/boolean_true/output" 'DEPLOY SUCCEEDED'

run_case manifest_list success
assert_contains "${scratch}/manifest_list/output" 'DEPLOY SUCCEEDED'

run_case prior_override_success success
assert_contains "${scratch}/prior_override_success/output" 'migration override accepted'

run_case prior_override_required failure
assert_contains "${scratch}/prior_override_required/output" \
  'BUZZ_PRIOR_MIGRATION_OVERRIDE=sha256:1111111111111111111111111111111111111111111111111111111111111111@31'
assert_not_contains "${scratch}/prior_override_required/commands.log" \
  ' up -d --no-deps --force-recreate relay'

run_case prior_override_mismatch failure
assert_contains "${scratch}/prior_override_mismatch/output" \
  'BUZZ_PRIOR_MIGRATION_OVERRIDE must match'
assert_not_contains "${scratch}/prior_override_mismatch/commands.log" \
  ' up -d --no-deps --force-recreate relay'

run_case healthy success
healthy_log=${scratch}/healthy/commands.log
dump_line=$(grep -n '^docker .*exec -T postgres sh -euc.*pg_dump' "${healthy_log}" | head -1 | cut -d: -f1)
migrate_line=$(grep -n '^docker .*run --rm --no-deps.*buzz-admin relay migrate' "${healthy_log}" | head -1 | cut -d: -f1)
swap_line=$(grep -n '^docker .*up -d --no-deps --force-recreate relay' "${healthy_log}" | head -1 | cut -d: -f1)
[[ -n ${dump_line} && -n ${migrate_line} && -n ${swap_line} ]] || fail 'healthy path did not run dump, migrate, and swap'
((dump_line < migrate_line && migrate_line < swap_line)) || fail 'healthy ordering is not dump before migrate before swap'
assert_contains "${scratch}/healthy/output" 'DEPLOY SUCCEEDED'

run_case post_swap_failure failure
assert_contains "${scratch}/post_swap_failure/output" 'AUTOMATIC ROLLBACK REFUSED: database migration 31 exceeds prior image requirement 28'
assert_contains "${scratch}/post_swap_failure/output" 'Database dump: .*/buzz-prod-before-.*[.]dump'
assert_contains "${scratch}/post_swap_failure/output" 'LOUD STOP: do not restore the prior image'
swap_count=$(grep -c '^docker .*up -d --no-deps --force-recreate relay' "${scratch}/post_swap_failure/commands.log")
[[ ${swap_count} -eq 1 ]] || fail "post-swap failure made ${swap_count} recreate calls, expected 1"
assert_not_contains "${scratch}/post_swap_failure/commands.log" 'BUZZ_IMAGE=localhost/buzz-relay:rollback-'

run_case post_swap_failure_unadvanced failure
assert_contains "${scratch}/post_swap_failure_unadvanced/output" 'ROLLBACK SUCCEEDED'
assert_contains "${scratch}/post_swap_failure_unadvanced/output" 'prior service was restored'
unadvanced_swap_count=$(grep -c '^docker .*up -d --no-deps --force-recreate relay' "${scratch}/post_swap_failure_unadvanced/commands.log")
[[ ${unadvanced_swap_count} -eq 2 ]] || fail "unadvanced post-swap failure made ${unadvanced_swap_count} recreate calls, expected 2"
assert_contains "${scratch}/post_swap_failure_unadvanced/commands.log" 'BUZZ_IMAGE=localhost/buzz-relay:rollback-'

run_case stalled_probe failure
assert_contains "${scratch}/stalled_probe/output" 'ROLLBACK SUCCEEDED'
assert_contains "${scratch}/stalled_probe/output" 'prior service was restored'
stalled_swap_count=$(grep -c '^docker .*up -d --no-deps --force-recreate relay' "${scratch}/stalled_probe/commands.log")
[[ ${stalled_swap_count} -eq 2 ]] || fail "stalled probe made ${stalled_swap_count} recreate calls, expected 2"
assert_contains "${scratch}/stalled_probe/commands.log" 'BUZZ_IMAGE=localhost/buzz-relay:rollback-'

for secret_value in test-relay-key test-hook-secret test-postgres-password \
  test-redis-password test-s3-access test-s3-secret test-owner-pubkey; do
  if rg -F "${secret_value}" "${scratch}" --glob output --glob commands.log >/dev/null; then
    fail "secret value appeared in output or command logs: ${secret_value}"
  fi
done

printf 'PASS: deploy-local stubbed scenarios\n'
