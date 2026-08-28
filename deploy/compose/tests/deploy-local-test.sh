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
prior_id=sha256:1111111111111111111111111111111111111111111111111111111111111111
new_id=sha256:2222222222222222222222222222222222222222222222222222222222222222
mismatch_id=sha256:9999999999999999999999999999999999999999999999999999999999999999

case "${args}" in
  *" build "*) exit 0 ;;
  *" image inspect localhost/buzz-relay:${TEST_COMMIT:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa} "*)
    if [[ ${TEST_SCENARIO} == manifest_list ]]; then
      printf 'sha256:3333333333333333333333333333333333333333333333333333333333333333\n'
    fi
    printf 'sha256:2222222222222222222222222222222222222222222222222222222222222222\n'
    ;;
  *" image inspect ${prior_id} "*)
    case "${TEST_SCENARIO}" in
      prior_child_uninspectable_valid_ref|prior_ref_platform_mismatch|prior_ref_revision_mismatch|prior_image_unavailable)
        exit 1
        ;;
    esac
    printf '%s\n' "${prior_id}"
    ;;
  *" image tag "*) exit 0 ;;
  *"org.opencontainers.image.revision"*)
    target=${!#}
    if [[ ${TEST_SCENARIO} == prior_ref_revision_mismatch && ${target} != relay-old ]]; then
      printf 'dddddddddddddddddddddddddddddddddddddddd\n'
    else
      printf 'cccccccccccccccccccccccccccccccccccccccc\n'
    fi
    ;;
  *"org.block.buzz.required-migration"*)
    if [[ ${TEST_SCENARIO} == prior_label_inspect_failure* ]]; then
      exit 26
    fi
    printf '%s\n' "${TEST_PRIOR_REQUIRED_MIGRATION}"
    ;;
  *" inspect --format {{.Image}} "*)
    target=${!#}
    case "${target}" in
      relay-old|relay-rollback) printf '%s\n' "${prior_id}" ;;
      relay-new) printf '%s\n' "${new_id}" ;;
      *)
        create_count=$(cat "${TEST_VERIFY_CREATE_COUNT}")
        case "${TEST_SCENARIO}:${create_count}" in
          prior_ref_platform_mismatch:*|explicit_platform_mismatch:*|post_create_validation_failure:*|rollback_revalidation_mismatch:2)
            printf '%s\n' "${mismatch_id}"
            ;;
          *) printf '%s\n' "${prior_id}" ;;
        esac
        ;;
    esac
    ;;
  *" inspect --format {{.Config.Image}} "*)
    case "${TEST_SCENARIO}" in
      prior_ref_bare) printf 'localhost/buzz-relay\n' ;;
      prior_ref_main) printf 'localhost/buzz-relay:main\n' ;;
      prior_ref_latest) printf 'localhost/buzz-relay:latest\n' ;;
      prior_ref_leading_option) printf '%s\n' '--pull=always' ;;
      prior_ref_malformed) printf 'localhost//buzz-relay:old\n' ;;
      *) printf 'localhost/buzz-relay:old\n' ;;
    esac
    ;;
  *" create --pull=never "*)
    if [[ ${TEST_SCENARIO} == prior_image_unavailable ]]; then
      exit 1
    fi
    create_count=$(( $(cat "${TEST_VERIFY_CREATE_COUNT}") + 1 ))
    printf '%d\n' "${create_count}" >"${TEST_VERIFY_CREATE_COUNT}"
    case "${TEST_SCENARIO}" in
      create_stdout_empty) ;;
      create_stdout_contaminated)
        printf 'unexpected create output\n%064x\n' "${create_count}"
        ;;
      *) printf '%064x\n' "${create_count}" ;;
    esac
    ;;
  *" cp "*)
    source=$2
    destination=$3
    if [[ ${TEST_SCENARIO} == verification_copy_failure && ${source} != relay-old:* ]]; then
      exit 23
    fi
    case "${source}" in
      relay-new:*) printf 'new relay binary\n' >"${destination}" ;;
      *) printf 'prior relay binary\n' >"${destination}" ;;
    esac
    ;;
  *" rm -v "*)
    remove_count=$(( $(cat "${TEST_VERIFY_REMOVE_COUNT}") + 1 ))
    printf '%d\n' "${remove_count}" >"${TEST_VERIFY_REMOVE_COUNT}"
    if [[ (${TEST_SCENARIO} == verification_remove_failure && ${remove_count} -eq 1) || \
      (${TEST_SCENARIO} == rollback_verification_remove_failure && ${remove_count} -eq 2) ]]; then
      exit 24
    fi
    printf '%s\n' "${!#}"
    ;;
  *" exec "*" bash -ec "*)
    if [[ (${TEST_SCENARIO} == post_swap_failure* || \
      ${TEST_SCENARIO} == rollback_revalidation_mismatch || \
      ${TEST_SCENARIO} == rollback_db_read_* || \
      ${TEST_SCENARIO} == rollback_verification_remove_failure) && ${state} == new ]]; then
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
  *" compose "*" config --format json "*)
    case "${TEST_SCENARIO}" in
      explicit_platform|explicit_platform_mismatch)
        printf '{"services":{"relay":{"platform":"linux/amd64"}}}\n'
        ;;
      malformed_platform)
        printf '{"services":{"relay":{"platform":"linux/amd64;bad"}}}\n'
        ;;
      *) printf '{"services":{"relay":{}}}\n' ;;
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
      db_read_count=$(( $(cat "${TEST_DB_READ_COUNT}") + 1 ))
      printf '%d\n' "${db_read_count}" >"${TEST_DB_READ_COUNT}"
      case "${TEST_SCENARIO}:${db_read_count}" in
        rollback_db_read_failure:2) exit 25 ;;
        rollback_db_read_empty:2|db_marker_empty:*) ;;
        rollback_db_read_malformed:2|db_marker_malformed:*) printf 'unknown\n' ;;
        boolean_true:*) printf '  true  \n' ;;
        *) printf 't\n' ;;
      esac
    else
      case "${TEST_SCENARIO}" in
        db_row_empty) ;;
        db_row_malformed) printf '31|t|extra\n' ;;
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
  local receipt_timestamp prior_migration_override='' docker_default_platform=''
  if [[ ${scenario} == post_swap_failure_unadvanced || ${scenario} == stalled_probe || \
    ${scenario} == rollback_revalidation_mismatch || ${scenario} == rollback_db_read_* || \
    ${scenario} == rollback_verification_remove_failure ]]; then
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
    prior_override_with_valid_label)
      initial_db=31
      prior_required_migration=28
      prior_migration_override=sha256:1111111111111111111111111111111111111111111111111111111111111111@31
      ;;
    prior_label_inspect_failure_override)
      initial_db=31
      prior_migration_override=sha256:1111111111111111111111111111111111111111111111111111111111111111@31
      ;;
    docker_default_platform) docker_default_platform=linux/amd64 ;;
  esac
  receipt_timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  [[ ${scenario} == stale_receipt ]] && receipt_timestamp=2000-01-01T00:00:00Z

  mkdir -p "${case_dir}/bin" "${case_dir}/logs" "${case_dir}/build" "${case_dir}/repo"
  chmod 700 "${case_dir}"
  make_stubs "${case_dir}/bin"
  printf 'old\n' >"${case_dir}/container-state"
  printf '%d\n' "${initial_db}" >"${case_dir}/db-state"
  printf '0\n' >"${case_dir}/verify-create-count"
  printf '0\n' >"${case_dir}/verify-remove-count"
  printf '0\n' >"${case_dir}/db-read-count"
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
    TEST_DB_READ_COUNT="${case_dir}/db-read-count" \
    TEST_VERIFY_CREATE_COUNT="${case_dir}/verify-create-count" \
    TEST_VERIFY_REMOVE_COUNT="${case_dir}/verify-remove-count" \
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
    DOCKER_DEFAULT_PLATFORM="${docker_default_platform}" \
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
  printf '0\n' >"${case_dir}/verify-create-count"
  printf '0\n' >"${case_dir}/verify-remove-count"
  printf '0\n' >"${case_dir}/db-read-count"
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
      TEST_DB_READ_COUNT="${case_dir}/db-read-count" \
      TEST_VERIFY_CREATE_COUNT="${case_dir}/verify-create-count" \
      TEST_VERIFY_REMOVE_COUNT="${case_dir}/verify-remove-count" \
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
      TEST_DB_READ_COUNT="${case_dir}/db-read-count" \
      TEST_VERIFY_CREATE_COUNT="${case_dir}/verify-create-count" \
      TEST_VERIFY_REMOVE_COUNT="${case_dir}/verify-remove-count" \
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

for invalid_db_read in db_marker_empty db_marker_malformed db_row_empty db_row_malformed; do
  run_case "${invalid_db_read}" failure
  assert_not_contains "${scratch}/${invalid_db_read}/commands.log" ' run --rm --no-deps '
  assert_not_contains "${scratch}/${invalid_db_read}/commands.log" \
    ' up -d --no-deps --force-recreate relay'
done
assert_contains "${scratch}/db_marker_empty/output" \
  'database migration table marker is empty or malformed: <empty>'
assert_contains "${scratch}/db_marker_malformed/output" \
  'database migration table marker is empty or malformed: unknown'
assert_contains "${scratch}/db_row_empty/output" \
  'database latest-migration row is empty or malformed: <empty>'
assert_contains "${scratch}/db_row_malformed/output" \
  'database latest-migration row is empty or malformed: 31\|t\|extra'

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

run_case prior_override_with_valid_label failure
assert_contains "${scratch}/prior_override_with_valid_label/output" \
  'BUZZ_PRIOR_MIGRATION_OVERRIDE is not permitted because the prior image has valid required-migration label 28'
assert_not_contains "${scratch}/prior_override_with_valid_label/output" \
  'migration override accepted'
assert_not_contains "${scratch}/prior_override_with_valid_label/commands.log" \
  ' up -d --no-deps --force-recreate relay'

for label_inspect_failure in prior_label_inspect_failure \
  prior_label_inspect_failure_override; do
  run_case "${label_inspect_failure}" failure
  assert_contains "${scratch}/${label_inspect_failure}/output" \
    'prior image required-migration label could not be inspected; rollback compatibility is unreadable and BUZZ_PRIOR_MIGRATION_OVERRIDE is not permitted'
  assert_not_contains "${scratch}/${label_inspect_failure}/commands.log" \
    'exec -T postgres sh -euc.*pg_dump'
  assert_not_contains "${scratch}/${label_inspect_failure}/commands.log" \
    ' run --rm --no-deps '
  assert_not_contains "${scratch}/${label_inspect_failure}/commands.log" \
    ' up -d --no-deps --force-recreate relay'
done
assert_not_contains "${scratch}/prior_label_inspect_failure_override/output" \
  'migration override accepted'

run_case prior_child_inspectable success
assert_contains "${scratch}/prior_child_inspectable/commands.log" \
  'image tag sha256:1111111111111111111111111111111111111111111111111111111111111111 localhost/buzz-relay:rollback-'
assert_contains "${scratch}/prior_child_inspectable/commands.log" \
  'create --pull=never --name buzz-rollback-verify-.* localhost/buzz-relay:rollback-'
assert_contains "${scratch}/prior_child_inspectable/commands.log" \
  'rm -v buzz-rollback-verify-.*-1'
assert_not_contains "${scratch}/prior_child_inspectable/commands.log" \
  'create --pull=never .* --platform '
inspectable_source=$(rg --files "${scratch}/prior_child_inspectable/logs" | \
  grep '/rollback-source[.]txt$')
assert_contains "${inspectable_source}" \
  '^sha256:1111111111111111111111111111111111111111111111111111111111111111$'
assert_contains "${scratch}/prior_child_inspectable/output" 'DEPLOY SUCCEEDED'

run_case prior_child_uninspectable_valid_ref success
assert_contains "${scratch}/prior_child_uninspectable_valid_ref/output" \
  'is not directly inspectable; binding configured image localhost/buzz-relay:old to its platform ID'
assert_contains "${scratch}/prior_child_uninspectable_valid_ref/commands.log" \
  'create --pull=never --name buzz-rollback-verify-.* localhost/buzz-relay:old'
assert_not_contains "${scratch}/prior_child_uninspectable_valid_ref/commands.log" \
  'image inspect localhost/buzz-relay:old'
assert_contains "${scratch}/prior_child_uninspectable_valid_ref/commands.log" \
  'image tag localhost/buzz-relay:old localhost/buzz-relay:rollback-'
fallback_source=$(rg --files "${scratch}/prior_child_uninspectable_valid_ref/logs" | \
  grep '/rollback-source[.]txt$')
fallback_source_id=$(rg --files "${scratch}/prior_child_uninspectable_valid_ref/logs" | \
  grep '/rollback-source-image-id[.]txt$')
assert_contains "${fallback_source}" '^localhost/buzz-relay:old$'
assert_contains "${fallback_source_id}" \
  '^sha256:1111111111111111111111111111111111111111111111111111111111111111$'
[[ $(cat "${scratch}/prior_child_uninspectable_valid_ref/verify-create-count") -eq 2 ]] || \
  fail 'valid configured ref did not create both source and retained-tag verification containers'
[[ $(cat "${scratch}/prior_child_uninspectable_valid_ref/verify-remove-count") -eq 2 ]] || \
  fail 'valid configured ref did not remove both stopped containers with their volumes'
assert_contains "${scratch}/prior_child_uninspectable_valid_ref/output" 'DEPLOY SUCCEEDED'

for bad_prior in prior_ref_platform_mismatch prior_ref_revision_mismatch prior_image_unavailable; do
  run_case "${bad_prior}" failure
  assert_not_contains "${scratch}/${bad_prior}/commands.log" 'exec -T postgres sh -euc.*pg_dump'
  assert_not_contains "${scratch}/${bad_prior}/commands.log" \
    ' up -d --no-deps --force-recreate relay'
done
assert_contains "${scratch}/prior_ref_platform_mismatch/output" \
  'resolves to platform image sha256:999999.*expected running image sha256:111111'
assert_contains "${scratch}/prior_ref_revision_mismatch/output" \
  'revision dddddddd.*does not match running container revision cccccccc'
assert_contains "${scratch}/prior_image_unavailable/output" \
  'is not directly inspectable; binding configured image'

for invalid_ref in prior_ref_bare prior_ref_main prior_ref_latest \
  prior_ref_leading_option prior_ref_malformed; do
  run_case "${invalid_ref}" failure
  assert_not_contains "${scratch}/${invalid_ref}/commands.log" ' create --pull=never '
  assert_not_contains "${scratch}/${invalid_ref}/commands.log" 'exec -T postgres sh -euc.*pg_dump'
done
assert_contains "${scratch}/prior_ref_bare/output" 'uses implicit latest'
assert_contains "${scratch}/prior_ref_main/output" 'forbidden mutable tag main'
assert_contains "${scratch}/prior_ref_latest/output" 'forbidden mutable tag latest'
assert_contains "${scratch}/prior_ref_leading_option/output" 'unsafe or empty configured image reference'
assert_contains "${scratch}/prior_ref_malformed/output" 'malformed configured image reference'

run_case verification_copy_failure failure
assert_contains "${scratch}/verification_copy_failure/commands.log" ' cp 0000000000000000000000000000000000000000000000000000000000000001:'
assert_contains "${scratch}/verification_copy_failure/commands.log" ' rm -v buzz-rollback-verify-.*-1'
assert_not_contains "${scratch}/verification_copy_failure/commands.log" 'exec -T postgres sh -euc.*pg_dump'

for create_failure in create_stdout_empty create_stdout_contaminated \
  post_create_validation_failure; do
  run_case "${create_failure}" failure
  assert_contains "${scratch}/${create_failure}/commands.log" \
    ' create --pull=never --name buzz-rollback-verify-.*-1 localhost/buzz-relay:rollback-'
  assert_contains "${scratch}/${create_failure}/commands.log" \
    ' rm -v buzz-rollback-verify-.*-1'
  assert_not_contains "${scratch}/${create_failure}/commands.log" \
    'exec -T postgres sh -euc.*pg_dump'
  assert_not_contains "${scratch}/${create_failure}/commands.log" \
    ' run --rm --no-deps '
  assert_not_contains "${scratch}/${create_failure}/commands.log" \
    ' up -d --no-deps --force-recreate relay'
done
assert_contains "${scratch}/create_stdout_empty/output" \
  'docker create returned an invalid verification container ID:'
assert_contains "${scratch}/create_stdout_contaminated/output" \
  'docker create returned an invalid verification container ID: unexpected create output'
assert_contains "${scratch}/post_create_validation_failure/output" \
  'resolves to platform image sha256:999999.*expected running image sha256:111111'

run_case verification_remove_failure failure
[[ $(cat "${scratch}/verification_remove_failure/verify-remove-count") -eq 2 ]] || \
  fail 'failed immediate verification cleanup was not retried by EXIT cleanup'
assert_contains "${scratch}/verification_remove_failure/output" \
  'could not remove stopped verification container'
assert_not_contains "${scratch}/verification_remove_failure/commands.log" 'exec -T postgres sh -euc.*pg_dump'

run_case explicit_platform success
assert_contains "${scratch}/explicit_platform/commands.log" \
  'create --pull=never --name buzz-rollback-verify-.* --platform linux/amd64 localhost/buzz-relay:rollback-'

for bad_platform in explicit_platform_mismatch malformed_platform docker_default_platform; do
  run_case "${bad_platform}" failure
  assert_not_contains "${scratch}/${bad_platform}/commands.log" 'exec -T postgres sh -euc.*pg_dump'
done
assert_contains "${scratch}/explicit_platform_mismatch/output" 'resolves to platform image sha256:999999'
assert_contains "${scratch}/malformed_platform/output" 'invalid relay service platform'
assert_contains "${scratch}/docker_default_platform/output" 'DOCKER_DEFAULT_PLATFORM is set'

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
[[ $(cat "${scratch}/post_swap_failure_unadvanced/verify-create-count") -eq 2 ]] || \
  fail 'rollback path did not re-create a stopped container for retained-tag revalidation'
revalidate_line=$(grep -n 'create --pull=never .*localhost/buzz-relay:rollback-' \
  "${scratch}/post_swap_failure_unadvanced/commands.log" | tail -1 | cut -d: -f1)
rollback_swap_line=$(grep -n 'BUZZ_IMAGE=localhost/buzz-relay:rollback-.* up -d --no-deps --force-recreate relay' \
  "${scratch}/post_swap_failure_unadvanced/commands.log" | head -1 | cut -d: -f1)
[[ -n ${revalidate_line} && -n ${rollback_swap_line} && ${revalidate_line} -lt ${rollback_swap_line} ]] || \
  fail 'retained rollback tag was not revalidated immediately before Compose rollback'

run_case rollback_revalidation_mismatch failure
assert_contains "${scratch}/rollback_revalidation_mismatch/output" \
  'AUTOMATIC ROLLBACK REFUSED: retained rollback image identity could not be verified'
rollback_mismatch_swap_count=$(grep -c '^docker .*up -d --no-deps --force-recreate relay' \
  "${scratch}/rollback_revalidation_mismatch/commands.log")
[[ ${rollback_mismatch_swap_count} -eq 1 ]] || \
  fail "rollback revalidation mismatch made ${rollback_mismatch_swap_count} recreate calls, expected 1"
assert_not_contains "${scratch}/rollback_revalidation_mismatch/commands.log" \
  'BUZZ_IMAGE=localhost/buzz-relay:rollback-.* up -d'

for rollback_db_failure in rollback_db_read_failure rollback_db_read_empty \
  rollback_db_read_malformed; do
  run_case "${rollback_db_failure}" failure
  assert_contains "${scratch}/${rollback_db_failure}/output" \
    'AUTOMATIC ROLLBACK REFUSED: could not read the database migration state'
  assert_contains "${scratch}/${rollback_db_failure}/output" \
    'LOUD FAILURE: deploy failed and automatic rollback did not recover service'
  rollback_db_swap_count=$(grep -c '^docker .*up -d --no-deps --force-recreate relay' \
    "${scratch}/${rollback_db_failure}/commands.log")
  [[ ${rollback_db_swap_count} -eq 1 ]] || \
    fail "${rollback_db_failure} made ${rollback_db_swap_count} recreate calls, expected 1"
  assert_not_contains "${scratch}/${rollback_db_failure}/commands.log" \
    'BUZZ_IMAGE=localhost/buzz-relay:rollback-.* up -d'
done
assert_contains "${scratch}/rollback_db_read_failure/output" \
  'database migration table-marker query failed'
assert_contains "${scratch}/rollback_db_read_empty/output" \
  'database migration table marker is empty or malformed: <empty>'
assert_contains "${scratch}/rollback_db_read_malformed/output" \
  'database migration table marker is empty or malformed: unknown'

run_case rollback_verification_remove_failure failure
assert_contains "${scratch}/rollback_verification_remove_failure/output" \
  'AUTOMATIC ROLLBACK REFUSED: rollback image identity passed, but its stopped verification container and anonymous volumes could not be removed'
assert_not_contains "${scratch}/rollback_verification_remove_failure/output" \
  'retained rollback image identity could not be verified'
rollback_cleanup_swap_count=$(grep -c '^docker .*up -d --no-deps --force-recreate relay' \
  "${scratch}/rollback_verification_remove_failure/commands.log")
[[ ${rollback_cleanup_swap_count} -eq 1 ]] || \
  fail "rollback cleanup failure made ${rollback_cleanup_swap_count} recreate calls, expected 1"
[[ $(cat "${scratch}/rollback_verification_remove_failure/verify-remove-count") -eq 3 ]] || \
  fail 'rollback verification cleanup failure was not retried during EXIT cleanup'
assert_not_contains "${scratch}/rollback_verification_remove_failure/commands.log" \
  'BUZZ_IMAGE=localhost/buzz-relay:rollback-.* up -d'

run_case stalled_probe failure
assert_contains "${scratch}/stalled_probe/output" 'ROLLBACK SUCCEEDED'
assert_contains "${scratch}/stalled_probe/output" 'prior service was restored'
stalled_swap_count=$(grep -c '^docker .*up -d --no-deps --force-recreate relay' "${scratch}/stalled_probe/commands.log")
[[ ${stalled_swap_count} -eq 2 ]] || fail "stalled probe made ${stalled_swap_count} recreate calls, expected 2"
assert_contains "${scratch}/stalled_probe/commands.log" 'BUZZ_IMAGE=localhost/buzz-relay:rollback-'

assert_not_contains <(find "${scratch}" -name commands.log -type f -exec cat {} +) \
  'docker .* (exec|run).*sha256sum'
assert_not_contains <(find "${scratch}" -name commands.log -type f -exec cat {} +) \
  'docker .* start '

if find "${scratch}" -name '.relay-binary.*' -type f -print -quit | grep -q .; then
  fail 'temporary relay binary copy leaked into deployment evidence'
fi

for secret_value in test-relay-key test-hook-secret test-postgres-password \
  test-redis-password test-s3-access test-s3-secret test-owner-pubkey; do
  if rg -F "${secret_value}" "${scratch}" --glob output --glob commands.log >/dev/null; then
    fail "secret value appeared in output or command logs: ${secret_value}"
  fi
done

printf 'PASS: deploy-local stubbed scenarios\n'
