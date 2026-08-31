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

assert_check_runtime_readonly() {
  local case_dir=$1 line
  while IFS= read -r line; do
    case "${line}" in
      docker\ *)
        [[ ${line} == *" DOCKER_HOST=unix://${case_dir}/docker.sock "* ]] || \
          fail "check Docker command was not bound to the validated socket: ${line}"
        case "${line}" in
          *" info --format {{.ServerVersion}}"|*" compose version --short"|\
          *" compose "*" ps -q relay"|*" compose "*" ps -q postgres"|\
          *" compose "*" config --format json"|\
          *" compose "*" ps --all --format json"|\
          *" inspect --format {{.Image}} "*|*" inspect --format {{.Config.Image}} "*|\
          *" inspect --format {{json .NetworkSettings.Networks}} "*|\
          *" inspect --format {{index .Config.Labels \"org.opencontainers.image.revision\"}} "*|\
          *" inspect --format {{json .ImageManifestDescriptor}} "*|\
          *" image inspect --platform linux/amd64 --format {{json .Descriptor}} "*|\
          *" image inspect --platform linux/amd64 --format {{.Id}} "*|\
          *" inspect --format {{index .Config.Labels \"org.block.buzz.required-migration\"}} "*) ;;
          *) fail "check used unapproved Docker argv: ${line}" ;;
        esac
        ;;
      curl\ *)
        case "${line}" in
          "curl --disable --noproxy * --fail --silent --show-error --unix-socket ${case_dir}/docker.sock --get --data-urlencode path=/usr/local/bin/buzz-relay http://localhost/containers/relay-old/archive"|\
          "curl --disable --noproxy * --fail --silent --show-error --max-time 0.1 http://172.30.0.2:8080/_readiness"|\
          "curl --disable --noproxy * --fail --silent --show-error --max-time 0.1 --header Accept: application/nostr+json http://172.30.0.2:3000/") ;;
          *) fail "check used unapproved host/archive curl argv: ${line}" ;;
        esac
        ;;
      psql\ *)
        [[ ${line} == *"PGCONNECT_TIMEOUT=5 PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000"* ]] || \
          fail "check psql did not force a read-only bounded session: ${line}"
        [[ ${line} == *"--host 172.30.0.3 --port 5432 --username buzz --dbname buzz --command BEGIN TRANSACTION READ ONLY;"*"; ROLLBACK;" ]] || \
          fail "check used unapproved psql argv: ${line}"
        ;;
    esac
  done <"${case_dir}/commands.log"
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
[[ ${GIT_OPTIONAL_LOCKS:-} == 0 ]] || {
  printf 'git invocation did not disable optional index locks\n' >&2
  exit 91
}
printf 'git %s\n' "$*" >>"${TEST_COMMAND_LOG}"
args=" $* "
case "${args}" in
  *" rev-parse --show-toplevel "*) printf '%s\n' "${TEST_REPO_ROOT}" ;;
  *" cat-file -e "*) exit 0 ;;
  *" rev-parse --verify refs/remotes/origin/main"*) printf '%s\n' "${TEST_SOURCE_HEAD}" ;;
  *" rev-parse --verify HEAD"*) printf '%s\n' "${TEST_CHECKOUT_HEAD}" ;;
  *" rev-parse --verify "*|*" rev-parse HEAD "*) printf '%s\n' "${TEST_COMMIT}" ;;
  *" merge-base --is-ancestor "*) exit 0 ;;
  *" check-ref-format "*) exit 0 ;;
  *" diff --quiet "*) exit 0 ;;
  *" ls-tree -r --name-only "*) printf 'migrations/0031_workflow_approval_foundations.sql\n' ;;
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

  cat >"${bin_dir}/stat" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
format=$2
target=$3
if [[ -n ${TEST_DOCKER_SOCKET:-} && ${target} == "${TEST_DOCKER_SOCKET}" ]]; then
  case "${format}" in
    %u) printf '0\n' ;;
    %G) printf 'docker\n' ;;
    %a) printf '660\n' ;;
    *) exit 92 ;;
  esac
  exit 0
fi
if [[ ${TEST_SCENARIO} == check_bad_owner && ${target} == "${BUZZ_COMPOSE_ENV_FILE}" && ${format} == %u ]]; then
  printf '99999\n'
  exit 0
fi
exec /usr/bin/stat "$@"
STUB

  local fs_command
  for fs_command in mkdir chmod mktemp rmdir rm tee; do
    cat >"${bin_dir}/${fs_command}" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
command_name=${0##*/}
printf 'fs %s %s\n' "${command_name}" "$*" >>"${TEST_COMMAND_LOG}"
exec "/usr/bin/${command_name}" "$@"
STUB
  done

  cat >"${bin_dir}/run-local-sentinel" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'run-local %s\n' "$*" >>"${TEST_COMMAND_LOG}"
exit 99
STUB

  cat >"${bin_dir}/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'curl %s\n' "$*" >>"${TEST_COMMAND_LOG}"
if [[ -n ${CURL_HOME:-} && -f ${CURL_HOME}/.curlrc && ${1:-} != --disable ]]; then
  : >"${TEST_CURL_POISON_OUTPUT}"
fi
[[ ${1:-} == --disable ]] || exit 92
[[ -z ${http_proxy:-}${HTTP_PROXY:-}${https_proxy:-}${HTTPS_PROXY:-}${all_proxy:-}${ALL_PROXY:-} ]] || {
  printf 'curl inherited a proxy environment\n' >&2
  exit 93
}
[[ " $* " == *" --noproxy * "* ]] || exit 94
case " $* " in
  *"/containers/relay-old/archive "*)
    if [[ ${TEST_SCENARIO} == check_binary_archive_invalid ]]; then
      printf 'not a tar stream\n'
      exit 0
    fi
    python3 - <<'PY'
import io
import sys
import tarfile

data = b"prior relay binary\n"
member = tarfile.TarInfo("buzz-relay")
member.mode = 0o755
member.size = len(data)
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
    archive.addfile(member, io.BytesIO(data))
PY
    ;;
  *" http://172.30.0.2:8080/_readiness "*) printf '{"ready":true}\n' ;;
  *" http://172.30.0.2:3000/ "*) printf '{"supported_nips":[1,11]}\n' ;;
  *) printf 'unexpected curl invocation: %s\n' "$*" >&2; exit 92 ;;
esac
STUB

  cat >"${bin_dir}/psql" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'psql PGCONNECT_TIMEOUT=%s PGOPTIONS=%s %s\n' \
  "${PGCONNECT_TIMEOUT:-}" "${PGOPTIONS:-}" "$*" >>"${TEST_COMMAND_LOG}"
[[ ${PGCONNECT_TIMEOUT:-} == 5 ]] || exit 92
[[ ${PGOPTIONS:-} == *default_transaction_read_only=on* ]] || exit 93
[[ -z ${PGHOSTADDR:-} ]] || exit 95
[[ " $* " == *" BEGIN TRANSACTION READ ONLY; "*"; ROLLBACK; "* ]] || exit 94
[[ ${TEST_SCENARIO} != check_db_unreachable ]] || exec sleep 60
if [[ " $* " == *"to_regclass"* ]]; then
  db_read_count=$(( $(cat "${TEST_DB_READ_COUNT}") + 1 ))
  printf '%d\n' "${db_read_count}" >"${TEST_DB_READ_COUNT}"
  case "${TEST_SCENARIO}:${db_read_count}" in
    check_db_read_failure:*) exit 25 ;;
    *) printf 't\n' ;;
  esac
elif [[ " $* " == *"SELECT count"* ]]; then
  [[ ${TEST_SCENARIO} == check_db_failed_rows ]] && printf '1\n' || printf '0\n'
else
  [[ ${TEST_SCENARIO} == check_db_malformed ]] && printf '31|t|extra\n' || \
    printf '%s|t\n' "$(cat "${TEST_DB_STATE}")"
fi
STUB

  cat >"${bin_dir}/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n ${DOCKER_HOST:-} ]]; then
  printf 'docker BUZZ_IMAGE=%s DOCKER_HOST=%s %s\n' \
    "${BUZZ_IMAGE:-}" "${DOCKER_HOST}" "$*" >>"${TEST_COMMAND_LOG}"
else
  printf 'docker BUZZ_IMAGE=%s %s\n' "${BUZZ_IMAGE:-}" "$*" >>"${TEST_COMMAND_LOG}"
fi
args=" $* "
state=$(cat "${TEST_CONTAINER_STATE}")
prior_id=sha256:1111111111111111111111111111111111111111111111111111111111111111
platform_id=${prior_id}
new_id=sha256:2222222222222222222222222222222222222222222222222222222222222222
mismatch_id=sha256:9999999999999999999999999999999999999999999999999999999999999999
case "${TEST_SCENARIO}" in
  prior_index_platform_survives|post_swap_failure_idxplat|platform_digest_untaggable)
    prior_id=sha256:4444444444444444444444444444444444444444444444444444444444444444
    platform_id=sha256:5555555555555555555555555555555555555555555555555555555555555555
    ;;
esac

case "${args}" in
  *" info --format "*) printf '29.7.2\n' ;;
  *" compose version --short "*) printf '5.4.0\n' ;;
  *" build "*) exit 0 ;;
  *" inspect --format {{json .NetworkSettings.Networks}} relay-old "*)
    printf '{"buzz-prod_buzz-net":{"IPAddress":"172.30.0.2"}}\n'
    ;;
  *" inspect --format {{json .NetworkSettings.Networks}} postgres-old "*)
    printf '{"buzz-prod_buzz-net":{"IPAddress":"172.30.0.3"}}\n'
    ;;
  *" inspect --format {{json .ImageManifestDescriptor}} "*)
    if [[ ${TEST_SCENARIO} == check_descriptor_mismatch ]]; then
      digest=sha256:8888888888888888888888888888888888888888888888888888888888888888
    else
      digest=sha256:7777777777777777777777777777777777777777777777777777777777777777
    fi
    printf '{"digest":"%s","platform":{"os":"linux","architecture":"amd64"}}\n' "${digest}"
    ;;
  *" image inspect --platform linux/amd64 --format {{json .Descriptor}} "*)
    printf '{"digest":"sha256:7777777777777777777777777777777777777777777777777777777777777777"}\n'
    ;;
  *" image inspect --platform linux/amd64 --format {{.Id}} "*)
    printf '%s\n' "${platform_id}"
    ;;
  *" image inspect localhost/buzz-relay:${TEST_COMMIT:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa} "*)
    if [[ ${TEST_SCENARIO} == manifest_list ]]; then
      printf 'sha256:3333333333333333333333333333333333333333333333333333333333333333\n'
    fi
    printf 'sha256:2222222222222222222222222222222222222222222222222222222222222222\n'
    ;;
  *" image inspect ${prior_id} "*)
    case "${TEST_SCENARIO}" in
      prior_child_uninspectable_valid_ref|prior_ref_platform_mismatch|prior_ref_revision_mismatch|\
        prior_image_unavailable|prior_index_platform_survives|post_swap_failure_idxplat)
        exit 1
        ;;
    esac
    printf '%s\n' "${prior_id}"
    ;;
  *" image tag "*)
    if [[ ${TEST_SCENARIO} == platform_digest_untaggable && ${3:-} == "${platform_id}" ]]; then
      exit 1
    fi
    exit 0
    ;;
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
      relay-old) printf '%s\n' "${prior_id}" ;;
      relay-rollback) printf '%s\n' "${platform_id}" ;;
      relay-new) printf '%s\n' "${new_id}" ;;
      *)
        create_count=$(cat "${TEST_VERIFY_CREATE_COUNT}")
        case "${TEST_SCENARIO}:${create_count}" in
          prior_ref_platform_mismatch:*|explicit_platform_mismatch:*|post_create_validation_failure:*|rollback_revalidation_mismatch:2)
            printf '%s\n' "${mismatch_id}"
            ;;
          *) printf '%s\n' "${platform_id}" ;;
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
  *" compose "*" ps -q postgres "*) printf 'postgres-old\n' ;;
  *" compose "*" ps --all --format json "*)
    if [[ ${TEST_SCENARIO} == check_service_unhealthy ]]; then
      relay_health=unhealthy
    else
      relay_health=healthy
    fi
    printf '[{"Service":"relay","State":"running","Health":"%s"},{"Service":"pair-relay","State":"running","Health":"healthy"},{"Service":"postgres","State":"running","Health":"healthy"},{"Service":"redis","State":"running","Health":"healthy"},{"Service":"minio","State":"running","Health":"healthy"},{"Service":"minio-init","State":"exited","ExitCode":0}]\n' "${relay_health}"
    ;;
  *" compose "*" config --format json "*)
    case "${TEST_SCENARIO}" in
      explicit_platform|explicit_platform_mismatch)
        printf '{"services":{"relay":{"image":"%s","platform":"linux/amd64"}}}\n' "${BUZZ_IMAGE:-ghcr.io/block/buzz:main}"
        ;;
      check_platform_mismatch)
        printf '{"services":{"relay":{"image":"%s","platform":"linux/arm64"}}}\n' "${BUZZ_IMAGE:-ghcr.io/block/buzz:main}"
        ;;
      check_compose_image_mismatch)
        printf '{"services":{"relay":{"image":"localhost/buzz-relay:other"}}}\n'
        ;;
      malformed_platform)
        printf '{"services":{"relay":{"platform":"linux/amd64;bad"}}}\n'
        ;;
      *) printf '{"services":{"relay":{"image":"%s"}}}\n' "${BUZZ_IMAGE:-ghcr.io/block/buzz:main}" ;;
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
        check_db_read_failure:*) exit 25 ;;
        rollback_db_read_failure:4) exit 25 ;;
        rollback_db_read_empty:4|db_marker_empty:*) ;;
        rollback_db_read_malformed:4|db_marker_malformed:*) printf 'unknown\n' ;;
        boolean_true:*) printf '  true  \n' ;;
        *) printf 't\n' ;;
      esac
    elif [[ ${args} == *"SELECT count"* ]]; then
      if [[ ${TEST_SCENARIO} == check_db_failed_rows ]]; then
        printf '1\n'
      else
        printf '0\n'
      fi
    else
      case "${TEST_SCENARIO}" in
        check_db_malformed) printf '31|t|extra\n' ;;
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

  chmod 755 "${bin_dir}/sudo" "${bin_dir}/git" "${bin_dir}/docker" "${bin_dir}/stat" \
    "${bin_dir}/mkdir" "${bin_dir}/chmod" "${bin_dir}/mktemp" "${bin_dir}/rmdir" \
    "${bin_dir}/rm" "${bin_dir}/tee" "${bin_dir}/run-local-sentinel" \
    "${bin_dir}/curl" "${bin_dir}/psql"
}

run_case() {
  local scenario=$1 expected=$2
  local invocation_mode=${3:-deploy}
  local case_dir=${scratch}/${scenario}
  local initial_db=28 prior_required_migration=28
  local checkout_head=${test_commit} source_head=${test_commit} dirty_checkout=0
  local pre_freeze_head=${test_commit} protected_ci_head=${test_commit}
  local receipt_timestamp prior_migration_override='' docker_default_platform=''
  local deploy_log_root=${case_dir}/logs deploy_build_root=${case_dir}/build
  local run_local_override=${compose_dir}/run-local.sh deploy_source_ref=refs/remotes/origin/main
  local docker_host='' docker_context=''
  local proxy_url=''
  local curl_home='' curl_poison_output=${case_dir}/curl-config-output pg_hostaddr=''
  local -a deploy_args=("${test_commit}")
  local -a compose_env_args=(BUZZ_COMPOSE_ENV_FILE="${case_dir}/compose.env")
  if [[ ${invocation_mode} == check ]]; then
    deploy_args=(--check "${test_commit}")
    deploy_log_root=${case_dir}/check-logs
    deploy_build_root=${case_dir}/check-build
  fi
  if [[ ${scenario} == post_swap_failure_unadvanced || ${scenario} == stalled_probe || \
    ${scenario} == post_swap_failure_idxplat || \
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
    stale_checkout|check_stale_checkout) checkout_head=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    stale_source|check_stale_source) source_head=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    dirty_checkout|check_dirty_checkout) dirty_checkout=1 ;;
    check_raw_source_ref) deploy_source_ref=${test_commit} ;;
    check_runner_override) run_local_override=${case_dir}/bin/run-local-sentinel ;;
    check_docker_host) docker_host=tcp://127.0.0.1:2375 ;;
    check_docker_context) docker_context=unexpected ;;
    check_proxy_env) proxy_url=http://127.0.0.1:9 ;;
    check_curl_config) curl_home=${case_dir}/curl-home ;;
    check_pg_hostaddr) pg_hostaddr=203.0.113.1 ;;
    check_compose_env_required) compose_env_args=() ;;
    check_root_slash) deploy_build_root=/ ;;
    check_root_relative) deploy_build_root=relative/build ;;
    check_root_noncanonical) deploy_build_root=${case_dir}/../${scenario}/check-build ;;
    check_root_overlap) deploy_log_root=${deploy_build_root} ;;
    check_root_repo) deploy_build_root=${case_dir}/repo ;;
    check_root_symlink) deploy_build_root=${case_dir}/check-build ;;
    check_root_unsafe_parent) deploy_build_root=${case_dir}/unsafe/new ;;
    short_receipt) pre_freeze_head=aaaaaaaaaaaa ;;
    mismatched_receipt|check_bad_receipt) protected_ci_head=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
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
  chmod 700 "${case_dir}" "${case_dir}/logs" "${case_dir}/build"
  make_stubs "${case_dir}/bin"
  printf 'old\n' >"${case_dir}/container-state"
  printf '%d\n' "${initial_db}" >"${case_dir}/db-state"
  printf '0\n' >"${case_dir}/verify-create-count"
  printf '0\n' >"${case_dir}/verify-remove-count"
  printf '0\n' >"${case_dir}/db-read-count"
  : >"${case_dir}/commands.log"
  : >"${case_dir}/compose.env"
  chmod 640 "${case_dir}/compose.env"
  python3 - "${case_dir}/docker.sock" <<'PY'
import socket
import sys
sock = socket.socket(socket.AF_UNIX)
sock.bind(sys.argv[1])
sock.close()
PY
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
  case "${scenario}" in
    check_bad_mode) chmod 600 "${case_dir}/compose.env" ;;
    check_symlink)
      mv "${case_dir}/compose.env" "${case_dir}/compose.env.target"
      ln -s "${case_dir}/compose.env.target" "${case_dir}/compose.env"
      ;;
    check_missing_secret) sed -i '/^BUZZ_RELAY_OWNER_PUBKEY=/d' "${case_dir}/secrets.env" ;;
    check_root_symlink)
      mkdir "${case_dir}/safe-root"
      chmod 700 "${case_dir}/safe-root"
      ln -s "${case_dir}/safe-root" "${case_dir}/check-build"
      ;;
    check_root_unsafe_parent)
      mkdir "${case_dir}/unsafe"
      chmod 777 "${case_dir}/unsafe"
      ;;
    check_curl_config)
      mkdir "${curl_home}"
      printf 'output = "%s"\n' "${curl_poison_output}" >"${curl_home}/.curlrc"
      ;;
  esac

  local repetitions=1 iteration rc=0 inventory_before='' inventory_after=''
  local started_ms=0 elapsed_ms=0
  [[ ${scenario} == check_success ]] && repetitions=2
  : >"${case_dir}/output"
  if [[ ${invocation_mode} == check ]]; then
    inventory_before=$(find "${case_dir}" -mindepth 1 -printf '%P|%y|%m\n' | sort)
  fi
  set +e
  [[ ${scenario} != check_db_unreachable ]] || started_ms=$(date +%s%3N)
  for ((iteration = 1; iteration <= repetitions; iteration++)); do
    env -u EGID -u BUZZ_COMPOSE_ENV_FILE \
      "${compose_env_args[@]}" \
      PATH="${case_dir}/bin:${PATH}" \
      TEST_SCENARIO=${scenario} \
      TEST_COMMAND_LOG="${case_dir}/commands.log" \
      TEST_CONTAINER_STATE="${case_dir}/container-state" \
      TEST_DB_STATE="${case_dir}/db-state" \
      TEST_DB_READ_COUNT="${case_dir}/db-read-count" \
      TEST_VERIFY_CREATE_COUNT="${case_dir}/verify-create-count" \
      TEST_VERIFY_REMOVE_COUNT="${case_dir}/verify-remove-count" \
      TEST_DOCKER_SOCKET="${case_dir}/docker.sock" \
      TEST_PRIOR_REQUIRED_MIGRATION="${prior_required_migration}" \
      TEST_REPO_ROOT="${case_dir}/repo" \
      TEST_COMMIT=${test_commit} \
      TEST_CHECKOUT_HEAD="${checkout_head}" \
      TEST_SOURCE_HEAD="${source_head}" \
      TEST_DIRTY_CHECKOUT="${dirty_checkout}" \
      BUZZ_RUN_LOCAL="${run_local_override}" \
      BUZZ_DEPLOY_SOURCE_REF="${deploy_source_ref}" \
      BUZZ_SECRET_ENV_FILE="${case_dir}/secrets.env" \
      BUZZ_DOCKER_SOCKET="${case_dir}/docker.sock" \
      BUZZ_PRE_FREEZE_RECEIPT="${case_dir}/pre-freeze-receipt.json" \
      BUZZ_PROTECTED_CI_RECEIPT="${case_dir}/protected-ci-receipt.json" \
      BUZZ_PRIOR_MIGRATION_OVERRIDE="${prior_migration_override}" \
      DOCKER_HOST="${docker_host}" \
      DOCKER_CONTEXT="${docker_context}" \
      http_proxy="${proxy_url}" \
      HTTP_PROXY="${proxy_url}" \
      https_proxy="${proxy_url}" \
      HTTPS_PROXY="${proxy_url}" \
      all_proxy="${proxy_url}" \
      ALL_PROXY="${proxy_url}" \
      CURL_HOME="${curl_home}" \
      TEST_CURL_POISON_OUTPUT="${curl_poison_output}" \
      PGHOSTADDR="${pg_hostaddr}" \
      DOCKER_DEFAULT_PLATFORM="${docker_default_platform}" \
      BUZZ_DEPLOY_LOG_ROOT="${deploy_log_root}" \
      BUZZ_DEPLOY_BUILD_ROOT="${deploy_build_root}" \
      BUZZ_DEPLOY_HEALTH_ATTEMPTS=1 \
      BUZZ_DEPLOY_HEALTH_INTERVAL=0 \
      BUZZ_DEPLOY_PROBE_TIMEOUT=0.1 \
      "${deploy_script}" "${deploy_args[@]}" >>"${case_dir}/output" 2>&1
    rc=$?
    ((rc == 0)) || break
  done
  set -e
  if [[ ${scenario} == check_db_unreachable ]]; then
    elapsed_ms=$(( $(date +%s%3N) - started_ms ))
    ((elapsed_ms < 5000)) || fail "${scenario} exceeded its 5-second outer deadline (${elapsed_ms} ms)"
  fi
  if [[ ${invocation_mode} == check ]]; then
    inventory_after=$(find "${case_dir}" -mindepth 1 -printf '%P|%y|%m\n' | sort)
    [[ ${inventory_after} == "${inventory_before}" ]] || \
      fail "${scenario} changed the fixture path inventory"
  fi

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

set +e
"${deploy_script}" --check abc >"${scratch}/check-invalid-sha.output" 2>&1
invalid_sha_rc=$?
set -e
[[ ${invalid_sha_rc} -ne 0 ]] || fail 'check mode accepted a short commit'
assert_contains "${scratch}/check-invalid-sha.output" \
  'commit must be exactly 40 lowercase hexadecimal characters'

run_case check_success success check
assert_contains "${scratch}/check_success/output" '^PREFLIGHT PASSED:'
assert_contains "${scratch}/check_success/output" '^CHECK PASSED: no files, images, containers, services, or database state were changed$'
[[ ! -e ${scratch}/check_success/check-logs ]] || fail 'check mode created its log root'
[[ ! -e ${scratch}/check_success/check-build ]] || fail 'check mode created its build root'
assert_not_contains "${scratch}/check_success/commands.log" '^sudo '
assert_not_contains "${scratch}/check_success/commands.log" '^fs '
assert_not_contains "${scratch}/check_success/commands.log" 'worktree add'
assert_not_contains "${scratch}/check_success/commands.log" \
  '^docker .* (build|create|run|tag|cp|rm) '
assert_not_contains "${scratch}/check_success/commands.log" \
  ' compose .* (run|up) '
assert_not_contains "${scratch}/check_success/commands.log" 'pg_dump'
assert_not_contains "${scratch}/check_success/commands.log" '^docker .* exec '
assert_not_contains "${scratch}/check_success/commands.log" ' compose .* exec '

run_case check_compose_env_required failure check
assert_contains "${scratch}/check_compose_env_required/output" \
  '^REFUSED: --check requires an explicit BUZZ_COMPOSE_ENV_FILE path$'
assert_not_contains "${scratch}/check_compose_env_required/commands.log" '^git '
assert_not_contains "${scratch}/check_compose_env_required/commands.log" '^docker '

run_case check_external_compose_env success check
assert_contains "${scratch}/check_external_compose_env/output" '^CHECK PASSED:'
assert_contains "${scratch}/check_external_compose_env/commands.log" \
  " compose --env-file ${scratch}/check_external_compose_env/compose.env "
[[ ! -e ${scratch}/check_external_compose_env/repo/deploy/compose/.env ]] || \
  fail 'explicit external Compose env check required a checkout-local .env'
assert_check_runtime_readonly "${scratch}/check_external_compose_env"

run_case check_proxy_env success check
assert_contains "${scratch}/check_proxy_env/output" '^CHECK PASSED:'
assert_check_runtime_readonly "${scratch}/check_proxy_env"

run_case check_curl_config success check
assert_contains "${scratch}/check_curl_config/output" '^CHECK PASSED:'
[[ ! -e ${scratch}/check_curl_config/curl-config-output ]] || \
  fail 'check mode honored a poisoned curl config'
assert_check_runtime_readonly "${scratch}/check_curl_config"

run_case check_pg_hostaddr success check
assert_contains "${scratch}/check_pg_hostaddr/output" '^CHECK PASSED:'
assert_check_runtime_readonly "${scratch}/check_pg_hostaddr"

run_case check_concurrent_a success check &
concurrent_a=$!
run_case check_concurrent_b success check &
concurrent_b=$!
wait "${concurrent_a}"
wait "${concurrent_b}"
assert_check_runtime_readonly "${scratch}/check_concurrent_a"
assert_check_runtime_readonly "${scratch}/check_concurrent_b"

for check_early_failure in check_stale_checkout check_stale_source \
  check_dirty_checkout check_raw_source_ref check_runner_override check_bad_receipt \
  check_bad_owner check_bad_mode check_symlink check_missing_secret check_docker_host \
  check_docker_context check_root_slash check_root_relative check_root_noncanonical \
  check_root_overlap check_root_repo check_root_symlink check_root_unsafe_parent; do
  run_case "${check_early_failure}" failure check
  assert_not_contains "${scratch}/${check_early_failure}/commands.log" '^docker '
  assert_not_contains "${scratch}/${check_early_failure}/commands.log" '^fs '
  [[ ! -e ${scratch}/${check_early_failure}/check-logs ]] || \
    fail "${check_early_failure} created its log root"
  if [[ ${check_early_failure} != check_root_symlink ]]; then
    [[ ! -e ${scratch}/${check_early_failure}/check-build ]] || \
      fail "${check_early_failure} created its build root"
  fi
done
assert_contains "${scratch}/check_bad_owner/output" 'Compose environment file must be owned'
assert_contains "${scratch}/check_bad_mode/output" 'Compose environment file must have mode 640'
assert_contains "${scratch}/check_symlink/output" 'Compose environment file is missing, is not a regular file, or is a symlink'
assert_contains "${scratch}/check_missing_secret/output" 'required secret name is missing: BUZZ_RELAY_OWNER_PUBKEY'
assert_contains "${scratch}/check_raw_source_ref/output" \
  'deployment source ref must be a remote-tracking branch, not a raw commit'
assert_contains "${scratch}/check_runner_override/output" \
  'BUZZ_RUN_LOCAL may not replace the commit-bound Compose runner'
assert_contains "${scratch}/check_docker_host/output" \
  'DOCKER_HOST and DOCKER_CONTEXT must be unset'
assert_contains "${scratch}/check_docker_context/output" \
  'DOCKER_HOST and DOCKER_CONTEXT must be unset'
assert_contains "${scratch}/check_root_slash/output" 'build root must be an absolute canonical non-root path'
assert_contains "${scratch}/check_root_relative/output" 'build root must be an absolute canonical non-root path'
assert_contains "${scratch}/check_root_noncanonical/output" 'build root must be an absolute canonical non-root path'
assert_contains "${scratch}/check_root_overlap/output" 'build and log roots overlap'
assert_contains "${scratch}/check_root_repo/output" 'build root overlaps the repository root'
assert_contains "${scratch}/check_root_symlink/output" 'build root has a symlinked existing ancestor'
assert_contains "${scratch}/check_root_unsafe_parent/output" \
  'build root has a group- or world-writable existing ancestor'
assert_not_contains "${scratch}/check_success/commands.log" '^run-local '
assert_check_runtime_readonly "${scratch}/check_success"

for check_runtime_failure in check_compose_image_mismatch check_descriptor_mismatch \
  check_platform_mismatch check_service_unhealthy check_binary_archive_invalid \
  check_db_read_failure check_db_unreachable check_db_malformed \
  check_db_failed_rows; do
  run_case "${check_runtime_failure}" failure check
  assert_not_contains "${scratch}/${check_runtime_failure}/commands.log" '^sudo '
  assert_not_contains "${scratch}/${check_runtime_failure}/commands.log" '^fs '
  assert_not_contains "${scratch}/${check_runtime_failure}/commands.log" 'worktree add'
  assert_not_contains "${scratch}/${check_runtime_failure}/commands.log" \
    '^docker .* (build|create|run|tag|cp|rm) '
  assert_not_contains "${scratch}/${check_runtime_failure}/commands.log" \
    ' compose .* (run|up) '
  assert_not_contains "${scratch}/${check_runtime_failure}/commands.log" 'pg_dump'
  assert_check_runtime_readonly "${scratch}/${check_runtime_failure}"
done
assert_contains "${scratch}/check_descriptor_mismatch/output" 'running container descriptor .* does not match configured ref descriptor'
assert_contains "${scratch}/check_compose_image_mismatch/output" \
  'Compose relay image localhost/buzz-relay:other does not match running configured ref localhost/buzz-relay:old'
assert_contains "${scratch}/check_platform_mismatch/output" 'Compose relay platform linux/arm64 does not match running descriptor platform linux/amd64'
assert_contains "${scratch}/check_service_unhealthy/output" 'Compose service relay is not running and healthy'
assert_contains "${scratch}/check_binary_archive_invalid/output" 'relay binary archive stream is invalid'
assert_contains "${scratch}/check_db_read_failure/output" 'database migration table-marker query failed'
assert_contains "${scratch}/check_db_unreachable/output" 'database migration table-marker query failed'
assert_contains "${scratch}/check_db_malformed/output" 'database latest-migration row is empty or malformed'
assert_contains "${scratch}/check_db_failed_rows/output" 'database contains 1 failed migration rows'

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
assert_contains "${scratch}/prior_child_uninspectable_valid_ref/commands.log" \
  'image inspect --platform linux/amd64 --format {{.Id}} localhost/buzz-relay:old'
assert_not_contains "${scratch}/prior_child_uninspectable_valid_ref/commands.log" \
  'image inspect localhost/buzz-relay:old'
assert_contains "${scratch}/prior_child_uninspectable_valid_ref/commands.log" \
  'image tag sha256:1111111111111111111111111111111111111111111111111111111111111111 localhost/buzz-relay:rollback-'
fallback_source=$(rg --files "${scratch}/prior_child_uninspectable_valid_ref/logs" | \
  grep '/rollback-source[.]txt$')
fallback_source_id=$(rg --files "${scratch}/prior_child_uninspectable_valid_ref/logs" | \
  grep '/rollback-source-image-id[.]txt$')
assert_contains "${fallback_source}" \
  '^sha256:1111111111111111111111111111111111111111111111111111111111111111$'
assert_contains "${fallback_source_id}" \
  '^sha256:1111111111111111111111111111111111111111111111111111111111111111$'
[[ $(cat "${scratch}/prior_child_uninspectable_valid_ref/verify-create-count") -eq 1 ]] || \
  fail 'valid platform image did not create one retained-tag verification container'
[[ $(cat "${scratch}/prior_child_uninspectable_valid_ref/verify-remove-count") -eq 1 ]] || \
  fail 'valid platform image did not remove its stopped verification container and volumes'
assert_contains "${scratch}/prior_child_uninspectable_valid_ref/output" 'DEPLOY SUCCEEDED'

run_case prior_index_platform_survives success
assert_contains "${scratch}/prior_index_platform_survives/output" \
  'Prior container image index sha256:444444.*differs from runnable platform image sha256:555555'
assert_contains "${scratch}/prior_index_platform_survives/commands.log" \
  'image tag sha256:5555555555555555555555555555555555555555555555555555555555555555 localhost/buzz-relay:rollback-'
assert_not_contains "${scratch}/prior_index_platform_survives/commands.log" \
  'image inspect sha256:4444444444444444444444444444444444444444444444444444444444444444'
index_evidence=$(rg --files "${scratch}/prior_index_platform_survives/logs" | \
  grep '/prior-image-id[.]txt$')
platform_evidence=$(rg --files "${scratch}/prior_index_platform_survives/logs" | \
  grep '/prior-platform-image-id[.]txt$')
assert_contains "${index_evidence}" \
  '^sha256:4444444444444444444444444444444444444444444444444444444444444444$'
assert_contains "${platform_evidence}" \
  '^sha256:5555555555555555555555555555555555555555555555555555555555555555$'
index_resolution=$(rg --files "${scratch}/prior_index_platform_survives/logs" | \
  grep '/rollback-source-resolution[.]txt$')
assert_contains "${index_resolution}" '^platform-image-id$'
assert_contains "${scratch}/prior_index_platform_survives/output" 'DEPLOY SUCCEEDED'

run_case platform_digest_untaggable success
assert_contains "${scratch}/platform_digest_untaggable/commands.log" \
  'image tag sha256:5555555555555555555555555555555555555555555555555555555555555555 localhost/buzz-relay:rollback-'
assert_contains "${scratch}/platform_digest_untaggable/commands.log" \
  'image tag localhost/buzz-relay:old localhost/buzz-relay:rollback-'
assert_contains "${scratch}/platform_digest_untaggable/output" \
  'not taggable in the image store; falling back to prior image reference localhost/buzz-relay:old'
untaggable_source=$(rg --files "${scratch}/platform_digest_untaggable/logs" | \
  grep '/rollback-source[.]txt$')
untaggable_resolution=$(rg --files "${scratch}/platform_digest_untaggable/logs" | \
  grep '/rollback-source-resolution[.]txt$')
assert_contains "${untaggable_source}" '^localhost/buzz-relay:old$'
assert_contains "${untaggable_resolution}" '^prior-image-ref$'
assert_contains "${scratch}/platform_digest_untaggable/output" 'DEPLOY SUCCEEDED'

for bad_prior in prior_ref_platform_mismatch prior_ref_revision_mismatch prior_image_unavailable; do
  run_case "${bad_prior}" failure
  assert_not_contains "${scratch}/${bad_prior}/commands.log" 'exec -T postgres sh -euc.*pg_dump'
  assert_not_contains "${scratch}/${bad_prior}/commands.log" \
    ' up -d --no-deps --force-recreate relay'
done
assert_contains "${scratch}/prior_ref_platform_mismatch/output" \
  'resolves to platform image sha256:999999.*expected prior platform image sha256:111111'
assert_contains "${scratch}/prior_ref_revision_mismatch/output" \
  'revision dddddddd.*does not match running container revision cccccccc'
assert_contains "${scratch}/prior_image_unavailable/commands.log" \
  'create --pull=never --name buzz-rollback-verify-.* localhost/buzz-relay:rollback-'

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
  'resolves to platform image sha256:999999.*expected prior platform image sha256:111111'

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

run_case post_swap_failure_idxplat failure
assert_contains "${scratch}/post_swap_failure_idxplat/output" \
  'ROLLBACK SUCCEEDED: restored platform image sha256:555555'
assert_contains "${scratch}/post_swap_failure_idxplat/commands.log" \
  'image tag sha256:5555555555555555555555555555555555555555555555555555555555555555 localhost/buzz-relay:rollback-'
assert_not_contains "${scratch}/post_swap_failure_idxplat/commands.log" \
  'image inspect sha256:4444444444444444444444444444444444444444444444444444444444444444'
assert_contains "${scratch}/post_swap_failure_idxplat/commands.log" \
  'BUZZ_IMAGE=localhost/buzz-relay:rollback-.* up -d --no-deps --force-recreate relay'
index_rollback_swap_count=$(grep -c '^docker .*up -d --no-deps --force-recreate relay' \
  "${scratch}/post_swap_failure_idxplat/commands.log")
[[ ${index_rollback_swap_count} -eq 2 ]] || \
  fail "index/platform rollback made ${index_rollback_swap_count} recreate calls, expected 2"

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
