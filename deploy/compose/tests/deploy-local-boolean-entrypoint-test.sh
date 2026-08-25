#!/usr/bin/env bash
set -Eeuo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
compose_dir=$(cd "${test_dir}/.." && pwd)
deploy_script=${compose_dir}/deploy-local.sh
test_commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
scratch_root=${TEST_TMP_ROOT:-${TMPDIR:-/tmp}/buzz-relay-boolean-tests}
mkdir -p "${scratch_root}"
scratch=$(mktemp -d "${scratch_root}/stubbed.XXXXXX")
trap 'rm -rf -- "${scratch}"' EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local file=$1 pattern=$2
  grep -Eq "${pattern}" "${file}" || fail "${file} does not contain /${pattern}/"
}

make_stubs() {
  local bin_dir=$1
  mkdir -p "${bin_dir}"

  cat >"${bin_dir}/run-local" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
exec docker compose "$@"
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
        : >"${arg}/migrations/0031_boolean_entrypoint.sql"
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

  cat >"${bin_dir}/psql" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
query=
for arg in "$@"; do
  query=${arg}
done
if [[ ${query} == *to_regclass* ]]; then
  printf '%s\n' "${TEST_TABLE_PRESENT}"
else
  cat "${TEST_DB_ROW_FILE}"
fi
STUB

  cat >"${bin_dir}/pg_dump" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'stub custom dump\n'
STUB

  cat >"${bin_dir}/docker" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'docker BUZZ_IMAGE=%s %s\n' "${BUZZ_IMAGE:-}" "$*" >>"${TEST_COMMAND_LOG}"
args=" $* "

if [[ ${1:-} == compose ]]; then
  shift
  case ${1:-} in
    exec)
      shift
      [[ ${1:-} == -T ]] && shift
      [[ ${1:-} == postgres ]] || { printf 'unexpected compose exec service\n' >&2; exit 91; }
      shift
      [[ ${1:-} == sh && ${2:-} == -euc ]] || { printf 'unexpected compose exec command\n' >&2; exit 91; }
      command=$3
      shift 3
      if [[ ${command} == *pg_dump* ]]; then
        exec pg_dump "$@"
      fi
      if [[ ${command} == *psql* ]]; then
        exec env POSTGRES_USER=test POSTGRES_DB=test PATH="${TEST_BIN}:${PATH}" sh -euc "${command}" "$@"
      fi
      printf 'unexpected postgres command: %s\n' "${command}" >&2
      exit 91
      ;;
    ps)
      printf 'relay-%s\n' "$(cat "${TEST_CONTAINER_STATE}")"
      exit 0
      ;;
    run)
      if [[ ${TEST_SCENARIO} == migration_failure ]]; then
        exit 17
      fi
      printf '%s|%s\n' "${TEST_REQUIRED_MIGRATION}" "${TEST_DB_SUCCESS_AFTER}" >"${TEST_DB_ROW_FILE}"
      exit 0
      ;;
    up)
      if [[ ${BUZZ_IMAGE:-} == *:rollback-* ]]; then
        printf 'rollback\n' >"${TEST_CONTAINER_STATE}"
      else
        printf 'new\n' >"${TEST_CONTAINER_STATE}"
      fi
      exit 0
      ;;
    *) printf 'unexpected compose invocation: %s\n' "$*" >&2; exit 91 ;;
  esac
fi

case ${1:-} in
  build) exit 0 ;;
  image)
    [[ ${2:-} == inspect ]] && printf 'sha256:2222222222222222222222222222222222222222222222222222222222222222\n' && exit 0
    [[ ${2:-} == tag ]] && exit 0
    ;;
  inspect)
    case "${args}" in
      *"--format {{.Image}} "*)
        case $(cat "${TEST_CONTAINER_STATE}") in
          old|rollback) printf 'sha256:1111111111111111111111111111111111111111111111111111111111111111\n' ;;
          new) printf 'sha256:2222222222222222222222222222222222222222222222222222222222222222\n' ;;
        esac
        exit 0
        ;;
      *"--format {{.Config.Image}} "*) printf 'localhost/buzz-relay:old\n'; exit 0 ;;
      *"required-migration"*) printf '%s\n' "${TEST_PRIOR_REQUIRED_MIGRATION}"; exit 0 ;;
    esac
    ;;
  exec)
    case "${args}" in
      *" sha256sum /usr/local/bin/buzz-relay "*)
        case $(cat "${TEST_CONTAINER_STATE}") in
          old|rollback) printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /usr/local/bin/buzz-relay\n' ;;
          new) printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /usr/local/bin/buzz-relay\n' ;;
        esac
        exit 0
        ;;
      *" bash -ec "*)
        [[ ${TEST_SCENARIO} == rollback_true && $(cat "${TEST_CONTAINER_STATE}") == new ]] && exit 1
        exit 0
        ;;
    esac
    ;;
esac

printf 'unexpected docker invocation: %s\n' "$*" >&2
exit 91
STUB

  chmod 755 "${bin_dir}/run-local" "${bin_dir}/git" "${bin_dir}/psql" \
    "${bin_dir}/pg_dump" "${bin_dir}/docker"
}

run_case() {
  local scenario=$1 expected=$2 success_text=$3 table_text=$4
  local case_dir=${scratch}/${scenario}
  local initial_row
  mkdir -p "${case_dir}/bin" "${case_dir}/logs" "${case_dir}/build"
  chmod 700 "${case_dir}"
  make_stubs "${case_dir}/bin"
  printf 'old\n' >"${case_dir}/container-state"
  if [[ ${expected} == success ]]; then
    initial_row="30|${success_text}"
  else
    initial_row="31|${success_text}"
  fi
  printf '%s\n' "${initial_row}" >"${case_dir}/db-row"
  : >"${case_dir}/commands.log"

  set +e
  PATH="${case_dir}/bin:${PATH}" \
    TEST_BIN="${case_dir}/bin" \
    TEST_SCENARIO=${scenario} \
    TEST_COMMAND_LOG="${case_dir}/commands.log" \
    TEST_CONTAINER_STATE="${case_dir}/container-state" \
    TEST_DB_ROW_FILE="${case_dir}/db-row" \
    TEST_DB_SUCCESS_AFTER="${success_text}" \
    TEST_REQUIRED_MIGRATION=31 \
    TEST_PRIOR_REQUIRED_MIGRATION=31 \
    TEST_TABLE_PRESENT="${table_text}" \
    TEST_REPO_ROOT="${case_dir}/repo" \
    TEST_COMMIT=${test_commit} \
    BUZZ_RUN_LOCAL="${case_dir}/bin/run-local" \
    BUZZ_DEPLOY_LOG_ROOT="${case_dir}/logs" \
    BUZZ_DEPLOY_BUILD_ROOT="${case_dir}/build" \
    BUZZ_DEPLOY_HEALTH_ATTEMPTS=1 \
    BUZZ_DEPLOY_HEALTH_INTERVAL=0 \
    BUZZ_DEPLOY_PROBE_TIMEOUT=1 \
    "${deploy_script}" "${test_commit}" >"${case_dir}/output" 2>&1
  local rc=$?
  set -e

  if [[ ${expected} == success && ${rc} -ne 0 ]]; then
    sed -n '1,240p' "${case_dir}/output" >&2
    fail "${scenario} returned ${rc}, expected success"
  fi
  if [[ ${expected} == failure && ${rc} -eq 0 ]]; then
    fail "${scenario} succeeded, expected failure"
  fi
}

assert_image_admin_entrypoints() {
  local file line
  while IFS= read -r -d '' file; do
    while IFS= read -r line; do
      [[ ${line} == *buzz-admin* ]] || continue
      if [[ ${line} != *"docker run"* && ${line} != *"docker compose run"* && \
        ( ${line} != *compose_with_image* || ${line} != *" run "* ) ]]; then
        continue
      fi
      [[ ${line} == *"--entrypoint /usr/local/bin/buzz-admin"* ]] || \
        fail "image buzz-admin invocation lacks entrypoint: ${line}"
    done < <(rg -n -I 'buzz-admin' "${file}" || true)
  done < <(find "${compose_dir}" -type f -name '*.sh' ! -path '*/tests/*' -print0)
}

run_case accepted_t success t t
run_case accepted_true success true true
run_case accepted_true_whitespace success $'  true\t' $'\ttrue  '
run_case rejected_f failure f t
run_case rejected_false failure false t
run_case rejected_empty failure '' t
run_case rejected_garbage failure garbage t
run_case rollback_true failure true t

assert_contains "${scratch}/accepted_t/commands.log" \
  'run --rm --no-deps --entrypoint /usr/local/bin/buzz-admin relay migrate'
assert_contains "${scratch}/rollback_true/output" 'ROLLBACK SUCCEEDED'
assert_image_admin_entrypoints

printf 'PASS: deploy-local boolean and image entrypoint cases\n'
