#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(git -C "${script_dir}" rev-parse --show-toplevel)
run_local=${BUZZ_RUN_LOCAL:-${script_dir}/run-local.sh}
build_root=${BUZZ_DEPLOY_BUILD_ROOT:-${HOME}/work/buzz-relay-deploys}
log_root=${BUZZ_DEPLOY_LOG_ROOT:-${HOME}/.local/state/buzz-relay/deploys}
health_attempts=${BUZZ_DEPLOY_HEALTH_ATTEMPTS:-30}
health_interval=${BUZZ_DEPLOY_HEALTH_INTERVAL:-2}
probe_timeout=${BUZZ_DEPLOY_PROBE_TIMEOUT:-5}
source_ref=${BUZZ_DEPLOY_SOURCE_REF:-refs/remotes/origin/main}
pre_freeze_receipt=${BUZZ_PRE_FREEZE_RECEIPT:-${repo_root}/pre-freeze-receipt.json}
protected_ci_receipt=${BUZZ_PROTECTED_CI_RECEIPT:-${repo_root}/protected-ci-receipt.json}
receipt_max_age=${BUZZ_DEPLOY_RECEIPT_MAX_AGE_SECONDS:-86400}
prior_migration_override=${BUZZ_PRIOR_MIGRATION_OVERRIDE-}

usage() {
  printf 'Usage: %s <full-40-character-commit>\n' "${0##*/}" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 64
fi
commit=$1
if [[ ! ${commit} =~ ^[0-9a-f]{40}$ ]]; then
  printf 'REFUSED: commit must be exactly 40 lowercase hexadecimal characters\n' >&2
  exit 64
fi
if [[ ! ${health_attempts} =~ ^[1-9][0-9]*$ ]] || \
  [[ ! ${health_interval} =~ ^[0-9]+([.][0-9]+)?$ ]] || \
  [[ ! ${probe_timeout} =~ ^([1-9][0-9]*|0[.][0-9]*[1-9][0-9]*)$ ]] || \
  [[ ! ${receipt_max_age} =~ ^[1-9][0-9]*$ ]]; then
  printf 'REFUSED: health attempts, interval, and probe timeout must be positive numbers\n' >&2
  exit 64
fi
[[ -x ${run_local} ]] || {
  printf 'REFUSED: compose runner is not executable: %s\n' "${run_local}" >&2
  exit 1
}

validate_receipt() {
  local receipt_path=$1 receipt_source=$2
  [[ -f ${receipt_path} && ! -L ${receipt_path} ]] || {
    printf 'REFUSED: %s receipt is missing or is not a regular file: %s\n' \
      "${receipt_source}" "${receipt_path}" >&2
    return 1
  }
  python3 - "${receipt_path}" "${receipt_source}" "${commit}" "${receipt_max_age}" <<'PY'
import datetime
import json
import os
import re
import stat
import sys

path, expected_source, expected_commit, max_age_text = sys.argv[1:]

def refuse(message):
    print(f"REFUSED: {expected_source} receipt {message}: {path}", file=sys.stderr)
    raise SystemExit(1)

mode = os.stat(path, follow_symlinks=False).st_mode
if mode & (stat.S_IWGRP | stat.S_IWOTH):
    refuse("is group- or world-writable")

try:
    with open(path, encoding="utf-8") as receipt_file:
        receipt = json.load(receipt_file)
except (OSError, json.JSONDecodeError) as error:
    refuse(f"is unreadable or invalid JSON ({error})")

if receipt.get("schema_version") != 1:
    refuse("has unsupported schema_version")
if receipt.get("source") != expected_source:
    refuse("has the wrong source")
if receipt.get("repository") != "only21mil/buzz":
    refuse("has the wrong repository")

head_sha = receipt.get("head_sha")
if not isinstance(head_sha, str) or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
    refuse("head_sha must be a full 40-character lowercase commit")
if head_sha != expected_commit:
    refuse("does not match the requested commit")
if receipt.get("overall") != "PASS":
    refuse("does not record overall PASS")

timestamp = receipt.get("timestamp")
if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
    refuse("timestamp must be UTC RFC3339")
try:
    recorded_at = datetime.datetime.fromisoformat(timestamp[:-1] + "+00:00")
except ValueError:
    refuse("timestamp is invalid")
now = datetime.datetime.now(datetime.timezone.utc)
age = (now - recorded_at).total_seconds()
if age < -300:
    refuse("timestamp is more than 300 seconds in the future")
if age > int(max_age_text):
    refuse("is stale")

checks = receipt.get("checks")
if not isinstance(checks, list) or not checks:
    refuse("must contain at least one check")
if any(not isinstance(check, dict) or check.get("status") != "PASS" for check in checks):
    refuse("contains a check without PASS status")

if expected_source == "pre-freeze":
    base_sha = receipt.get("base_sha")
    if not isinstance(base_sha, str) or re.fullmatch(r"[0-9a-f]{40}", base_sha) is None:
        refuse("base_sha must be a full 40-character lowercase commit")
    print(base_sha)
elif expected_source == "protected-ci":
    if receipt.get("protected") is not True:
        refuse("does not attest protected CI")
    if receipt.get("full_exact_head") is not True:
        refuse("does not attest the full exact-head matrix")
PY
}

git -C "${repo_root}" cat-file -e "${commit}^{commit}"
resolved_commit=$(git -C "${repo_root}" rev-parse --verify "${commit}^{commit}")
[[ ${resolved_commit} == "${commit}" ]] || {
  printf 'REFUSED: requested commit resolves to %s\n' "${resolved_commit}" >&2
  exit 1
}
checkout_head=$(git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}')
[[ ${checkout_head} == "${commit}" ]] || {
  printf 'REFUSED: source checkout is at %s, expected %s\n' "${checkout_head}" "${commit}" >&2
  exit 1
}
source_head=$(git -C "${repo_root}" rev-parse --verify "${source_ref}^{commit}")
[[ ${source_head} == "${commit}" ]] || {
  printf 'REFUSED: source ref %s is at %s, expected %s\n' \
    "${source_ref}" "${source_head}" "${commit}" >&2
  exit 1
}
dirty_status=$(git -C "${repo_root}" status --porcelain --untracked-files=all)
filtered_dirty_status=
while IFS= read -r status_entry; do
  [[ -n ${status_entry} ]] || continue
  case "${status_entry}" in
    '?? pre-freeze-receipt.json'|'?? protected-ci-receipt.json') ;;
    *) filtered_dirty_status+="${status_entry}"$'\n' ;;
  esac
done <<<"${dirty_status}"
dirty_status=${filtered_dirty_status}
[[ -z ${dirty_status} ]] || {
  printf 'REFUSED: source checkout is dirty\n' >&2
  exit 1
}
pre_freeze_base=$(validate_receipt "${pre_freeze_receipt}" pre-freeze)
git -C "${repo_root}" cat-file -e "${pre_freeze_base}^{commit}"
git -C "${repo_root}" merge-base --is-ancestor "${pre_freeze_base}" "${commit}" || {
  printf 'REFUSED: pre-freeze receipt base %s is not an ancestor of %s\n' \
    "${pre_freeze_base}" "${commit}" >&2
  exit 1
}
validate_receipt "${protected_ci_receipt}" protected-ci

mkdir -p "${build_root}" "${log_root}"
chmod 700 "${build_root}" "${log_root}"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
deploy_dir=${log_root}/${timestamp}-${commit:0:12}
mkdir "${deploy_dir}"
chmod 700 "${deploy_dir}"
exec > >(tee -a "${deploy_dir}/deploy.log") 2>&1

build_worktree=
swapped=0
rollback_attempted=0
prior_container=
prior_image_id=
prior_image_ref=
prior_revision=
prior_required_migration=
prior_binary_sha=
rollback_tag=
rollback_source=
rollback_source_image_id=
relay_platform=
verification_container=
verification_cleanup_target=
verification_sequence=0
verification_containers=()
dump_file=

compose() {
  env -u BUZZ_IMAGE -u BUZZ_EXPECTED_IMAGE "${run_local}" "$@"
}

compose_with_image() {
  local image=$1
  shift
  [[ -n ${image} ]] || {
    printf 'REFUSED: deployment image is missing\n' >&2
    return 1
  }
  BUZZ_IMAGE=${image} BUZZ_EXPECTED_IMAGE=${image} "${run_local}" "$@"
}

pg_boolean_true() {
  local value=${1-}
  value=${value#"${value%%[![:space:]]*}"}
  value=${value%"${value##*[![:space:]]}"}
  [[ ${value} == t || ${value} == true ]]
}

normalize_pg_boolean() {
  local value=${1-}
  value=${value#"${value%%[![:space:]]*}"}
  value=${value%"${value##*[![:space:]]}"}
  case "${value}" in
    t|true|f|false) printf '%s\n' "${value}" ;;
    *) return 1 ;;
  esac
}

image_ids() {
  local image=$1 raw_ids raw_id seen=' '
  raw_ids=$(docker image inspect "${image}" --format '{{.Id}}') || return 1
  while IFS= read -r raw_id; do
    [[ -n ${raw_id} ]] || continue
    [[ ${raw_id} =~ ^sha256:[0-9a-f]{64}$ ]] || {
      printf 'REFUSED: image %s returned invalid image ID: %s\n' "${image}" "${raw_id}" >&2
      return 1
    }
    if [[ ${seen} != *" ${raw_id} "* ]]; then
      printf '%s\n' "${raw_id}"
      seen+="${raw_id} "
    fi
  done <<<"${raw_ids}"
}

image_ids_contain() {
  local ids=$1 expected=$2 image_id
  while IFS= read -r image_id; do
    [[ ${image_id} == "${expected}" ]] && return 0
  done <<<"${ids}"
  return 1
}

container_image_id() {
  local image_id
  image_id=$(docker inspect --format '{{.Image}}' "$1")
  [[ ${image_id} =~ ^sha256:[0-9a-f]{64}$ ]] || {
    printf 'Invalid image ID returned for container %s: %s\n' "$1" "${image_id}" >&2
    return 1
  }
  printf '%s\n' "${image_id}"
}

validate_image_ref() {
  local image_ref=$1 name tag at_suffix name_component registry_component
  local registry_host registry_port
  [[ -n ${image_ref} && ${image_ref} != -* && ${image_ref} != *[[:space:]]* ]] || {
    printf 'REFUSED: unsafe or empty configured image reference: %s\n' "${image_ref}" >&2
    return 1
  }
  [[ ${image_ref} =~ ^[A-Za-z0-9._/@:+-]+$ ]] || {
    printf 'REFUSED: malformed configured image reference: %s\n' "${image_ref}" >&2
    return 1
  }
  [[ ${image_ref} != *://* && ${image_ref} != *//* && ${image_ref} != *..* && \
    ${image_ref} != *::* && ${image_ref} != */ && ${image_ref} != */.* && \
    ${image_ref} != sha256:* ]] || {
    printf 'REFUSED: malformed configured image reference: %s\n' "${image_ref}" >&2
    return 1
  }

  if [[ ${image_ref} == *@* ]]; then
    [[ ${image_ref} != *@*@* ]] || {
      printf 'REFUSED: malformed configured image reference: %s\n' "${image_ref}" >&2
      return 1
    }
    name=${image_ref%@*}
    at_suffix=${image_ref#*@}
    [[ -n ${name} && ${at_suffix} =~ ^sha256:[0-9a-f]{64}$ ]] || {
      printf 'REFUSED: configured image digest is malformed: %s\n' "${image_ref}" >&2
      return 1
    }
  else
    name_component=${image_ref##*/}
    [[ ${name_component} == *:* ]] || {
      printf 'REFUSED: configured image reference uses implicit latest: %s\n' \
        "${image_ref}" >&2
      return 1
    }
    tag=${name_component##*:}
    name=${image_ref%":${tag}"}
    [[ ${tag} =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || {
      printf 'REFUSED: configured image tag is malformed: %s\n' "${image_ref}" >&2
      return 1
    }
    case "${tag}" in
      main|latest)
        printf 'REFUSED: configured image reference uses forbidden mutable tag %s: %s\n' \
          "${tag}" "${image_ref}" >&2
        return 1
        ;;
    esac
  fi

  [[ ${name} == "${name,,}" ]] || {
    printf 'REFUSED: configured image name must be lowercase: %s\n' "${image_ref}" >&2
    return 1
  }
  registry_component=${name%%/*}
  if [[ ${name} == */* && \
    (${registry_component} == localhost || ${registry_component} == *.* || \
      ${registry_component} == *:*) ]]; then
    registry_host=${registry_component%%:*}
    registry_port=
    if [[ ${registry_component} == *:* ]]; then
      registry_port=${registry_component##*:}
    fi
    [[ ${registry_host} =~ ^[a-z0-9]+([.-][a-z0-9]+)*$ ]] || {
      printf 'REFUSED: configured image registry is malformed: %s\n' "${image_ref}" >&2
      return 1
    }
    if [[ -n ${registry_port} ]]; then
      [[ ${registry_port} =~ ^[1-9][0-9]{0,4}$ ]] && \
        ((10#${registry_port} <= 65535)) || {
        printf 'REFUSED: configured image registry port is malformed: %s\n' \
          "${image_ref}" >&2
        return 1
      }
    fi
    name=${name#*/}
  fi
  [[ -n ${name} ]] || {
    printf 'REFUSED: configured image name is missing: %s\n' "${image_ref}" >&2
    return 1
  }
  while [[ ${name} == */* ]]; do
    name_component=${name%%/*}
    [[ ${name_component} =~ ^[a-z0-9]+(([.]|__?|-+)[a-z0-9]+)*$ ]] || {
      printf 'REFUSED: configured image name is malformed: %s\n' "${image_ref}" >&2
      return 1
    }
    name=${name#*/}
  done
  [[ ${name} =~ ^[a-z0-9]+(([.]|__?|-+)[a-z0-9]+)*$ ]] || {
    printf 'REFUSED: configured image name is malformed: %s\n' "${image_ref}" >&2
    return 1
  }
}

container_image_ref() {
  local image_ref
  image_ref=$(docker inspect --format '{{.Config.Image}}' "$1")
  validate_image_ref "${image_ref}" || return 1
  printf '%s\n' "${image_ref}"
}

object_revision() {
  local object=$1 revision
  revision=$(docker inspect --format \
    '{{index .Config.Labels "org.opencontainers.image.revision"}}' "${object}") || return 1
  [[ ${revision} =~ ^[0-9a-f]{40}$ ]] || {
    printf 'REFUSED: image or container %s has no valid OCI revision: %s\n' \
      "${object}" "${revision}" >&2
    return 1
  }
  printf '%s\n' "${revision}"
}

container_binary_sha() {
  local container=$1 binary_path binary_sha
  binary_path=$(mktemp "${deploy_dir}/.relay-binary.XXXXXX") || return 1
  if ! docker cp "${container}:/usr/local/bin/buzz-relay" "${binary_path}"; then
    rm -f -- "${binary_path}" || \
      printf 'WARNING: could not remove failed relay binary copy: %s\n' "${binary_path}" >&2
    return 1
  fi
  if ! binary_sha=$(sha256sum "${binary_path}" | awk '{print $1}'); then
    rm -f -- "${binary_path}" || \
      printf 'WARNING: could not remove relay binary after hash failure: %s\n' "${binary_path}" >&2
    return 1
  fi
  rm -f -- "${binary_path}" || {
    printf 'REFUSED: could not remove temporary relay binary copy: %s\n' "${binary_path}" >&2
    return 1
  }
  [[ ${binary_sha} =~ ^[0-9a-f]{64}$ ]] || {
    printf 'Invalid relay binary SHA-256 returned for container %s: %s\n' \
      "${container}" "${binary_sha}" >&2
    return 1
  }
  printf '%s\n' "${binary_sha}"
}

image_required_migration() {
  local required quiet=${2-}
  if ! required=$(docker inspect --format \
    '{{index .Config.Labels "org.block.buzz.required-migration"}}' "$1"); then
    if [[ ${quiet} != quiet ]]; then
      printf 'REFUSED: could not inspect required-migration label for image or container %s\n' \
        "$1" >&2
    fi
    return 2
  fi
  [[ ${required} =~ ^[0-9]+$ ]] || {
    if [[ ${quiet} != quiet ]]; then
      printf 'REFUSED: image %s has no valid required-migration label: %s\n' \
        "$1" "${required}" >&2
    fi
    return 1
  }
  printf '%d\n' "$((10#${required}))"
}

resolve_relay_platform() {
  local resolved
  [[ -z ${DOCKER_DEFAULT_PLATFORM:-} ]] || {
    printf 'REFUSED: DOCKER_DEFAULT_PLATFORM is set; use an explicit relay service platform or unset it\n' >&2
    return 1
  }
  resolved=$(compose config --format json | python3 -c '
import json
import sys

config = json.load(sys.stdin)
platform = config.get("services", {}).get("relay", {}).get("platform")
if platform is None:
    raise SystemExit(0)
if not isinstance(platform, str) or not platform:
    raise SystemExit(2)
print(platform)
') || {
    printf 'REFUSED: could not resolve the relay service platform from Compose\n' >&2
    return 1
  }
  if [[ -n ${resolved} && ! ${resolved} =~ ^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?$ ]]; then
    printf 'REFUSED: Compose returned an invalid relay service platform: %s\n' \
      "${resolved}" >&2
    return 1
  fi
  relay_platform=${resolved}
}

cleanup_verification_artifacts() {
  local container
  for container in "${verification_containers[@]}"; do
    [[ -n ${container} ]] || continue
    docker rm -v "${container}" >/dev/null 2>&1 || \
      printf 'WARNING: could not remove stopped verification container %s and its anonymous volumes\n' \
        "${container}" >&2
  done
}

untrack_verification_container() {
  local target=$1 index
  for index in "${!verification_containers[@]}"; do
    if [[ ${verification_containers[index]} == "${target}" ]]; then
      unset 'verification_containers[index]'
    fi
  done
}

create_verification_container() {
  local image=$1 name container_id
  local -a create_args=(create --pull=never)
  validate_image_ref "${image}" || return 1
  verification_sequence=$((verification_sequence + 1))
  name=buzz-rollback-verify-${timestamp}-${verification_sequence}
  create_args+=(--name "${name}")
  if [[ -n ${relay_platform} ]]; then
    create_args+=(--platform "${relay_platform}")
  fi
  create_args+=("${image}")
  verification_containers+=("${name}")
  verification_container=${name}
  verification_cleanup_target=${name}
  if ! container_id=$(env -u DOCKER_DEFAULT_PLATFORM docker "${create_args[@]}"); then
    untrack_verification_container "${name}"
    verification_container=
    verification_cleanup_target=
    return 1
  fi
  [[ ${container_id} =~ ^[0-9a-f]{64}$ ]] || {
    printf 'REFUSED: docker create returned an invalid verification container ID: %s\n' \
      "${container_id}" >&2
    return 1
  }
  verification_container=${container_id}
}

remove_verification_container() {
  local cleanup_target=$1
  docker rm -v "${cleanup_target}" >/dev/null || {
    printf 'REFUSED: could not remove stopped verification container %s and its anonymous volumes\n' \
      "${cleanup_target}" >&2
    return 1
  }
  untrack_verification_container "${cleanup_target}"
  verification_container=
  verification_cleanup_target=
}

verify_image_platform_binding() {
  local image=$1 container cleanup_target actual_id revision binary required
  create_verification_container "${image}" || return 1
  container=${verification_container}
  cleanup_target=${verification_cleanup_target}
  actual_id=$(container_image_id "${container}") || return 1
  [[ ${actual_id} == "${prior_image_id}" ]] || {
    printf 'REFUSED: image %s resolves to platform image %s, expected running image %s\n' \
      "${image}" "${actual_id}" "${prior_image_id}" >&2
    return 1
  }
  revision=$(object_revision "${container}") || return 1
  [[ ${revision} == "${prior_revision}" ]] || {
    printf 'REFUSED: image %s revision %s does not match running container revision %s\n' \
      "${image}" "${revision}" "${prior_revision}" >&2
    return 1
  }
  binary=$(container_binary_sha "${container}") || return 1
  [[ ${binary} == "${prior_binary_sha}" ]] || {
    printf 'REFUSED: image %s binary %s does not match running container binary %s\n' \
      "${image}" "${binary}" "${prior_binary_sha}" >&2
    return 1
  }
  if [[ -n ${prior_required_migration_label} ]]; then
    required=$(image_required_migration "${container}") || return 1
    [[ ${required} == "${prior_required_migration_label}" ]] || {
      printf 'REFUSED: image %s migration %s does not match running container migration %s\n' \
        "${image}" "${required}" "${prior_required_migration_label}" >&2
      return 1
    }
  fi
  if ! remove_verification_container "${cleanup_target}"; then
    return 2
  fi
}

capture_rollback_reference() {
  local direct_ids
  if direct_ids=$(image_ids "${prior_image_id}" 2>/dev/null); then
    [[ ${direct_ids} == "${prior_image_id}" ]] || {
      printf 'REFUSED: running container image ID %s resolves to mismatched or ambiguous IDs: %s\n' \
        "${prior_image_id}" "${direct_ids//$'\n'/,}" >&2
      return 1
    }
    rollback_source=${prior_image_id}
  else
    printf 'Prior container image ID %s is not directly inspectable; binding configured image %s to its platform ID\n' \
      "${prior_image_id}" "${prior_image_ref}"
    verify_image_platform_binding "${prior_image_ref}" || return 1
    rollback_source=${prior_image_ref}
  fi
  rollback_source_image_id=${prior_image_id}
  docker image tag "${rollback_source}" "${rollback_tag}"
  verify_image_platform_binding "${rollback_tag}"
}

relay_container() {
  compose ps -q relay
}

probe_relay() {
  local container=$1
  timeout --foreground "${probe_timeout}" docker exec "${container}" bash -ec \
    'exec 3<>/dev/tcp/127.0.0.1/8080; printf "GET /_readiness HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" >&3; grep -q "200 OK" <&3'
  timeout --foreground "${probe_timeout}" docker exec "${container}" bash -ec \
    'exec 3<>/dev/tcp/127.0.0.1/3000; printf "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n" >&3; response=$(cat <&3); grep -q "200 OK" <<<"$response"; grep -q '"'"'supported_nips'"'"' <<<"$response"'
}

wait_for_relay() {
  local container=$1
  local attempt
  for ((attempt = 1; attempt <= health_attempts; attempt++)); do
    if probe_relay "${container}" >/dev/null 2>&1; then
      printf 'Relay readiness and NIP-11 passed on attempt %d/%d\n' "${attempt}" "${health_attempts}"
      return 0
    fi
    if ((attempt < health_attempts)); then
      sleep "${health_interval}"
    fi
  done
  printf 'Relay failed readiness or NIP-11 after %d attempts\n' "${health_attempts}" >&2
  return 1
}

cleanup_build_worktree() {
  if [[ -n ${build_worktree} && -e ${build_worktree} ]]; then
    git -C "${repo_root}" worktree remove --force "${build_worktree}" >/dev/null 2>&1 || \
      printf 'WARNING: could not remove build worktree: %s\n' "${build_worktree}" >&2
  fi
}

rollback() {
  local rollback_container rollback_image rollback_sha rollback_db_state rollback_db_migration rollback_db_success
  local verification_rc=0
  rollback_attempted=1
  if ! rollback_db_state=$(read_db_migration); then
    printf 'AUTOMATIC ROLLBACK REFUSED: could not read the database migration state. Database dump: %s\n' \
      "${dump_file}" >&2
    return 1
  fi
  IFS='|' read -r rollback_db_migration rollback_db_success <<<"${rollback_db_state}"
  if [[ ! ${rollback_db_migration} =~ ^[0-9]+$ ]] || ! pg_boolean_true "${rollback_db_success}"; then
    printf 'AUTOMATIC ROLLBACK REFUSED: database migration state is %s. Prior image requires at most %d. Database dump: %s\n' \
      "${rollback_db_state}" "${prior_required_migration}" "${dump_file}" >&2
    return 1
  fi
  if ((rollback_db_migration > prior_required_migration)); then
    printf 'AUTOMATIC ROLLBACK REFUSED: database migration %d exceeds prior image requirement %d. Database dump: %s\n' \
      "${rollback_db_migration}" "${prior_required_migration}" "${dump_file}" >&2
    printf 'LOUD STOP: do not restore the prior image. Operator must restore the dump or roll forward.\n' >&2
    return 1
  fi
  verify_image_platform_binding "${rollback_tag}" || verification_rc=$?
  if ((verification_rc != 0)); then
    if ((verification_rc == 2)); then
      printf 'AUTOMATIC ROLLBACK REFUSED: rollback image identity passed, but its stopped verification container and anonymous volumes could not be removed. Rollback was not started. Database dump: %s\n' \
        "${dump_file}" >&2
    else
      printf 'AUTOMATIC ROLLBACK REFUSED: retained rollback image identity could not be verified. Database dump: %s\n' \
        "${dump_file}" >&2
    fi
    return 1
  fi
  printf '\nDEPLOY FAILED AFTER SWAP. ROLLING BACK TO %s\n' "${prior_image_id}" >&2
  if ! compose_with_image "${rollback_tag}" up -d --no-deps --force-recreate relay; then
    printf 'ROLLBACK FAILED: compose could not recreate relay with %s\n' "${prior_image_id}" >&2
    return 1
  fi
  rollback_container=$(relay_container)
  [[ -n ${rollback_container} ]] || {
    printf 'ROLLBACK FAILED: relay container is missing\n' >&2
    return 1
  }
  rollback_image=$(container_image_id "${rollback_container}")
  [[ ${rollback_image} == "${prior_image_id}" ]] || {
    printf 'ROLLBACK FAILED: running image %s does not match prior %s\n' "${rollback_image}" "${prior_image_id}" >&2
    return 1
  }
  if ! wait_for_relay "${rollback_container}"; then
    printf 'ROLLBACK FAILED: prior image did not recover readiness and NIP-11\n' >&2
    return 1
  fi
  rollback_sha=$(container_binary_sha "${rollback_container}")
  [[ ${rollback_sha} == "${prior_binary_sha}" ]] || {
    printf 'ROLLBACK FAILED: binary hash %s does not match prior %s\n' "${rollback_sha}" "${prior_binary_sha}" >&2
    return 1
  }
  printf '%s\n' "${rollback_sha}" >"${deploy_dir}/rollback-binary-sha256.txt"
  printf 'ROLLBACK SUCCEEDED: restored image %s with binary %s\n' "${prior_image_id}" "${rollback_sha}" >&2
}

on_exit() {
  local rc=$?
  trap - EXIT
  set +e
  if ((rc != 0 && swapped == 1 && rollback_attempted == 0)); then
    rollback
    rollback_rc=$?
    if ((rollback_rc != 0)); then
      printf 'LOUD FAILURE: deploy failed and automatic rollback did not recover service\n' >&2
    else
      printf 'LOUD FAILURE: new image was rejected after swap; prior service was restored\n' >&2
    fi
  fi
  cleanup_verification_artifacts
  cleanup_build_worktree
  exit "${rc}"
}
trap on_exit EXIT

resolve_relay_platform
printf 'Deploy candidate: %s\n' "${commit}"

build_worktree=$(mktemp -d "${build_root}/buzz-relay-${commit:0:12}-XXXXXX")
rmdir "${build_worktree}"
git -C "${repo_root}" worktree add --detach "${build_worktree}" "${commit}"
built_head=$(git -C "${build_worktree}" rev-parse HEAD)
[[ ${built_head} == "${commit}" ]] || {
  printf 'REFUSED: build worktree is at %s, expected %s\n' "${built_head}" "${commit}" >&2
  exit 1
}
if [[ -n $(git -C "${build_worktree}" status --porcelain --untracked-files=all) ]]; then
  printf 'REFUSED: build worktree is dirty\n' >&2
  exit 1
fi

required_raw=$(find "${build_worktree}/migrations" -maxdepth 1 -type f -printf '%f\n' \
  | sed -n 's/^\([0-9][0-9]*\)_.*[.]sql$/\1/p' | sort -n | tail -1)
[[ -n ${required_raw} ]] || {
  printf 'REFUSED: no numbered SQL migrations found at %s\n' "${commit}" >&2
  exit 1
}
required_migration=$((10#${required_raw}))
printf '%d\n' "${required_migration}" >"${deploy_dir}/required-migration.txt"

new_image=localhost/buzz-relay:${commit}
printf 'Building %s from clean commit worktree\n' "${new_image}"
docker build --label "org.opencontainers.image.revision=${commit}" \
  --label "org.block.buzz.required-migration=${required_migration}" \
  -t "${new_image}" -f "${build_worktree}/Dockerfile" "${build_worktree}"
new_image_ids=$(image_ids "${new_image}")
[[ -n ${new_image_ids} ]] || {
  printf 'REFUSED: built image returned no image IDs\n' >&2
  exit 1
}
printf '%s\n' "${new_image_ids}" >"${deploy_dir}/new-image-ids.txt"
printf '%s\n' "${new_image_ids%%$'\n'*}" >"${deploy_dir}/new-image-id.txt"
cleanup_build_worktree
build_worktree=

prior_container=$(relay_container)
[[ -n ${prior_container} ]] || {
  printf 'REFUSED: buzz-prod relay is not running\n' >&2
  exit 1
}
prior_image_id=$(container_image_id "${prior_container}")
prior_image_ref=$(container_image_ref "${prior_container}")
prior_revision=$(object_revision "${prior_container}")
prior_required_migration_status=0
prior_required_migration_label=$(image_required_migration "${prior_container}" quiet) || \
  prior_required_migration_status=$?
case "${prior_required_migration_status}" in
  0) ;;
  1) prior_required_migration_label= ;;
  2)
    printf 'REFUSED: prior image required-migration label could not be inspected; rollback compatibility is unreadable and BUZZ_PRIOR_MIGRATION_OVERRIDE is not permitted\n' >&2
    exit 1
    ;;
  *)
    printf 'REFUSED: unexpected prior image required-migration label status: %s\n' \
      "${prior_required_migration_status}" >&2
    exit 1
    ;;
esac
prior_binary_sha=$(container_binary_sha "${prior_container}")
printf '%s\n' "${prior_container}" >"${deploy_dir}/prior-container-id.txt"
printf '%s\n' "${prior_image_id}" >"${deploy_dir}/prior-image-id.txt"
printf '%s\n' "${prior_image_ref}" >"${deploy_dir}/prior-image-ref.txt"
printf '%s\n' "${prior_revision}" >"${deploy_dir}/prior-revision.txt"
printf '%s\n' "${prior_binary_sha}" >"${deploy_dir}/prior-binary-sha256.txt"
rollback_tag=localhost/buzz-relay:rollback-${timestamp}-${prior_image_id#sha256:}
rollback_tag=${rollback_tag:0:127}
capture_rollback_reference
printf '%s\n' "${rollback_source}" >"${deploy_dir}/rollback-source.txt"
printf '%s\n' "${rollback_source_image_id}" >"${deploy_dir}/rollback-source-image-id.txt"
printf '%s\n' "${rollback_tag}" >"${deploy_dir}/rollback-image-tag.txt"

dump_file=${deploy_dir}/buzz-prod-before-${timestamp}.dump
printf 'Writing Postgres custom-format dump: %s\n' "${dump_file}"
compose exec -T postgres sh -euc \
  'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' >"${dump_file}"
[[ -s ${dump_file} ]] || {
  printf 'REFUSED: Postgres dump is empty\n' >&2
  exit 1
}

read_db_migration() {
  local table_present table_present_normalized row row_version row_success_normalized
  if ! table_present=$(compose exec -T postgres sh -euc \
    'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "$1"' sh \
    "SELECT to_regclass('_sqlx_migrations') IS NOT NULL"); then
    printf 'REFUSED: database migration table-marker query failed\n' >&2
    return 1
  fi
  if ! table_present_normalized=$(normalize_pg_boolean "${table_present}"); then
    printf 'REFUSED: database migration table marker is empty or malformed: %s\n' \
      "${table_present:-<empty>}" >&2
    return 1
  fi
  if [[ ${table_present_normalized} == f || ${table_present_normalized} == false ]]; then
    printf '0|t\n'
    return 0
  fi
  if ! row=$(compose exec -T postgres sh -euc \
    'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "$1"' sh \
    "SELECT version || '|' || success FROM _sqlx_migrations ORDER BY version DESC LIMIT 1"); then
    printf 'REFUSED: database latest-migration query failed\n' >&2
    return 1
  fi
  if [[ ! ${row} =~ ^([0-9]+)\|(t|true|f|false)$ ]]; then
    printf 'REFUSED: database latest-migration row is empty or malformed: %s\n' \
      "${row:-<empty>}" >&2
    return 1
  fi
  row_version=${BASH_REMATCH[1]}
  row_success_normalized=$(normalize_pg_boolean "${BASH_REMATCH[2]}")
  printf '%s|%s\n' "${row_version}" "${row_success_normalized}"
}

db_state=$(read_db_migration)
IFS='|' read -r db_migration db_success <<<"${db_state}"
[[ ${db_migration} =~ ^[0-9]+$ ]] || {
  printf 'REFUSED: invalid migration version returned by database: %s\n' "${db_state}" >&2
  exit 1
}
if ! pg_boolean_true "${db_success}"; then
  printf 'REFUSED: database migration %s is recorded with success=%s\n' "${db_migration}" "${db_success}" >&2
  exit 1
fi

expected_override=${prior_image_id}@${db_migration}
if [[ -n ${prior_migration_override} ]]; then
  [[ -z ${prior_required_migration_label} ]] || {
    printf 'REFUSED: BUZZ_PRIOR_MIGRATION_OVERRIDE is not permitted because the prior image has valid required-migration label %s\n' \
      "${prior_required_migration_label}" >&2
    exit 1
  }
  [[ ${prior_migration_override} == "${expected_override}" ]] || {
    printf 'REFUSED: BUZZ_PRIOR_MIGRATION_OVERRIDE must match the current prior-image/database binding %s\n' \
      "${expected_override}" >&2
    exit 1
  }
  prior_required_migration=${db_migration}
  printf 'Prior-image migration override accepted for image %s at database migration %d\n' \
    "${prior_image_id}" "${db_migration}"
else
  [[ -n ${prior_required_migration_label} ]] || {
    printf 'REFUSED: prior image has no valid required-migration label; rerun with BUZZ_PRIOR_MIGRATION_OVERRIDE=%s only after verifying compatibility\n' \
      "${expected_override}" >&2
    exit 1
  }
  prior_required_migration=${prior_required_migration_label}
fi
printf '%d\n' "${prior_required_migration}" >"${deploy_dir}/prior-required-migration.txt"
printf 'Prior image: %s, required migration: %d, binary: %s\n' \
  "${prior_image_id}" "${prior_required_migration}" "${prior_binary_sha}"
printf 'Migration gate: image requires %d, database is at %d success=%s\n' \
  "${required_migration}" "${db_migration}" "${db_success}"

if ((db_migration > required_migration)); then
  printf 'REFUSED: database migration %d is newer than image requirement %d; rollback needs a compatible image\n' \
    "${db_migration}" "${required_migration}" >&2
  exit 1
fi
if ((db_migration < required_migration)); then
  printf 'Database is behind. Running migrations from %s before relay swap\n' "${new_image}"
  if ! compose_with_image "${new_image}" run --rm --no-deps --entrypoint /usr/local/bin/buzz-admin relay migrate; then
    printf 'REFUSED: migration command failed; relay image was not swapped\n' >&2
    exit 1
  fi
  db_state=$(read_db_migration)
  IFS='|' read -r db_migration db_success <<<"${db_state}"
  if [[ ! ${db_migration} =~ ^[0-9]+$ ]] || ! pg_boolean_true "${db_success}" || \
    ((db_migration != required_migration)); then
    printf 'REFUSED: database state after migrate is %s, expected %d with a true success value; relay image was not swapped\n' \
      "${db_state}" "${required_migration}" >&2
    exit 1
  fi
  printf 'Migration recheck passed at %d success=%s\n' "${db_migration}" "${db_success}"
fi

printf 'Recreating only buzz-prod relay with %s\n' "${new_image}"
swapped=1
compose_with_image "${new_image}" up -d --no-deps --force-recreate relay
new_container=$(relay_container)
[[ -n ${new_container} ]] || {
  printf 'Post-swap failure: relay container is missing\n' >&2
  exit 1
}
running_image_id=$(container_image_id "${new_container}")
image_ids_contain "${new_image_ids}" "${running_image_id}" || {
  printf 'Post-swap failure: running image %s is not one of the built image IDs: %s\n' \
    "${running_image_id}" "${new_image_ids//$'\n'/,}" >&2
  exit 1
}
wait_for_relay "${new_container}"
new_binary_sha=$(container_binary_sha "${new_container}")
printf '%s\n' "${new_container}" >"${deploy_dir}/new-container-id.txt"
printf '%s\n' "${running_image_id}" >"${deploy_dir}/running-image-id.txt"
printf '%s\n' "${new_binary_sha}" >"${deploy_dir}/new-binary-sha256.txt"
printf 'DEPLOY SUCCEEDED: commit %s, image %s, binary %s\n' \
  "${commit}" "${running_image_id}" "${new_binary_sha}"
