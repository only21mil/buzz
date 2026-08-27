#!/usr/bin/env bash
set -euo pipefail

compose_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
compose_env_file=${BUZZ_COMPOSE_ENV_FILE:-${compose_dir}/.env}
secret_env_file=${BUZZ_SECRET_ENV_FILE-${HOME}/.config/sats/secrets.env}
expected_image=${BUZZ_EXPECTED_IMAGE-}

if [[ -n ${expected_image} ]]; then
  [[ -n ${BUZZ_IMAGE:-} ]] || {
    printf 'refused: BUZZ_IMAGE is required when BUZZ_EXPECTED_IMAGE is set\n' >&2
    exit 1
  }
  [[ ${BUZZ_IMAGE} == "${expected_image}" ]] || {
    printf 'refused: BUZZ_IMAGE does not match BUZZ_EXPECTED_IMAGE\n' >&2
    exit 1
  }
  case "${expected_image}" in
    *:main|*:latest)
      printf 'refused: deployment image must be pinned, not a default tag: %s\n' \
        "${expected_image}" >&2
      exit 1
      ;;
  esac
  [[ ${expected_image} =~ ^[A-Za-z0-9._/@:+-]+$ ]] || {
    printf 'refused: deployment image contains unsupported characters\n' >&2
    exit 1
  }
fi

if [[ -n ${secret_env_file} ]]; then
  [[ -f ${secret_env_file} ]] || {
    printf 'secret env file is missing: %s\n' "${secret_env_file}" >&2
    exit 1
  }
  [[ $(stat -c %a "${secret_env_file}") == 600 ]] || {
    printf 'secret env file must have mode 0600: %s\n' "${secret_env_file}" >&2
    exit 1
  }
  [[ $(stat -c %a "$(dirname "${secret_env_file}")") == 700 ]] || {
    printf 'secret env file parent must have mode 0700: %s\n' "$(dirname "${secret_env_file}")" >&2
    exit 1
  }
  set -a
  # shellcheck disable=SC1090
  . "${secret_env_file}"
  set +a
fi

[[ -f ${compose_env_file} ]] || {
  printf 'compose env file is missing: %s\n' "${compose_env_file}" >&2
  exit 1
}

required=(
  BUZZ_RELAY_PRIVATE_KEY
  BUZZ_GIT_HOOK_HMAC_SECRET
  BUZZ_POSTGRES_PASSWORD
  BUZZ_REDIS_PASSWORD
  BUZZ_S3_ACCESS_KEY
  BUZZ_S3_SECRET_KEY
  BUZZ_RELAY_OWNER_PUBKEY
)
for name in "${required[@]}"; do
  [[ -n ${!name:-} ]] || {
    printf 'missing required variable: %s\n' "${name}" >&2
    exit 1
  }
done

export POSTGRES_PASSWORD=${BUZZ_POSTGRES_PASSWORD}
export REDIS_PASSWORD=${BUZZ_REDIS_PASSWORD}
export RELAY_OWNER_PUBKEY=${BUZZ_RELAY_OWNER_PUBKEY}
export BUZZ_SERVICE_ENV_FILE=${compose_env_file}

cd "${compose_dir}"
preserved_env=BUZZ_RELAY_PRIVATE_KEY,BUZZ_GIT_HOOK_HMAC_SECRET,BUZZ_S3_ACCESS_KEY,BUZZ_S3_SECRET_KEY,POSTGRES_PASSWORD,REDIS_PASSWORD,RELAY_OWNER_PUBKEY,BUZZ_SERVICE_ENV_FILE,BUZZ_HTTP_PORT,BUZZ_PAIRING_RELAY_URL,BUZZ_PAIR_RELAY_PORT
compose_files=(--env-file "${compose_env_file}" -f compose.yml -f compose.localhost.yml)

if [[ -n ${expected_image} ]]; then
  resolved_images=$(sudo --preserve-env="${preserved_env}" \
    env "BUZZ_IMAGE=${expected_image}" \
    docker compose "${compose_files[@]}" config --images)
  resolved_match=0
  while IFS= read -r resolved_image; do
    [[ -n ${resolved_image} ]] || continue
    if [[ ${resolved_image} == "${expected_image}" ]]; then
      resolved_match=1
    fi
  done <<<"${resolved_images}"
  ((resolved_match == 1)) || {
    printf 'refused: Compose did not resolve the expected deployment image: %s\n' \
      "${expected_image}" >&2
    exit 1
  }
  exec sudo --preserve-env="${preserved_env}" \
    env "BUZZ_IMAGE=${expected_image}" \
    docker compose "${compose_files[@]}" "$@"
fi

exec sudo --preserve-env="${preserved_env}" \
  docker compose "${compose_files[@]}" "$@"
