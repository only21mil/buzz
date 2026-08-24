#!/usr/bin/env bash
set -euo pipefail

compose_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
compose_env_file=${BUZZ_COMPOSE_ENV_FILE:-${compose_dir}/.env}
secret_env_file=${BUZZ_SECRET_ENV_FILE-${HOME}/.config/sats/secrets.env}

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
exec sudo --preserve-env=BUZZ_RELAY_PRIVATE_KEY,BUZZ_GIT_HOOK_HMAC_SECRET,BUZZ_S3_ACCESS_KEY,BUZZ_S3_SECRET_KEY,POSTGRES_PASSWORD,REDIS_PASSWORD,RELAY_OWNER_PUBKEY,BUZZ_SERVICE_ENV_FILE,BUZZ_IMAGE,BUZZ_HTTP_PORT,BUZZ_PAIRING_RELAY_URL,BUZZ_PAIR_RELAY_PORT \
  docker compose --env-file "${compose_env_file}" -f compose.yml -f compose.localhost.yml "$@"
