#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
export GIT_OPTIONAL_LOCKS=0

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
python3_bin=$(/usr/bin/readlink -f /usr/bin/python3)
unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT
usage() {
  printf 'Usage: %s [--check] <full-40-character-commit>\n' "${0##*/}" >&2
}

check_only=0
case $#:${1-} in
  1:*) commit=$1 ;;
  2:--check) check_only=1; commit=$2 ;;
  *) usage; exit 64 ;;
esac
if [[ ! ${commit} =~ ^[0-9a-f]{40}$ ]]; then
  printf 'REFUSED: commit must be exactly 40 lowercase hexadecimal characters\n' >&2
  exit 64
fi
if ((check_only == 1)) && [[ -z ${BUZZ_COMPOSE_ENV_FILE:-} ]]; then
  printf 'REFUSED: --check requires an explicit BUZZ_COMPOSE_ENV_FILE path\n' >&2
  exit 64
fi

repo_root=$(git -C "${script_dir}" rev-parse --show-toplevel)
canonical_run_local=${script_dir}/run-local.sh
run_local=${BUZZ_RUN_LOCAL:-${canonical_run_local}}
compose_file=${script_dir}/compose.yml
compose_local_file=${script_dir}/compose.localhost.yml
compose_env_file=${BUZZ_COMPOSE_ENV_FILE:-${script_dir}/.env}
secret_env_file=${BUZZ_SECRET_ENV_FILE-${HOME}/.config/sats/secrets.env}
docker_socket=${BUZZ_DOCKER_SOCKET:-/var/run/docker.sock}
build_root=${BUZZ_DEPLOY_BUILD_ROOT:-${HOME}/work/buzz-relay-deploys}
log_root=${BUZZ_DEPLOY_LOG_ROOT:-${HOME}/.local/state/buzz-relay/deploys}
minimum_free_kb=${BUZZ_DEPLOY_MIN_FREE_KB:-10485760}
health_attempts=${BUZZ_DEPLOY_HEALTH_ATTEMPTS:-30}
health_interval=${BUZZ_DEPLOY_HEALTH_INTERVAL:-2}
probe_timeout=${BUZZ_DEPLOY_PROBE_TIMEOUT:-5}
source_ref=${BUZZ_DEPLOY_SOURCE_REF:-refs/remotes/origin/main}
pre_freeze_receipt=${BUZZ_PRE_FREEZE_RECEIPT:-${repo_root}/pre-freeze-receipt.json}
protected_ci_receipt=${BUZZ_PROTECTED_CI_RECEIPT-}
protected_ci_tool=${repo_root}/scripts/protected-ci-receipt.py
receipt_max_age=${BUZZ_DEPLOY_RECEIPT_MAX_AGE_SECONDS:-86400}
prior_migration_override=${BUZZ_PRIOR_MIGRATION_OVERRIDE-}
if [[ -z ${protected_ci_receipt} || ${protected_ci_receipt} != /* ]]; then
  printf 'REFUSED: BUZZ_PROTECTED_CI_RECEIPT must name an explicit absolute receipt path\n' >&2
  exit 64
fi
# The receipt is re-verified against live GitHub through the pinned gh; GitHub
# does not sign REST responses, so an offline-consistent receipt is not enough.
if [[ -z ${GH_TOKEN-} ]]; then
  printf 'REFUSED: GH_TOKEN must be set so the protected-CI receipt can be re-verified against GitHub\n' >&2
  exit 64
fi

validate_pre_freeze_receipt() {
  local receipt_path=$1 receipt_source=pre-freeze
  [[ -f ${receipt_path} && ! -L ${receipt_path} ]] || {
    printf 'REFUSED: %s receipt is missing or is not a regular file: %s\n' \
      "${receipt_source}" "${receipt_path}" >&2
    return 1
  }
  "${python3_bin}" -I - "${receipt_path}" "${commit}" "${receipt_max_age}" <<'PY'
import datetime
import json
import os
import re
import stat
import sys

path, expected_commit, max_age_text = sys.argv[1:]
expected_source = "pre-freeze"

def refuse(message):
    print(f"REFUSED: {expected_source} receipt {message}: {path}", file=sys.stderr)
    raise SystemExit(1)

path_stat = os.stat(path, follow_symlinks=False)
mode = path_stat.st_mode
if path_stat.st_uid != os.geteuid():
    refuse("is not owned by the deployment user")
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

base_sha = receipt.get("base_sha")
if not isinstance(base_sha, str) or re.fullmatch(r"[0-9a-f]{40}", base_sha) is None:
    refuse("base_sha must be a full 40-character lowercase commit")
print(base_sha)
PY
}

validate_protected_ci_receipt() {
  "${python3_bin}" -I "${protected_ci_tool}" validate \
    --receipt "${protected_ci_receipt}" \
    --repository only21mil/buzz \
    --head "${commit}" \
    --scope main \
    --max-age-seconds "${receipt_max_age}" \
    --reverify
}

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
rollback_source_resolution=
relay_platform=
verification_container=
verification_cleanup_target=
verification_sequence=0
verification_containers=()
dump_file=
required_migration=
db_migration=
db_success=
prior_required_migration_label=
prior_descriptor_digest=
prior_platform=
prior_platform_image_id=
relay_network_ip=
postgres_network_ip=
preflight_active=0

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

docker_readonly() {
  env -u DOCKER_CONTEXT DOCKER_HOST="unix://${docker_socket}" docker "$@"
}

curl_readonly() {
  env -u http_proxy -u HTTP_PROXY -u https_proxy -u HTTPS_PROXY \
    -u all_proxy -u ALL_PROXY curl --disable --noproxy '*' "$@"
}

docker_state() {
  if ((preflight_active == 1)); then
    docker_readonly "$@"
  else
    docker "$@"
  fi
}

docker_state_with_timeout() {
  if ((preflight_active == 1)); then
    timeout --foreground "${probe_timeout}" env -u DOCKER_CONTEXT \
      DOCKER_HOST="unix://${docker_socket}" docker "$@"
  else
    timeout --foreground "${probe_timeout}" docker "$@"
  fi
}

compose_readonly() {
  local image=${1-}
  shift
  (
    unset BUZZ_IMAGE BUZZ_EXPECTED_IMAGE DOCKER_DEFAULT_PLATFORM
    export POSTGRES_PASSWORD=preflight-only
    export REDIS_PASSWORD=preflight-only
    export BUZZ_S3_ACCESS_KEY=preflight-only
    export BUZZ_S3_SECRET_KEY=preflight-only
    export BUZZ_RELAY_PRIVATE_KEY=preflight-only
    export BUZZ_GIT_HOOK_HMAC_SECRET=preflight-only
    export RELAY_OWNER_PUBKEY=preflight-only
    export BUZZ_SERVICE_ENV_FILE=${compose_env_file}
    if [[ -n ${image} ]]; then
      export BUZZ_IMAGE=${image}
    fi
    docker_readonly compose --env-file "${compose_env_file}" \
      -f "${compose_file}" -f "${compose_local_file}" "$@"
  )
}

db_compose() {
  if ((preflight_active == 1)); then
    compose_readonly "${prior_image_ref}" "$@"
  else
    compose "$@"
  fi
}

validate_owned_file() {
  local path=$1 expected_mode=$2 description=$3 actual_uid actual_gid actual_mode expected_gid
  [[ -f ${path} && ! -L ${path} ]] || {
    printf 'REFUSED: %s is missing, is not a regular file, or is a symlink: %s\n' \
      "${description}" "${path}" >&2
    return 1
  }
  actual_uid=$(stat -c %u "${path}") || return 1
  actual_gid=$(stat -c %g "${path}") || return 1
  actual_mode=$(stat -c %a "${path}") || return 1
  expected_gid=$(id -g) || return 1
  [[ ${actual_uid} == "${EUID}" ]] || {
    printf 'REFUSED: %s must be owned by uid %d: %s\n' "${description}" "${EUID}" "${path}" >&2
    return 1
  }
  [[ ${actual_gid} == "${expected_gid}" ]] || {
    printf 'REFUSED: %s must have deployment group gid %d: %s\n' \
      "${description}" "${expected_gid}" "${path}" >&2
    return 1
  }
  [[ ${actual_mode} == "${expected_mode}" ]] || {
    printf 'REFUSED: %s must have mode %s, found %s: %s\n' \
      "${description}" "${expected_mode}" "${actual_mode}" "${path}" >&2
    return 1
  }
}

validate_checkout_file() {
  local path=$1 executable=$2 description=$3 actual_uid actual_gid actual_mode mode_value
  [[ -f ${path} && ! -L ${path} ]] || {
    printf 'REFUSED: %s is missing, is not a regular file, or is a symlink: %s\n' \
      "${description}" "${path}" >&2
    return 1
  }
  actual_uid=$(/usr/bin/stat -c %u "${path}") || return 1
  actual_gid=$(/usr/bin/stat -c %g "${path}") || return 1
  actual_mode=$(/usr/bin/stat -c %a "${path}") || return 1
  mode_value=$((8#${actual_mode}))
  [[ ${actual_uid} == "${EUID}" && ${actual_gid} == "$(id -g)" && \
    $((mode_value & 8#022)) == 0 && $((mode_value & 8#400)) != 0 ]] || {
    printf 'REFUSED: %s must be caller-owned, readable, and not group/world writable: %s\n' \
      "${description}" "${path}" >&2
    return 1
  }
  if [[ ${executable} == yes ]]; then
    ((mode_value & 8#100)) || {
      printf 'REFUSED: %s must be owner-executable: %s\n' "${description}" "${path}" >&2
      return 1
    }
  else
    ((!(mode_value & 8#111))) || {
      printf 'REFUSED: %s must not be executable: %s\n' "${description}" "${path}" >&2
      return 1
    }
  fi
}

validate_root_owned_file() {
  local path=$1 expected_mode=$2 description=$3
  [[ ${path} == /usr/bin/python3.* && -f ${path} && ! -L ${path} ]] || {
    printf 'REFUSED: %s is not a resolved /usr/bin regular file: %s\n' \
      "${description}" "${path}" >&2
    return 1
  }
  [[ $(/usr/bin/stat -c %u "${path}") == 0 && \
    $(/usr/bin/stat -c %g "${path}") == 0 && \
    $(/usr/bin/stat -c %a "${path}") == "${expected_mode}" ]] || {
    printf 'REFUSED: %s must be root:root mode %s: %s\n' \
      "${description}" "${expected_mode}" "${path}" >&2
    return 1
  }
}

validate_safe_parent() {
  local path=$1 exact_mode=${2-} description=$3 parent actual_uid actual_mode
  parent=$(dirname "${path}")
  [[ -d ${parent} && ! -L ${parent} ]] || {
    printf 'REFUSED: %s parent is missing, is not a directory, or is a symlink: %s\n' \
      "${description}" "${parent}" >&2
    return 1
  }
  actual_uid=$(stat -c %u "${parent}") || return 1
  actual_mode=$(stat -c %a "${parent}") || return 1
  [[ ${actual_uid} == "${EUID}" ]] || {
    printf 'REFUSED: %s parent must be owned by uid %d: %s\n' \
      "${description}" "${EUID}" "${parent}" >&2
    return 1
  }
  if [[ -n ${exact_mode} ]]; then
    [[ ${actual_mode} == "${exact_mode}" ]] || {
      printf 'REFUSED: %s parent must have mode %s, found %s: %s\n' \
        "${description}" "${exact_mode}" "${actual_mode}" "${parent}" >&2
      return 1
    }
  elif ((8#${actual_mode} & 8#022)); then
    printf 'REFUSED: %s parent is group- or world-writable: %s\n' \
      "${description}" "${parent}" >&2
    return 1
  fi
}

validate_storage_roots() {
  "${python3_bin}" -I - "${repo_root}" "${build_root}" "${log_root}" "${EUID}" "$(id -g)" <<'PY'
import os
import stat
import sys

repo_text, build_text, log_text, uid_text, gid_text = sys.argv[1:]
uid = int(uid_text)
gid = int(gid_text)

def refuse(message):
    print(f"REFUSED: {message}", file=sys.stderr)
    raise SystemExit(1)

def normalized(label, text):
    if not os.path.isabs(text) or text == "/" or os.path.normpath(text) != text:
        refuse(f"{label} must be an absolute canonical non-root path: {text}")
    return text

def overlaps(left, right):
    return os.path.commonpath((left, right)) in (left, right)

def validate_root(label, path):
    current = "/"
    for component in path.strip("/").split("/"):
        current = os.path.join(current, component)
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode):
            refuse(f"{label} has a symlinked existing ancestor: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            refuse(f"{label} has a non-directory existing ancestor: {current}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            refuse(f"{label} has a group- or world-writable existing ancestor: {current}")

    if os.path.exists(path):
        metadata = os.lstat(path)
        if metadata.st_uid != uid or metadata.st_gid != gid:
            refuse(f"{label} must be owned by the deployment uid/gid: {path}")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            refuse(f"{label} must have mode 700 before deployment: {path}")
        if not os.access(path, os.W_OK | os.X_OK):
            refuse(f"{label} is not writable and searchable by the deployment user: {path}")
        return

    parent = os.path.dirname(path)
    while not os.path.exists(parent):
        parent = os.path.dirname(parent)
    metadata = os.lstat(parent)
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != uid or metadata.st_gid != gid:
        refuse(f"{label} nearest existing parent must be owned by the deployment uid/gid: {parent}")
    if mode & 0o022 or mode & 0o300 != 0o300 or not os.access(parent, os.W_OK | os.X_OK):
        refuse(f"{label} nearest existing parent is not safely writable and searchable: {parent}")

repo = normalized("repository root", os.path.normpath(repo_text))
build = normalized("build root", build_text)
log = normalized("log root", log_text)
if overlaps(repo, build):
    refuse(f"build root overlaps the repository root: {build}")
if overlaps(repo, log):
    refuse(f"log root overlaps the repository root: {log}")
if overlaps(build, log):
    refuse(f"build and log roots overlap: {build} and {log}")
validate_root("build root", build)
validate_root("log root", log)
PY
}

validate_required_secret_names() {
  "${python3_bin}" -I - "${secret_env_file}" <<'PY'
import re
import sys

path = sys.argv[1]
required = {
    "BUZZ_RELAY_PRIVATE_KEY",
    "BUZZ_GIT_HOOK_HMAC_SECRET",
    "BUZZ_POSTGRES_PASSWORD",
    "BUZZ_REDIS_PASSWORD",
    "BUZZ_S3_ACCESS_KEY",
    "BUZZ_S3_SECRET_KEY",
    "BUZZ_RELAY_OWNER_PUBKEY",
}
found = {}
with open(path, encoding="utf-8") as source:
    for line in source:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)", stripped)
        if match is None or match.group(1) not in required:
            continue
        name, raw_value = match.groups()
        if name in found:
            print(f"REFUSED: required secret name is assigned more than once: {name}", file=sys.stderr)
            raise SystemExit(1)
        value = raw_value.strip()
        if value in {"", "''", '""'}:
            print(f"REFUSED: required secret name is empty: {name}", file=sys.stderr)
            raise SystemExit(1)
        found[name] = True
missing = sorted(required - found.keys())
if missing:
    print(f"REFUSED: required secret name is missing: {missing[0]}", file=sys.stderr)
    raise SystemExit(1)
PY
}

candidate_required_migration() {
  local required_raw
  required_raw=$(git -C "${repo_root}" ls-tree -r --name-only "${commit}" -- migrations \
    | sed -n 's#^migrations/\([0-9][0-9]*\)_.*[.]sql$#\1#p' | sort -n | tail -1)
  [[ -n ${required_raw} ]] || {
    printf 'REFUSED: no numbered SQL migrations found at %s\n' "${commit}" >&2
    return 1
  }
  printf '%d\n' "$((10#${required_raw}))"
}

container_network_ip() {
  local container=$1
  docker_state inspect --format '{{json .NetworkSettings.Networks}}' "${container}" | "${python3_bin}" -I -c '
import ipaddress
import json
import sys

try:
    networks = json.load(sys.stdin)
except json.JSONDecodeError as error:
    print(f"REFUSED: container network metadata is malformed ({error})", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(networks, dict) or len(networks) != 1:
    print("REFUSED: container must have exactly one inspectable network endpoint", file=sys.stderr)
    raise SystemExit(1)
row = next(iter(networks.values()))
address_text = row.get("IPAddress") if isinstance(row, dict) else None
try:
    address = ipaddress.ip_address(address_text)
except ValueError:
    print("REFUSED: container network address is missing or malformed", file=sys.stderr)
    raise SystemExit(1)
if address.version != 4 or address.is_unspecified or address.is_loopback or address.is_multicast:
    print("REFUSED: container network address is not a usable IPv4 endpoint", file=sys.stderr)
    raise SystemExit(1)
print(address)
'
}

db_query_readonly() {
  local sql=$1
  timeout --foreground "${probe_timeout}" \
    "${python3_bin}" -I - "${compose_env_file}" "${secret_env_file}" "${postgres_network_ip}" "${sql}" <<'PY'
import os
import re
import shlex
import sys

compose_path, secret_path, host, sql = sys.argv[1:]

def refuse(message):
    print(f"REFUSED: {message}", file=sys.stderr)
    raise SystemExit(1)

def assignments(path, wanted):
    found = {}
    with open(path, encoding="utf-8") as source:
        for line in source:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.fullmatch(r"(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)", stripped)
            if match is None:
                continue
            name, raw = match.groups()
            if name not in wanted:
                continue
            if name in found:
                refuse(f"database connection variable is assigned more than once: {name}")
            if "$" in raw or "`" in raw:
                refuse(f"database connection variable requires shell evaluation, which check mode forbids: {name}")
            lexer = shlex.shlex(raw, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#"
            try:
                values = list(lexer)
            except ValueError:
                refuse(f"database connection variable has malformed quoting: {name}")
            if len(values) != 1 or not values[0]:
                refuse(f"database connection variable is empty or malformed: {name}")
            found[name] = values[0]
    return found

compose_values = assignments(compose_path, {"POSTGRES_USER", "POSTGRES_DB"})
secret_values = assignments(secret_path, {"BUZZ_POSTGRES_PASSWORD"})
user = compose_values.get("POSTGRES_USER", "buzz")
database = compose_values.get("POSTGRES_DB", "buzz")
password = secret_values.get("BUZZ_POSTGRES_PASSWORD")
if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", user):
    refuse("POSTGRES_USER is unsafe for a direct read-only connection")
if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", database):
    refuse("POSTGRES_DB is unsafe for a direct read-only connection")
if password is None:
    refuse("BUZZ_POSTGRES_PASSWORD is unavailable for the read-only database check")

environment = {
    name: value for name, value in os.environ.items()
    if not name.upper().startswith("PG")
}
environment["PGPASSWORD"] = password
environment["PGOPTIONS"] = "-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000"
environment["PGCONNECT_TIMEOUT"] = "5"
argv = [
    "psql", "-X", "--no-password", "--no-align", "--tuples-only", "--quiet",
    "--set=ON_ERROR_STOP=1", "--host", host, "--port", "5432", "--username", user,
    "--dbname", database, "--command", f"BEGIN TRANSACTION READ ONLY; {sql}; ROLLBACK;",
]
os.execvpe(argv[0], argv, environment)
PY
}

db_query() {
  local sql=$1
  if ((preflight_active == 1)); then
    db_query_readonly "${sql}"
  else
    db_compose exec -T postgres sh -euc \
      'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "$1"' sh "${sql}"
  fi
}

container_binary_sha_readonly() {
  local container=$1
  [[ ${container} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || {
    printf 'REFUSED: running relay container identifier is unsafe: %s\n' "${container}" >&2
    return 1
  }
  curl_readonly --fail --silent --show-error --unix-socket "${docker_socket}" \
    --get --data-urlencode 'path=/usr/local/bin/buzz-relay' \
    "http://localhost/containers/${container}/archive" | "${python3_bin}" -I -c '
import hashlib
import sys
import tarfile

expected = {"buzz-relay", "usr/local/bin/buzz-relay"}
found = False
digest = hashlib.sha256()
try:
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            if name not in expected or found or not member.isfile() or member.size <= 0:
                raise ValueError("archive shape is not one exact regular relay binary")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("relay binary archive member is unreadable")
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
            found = True
except (OSError, tarfile.TarError, ValueError) as error:
    print(f"REFUSED: relay binary archive stream is invalid ({error})", file=sys.stderr)
    raise SystemExit(1)
if not found:
    print("REFUSED: relay binary archive stream contains no binary", file=sys.stderr)
    raise SystemExit(1)
print(digest.hexdigest())
'
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

read_db_migration() {
  local table_present table_present_normalized row row_version row_success_normalized failed_rows
  if ! table_present=$(db_query \
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
  if ! row=$(db_query \
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
  if ! failed_rows=$(db_query \
    "SELECT count(*) FROM _sqlx_migrations WHERE NOT success"); then
    printf 'REFUSED: database failed-migration query failed\n' >&2
    return 1
  fi
  [[ ${failed_rows} =~ ^[0-9]+$ ]] || {
    printf 'REFUSED: database failed-migration count is empty or malformed: %s\n' \
      "${failed_rows:-<empty>}" >&2
    return 1
  }
  ((10#${failed_rows} == 0)) || {
    printf 'REFUSED: database contains %d failed migration rows\n' "$((10#${failed_rows}))" >&2
    return 1
  }
  printf '%s|%s\n' "${row_version}" "${row_success_normalized}"
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
  image_id=$(docker_state inspect --format '{{.Image}}' "$1")
  [[ ${image_id} =~ ^sha256:[0-9a-f]{64}$ ]] || {
    printf 'Invalid image ID returned for container %s: %s\n' "$1" "${image_id}" >&2
    return 1
  }
  printf '%s\n' "${image_id}"
}

platform_image_id() {
  local image=$1 platform=$2 image_id
  image_id=$(docker_state image inspect --platform "${platform}" --format '{{.Id}}' "${image}") || return 1
  [[ ${image_id} =~ ^sha256:[0-9a-f]{64}$ ]] || {
    printf 'REFUSED: image %s returned invalid platform image ID for %s: %s\n' \
      "${image}" "${platform}" "${image_id}" >&2
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
  image_ref=$(docker_state inspect --format '{{.Config.Image}}' "$1")
  validate_image_ref "${image_ref}" || return 1
  printf '%s\n' "${image_ref}"
}

object_revision() {
  local object=$1 revision
  revision=$(docker_state inspect --format \
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
  if ! required=$(docker_state inspect --format \
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
  resolved=$(compose_readonly "${prior_image_ref}" config --format json | "${python3_bin}" -I -c '
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

descriptor_evidence() {
  local object=$1 kind=$2 platform=${3-} descriptor
  case "${kind}" in
    container)
      descriptor=$(docker_readonly inspect --format '{{json .ImageManifestDescriptor}}' "${object}") || return 1
      ;;
    image)
      [[ -n ${platform} ]] || return 1
      descriptor=$(docker_readonly image inspect --platform "${platform}" \
        --format '{{json .Descriptor}}' "${object}") || return 1
      ;;
    *) return 1 ;;
  esac
  "${python3_bin}" -I - "${kind}" "${object}" "${descriptor}" <<'PY'
import json
import re
import sys

kind, object_name, raw = sys.argv[1:]
try:
    descriptor = json.loads(raw)
except json.JSONDecodeError:
    print(f"REFUSED: {kind} descriptor is invalid JSON for {object_name}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(descriptor, dict):
    print(f"REFUSED: {kind} descriptor is missing for {object_name}", file=sys.stderr)
    raise SystemExit(1)
digest = descriptor.get("digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    print(f"REFUSED: {kind} descriptor digest is missing or malformed for {object_name}", file=sys.stderr)
    raise SystemExit(1)
platform = descriptor.get("platform")
platform_text = ""
if platform is not None:
    if not isinstance(platform, dict):
        print(f"REFUSED: {kind} descriptor platform is malformed for {object_name}", file=sys.stderr)
        raise SystemExit(1)
    os_name = platform.get("os")
    architecture = platform.get("architecture")
    variant = platform.get("variant")
    if not isinstance(os_name, str) or not isinstance(architecture, str):
        print(f"REFUSED: {kind} descriptor platform is incomplete for {object_name}", file=sys.stderr)
        raise SystemExit(1)
    platform_text = f"{os_name}/{architecture}"
    if variant is not None:
        if not isinstance(variant, str) or not variant:
            print(f"REFUSED: {kind} descriptor platform variant is malformed for {object_name}", file=sys.stderr)
            raise SystemExit(1)
        platform_text += f"/{variant}"
print(f"{digest}|{platform_text}")
PY
}

validate_compose_services() {
  compose_readonly "${prior_image_ref}" ps --all --format json | "${python3_bin}" -I -c '
import json
import sys

raw = sys.stdin.read().strip()
try:
    parsed = json.loads(raw)
    rows = parsed if isinstance(parsed, list) else [parsed]
except json.JSONDecodeError:
    rows = []
    for line in raw.splitlines():
        if line.strip():
            rows.append(json.loads(line))
by_service = {}
for row in rows:
    if not isinstance(row, dict):
        continue
    service = row.get("Service") or row.get("service")
    if isinstance(service, str):
        by_service.setdefault(service, []).append(row)
for service in ("relay", "pair-relay", "postgres", "redis", "minio"):
    entries = by_service.get(service, [])
    if len(entries) != 1:
        print(f"REFUSED: Compose service {service} does not have exactly one container", file=sys.stderr)
        raise SystemExit(1)
    row = entries[0]
    state = str(row.get("State") or row.get("state") or "").lower()
    health = str(row.get("Health") or row.get("health") or "").lower()
    if state != "running" or health != "healthy":
        print(f"REFUSED: Compose service {service} is not running and healthy", file=sys.stderr)
        raise SystemExit(1)
entries = by_service.get("minio-init", [])
if len(entries) != 1:
    print("REFUSED: Compose service minio-init does not have exactly one container", file=sys.stderr)
    raise SystemExit(1)
row = entries[0]
state = str(row.get("State") or row.get("state") or "").lower()
exit_code = row.get("ExitCode", row.get("exitCode"))
if state != "exited" or str(exit_code) != "0":
    print("REFUSED: Compose service minio-init has not completed successfully", file=sys.stderr)
    raise SystemExit(1)
'
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
  if [[ ${rollback_source_resolution} == prior-image-ref && ${actual_id} == "${prior_image_id}" ]]; then
    printf 'Index-digest binding for name-based rollback reference %s resolves to prior image index %s; revision/binary/migration bindings enforced separately\n' \
      "${image}" "${actual_id}"
  elif [[ ${actual_id} != "${prior_platform_image_id}" ]]; then
    printf 'REFUSED: image %s resolves to platform image %s, expected prior platform image %s\n' \
      "${image}" "${actual_id}" "${prior_platform_image_id}" >&2
    return 1
  fi
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
  rollback_source=${prior_platform_image_id}
  rollback_source_image_id=${prior_platform_image_id}
  rollback_source_resolution=platform-image-id
  if [[ ${prior_image_id} != "${prior_platform_image_id}" ]]; then
    printf 'Prior container image index %s differs from runnable platform image %s; preserving the index as evidence and retaining the platform image\n' \
      "${prior_image_id}" "${prior_platform_image_id}"
  fi
  if ! docker image tag "${rollback_source}" "${rollback_tag}"; then
    printf 'Platform image %s is not taggable in the image store; falling back to prior image reference %s\n' \
      "${rollback_source}" "${prior_image_ref}"
    rollback_source=${prior_image_ref}
    rollback_source_resolution=prior-image-ref
    docker image tag "${rollback_source}" "${rollback_tag}"
  fi
}

relay_container() {
  compose ps -q relay
}

probe_relay() {
  local container=$1
  if ((preflight_active == 1)); then
    curl_readonly --fail --silent --show-error --max-time "${probe_timeout}" \
      "http://${relay_network_ip}:8080/_readiness" >/dev/null
    curl_readonly --fail --silent --show-error --max-time "${probe_timeout}" \
      --header 'Accept: application/nostr+json' "http://${relay_network_ip}:3000/" | \
      "${python3_bin}" -I -c '
import json
import sys
try:
    document = json.load(sys.stdin)
except json.JSONDecodeError as error:
    print(f"REFUSED: relay NIP-11 response is malformed ({error})", file=sys.stderr)
    raise SystemExit(1)
supported = document.get("supported_nips") if isinstance(document, dict) else None
if not isinstance(supported, list):
    print("REFUSED: relay NIP-11 response has no supported_nips list", file=sys.stderr)
    raise SystemExit(1)
'
    return
  fi
  docker_state_with_timeout exec "${container}" bash -ec \
    'exec 3<>/dev/tcp/127.0.0.1/8080; printf "GET /_readiness HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" >&3; grep -q "200 OK" <&3'
  docker_state_with_timeout exec "${container}" bash -ec \
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
  printf '\nDEPLOY FAILED AFTER SWAP. ROLLING BACK TO %s\n' "${prior_platform_image_id}" >&2
  if ! compose_with_image "${rollback_tag}" up -d --no-deps --force-recreate relay; then
    printf 'ROLLBACK FAILED: compose could not recreate relay with %s\n' "${prior_platform_image_id}" >&2
    return 1
  fi
  rollback_container=$(relay_container)
  [[ -n ${rollback_container} ]] || {
    printf 'ROLLBACK FAILED: relay container is missing\n' >&2
    return 1
  }
  rollback_image=$(container_image_id "${rollback_container}")
  [[ ${rollback_image} == "${prior_platform_image_id}" ]] || {
    printf 'ROLLBACK FAILED: running image %s does not match prior platform image %s\n' \
      "${rollback_image}" "${prior_platform_image_id}" >&2
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
  printf 'ROLLBACK SUCCEEDED: restored platform image %s with binary %s\n' \
    "${prior_platform_image_id}" "${rollback_sha}" >&2
}

collect_static_preflight_blockers() {
  local output resolved checkout source dirty probe_path disk_probe available
  local -a blockers=()

  capture() {
    local fallback=$1
    shift
    output=
    if ! output=$("$@" 2>&1); then
      blockers+=("${output:-REFUSED: ${fallback}}")
    fi
  }

  if ! output=$(validate_root_owned_file "${python3_bin}" 755 'Python interpreter' 2>&1); then
    printf '%s\n' "${output}" >&2
    printf 'REFUSED: preflight will not execute an untrusted Python interpreter\n' >&2
    unset -f capture
    return 1
  fi
  if ! output=$(validate_checkout_file "${protected_ci_tool}" yes 'protected-CI validator' 2>&1) || \
    ! validate_safe_parent "${protected_ci_tool}" '' 'protected-CI validator' >/dev/null 2>&1 || \
    ! git -C "${repo_root}" diff --quiet "${commit}" -- scripts/protected-ci-receipt.py; then
    printf '%s\n' "${output:-REFUSED: protected-CI validator is unsafe or differs from the requested commit}" >&2
    printf 'REFUSED: preflight will not execute an untrusted protected-CI validator\n' >&2
    unset -f capture
    return 1
  fi

  if [[ ! ${health_attempts} =~ ^[1-9][0-9]*$ ]] || \
    [[ ! ${health_interval} =~ ^[0-9]+([.][0-9]+)?$ ]] || \
    [[ ! ${probe_timeout} =~ ^([1-9][0-9]*|0[.][0-9]*[1-9][0-9]*)$ ]] || \
    [[ ! ${receipt_max_age} =~ ^[1-9][0-9]*$ ]] || \
    [[ ! ${minimum_free_kb} =~ ^[1-9][0-9]*$ ]]; then
    blockers+=('REFUSED: health, receipt-age, and free-disk settings must be positive numbers')
  fi

  if resolved=$(git -C "${repo_root}" rev-parse --verify "${commit}^{commit}" 2>/dev/null); then
    [[ ${resolved} == "${commit}" ]] || \
      blockers+=("REFUSED: requested commit resolves to ${resolved}")
  else
    blockers+=("REFUSED: requested commit is not a readable commit: ${commit}")
  fi
  if checkout=$(git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null); then
    [[ ${checkout} == "${commit}" ]] || \
      blockers+=("REFUSED: source checkout is at ${checkout}, expected ${commit}")
  else
    blockers+=('REFUSED: source checkout HEAD is unreadable')
  fi
  if [[ ${source_ref} != refs/remotes/*/* ]] || \
    ! git -C "${repo_root}" check-ref-format "${source_ref}" >/dev/null 2>&1; then
    blockers+=("REFUSED: deployment source ref must be a remote-tracking branch, not a raw commit: ${source_ref}")
  elif source=$(git -C "${repo_root}" rev-parse --verify "${source_ref}^{commit}" 2>/dev/null); then
    [[ ${source} == "${commit}" ]] || \
      blockers+=("REFUSED: source ref ${source_ref} is at ${source}, expected ${commit}")
  else
    blockers+=("REFUSED: source ref is unreadable: ${source_ref}")
  fi
  if dirty=$(git -C "${repo_root}" status --porcelain --untracked-files=all 2>/dev/null); then
    dirty=$(printf '%s\n' "${dirty}" | sed \
      -e '/^?? pre-freeze-receipt[.]json$/d' \
      -e '/^?? protected-ci-receipt[.]json$/d')
    [[ -z ${dirty} ]] || blockers+=('REFUSED: source checkout is dirty')
  else
    blockers+=('REFUSED: source checkout status is unreadable')
  fi
  [[ ${run_local} == "${canonical_run_local}" ]] || \
    blockers+=("REFUSED: BUZZ_RUN_LOCAL may not replace the commit-bound Compose runner: ${run_local}")
  capture 'deployment scripts or Compose inputs differ from the requested commit' \
    git -C "${repo_root}" diff --quiet "${commit}" -- \
    deploy/compose/run-local.sh deploy/compose/compose.yml \
    deploy/compose/compose.localhost.yml deploy/compose/deploy-local.sh \
    scripts/protected-ci-receipt.py

  capture 'Compose runner validation failed' \
    validate_checkout_file "${run_local}" yes 'Compose runner'
  capture 'Compose runner parent validation failed' \
    validate_safe_parent "${run_local}" '' 'Compose runner'
  capture 'base Compose file validation failed' \
    validate_checkout_file "${compose_file}" no 'base Compose file'
  capture 'localhost Compose file validation failed' \
    validate_checkout_file "${compose_local_file}" no 'localhost Compose file'
  capture 'Compose environment file validation failed' \
    validate_owned_file "${compose_env_file}" 640 'Compose environment file'
  capture 'Compose environment parent validation failed' \
    validate_safe_parent "${compose_env_file}" '' 'Compose environment file'
  capture 'secret environment file validation failed' \
    validate_owned_file "${secret_env_file}" 600 'secret environment file'
  capture 'secret environment parent validation failed' \
    validate_safe_parent "${secret_env_file}" 700 'secret environment file'
  if [[ -f ${secret_env_file} && ! -L ${secret_env_file} ]]; then
    capture 'required secret-name validation failed' validate_required_secret_names
  fi
  capture 'pre-freeze receipt parent validation failed' \
    validate_safe_parent "${pre_freeze_receipt}" '' 'pre-freeze receipt'
  capture 'protected-CI receipt parent validation failed' \
    validate_safe_parent "${protected_ci_receipt}" 700 'protected-CI receipt'
  if [[ ${receipt_max_age} =~ ^[1-9][0-9]*$ ]]; then
    capture 'pre-freeze receipt validation failed' \
      validate_pre_freeze_receipt "${pre_freeze_receipt}"
    capture 'protected-CI receipt validation failed' \
      validate_protected_ci_receipt
  fi
  capture 'candidate migration could not be read from the Git object' candidate_required_migration
  capture 'deployment storage-root validation failed' validate_storage_roots

  for tool in git docker curl psql timeout env sha256sum awk sed sort tail df stat dirname id; do
    command -v "${tool}" >/dev/null || \
      blockers+=("REFUSED: required deployment tool is unavailable: ${tool}")
  done
  if [[ ${docker_socket} != /* || ${docker_socket} == *[[:space:]]* || \
    ! -S ${docker_socket} || -L ${docker_socket} ]]; then
    blockers+=("REFUSED: Docker socket is missing, is not an absolute socket, or is a symlink: ${docker_socket}")
  else
    [[ $(stat -c %u "${docker_socket}" 2>/dev/null) == 0 && \
      $(stat -c %G "${docker_socket}" 2>/dev/null) == docker && \
      $(stat -c %a "${docker_socket}" 2>/dev/null) == 660 ]] || \
      blockers+=("REFUSED: Docker socket must be root:docker mode 0660: ${docker_socket}")
  fi
  [[ -z ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} ]] || \
    blockers+=('REFUSED: DOCKER_HOST and DOCKER_CONTEXT must be unset; preflight binds the validated socket explicitly')
  if [[ ${minimum_free_kb} =~ ^[1-9][0-9]*$ ]]; then
    for probe_path in "${repo_root}" "${build_root}" "${log_root}"; do
      disk_probe=${probe_path}
      while [[ ! -e ${disk_probe} && ${disk_probe} != / ]]; do
        disk_probe=$(dirname "${disk_probe}")
      done
      available=$(df -Pk "${disk_probe}" 2>/dev/null | awk 'NR > 1 {value=$4} END {print value}')
      [[ ${available} =~ ^[0-9]+$ ]] && ((10#${available} >= minimum_free_kb)) || \
        blockers+=("REFUSED: deployment filesystem for ${probe_path} has less than ${minimum_free_kb} KiB free")
    done
  fi

  unset -f capture
  ((${#blockers[@]} == 0)) && return 0
  printf '%s\n' "${blockers[@]}" >&2
  printf 'REFUSED: preflight found %d independent static blocker(s)\n' "${#blockers[@]}" >&2
  return 1
}

deployment_preflight() {
  local tool socket_uid socket_group socket_mode available_kb resolved_commit checkout_head
  local source_head dirty_status filtered_dirty_status status_entry pre_freeze_base
  local relay_ids postgres_ids resolved_image container_descriptor image_descriptor image_descriptor_platform
  local image_descriptor_digest prior_required_migration_status=0 db_state expected_override
  local disk_path disk_probe

  collect_static_preflight_blockers || return 1

  if [[ ! ${health_attempts} =~ ^[1-9][0-9]*$ ]] || \
    [[ ! ${health_interval} =~ ^[0-9]+([.][0-9]+)?$ ]] || \
    [[ ! ${probe_timeout} =~ ^([1-9][0-9]*|0[.][0-9]*[1-9][0-9]*)$ ]] || \
    [[ ! ${receipt_max_age} =~ ^[1-9][0-9]*$ ]] || \
    [[ ! ${minimum_free_kb} =~ ^[1-9][0-9]*$ ]]; then
    printf 'REFUSED: health, receipt-age, and free-disk settings must be positive numbers\n' >&2
    return 1
  fi

  git -C "${repo_root}" cat-file -e "${commit}^{commit}"
  resolved_commit=$(git -C "${repo_root}" rev-parse --verify "${commit}^{commit}")
  [[ ${resolved_commit} == "${commit}" ]] || {
    printf 'REFUSED: requested commit resolves to %s\n' "${resolved_commit}" >&2
    return 1
  }
  checkout_head=$(git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}')
  [[ ${checkout_head} == "${commit}" ]] || {
    printf 'REFUSED: source checkout is at %s, expected %s\n' "${checkout_head}" "${commit}" >&2
    return 1
  }
  [[ ${source_ref} == refs/remotes/*/* ]] && \
    git -C "${repo_root}" check-ref-format "${source_ref}" || {
    printf 'REFUSED: deployment source ref must be a remote-tracking branch, not a raw commit: %s\n' \
      "${source_ref}" >&2
    return 1
  }
  source_head=$(git -C "${repo_root}" rev-parse --verify "${source_ref}^{commit}")
  [[ ${source_head} == "${commit}" ]] || {
    printf 'REFUSED: source ref %s is at %s, expected %s\n' \
      "${source_ref}" "${source_head}" "${commit}" >&2
    return 1
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
  [[ -z ${filtered_dirty_status} ]] || {
    printf 'REFUSED: source checkout is dirty\n' >&2
    return 1
  }
  [[ ${run_local} == "${canonical_run_local}" ]] || {
    printf 'REFUSED: BUZZ_RUN_LOCAL may not replace the commit-bound Compose runner: %s\n' \
      "${run_local}" >&2
    return 1
  }
  git -C "${repo_root}" diff --quiet "${commit}" -- \
    deploy/compose/run-local.sh deploy/compose/compose.yml \
    deploy/compose/compose.localhost.yml deploy/compose/deploy-local.sh \
    scripts/protected-ci-receipt.py || {
    printf 'REFUSED: deployment scripts or Compose inputs differ from the requested commit\n' >&2
    return 1
  }
  validate_safe_parent "${pre_freeze_receipt}" '' 'pre-freeze receipt'
  validate_safe_parent "${protected_ci_receipt}" 700 'protected-CI receipt'
  pre_freeze_base=$(validate_pre_freeze_receipt "${pre_freeze_receipt}")
  git -C "${repo_root}" cat-file -e "${pre_freeze_base}^{commit}"
  git -C "${repo_root}" merge-base --is-ancestor "${pre_freeze_base}" "${commit}" || {
    printf 'REFUSED: pre-freeze receipt base %s is not an ancestor of %s\n' \
      "${pre_freeze_base}" "${commit}" >&2
    return 1
  }
  validate_protected_ci_receipt
  required_migration=$(candidate_required_migration)

  validate_checkout_file "${run_local}" yes 'Compose runner'
  validate_safe_parent "${run_local}" '' 'Compose runner'
  validate_checkout_file "${protected_ci_tool}" yes 'protected-CI validator'
  validate_safe_parent "${protected_ci_tool}" '' 'protected-CI validator'
  validate_checkout_file "${compose_file}" no 'base Compose file'
  validate_checkout_file "${compose_local_file}" no 'localhost Compose file'
  validate_owned_file "${compose_env_file}" 640 'Compose environment file'
  validate_safe_parent "${compose_env_file}" '' 'Compose environment file'
  validate_owned_file "${secret_env_file}" 600 'secret environment file'
  validate_safe_parent "${secret_env_file}" 700 'secret environment file'
  validate_required_secret_names
  validate_storage_roots

  for tool in git docker curl psql timeout env sha256sum awk sed sort tail df stat dirname id; do
    command -v "${tool}" >/dev/null || {
      printf 'REFUSED: required deployment tool is unavailable: %s\n' "${tool}" >&2
      return 1
    }
  done
  [[ ${docker_socket} == /* && ${docker_socket} != *[[:space:]]* && \
    -S ${docker_socket} && ! -L ${docker_socket} ]] || {
    printf 'REFUSED: Docker socket is missing, is not a socket, or is a symlink: %s\n' \
      "${docker_socket}" >&2
    return 1
  }
  socket_uid=$(stat -c %u "${docker_socket}") || return 1
  socket_group=$(stat -c %G "${docker_socket}") || return 1
  socket_mode=$(stat -c %a "${docker_socket}") || return 1
  [[ ${socket_uid} == 0 && ${socket_group} == docker && ${socket_mode} == 660 ]] || {
    printf 'REFUSED: Docker socket must be root:docker mode 0660: %s\n' "${docker_socket}" >&2
    return 1
  }
  [[ -z ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} ]] || {
    printf 'REFUSED: DOCKER_HOST and DOCKER_CONTEXT must be unset; preflight binds the validated socket explicitly\n' >&2
    return 1
  }
  preflight_active=1
  docker_readonly info --format '{{.ServerVersion}}' >/dev/null || {
    printf 'REFUSED: deployment user cannot access the Docker daemon\n' >&2
    return 1
  }
  docker_readonly compose version --short >/dev/null || {
    printf 'REFUSED: Docker Compose is unavailable\n' >&2
    return 1
  }
  for disk_path in "${repo_root}" "${build_root}" "${log_root}"; do
    disk_probe=${disk_path}
    while [[ ! -e ${disk_probe} && ${disk_probe} != / ]]; do
      disk_probe=$(dirname "${disk_probe}")
    done
    available_kb=$(df -Pk "${disk_probe}" | awk 'NR > 1 {value=$4} END {print value}')
    [[ ${available_kb} =~ ^[0-9]+$ ]] && ((10#${available_kb} >= minimum_free_kb)) || {
      printf 'REFUSED: deployment filesystem for %s has less than %d KiB free\n' \
        "${disk_path}" "${minimum_free_kb}" >&2
      return 1
    }
  done

  relay_ids=$(compose_readonly '' ps -q relay)
  [[ -n ${relay_ids} && ${relay_ids} != *$'\n'* ]] || {
    printf 'REFUSED: Compose relay does not resolve to exactly one running container\n' >&2
    return 1
  }
  prior_container=${relay_ids}
  prior_image_id=$(container_image_id "${prior_container}")
  prior_image_ref=$(container_image_ref "${prior_container}")
  prior_revision=$(object_revision "${prior_container}")
  resolve_relay_platform
  resolved_image=$(compose_readonly "${prior_image_ref}" config --format json | "${python3_bin}" -I -c '
import json
import sys
image = json.load(sys.stdin).get("services", {}).get("relay", {}).get("image")
if not isinstance(image, str) or not image:
    raise SystemExit(1)
print(image)
') || {
    printf 'REFUSED: Compose relay image could not be resolved\n' >&2
    return 1
  }
  [[ ${resolved_image} == "${prior_image_ref}" ]] || {
    printf 'REFUSED: Compose relay image %s does not match running configured ref %s\n' \
      "${resolved_image}" "${prior_image_ref}" >&2
    return 1
  }
  validate_compose_services
  relay_network_ip=$(container_network_ip "${prior_container}")
  postgres_ids=$(compose_readonly "${prior_image_ref}" ps -q postgres)
  [[ -n ${postgres_ids} && ${postgres_ids} != *$'\n'* ]] || {
    printf 'REFUSED: Compose postgres does not resolve to exactly one running container\n' >&2
    return 1
  }
  postgres_network_ip=$(container_network_ip "${postgres_ids}")

  container_descriptor=$(descriptor_evidence "${prior_container}" container)
  IFS='|' read -r prior_descriptor_digest prior_platform <<<"${container_descriptor}"
  image_descriptor=$(descriptor_evidence "${prior_image_ref}" image "${prior_platform}")
  IFS='|' read -r image_descriptor_digest image_descriptor_platform <<<"${image_descriptor}"
  [[ ${prior_descriptor_digest} == "${image_descriptor_digest}" ]] || {
    printf 'REFUSED: running container descriptor %s does not match configured ref descriptor %s\n' \
      "${prior_descriptor_digest}" "${image_descriptor_digest}" >&2
    return 1
  }
  [[ ${prior_platform} =~ ^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?$ ]] || {
    printf 'REFUSED: running container descriptor platform is missing or malformed: %s\n' \
      "${prior_platform:-<empty>}" >&2
    return 1
  }
  if [[ -n ${relay_platform} && ${relay_platform} != "${prior_platform}" ]]; then
    printf 'REFUSED: Compose relay platform %s does not match running descriptor platform %s\n' \
      "${relay_platform}" "${prior_platform}" >&2
    return 1
  fi
  if [[ -n ${image_descriptor_platform} && ${image_descriptor_platform} != "${prior_platform}" ]]; then
    printf 'REFUSED: configured ref descriptor platform %s does not match running descriptor platform %s\n' \
      "${image_descriptor_platform}" "${prior_platform}" >&2
    return 1
  fi
  prior_platform_image_id=$(platform_image_id "${prior_image_ref}" "${prior_platform}")

  prior_required_migration_label=$(image_required_migration "${prior_container}" quiet) || \
    prior_required_migration_status=$?
  case "${prior_required_migration_status}" in
    0) ;;
    1) prior_required_migration_label= ;;
    2)
      printf 'REFUSED: prior image required-migration label could not be inspected; rollback compatibility is unreadable and BUZZ_PRIOR_MIGRATION_OVERRIDE is not permitted\n' >&2
      return 1
      ;;
    *)
      printf 'REFUSED: unexpected prior image required-migration label status: %s\n' \
        "${prior_required_migration_status}" >&2
      return 1
      ;;
  esac
  prior_binary_sha=$(container_binary_sha_readonly "${prior_container}")
  probe_relay "${prior_container}" >/dev/null || {
    printf 'REFUSED: running relay failed readiness or NIP-11 readback\n' >&2
    return 1
  }

  if ! db_state=$(read_db_migration); then
    preflight_active=0
    return 1
  fi
  preflight_active=0
  IFS='|' read -r db_migration db_success <<<"${db_state}"
  [[ ${db_migration} =~ ^[0-9]+$ ]] || {
    printf 'REFUSED: invalid migration version returned by database: %s\n' "${db_state}" >&2
    return 1
  }
  pg_boolean_true "${db_success}" || {
    printf 'REFUSED: database migration %s is recorded with success=%s\n' \
      "${db_migration}" "${db_success}" >&2
    return 1
  }
  expected_override=${prior_image_id}@${db_migration}
  if [[ -n ${prior_migration_override} ]]; then
    [[ -z ${prior_required_migration_label} ]] || {
      printf 'REFUSED: BUZZ_PRIOR_MIGRATION_OVERRIDE is not permitted because the prior image has valid required-migration label %s\n' \
        "${prior_required_migration_label}" >&2
      return 1
    }
    [[ ${prior_migration_override} == "${expected_override}" ]] || {
      printf 'REFUSED: BUZZ_PRIOR_MIGRATION_OVERRIDE must match the current prior-image/database binding %s\n' \
        "${expected_override}" >&2
      return 1
    }
    prior_required_migration=${db_migration}
  else
    [[ -n ${prior_required_migration_label} ]] || {
      printf 'REFUSED: prior image has no valid required-migration label; rerun with BUZZ_PRIOR_MIGRATION_OVERRIDE=%s only after verifying compatibility\n' \
        "${expected_override}" >&2
      return 1
    }
    prior_required_migration=${prior_required_migration_label}
  fi
  ((db_migration <= required_migration)) || {
    printf 'REFUSED: database migration %d is newer than image requirement %d; rollback needs a compatible image\n' \
      "${db_migration}" "${required_migration}" >&2
    return 1
  }
  preflight_active=0
  printf 'PREFLIGHT PASSED: commit %s, running revision %s, platform %s, database %d, candidate migration %d\n' \
    "${commit}" "${prior_revision}" "${prior_platform}" "${db_migration}" "${required_migration}"
}

on_exit() {
  local rc=$?
  trap - EXIT
  set +e
  preflight_active=0
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

deployment_preflight
if ((check_only == 1)); then
  printf 'CHECK PASSED: no files, images, containers, services, or database state were changed\n'
  exit 0
fi

trap on_exit EXIT
mkdir -p "${build_root}" "${log_root}"
chmod 700 "${build_root}" "${log_root}"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
deploy_dir=${log_root}/${timestamp}-${commit:0:12}
mkdir "${deploy_dir}"
chmod 700 "${deploy_dir}"
exec > >(tee -a "${deploy_dir}/deploy.log") 2>&1

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

# The build may take long enough for live state to drift. Re-run the same
# side-effect-free preflight before capturing rollback evidence or the dump.
deployment_preflight
printf '%s\n' "${prior_container}" >"${deploy_dir}/prior-container-id.txt"
printf '%s\n' "${prior_image_id}" >"${deploy_dir}/prior-image-id.txt"
printf '%s\n' "${prior_platform_image_id}" >"${deploy_dir}/prior-platform-image-id.txt"
printf '%s\n' "${prior_image_ref}" >"${deploy_dir}/prior-image-ref.txt"
printf '%s\n' "${prior_revision}" >"${deploy_dir}/prior-revision.txt"
printf '%s\n' "${prior_binary_sha}" >"${deploy_dir}/prior-binary-sha256.txt"
rollback_tag=localhost/buzz-relay:rollback-${timestamp}-${prior_platform_image_id#sha256:}
rollback_tag=${rollback_tag:0:127}
capture_rollback_reference
printf '%s\n' "${rollback_source}" >"${deploy_dir}/rollback-source.txt"
printf '%s\n' "${rollback_source_image_id}" >"${deploy_dir}/rollback-source-image-id.txt"
printf '%s\n' "${rollback_source_resolution}" >"${deploy_dir}/rollback-source-resolution.txt"
printf '%s\n' "${rollback_tag}" >"${deploy_dir}/rollback-image-tag.txt"
verify_image_platform_binding "${rollback_tag}"

dump_file=${deploy_dir}/buzz-prod-before-${timestamp}.dump
printf 'Writing Postgres custom-format dump: %s\n' "${dump_file}"
compose exec -T postgres sh -euc \
  'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' >"${dump_file}"
[[ -s ${dump_file} ]] || {
  printf 'REFUSED: Postgres dump is empty\n' >&2
  exit 1
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
