#!/usr/bin/bash -p
# shellcheck disable=SC2034

# Privileged mode ignores BASH_ENV, SHELLOPTS, and imported BASH_FUNC_*
# definitions before the first script statement. The launcher still clears
# every exported variable and unexpected function before AppImage execution.
builtin set -euo pipefail
builtin set +x
builtin umask 077

readonly secret_dir=/home/victor/.config/sats
readonly secret_file=${secret_dir}/secrets.env
readonly trusted_home=/home/victor
readonly trusted_owner=victor
readonly appimage=/home/victor/work/buzz-client/Buzz_0.5.9-test.11_amd64.AppImage
readonly appimage_sha256=404829a7fba15a9887e847c3b0fbf5b208f6759e097367bba51ca044437f2009
readonly appimage_manifest=/home/victor/work/buzz-client/Buzz_0.5.9-test.11_amd64.AppImage.manifest.json
readonly appimage_manifest_sha256=b18b3b5185da563a267df2f31336ac26138d39b6808616c6735bf76d6f611168
readonly relay_url=wss://framework-desktop.tail69757d.ts.net:38443
readonly runtime_dir=/run/user/1000
readonly fallback_xauthority=/home/victor/.Xauthority
readonly session_display=${DISPLAY:-}
readonly session_wayland_display=${WAYLAND_DISPLAY:-}
readonly session_xauthority=${XAUTHORITY:-}
desktop_xauthority=
builtin export -n desktop_xauthority

fail() {
  builtin printf 'Buzz desktop launch blocked: %s\n' "$1" >&2
  builtin exit 1
}

validate_trusted_directory() {
  local directory=$1
  local canonical

  [[ -d ${directory} && ! -L ${directory} ]] || fail "trusted directory is missing or a symlink: ${directory}"
  canonical=$(/usr/bin/readlink -e -- "${directory}") || fail "cannot resolve trusted directory: ${directory}"
  [[ ${canonical} == "${directory}" && \
    $(/usr/bin/stat -c '%U:%G' -- "${directory}") == victor:victor && \
    $(/usr/bin/stat -c %a -- "${directory}") == 700 && \
    -w ${directory} && -x ${directory} ]] || fail "trusted directory has unsafe identity, ownership, mode, or access: ${directory}"
}

validate_xauthority() {
  builtin local path=$1
  builtin local canonical
  builtin local mode

  [[ ${path} == /* ]] || fail "XAUTHORITY must be an absolute path"
  [[ -e ${path} ]] || fail "XAUTHORITY is missing: ${path}"
  [[ -f ${path} && ! -L ${path} ]] || fail "XAUTHORITY is linked or not a regular file: ${path}"
  [[ -r ${path} ]] || fail "XAUTHORITY is not readable: ${path}"
  canonical=$(/usr/bin/readlink -e -- "${path}") || fail "XAUTHORITY cannot be resolved: ${path}"
  [[ ${canonical} == "${path}" ]] || fail "XAUTHORITY has a non-canonical or linked path: ${path}"
  [[ $(/usr/bin/stat -c %U -- "${path}") == victor ]] || fail "XAUTHORITY is not owned by victor: ${path}"
  mode=$(/usr/bin/stat -c %a -- "${path}") || fail "XAUTHORITY mode cannot be read: ${path}"
  (( (8#${mode} & 0022) == 0 )) || fail "XAUTHORITY is group/world-writable: ${path}"
}

validate_owned_directory_chain() {
  builtin local target=$1
  builtin local current=${trusted_home}
  builtin local remaining
  builtin local component
  builtin local canonical
  builtin local mode

  [[ ${target} == "${trusted_home}" || ${target} == "${trusted_home}/"* ]] || \
    fail "reviewed artifact directory is outside the trusted home: ${target}"
  remaining=${target#"${trusted_home}"}
  remaining=${remaining#/}
  while :; do
    [[ -d ${current} && ! -L ${current} && -r ${current} && -x ${current} ]] || \
      fail "reviewed artifact directory is missing, linked, or inaccessible: ${current}"
    canonical=$(/usr/bin/readlink -e -- "${current}") || \
      fail "reviewed artifact directory cannot be resolved: ${current}"
    [[ ${canonical} == "${current}" && $(/usr/bin/stat -c %U -- "${current}") == "${trusted_owner}" ]] || \
      fail "reviewed artifact directory has unsafe identity or ownership: ${current}"
    mode=$(/usr/bin/stat -c %a -- "${current}") || \
      fail "reviewed artifact directory mode cannot be read: ${current}"
    (( (8#${mode} & 0022) == 0 )) || \
      fail "reviewed artifact directory is group/world-writable: ${current}"
    [[ -z ${remaining} ]] && break
    if [[ ${remaining} == */* ]]; then
      component=${remaining%%/*}
      remaining=${remaining#*/}
    else
      component=${remaining}
      remaining=
    fi
    [[ -n ${component} && ${component} != . && ${component} != .. ]] || \
      fail "reviewed artifact directory contains an unsafe component: ${target}"
    current=${current}/${component}
  done
}

validate_appimage() {
  builtin local path=$1
  builtin local mode

  validate_owned_directory_chain "${path%/*}"
  [[ -f ${path} && ! -L ${path} && -r ${path} && -x ${path} ]] || \
    fail "Buzz AppImage is missing, linked, unreadable, or not executable: ${path}"
  [[ $(/usr/bin/stat -c %U -- "${path}") == "${trusted_owner}" && \
    $(/usr/bin/stat -c %h -- "${path}") == 1 ]] || \
    fail "Buzz AppImage has unsafe ownership or link count: ${path}"
  mode=$(/usr/bin/stat -c %a -- "${path}") || fail "Buzz AppImage mode cannot be read: ${path}"
  (( (8#${mode} & 0022) == 0 )) || fail "Buzz AppImage is group/world-writable: ${path}"
}

clear_exported_environment() {
  builtin local name
  builtin local -a exported_names
  builtin local -a function_names
  exported_names=()
  function_names=()

  builtin mapfile -t exported_names < <(builtin compgen -e)
  builtin mapfile -t function_names < <(builtin compgen -A function)
  for name in "${function_names[@]}"; do
    case ${name} in
      assert_exact_exported_environment|clear_exported_environment|exec_reviewed_environment|fail|validate_appimage|validate_owned_directory_chain|validate_trusted_directory|validate_xauthority)
        builtin export -nf "${name?}"
        ;;
      *)
        builtin unset -f "${name?}"
        ;;
    esac
  done
  for name in "${exported_names[@]}"; do
    if ! builtin unset -v "${name}" 2>/dev/null; then
      builtin export -n "${name?}"
    fi
  done
  [[ -z $(builtin compgen -e) ]] || fail 'inherited exported environment was not fully cleared'
  while IFS= read -r name; do
    case ${name} in
      assert_exact_exported_environment|clear_exported_environment|exec_reviewed_environment|fail|validate_appimage|validate_owned_directory_chain|validate_trusted_directory|validate_xauthority) ;;
      *) fail "unexpected shell function survived clearing: ${name}" ;;
    esac
  done < <(builtin compgen -A function)
}

assert_exact_exported_environment() {
  builtin local exported_name
  builtin local -A expected_exports
  expected_exports=(
    [HOME]=1
    [USER]=1
    [LOGNAME]=1
    [PATH]=1
    [LANG]=1
    [LC_ALL]=1
    [TMPDIR]=1
    [XDG_RUNTIME_DIR]=1
    [DBUS_SESSION_BUS_ADDRESS]=1
    [HF_HUB_CACHE]=1
    [HF_XET_CACHE]=1
    [MESH_LLM_NATIVE_RUNTIME_CACHE_DIR]=1
    [BUZZ_PRIVATE_KEY]=1
    [BUZZ_SHARE_IDENTITY]=1
    [BUZZ_RELAY_URL]=1
  )

  [[ -z ${session_display} ]] || expected_exports[DISPLAY]=1
  [[ -z ${session_wayland_display} ]] || expected_exports[WAYLAND_DISPLAY]=1
  [[ -z ${desktop_xauthority} ]] || expected_exports[XAUTHORITY]=1
  while IFS= read -r exported_name; do
    [[ ${expected_exports["${exported_name}"]+present} == present ]] || \
      fail "unexpected exported environment name: ${exported_name}"
    builtin unset "expected_exports[${exported_name}]"
  done < <(builtin compgen -e)
  ((${#expected_exports[@]} == 0)) || fail 'minimal exported environment is incomplete'
}

exec_reviewed_environment() {
  builtin local name_csv
  builtin local -a names

  builtin mapfile -t names < <(builtin compgen -e)
  builtin printf -v name_csv '%s,' "${names[@]}"
  name_csv=${name_csv%,}
  builtin exec /usr/bin/python3 -I -S -E -c '
import os
import sys

names = sys.argv[1].split(",") if sys.argv[1] else []
target = sys.argv[2]
environment = {name: os.environ[name] for name in names}
os.execve(target, [target, *sys.argv[3:]], environment)
' "${name_csv}" "${appimage}" "$@"
}

validate_trusted_directory /home/victor/.cache
validate_trusted_directory /home/victor/.cache/tmp
validate_trusted_directory /home/victor/.cache/huggingface
validate_trusted_directory /home/victor/.cache/huggingface/hub
validate_trusted_directory /home/victor/.cache/huggingface/xet
validate_trusted_directory /home/victor/.cache/mesh-llm
validate_trusted_directory /home/victor/.cache/mesh-llm/native-runtimes

[[ -d ${secret_dir} && ! -L ${secret_dir} && \
  $(/usr/bin/stat -c '%U:%G:%a' "${secret_dir}") == victor:victor:700 ]] || fail "sanctioned secrets directory is missing or unsafe"
[[ -f ${secret_file} && ! -L ${secret_file} && \
  $(/usr/bin/stat -c '%U:%G:%a:%h' "${secret_file}") == victor:victor:600:1 ]] || fail "sanctioned secrets file is missing or unsafe"
validate_appimage "${appimage}"
[[ -f ${appimage_manifest} && ! -L ${appimage_manifest} && \
  $(/usr/bin/stat -c '%U:%G:%a:%h' "${appimage_manifest}") == victor:victor:600:1 ]] || fail "Buzz AppImage manifest is missing or unsafe"
[[ $(/usr/bin/sha256sum -- "${appimage}" | /usr/bin/cut -d' ' -f1) == "${appimage_sha256}" ]] || fail "Buzz AppImage hash does not match the reviewed artifact"
[[ $(/usr/bin/sha256sum -- "${appimage_manifest}" | /usr/bin/cut -d' ' -f1) == "${appimage_manifest_sha256}" ]] || fail "Buzz AppImage manifest hash does not match the reviewed artifact"
[[ -z ${session_display} || ${session_display} =~ ^(:[0-9]+(\.[0-9]+)?)$ ]] || fail "DISPLAY has an unsupported value"
[[ -z ${session_wayland_display} || ${session_wayland_display} =~ ^wayland-[0-9]+$ ]] || fail "WAYLAND_DISPLAY has an unsupported value"
[[ -n ${session_display} || -n ${session_wayland_display} ]] || fail "desktop session display is missing"
if [[ -n ${session_display} ]]; then
  if [[ -n ${session_xauthority} ]]; then
    desktop_xauthority=${session_xauthority}
  else
    [[ -e ${fallback_xauthority} || -L ${fallback_xauthority} ]] || \
      fail "XAUTHORITY is unset and fallback is missing: ${fallback_xauthority}"
    desktop_xauthority=${fallback_xauthority}
  fi
  validate_xauthority "${desktop_xauthority}"
elif [[ -n ${session_xauthority} ]]; then
  fail "XAUTHORITY is set without X11 or XWayland"
fi

# shellcheck disable=SC1090
. "${secret_file}"
[[ ${BUZZ_OWNER_PRIVATE_KEY:-} =~ ^[0-9a-f]{64}$ ]] || fail "BUZZ_OWNER_PRIVATE_KEY is missing or invalid"
readonly desktop_private_key=${BUZZ_OWNER_PRIVATE_KEY}

clear_exported_environment
builtin export HOME=/home/victor
builtin export USER=victor
builtin export LOGNAME=victor
builtin export PATH=/home/victor/.local/bin:/usr/local/bin:/usr/bin:/bin
builtin export LANG=C.UTF-8
builtin export LC_ALL=C.UTF-8
builtin export TMPDIR=/home/victor/.cache/tmp
builtin export XDG_RUNTIME_DIR=${runtime_dir}
builtin export DBUS_SESSION_BUS_ADDRESS=unix:path=${runtime_dir}/bus
[[ -z ${session_display} ]] || builtin export DISPLAY=${session_display}
[[ -z ${session_wayland_display} ]] || builtin export WAYLAND_DISPLAY=${session_wayland_display}
[[ -z ${desktop_xauthority} ]] || builtin export XAUTHORITY=${desktop_xauthority}
builtin export BUZZ_PRIVATE_KEY=${desktop_private_key}
builtin export BUZZ_SHARE_IDENTITY=1
builtin export BUZZ_RELAY_URL=${relay_url}
builtin export HF_HUB_CACHE=/home/victor/.cache/huggingface/hub
builtin export HF_XET_CACHE=/home/victor/.cache/huggingface/xet
builtin export MESH_LLM_NATIVE_RUNTIME_CACHE_DIR=/home/victor/.cache/mesh-llm/native-runtimes
assert_exact_exported_environment

exec_reviewed_environment "$@"
