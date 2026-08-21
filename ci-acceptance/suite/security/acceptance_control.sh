#!/usr/bin/env bash
# Shared qualification-control helpers for TM-06, TM-07, and TM-12 through TM-17.
# Callers provide TEST_ID, TIMEOUT_SECONDS, harness_text, and SUDO.

acceptance_env_get() {
  local key=$1
  # shellcheck disable=SC2154 # harness_text is assigned by every sourcing TM script.
  printf '%s\n' "$harness_text" | timeout "$TIMEOUT_SECONDS" awk -F= -v key="$key" \
    '$1==key{print substr($0,index($0,"=")+1); exit}'
}

acceptance_control_init() {
  local ctl_stat ctl_owner ctl_group ctl_mode ctl_kind root_stat root_owner root_group root_mode root_kind
  local case_dir case_dir_stat case_dir_owner case_dir_group case_dir_mode case_dir_kind
  ACCEPTANCE_CTL=$(acceptance_env_get BUZZ_CI_ACCEPTANCE_CTL)
  QUALIFICATION_CASE_ROOT=$(acceptance_env_get BUZZ_CI_QUALIFICATION_CASE_ROOT)
  # shellcheck disable=SC2034 # consumed by the sourcing TM script.
  ACCEPTANCE_UNAVAILABLE=''

  if ((${#SUDO[@]} == 0)); then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE='Qualification case readback and the buzzci-ctl invocation require SUITE_SUDO or passwordless sudo'
    return 3
  fi
  if [[ ! $ACCEPTANCE_CTL == /* || ! -x $ACCEPTANCE_CTL ]]; then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE='harness.env lacks an absolute executable BUZZ_CI_ACCEPTANCE_CTL'
    return 3
  fi
  ctl_stat=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -c '%U %G %a %F' -- "$ACCEPTANCE_CTL" 2>/dev/null) || return 3
  read -r ctl_owner ctl_group ctl_mode ctl_kind <<<"$ctl_stat"
  if [[ $ctl_owner != root || $ctl_group != buzzci-ctl || $ctl_mode != 750 || $ctl_kind != 'regular file' ]]; then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE='BUZZ_CI_ACCEPTANCE_CTL is not the root:buzzci-ctl mode 0750 regular binary'
    return 3
  fi
  if [[ ! $QUALIFICATION_CASE_ROOT == /* ]] \
    || ! timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" test -d "$QUALIFICATION_CASE_ROOT"; then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE='harness.env lacks an absolute readable BUZZ_CI_QUALIFICATION_CASE_ROOT'
    return 3
  fi
  root_stat=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -c '%U %G %a %F' -- "$QUALIFICATION_CASE_ROOT" 2>/dev/null) || return 3
  read -r root_owner root_group root_mode root_kind <<<"$root_stat"
  if [[ $root_owner != root || $root_group != root || $root_mode != 755 || $root_kind != directory ]]; then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE='BUZZ_CI_QUALIFICATION_CASE_ROOT is not a root:root mode 0755 directory'
    return 3
  fi
  case_dir=$QUALIFICATION_CASE_ROOT/$TEST_ID
  case_dir_stat=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -c '%U %G %a %F' -- "$case_dir" 2>/dev/null) || return 3
  read -r case_dir_owner case_dir_group case_dir_mode case_dir_kind <<<"$case_dir_stat"
  if [[ $case_dir_owner != root || $case_dir_group != root || $case_dir_mode != 755 || $case_dir_kind != directory ]]; then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE="Qualification case directory for $TEST_ID is not root:root mode 0755"
    return 3
  fi
}

acceptance_case_path() {
  local case_name=$1
  [[ $case_name =~ ^[a-z0-9][a-z0-9_-]*$ ]] || return 4
  printf '%s/%s/%s.json' "$QUALIFICATION_CASE_ROOT" "$TEST_ID" "$case_name"
}

# Invoke one root-authored qualification case. The JSON bytes are never parsed,
# copied, or rebuilt by the suite; the exact file is streamed to the closed
# acceptance control on stdin. Returns 3 for a missing/unsafe fixture, otherwise
# the control's status.
acceptance_control_run() {
  local case_name=$1 output=$2 error=$3 case_file stat_line owner group mode kind
  case_file=$(acceptance_case_path "$case_name") || return $?
  stat_line=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -c '%U %G %a %F' -- "$case_file" 2>/dev/null) || return 3
  read -r owner group mode kind <<<"$stat_line"
  [[ $owner == root && $group == root && $mode == 444 && $kind == 'regular file' ]] || return 3

  set +e
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat -- "$case_file" 2>>"$error" \
    | timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" -u buzzci-ctl "$ACCEPTANCE_CTL" >"$output" 2>>"$error"
  local pipe_status=("${PIPESTATUS[@]}")
  set -e
  ((pipe_status[0] == 0)) || return 3
  return "${pipe_status[1]}"
}

acceptance_error_is() {
  local expected=$1 output=$2 error=$3
  timeout 10 jq -e --arg expected "$expected" '.error == $expected or .code == $expected' "$output" >/dev/null 2>&1 \
    || timeout 10 jq -e --arg expected "$expected" '.error == $expected or .code == $expected' "$error" >/dev/null 2>&1
}
