#!/usr/bin/env bash
set -euo pipefail

TEST_ID="TM-02"
TITLE='Pin one exact reviewed `act` release at or after the `0.2.86` security floor'
DEFAULT_TIMEOUT=600
script_source=${BASH_SOURCE[0]}
[[ $script_source == */* ]] || script_source="./$script_source"
SCRIPT_DIR=$(cd -- "${script_source%/*}" && pwd -P)
PIN_FILE="$SCRIPT_DIR/../pins/toolchain.json"

candidate=""
candidate_dir=""
evidence_dir=""
plan=0
checks=()
evidence_files=()
preconditions=("act and podman installed on PATH" "runner image digest pinned and present in local Podman storage")
saw_fail=0
saw_not_runnable=0

usage() { printf 'usage: %s --candidate <full-sha> --candidate-dir <path> --evidence-dir <path> [--plan]\n' "${0##*/}" >&2; exit 4; }
add_check() {
  local name=$1 status=$2 detail=$3
  checks+=("$(timeout 10 jq -cn --arg name "$name" --arg status "$status" --arg detail "$detail" '{name:$name,status:$status,detail:$detail}')")
  [[ $status != fail ]] || saw_fail=1
  [[ $status != not_runnable ]] || saw_not_runnable=1
}
emit_result() {
  local status=$1 pass_json=$2 summary=$3 rc=$4 checks_json evidence_json preconditions_json
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout 10 jq -sc '.')
  evidence_json=$(printf '%s\n' "${evidence_files[@]}" | timeout 10 jq -Rsc 'split("\n") | map(select(length > 0))')
  preconditions_json=$(printf '%s\n' "${preconditions[@]}" | timeout 10 jq -Rsc 'split("\n") | map(select(length > 0))')
  timeout 10 jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" --argjson pass "$pass_json" \
    --arg summary "$summary" --argjson checks "$checks_json" --argjson evidence_files "$evidence_json" \
    --argjson preconditions "$preconditions_json" \
    '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
  exit "$rc"
}
version_at_least() {
  local actual=$1 floor=$2 a b c x y z
  IFS=. read -r a b c <<<"$actual"
  IFS=. read -r x y z <<<"$floor"
  ((10#$a > 10#$x || (10#$a == 10#$x && 10#$b > 10#$y) || (10#$a == 10#$x && 10#$b == 10#$y && 10#$c >= 10#$z)))
}

while (($#)); do
  case $1 in
    --candidate) (($# >= 2)) || usage; candidate=$2; shift 2 ;;
    --candidate-dir) (($# >= 2)) || usage; candidate_dir=$2; shift 2 ;;
    --evidence-dir) (($# >= 2)) || usage; evidence_dir=$2; shift 2 ;;
    --plan) plan=1; shift ;;
    *) usage ;;
  esac
done
[[ $candidate =~ ^[0-9a-f]{40}$ && -n $candidate_dir && -n $evidence_dir ]] || usage
if ((plan)); then
  add_check act_security_floor plan "Require act version 0.2.86 or newer."
  add_check act_exact_pin plan "Compare the installed act version with the reviewed pin."
  add_check act_sha256 plan "Compare the installed act binary SHA-256 with the reviewed pin."
  add_check podman_exact_pin plan "Compare the installed Podman version with the pin."
  add_check runner_image_digest plan "Require a pinned digest present in local Podman storage."
  emit_result plan false "Plan only; no tool execution or filesystem writes were performed." 0
fi

timeout_seconds=${SUITE_TIMEOUT_SECONDS:-$DEFAULT_TIMEOUT}
[[ $timeout_seconds =~ ^[1-9][0-9]*$ ]] || usage
[[ -d $candidate_dir && -f $PIN_FILE ]] || { printf 'candidate directory or pin file missing\n' >&2; exit 4; }
head_sha=$(timeout 15 git -C "$candidate_dir" rev-parse HEAD 2>/dev/null) || { printf 'cannot read candidate HEAD\n' >&2; exit 4; }
[[ $head_sha == "$candidate" ]] || { printf 'candidate directory HEAD does not match --candidate\n' >&2; exit 4; }
timeout 10 jq -e '.act.version and .act.sha256 and .podman.version and (.runner_image | has("digest"))' "$PIN_FILE" >/dev/null || { printf 'invalid toolchain pin file\n' >&2; exit 4; }

tm_dir="$evidence_dir/$TEST_ID"
timeout 10 mkdir -p -- "$tm_dir"
timeout 10 cp -- "$PIN_FILE" "$tm_dir/toolchain-pin.json"
evidence_files+=("$TEST_ID/toolchain-pin.json")
pin_act_version=$(timeout 10 jq -r '.act.version' "$PIN_FILE")
pin_act_sha=$(timeout 10 jq -r '.act.sha256' "$PIN_FILE")
pin_podman_version=$(timeout 10 jq -r '.podman.version' "$PIN_FILE")
runner_digest=$(timeout 10 jq -r '.runner_image.digest // empty' "$PIN_FILE")

if act_path=$(command -v act 2>/dev/null); then
  act_version_file="$tm_dir/act-version.txt"
  set +e
  timeout "$timeout_seconds" "$act_path" --version >"$act_version_file" 2>&1
  act_rc=$?
  set -e
  evidence_files+=("$TEST_ID/act-version.txt")
  if ((act_rc == 0)); then
    act_version=$(<"$act_version_file")
    act_version=${act_version##* }
    if [[ $act_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && version_at_least "$act_version" 0.2.86; then
      add_check act_security_floor pass "Installed act $act_version meets the 0.2.86 security floor."
    else
      add_check act_security_floor fail "Installed act version does not meet the 0.2.86 security floor."
    fi
    if [[ $act_version == "$pin_act_version" ]]; then
      add_check act_exact_pin pass "Installed act version matches pin $pin_act_version."
    else
      add_check act_exact_pin fail "Installed act $act_version does not match pin $pin_act_version."
    fi
    act_sha_file="$tm_dir/act-sha256.txt"
    timeout "$timeout_seconds" sha256sum "$act_path" >"$act_sha_file"
    evidence_files+=("$TEST_ID/act-sha256.txt")
    actual_sha=$(<"$act_sha_file"); actual_sha=${actual_sha%% *}
    if [[ $actual_sha == "$pin_act_sha" ]]; then
      add_check act_sha256 pass "Installed act SHA-256 matches the reviewed pin."
    else
      add_check act_sha256 fail "Installed act SHA-256 does not match the reviewed pin."
    fi
  else
    add_check act_security_floor not_runnable "act --version failed."
    add_check act_exact_pin not_runnable "act --version failed."
    add_check act_sha256 not_runnable "The installed act binary could not be identified."
  fi
else
  add_check act_security_floor not_runnable "act is not installed on PATH."
  add_check act_exact_pin not_runnable "act is not installed on PATH."
  add_check act_sha256 not_runnable "act is not installed on PATH."
fi

if command -v podman >/dev/null 2>&1; then
  podman_file="$tm_dir/podman-version.txt"
  set +e
  timeout "$timeout_seconds" podman --version >"$podman_file" 2>&1
  podman_rc=$?
  set -e
  evidence_files+=("$TEST_ID/podman-version.txt")
  if ((podman_rc == 0)); then
    podman_version=$(<"$podman_file"); podman_version=${podman_version##* }
    if [[ $podman_version == "$pin_podman_version" ]]; then
      add_check podman_exact_pin pass "Installed Podman version matches pin $pin_podman_version."
    else
      add_check podman_exact_pin fail "Installed Podman $podman_version does not match pin $pin_podman_version."
    fi
  else
    add_check podman_exact_pin not_runnable "podman --version failed."
  fi
else
  add_check podman_exact_pin not_runnable "podman is not installed on PATH."
fi

if [[ -z $runner_digest ]]; then
  add_check runner_image_digest fail "runner image digest not pinned"
elif ! command -v podman >/dev/null 2>&1; then
  add_check runner_image_digest not_runnable "Podman is required to inspect the pinned runner image."
else
  image_file="$tm_dir/runner-image-inspect.json"
  set +e
  timeout "$timeout_seconds" podman image inspect "$runner_digest" >"$image_file" 2>&1
  image_rc=$?
  set -e
  evidence_files+=("$TEST_ID/runner-image-inspect.json")
  if ((image_rc == 0)); then
    add_check runner_image_digest pass "Pinned runner image digest is present in local Podman storage."
  else
    add_check runner_image_digest fail "Pinned runner image digest is absent from local Podman storage."
  fi
fi

if ((saw_fail)); then emit_result fail false "The pinned toolchain is incomplete or does not match this host." 1; fi
if ((saw_not_runnable)); then emit_result not_runnable false "The pinned toolchain could not be fully checked on this host." 3; fi
emit_result pass true "The installed toolchain and runner image match the reviewed pins." 0
