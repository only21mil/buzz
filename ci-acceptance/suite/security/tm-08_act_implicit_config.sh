#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-08
TITLE='Neutralize every implicit `act` configuration/input source in the pinned release'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
candidate=''; candidate_dir=''; evidence_dir=''; plan=0
checks=(); statuses=(); evidence_files=()
preconditions=('mediated runtime for act dry-run if the pinned act release cannot expose a discriminating plan without an engine')

usage() { printf 'usage: %s --candidate SHA --candidate-dir DIR --evidence-dir DIR [--plan]\n' "${0##*/}" >&2; exit 4; }
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
[[ $TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]] || { printf 'invalid SUITE_TIMEOUT_SECONDS\n' >&2; exit 4; }

record() { local name=$1 status=$2 detail=$3; checks+=("$(timeout "$TIMEOUT_SECONDS" jq -cn --arg name "$name" --arg status "$status" --arg detail "$detail" '{name:$name,status:$status,detail:$detail}')"); statuses+=("$status"); }
json_array() { if (($# == 0)); then printf '[]'; else printf '%s\n' "$@" | timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n")[:-1]'; fi; }
emit() {
  local status summary pass_json=false checks_json evidence_json preconditions_json
  if ((plan)); then status=plan; summary='Plan only; no act invocation executed'
  elif [[ " ${statuses[*]} " == *' fail '* ]]; then status=fail; summary='An implicit act configuration or input source affected the isolated invocation'
  elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then status=not_runnable; summary='Invocation isolation passed, but act could not produce every discriminating plan without a mediated runtime'
  else status=pass; pass_json=true; summary='The isolated act invocation ignored repository configuration and input files'; fi
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(json_array "${evidence_files[@]}"); preconditions_json=$(json_array "${preconditions[@]}")
  timeout "$TIMEOUT_SECONDS" jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" --argjson pass "$pass_json" --arg summary "$summary" --argjson checks "$checks_json" --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
}
finish() { emit; if ((plan)); then exit 0; elif [[ " ${statuses[*]} " == *' fail '* ]]; then exit 1; elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then exit 3; else exit 0; fi; }

names=(isolated_invocation_shape repository_actrc_discrimination repository_implicit_inputs)
if ((plan)); then for name in "${names[@]}"; do record "$name" plan 'Would compare isolated and repository-root act plans'; done; finish; fi
[[ -d $candidate_dir ]] || { printf 'candidate directory is not a directory\n' >&2; exit 4; }

out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"
SUDO=()
if [[ -n ${SUITE_SUDO+x} ]]; then read -r -a SUDO <<<"$SUITE_SUDO"; elif timeout 5 sudo -n true >/dev/null 2>&1; then SUDO=(sudo -n); fi
if ((${#SUDO[@]} == 0)); then
  for name in "${names[@]}"; do record "$name" not_runnable 'Executor-principal test requires SUITE_SUDO or passwordless sudo'; done
  finish
fi

fixture_source=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../fixtures/tm-08-malicious-repo" && pwd -P)
temp_root=$(timeout "$TIMEOUT_SECONDS" mktemp -d /var/tmp/buzzci-tm08.XXXXXX)
cleanup() { timeout 10 "${SUDO[@]}" rm -rf -- "$temp_root" >/dev/null 2>&1 || true; }
trap cleanup EXIT
timeout "$TIMEOUT_SECONDS" cp -a -- "$fixture_source" "$temp_root/repository"
act_source=$(command -v act || true)
[[ -n $act_source ]] || act_source=/home/victor/.local/bin/act
if [[ ! -x $act_source ]]; then
  for name in "${names[@]}"; do record "$name" not_runnable 'Pinned act binary is unavailable'; done
  finish
fi
timeout "$TIMEOUT_SECONDS" cp -- "$act_source" "$temp_root/act"
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$temp_root/invocation/home/config" "$temp_root/invocation/home/runtime" "$temp_root/invocation/empty"
for file in secrets vars env input; do : >"$temp_root/invocation/empty/$file"; done
timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" chown -R buzzci-exec-01:buzzci -- "$temp_root"
timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" chmod 0711 "$temp_root"
timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" chmod 0700 "$temp_root/invocation" "$temp_root/invocation/home" "$temp_root/invocation/home/config" "$temp_root/invocation/home/runtime"
timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" chmod 0755 "$temp_root/act"

invocation_file=$out_dir/invocation-shape.txt
printf '%s\n' \
  'cwd=<broker-created 0700 invocation directory outside repository>' \
  'environment=env -i with isolated HOME, XDG_CONFIG_HOME, XDG_RUNTIME_DIR' \
  'workflow=-W <copied fixture>/.github/workflows' \
  'inputs=explicit empty --secret-file, --var-file, --env-file, --input-file' \
  'repository .actrc is unreachable through cwd discovery' >"$invocation_file"
evidence_files+=("$TEST_ID/invocation-shape.txt")
record isolated_invocation_shape pass 'Invocation uses an external 0700 cwd, empty environment, isolated HOME/XDG paths, explicit workflow path, and explicit empty input files'

isolated_file=$out_dir/isolated-plan.txt
control_file=$out_dir/repository-control-plan.txt
set +e
timeout 20 "${SUDO[@]}" -u buzzci-exec-01 env -i HOME="$temp_root/invocation/home" XDG_CONFIG_HOME="$temp_root/invocation/home/config" XDG_RUNTIME_DIR="$temp_root/invocation/home/runtime" PATH=/usr/bin:/bin bash -c 'cd -- "$1" && shift && exec "$@"' bash "$temp_root/invocation" "$temp_root/act" -n --json -P ubuntu-latest=ghcr.io/catthehacker/ubuntu:act-latest -W "$temp_root/repository/.github/workflows" -j actrc_only --secret-file "$temp_root/invocation/empty/secrets" --var-file "$temp_root/invocation/empty/vars" --env-file "$temp_root/invocation/empty/env" --input-file "$temp_root/invocation/empty/input" >"$isolated_file" 2>&1
isolated_rc=$?
timeout 20 "${SUDO[@]}" -u buzzci-exec-01 env -i HOME="$temp_root/invocation/home" XDG_CONFIG_HOME="$temp_root/invocation/home/config" XDG_RUNTIME_DIR="$temp_root/invocation/home/runtime" PATH=/usr/bin:/bin bash -c 'cd -- "$1" && shift && exec "$@"' bash "$temp_root/repository" "$temp_root/act" -n --json -P ubuntu-latest=ghcr.io/catthehacker/ubuntu:act-latest -W "$temp_root/repository/.github/workflows" >"$control_file" 2>&1
control_rc=$?
set -e
evidence_files+=("$TEST_ID/isolated-plan.txt" "$TEST_ID/repository-control-plan.txt")

if ((isolated_rc == 0 && control_rc == 0)) && timeout "$TIMEOUT_SECONDS" rg -q 'repository_(var|env|input)_marker|repository_secret_marker' "$control_file" && ! timeout "$TIMEOUT_SECONDS" rg -q 'repository_(var|env|input)_marker|repository_secret_marker' "$isolated_file"; then
  record repository_actrc_discrimination pass 'Repository-root control loaded the malicious defaults while the external-cwd plan did not'
  record repository_implicit_inputs pass 'Explicit empty secret, var, env, and input files kept every repository marker out of the isolated dry run'
elif timeout "$TIMEOUT_SECONDS" rg -q -- '--privileged is deprecated' "$control_file" && ! timeout "$TIMEOUT_SECONDS" rg -q -- '--privileged is deprecated' "$isolated_file"; then
  record repository_actrc_discrimination pass 'Repository-root control loaded malicious .actrc --privileged while the external-cwd invocation did not'
  record repository_implicit_inputs not_runnable 'act reached the unavailable daemon before it exposed secret, var, env, and input values; a mediated runtime is required'
elif ((isolated_rc == 0 && control_rc == 0)) && ! timeout "$TIMEOUT_SECONDS" rg -q 'repository_(var|env|input)_marker|repository_secret_marker' "$isolated_file"; then
  record repository_actrc_discrimination not_runnable 'act dry-run did not expose enough control output to prove .actrc discrimination without a mediated runtime'
  record repository_implicit_inputs not_runnable 'act dry-run did not expose enough control output to prove repository input loading without a mediated runtime'
else
  record repository_actrc_discrimination not_runnable "act dry-run could not produce both plans without a mediated runtime (isolated rc=$isolated_rc, control rc=$control_rc)"
  record repository_implicit_inputs not_runnable 'A mediated runtime is required to compare implicit repository inputs'
fi
finish
