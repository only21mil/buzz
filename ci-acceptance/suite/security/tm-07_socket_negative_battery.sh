#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-07
TITLE='Negative-test rootful Docker fallback, direct raw Podman access, TCP endpoint, wrong socket owner, missing proxy/upstream, agent-controlled `DOCKER_HOST`, and the reported ignored-`--container-daemon-socket` class'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
candidate=''; candidate_dir=''; evidence_dir=''; plan=0
checks=(); statuses=(); evidence_files=()
preconditions=(
  'policy proxy + broker lease path live (proxy is not act-compatible yet per its README)'
)

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
  if ((plan)); then status=plan; summary='Plan only; no socket tests executed'
  elif [[ " ${statuses[*]} " == *' fail '* ]]; then status=fail; summary='At least one forbidden socket or endpoint remained reachable'
  elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then status=not_runnable; summary='Host socket negatives passed where runnable; mediated-job checks are unavailable'
  else status=pass; pass_json=true; summary='Every forbidden socket and endpoint refused access'; fi
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(json_array "${evidence_files[@]}"); preconditions_json=$(json_array "${preconditions[@]}")
  timeout "$TIMEOUT_SECONDS" jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" --argjson pass "$pass_json" --arg summary "$summary" --argjson checks "$checks_json" --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
}
finish() { emit; if ((plan)); then exit 0; elif [[ " ${statuses[*]} " == *' fail '* ]]; then exit 1; elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then exit 3; else exit 0; fi; }

names=(exec_rootful_docker run_rootful_docker exec_raw_run_socket docker_tcp_endpoints exec_docker_host_unix exec_docker_host_tcp wrong_socket_owner ignored_container_daemon_socket no_socket_inside_job)
if ((plan)); then for name in "${names[@]}"; do record "$name" plan 'Would attempt the forbidden path and require refusal'; done; finish; fi
[[ -d $candidate_dir ]] || { printf 'candidate directory is not a directory\n' >&2; exit 4; }

out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"
SUDO=()
if [[ -n ${SUITE_SUDO+x} ]]; then read -r -a SUDO <<<"$SUITE_SUDO"; elif timeout 5 sudo -n true >/dev/null 2>&1; then SUDO=(sudo -n); fi

if ((${#SUDO[@]} == 0)); then
  for name in exec_rootful_docker run_rootful_docker exec_raw_run_socket exec_docker_host_unix exec_docker_host_tcp wrong_socket_owner; do record "$name" not_runnable 'Principal-level negative test requires SUITE_SUDO or passwordless sudo'; done
else
  for principal in buzzci-exec-01 buzzci-run-01; do
    file=$out_dir/${principal}-docker-sock.txt
    set +e
    timeout 5 "${SUDO[@]}" -u "$principal" curl --silent --show-error --unix-socket /var/run/docker.sock http://localhost/_ping >"$file" 2>&1
    rc=$?
    set -e
    evidence_files+=("$TEST_ID/${principal}-docker-sock.txt")
    name=${principal#buzzci-}; name=${name%-01}_rootful_docker
    if ((rc != 0)); then record "$name" pass "$principal could not connect to the rootful Docker socket"; else record "$name" fail "$principal reached the rootful Docker API"; fi
  done

  raw_file=$out_dir/exec-run-podman-sock.txt
  set +e
  timeout 5 "${SUDO[@]}" -u buzzci-exec-01 curl --silent --show-error --unix-socket /run/user/964/podman/podman.sock http://localhost/_ping >"$raw_file" 2>&1
  raw_rc=$?
  set -e
  evidence_files+=("$TEST_ID/exec-run-podman-sock.txt")
  if ((raw_rc != 0)); then record exec_raw_run_socket pass 'Executor could not connect to the runtime principal Podman socket'; else record exec_raw_run_socket fail 'Executor reached the runtime principal Podman API'; fi

  fixture_source=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../fixtures/tm-08-malicious-repo" && pwd -P)
  temp_root=$(timeout "$TIMEOUT_SECONDS" mktemp -d /var/tmp/buzzci-tm07.XXXXXX)
  cleanup() {
    if [[ -n ${socket_pid-} ]]; then timeout 5 kill "$socket_pid" >/dev/null 2>&1 || true; wait "$socket_pid" 2>/dev/null || true; fi
    if [[ -n ${socket_root-} ]]; then timeout 10 rm -rf -- "$socket_root" >/dev/null 2>&1 || true; fi
    timeout 10 "${SUDO[@]}" rm -rf -- "$temp_root" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT
  timeout "$TIMEOUT_SECONDS" cp -a -- "$fixture_source" "$temp_root/fixture"
  act_source=$(command -v act || true)
  [[ -n $act_source ]] || act_source=/home/victor/.local/bin/act
  if [[ -x $act_source ]]; then
    timeout "$TIMEOUT_SECONDS" cp -- "$act_source" "$temp_root/act"
    timeout "$TIMEOUT_SECONDS" chmod 0755 "$temp_root/act"
    timeout "$TIMEOUT_SECONDS" mkdir -p -- "$temp_root/home" "$temp_root/cwd"
    timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" chown -R buzzci-exec-01:buzzci -- "$temp_root"
    timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" chmod 0700 "$temp_root" "$temp_root/home" "$temp_root/cwd"
    for mode in unix tcp; do
      if [[ $mode == unix ]]; then docker_host=unix:///var/run/docker.sock; else docker_host=tcp://127.0.0.1:2375; fi
      file=$out_dir/act-docker-host-$mode.txt
      set +e
      timeout 10 "${SUDO[@]}" -u buzzci-exec-01 env -i HOME="$temp_root/home" XDG_CONFIG_HOME="$temp_root/home/config" XDG_RUNTIME_DIR="$temp_root/home/runtime" PATH=/usr/bin:/bin DOCKER_HOST="$docker_host" bash -c 'cd -- "$1" && shift && exec "$@"' bash "$temp_root/cwd" "$temp_root/act" --pull=false -P ubuntu-latest=ghcr.io/catthehacker/ubuntu:act-latest -W "$temp_root/fixture/.github/workflows/trivial.yml" -j trivial >"$file" 2>&1
      rc=$?
      set -e
      evidence_files+=("$TEST_ID/act-docker-host-$mode.txt")
      if ((rc != 0)) && timeout "$TIMEOUT_SECONDS" rg -qi 'cannot connect to the docker daemon|dial (unix|tcp)|permission denied while trying to connect|connect: (permission denied|connection refused)|error during connect|context (deadline exceeded|canceled)' "$file" && ! timeout "$TIMEOUT_SECONDS" rg -q 'trivial.*echo trivial|echo trivial.*trivial' "$file"; then
        record "exec_docker_host_$mode" pass "Agent-controlled DOCKER_HOST=$mode failed at daemon connection before the trivial step"
      elif ((rc != 0)); then
        record "exec_docker_host_$mode" fail "act failed for DOCKER_HOST=$mode, but the evidence does not prove a pre-job daemon refusal"
      else
        record "exec_docker_host_$mode" fail "act accepted agent-controlled DOCKER_HOST=$mode"
      fi
    done
  else
    record exec_docker_host_unix not_runnable 'Pinned act binary is unavailable'
    record exec_docker_host_tcp not_runnable 'Pinned act binary is unavailable'
  fi

  socket_root=$(timeout "$TIMEOUT_SECONDS" mktemp -d /var/tmp/buzzci-tm07-socket.XXXXXX)
  socket_dir=$socket_root/wrong-owner
  timeout "$TIMEOUT_SECONDS" mkdir -p -- "$socket_dir"
  timeout "$TIMEOUT_SECONDS" chmod 0700 "$socket_dir"
  socket_path=$socket_dir/owner.sock
  timeout 30 python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1); time.sleep(25)' "$socket_path" &
  socket_pid=$!
  for _ in {1..20}; do [[ -S $socket_path ]] && break; read -r -t 0.05 _unused || true; done
  wrong_file=$out_dir/wrong-owner-socket.txt
  set +e
  timeout 5 "${SUDO[@]}" -u buzzci-exec-01 curl --silent --show-error --unix-socket "$socket_path" http://localhost/_ping >"$wrong_file" 2>&1
  wrong_rc=$?
  set -e
  evidence_files+=("$TEST_ID/wrong-owner-socket.txt")
  if ((wrong_rc != 0)); then record wrong_socket_owner pass 'Executor could not connect to a Victor-owned socket inside a 0700 directory'; else record wrong_socket_owner fail 'Executor connected to a socket owned by the wrong principal'; fi
  timeout 5 kill "$socket_pid" >/dev/null 2>&1 || true
  wait "$socket_pid" 2>/dev/null || true
  unset socket_pid
fi

tcp_file=$out_dir/tcp-listeners.txt
timeout "$TIMEOUT_SECONDS" ss -ltn >"$tcp_file" 2>&1
evidence_files+=("$TEST_ID/tcp-listeners.txt")
if timeout "$TIMEOUT_SECONDS" awk '$4 ~ /:(2375|2376)$/ {bad=1} END{exit bad}' "$tcp_file"; then record docker_tcp_endpoints pass 'No TCP Docker or Podman endpoint listens on 2375 or 2376'; else record docker_tcp_endpoints fail 'A TCP endpoint is listening on 2375 or 2376'; fi

record ignored_container_daemon_socket not_runnable 'Ignored --container-daemon-socket behavior requires the live policy proxy and broker lease path'
record no_socket_inside_job not_runnable 'Socket absence inside a real job requires the live policy proxy and broker lease path'
finish
