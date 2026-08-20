#!/usr/bin/env bash
set -euo pipefail

TEST_ID="TM-03"
TITLE="Implement the separate control process and fixed-schema trusted broker"
DEFAULT_TIMEOUT=600
candidate=""
candidate_dir=""
evidence_dir=""
plan=0
checks=()
evidence_files=()
preconditions=("Rust toolchain and candidate broker crates" "root-readable /etc/buzzci/harness.env publishing BUZZ_CI_EXECD_SOCKET")
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
  add_check broker_build plan "Build buzz-ci-execd and buzz-ci-runner."
  add_check zero_capacity_self_check plan "Require zero-capacity not_provisioned self-check output."
  add_check forbidden_environment plan "Require a forbidden environment key to fail closed."
  add_check normal_start_refusal plan "Require an unprovisioned normal start to fail closed."
  add_check dependency_posture plan "Inspect normal dependencies for network, TLS, HTTP, and key crates."
  add_check static_capability_scan plan "Scan execd source for network, process launch, HTTP, and relay-key access."
  add_check protocol_zero_dependencies plan "Require zero normal dependencies in broker-protocol."
  add_check broker_ipc_unreachable plan "Read the root-owned harness and verify agents cannot write the published execd socket."
  emit_result plan false "Plan only; no build, command, or filesystem write was performed." 0
fi

timeout_seconds=${SUITE_TIMEOUT_SECONDS:-$DEFAULT_TIMEOUT}
[[ $timeout_seconds =~ ^[1-9][0-9]*$ ]] || usage
broker_dir=${BUZZ_CI_BROKER_DIR:-$candidate_dir}
[[ -d $candidate_dir && -d $broker_dir ]] || { printf 'candidate or broker directory missing\n' >&2; exit 4; }
head_sha=$(timeout 15 git -C "$candidate_dir" rev-parse HEAD 2>/dev/null) || { printf 'cannot read candidate HEAD\n' >&2; exit 4; }
[[ $head_sha == "$candidate" ]] || { printf 'candidate directory HEAD does not match --candidate\n' >&2; exit 4; }
for path in crates/buzz-ci-broker-protocol crates/buzz-ci-execd crates/buzz-ci-runner; do
  [[ -d $broker_dir/$path ]] || { printf 'missing broker crate: %s\n' "$path" >&2; exit 4; }
done
tm_dir="$evidence_dir/$TEST_ID"
timeout 10 mkdir -p -- "$tm_dir"
sanitized_env=(env -u BUZZ_RELAY_PRIVATE_KEY -u BUZZ_PRIVATE_KEY -u NOSTR_PRIVATE_KEY -u BUZZ_AUTH_TAG -u GH_TOKEN -u GITHUB_TOKEN -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u DATABASE_URL -u REDIS_URL)
build_limit=$timeout_seconds
((build_limit <= 480)) || build_limit=480
build_file="$tm_dir/cargo-build.log"
set +e
timeout "$build_limit" "${sanitized_env[@]}" cargo build -p buzz-ci-execd -p buzz-ci-runner --manifest-path "$broker_dir/Cargo.toml" >"$build_file" 2>&1
build_rc=$?
set -e
evidence_files+=("$TEST_ID/cargo-build.log")
if ((build_rc == 0)); then add_check broker_build pass "buzz-ci-execd and buzz-ci-runner built successfully."; else add_check broker_build fail "Broker build failed or exceeded ${build_limit}s."; fi

execd="$broker_dir/target/debug/buzz-ci-execd"
if ((build_rc == 0)) && [[ -x $execd ]]; then
  self_out="$tm_dir/self-check.stdout.json"; self_err="$tm_dir/self-check.stderr.log"
  set +e
  timeout "$timeout_seconds" "${sanitized_env[@]}" "$execd" --self-check >"$self_out" 2>"$self_err"
  self_rc=$?
  set -e
  evidence_files+=("$TEST_ID/self-check.stdout.json" "$TEST_ID/self-check.stderr.log")
  if ((self_rc == 0)) && timeout 10 jq -e '.status == "not_provisioned"' "$self_out" >/dev/null 2>&1; then
    add_check zero_capacity_self_check pass "Self-check returned status not_provisioned with exit 0."
  else
    add_check zero_capacity_self_check fail "Self-check did not return exit 0 and status not_provisioned."
  fi

  forbidden_out="$tm_dir/forbidden-env.stdout.log"; forbidden_err="$tm_dir/forbidden-env.stderr.json"
  set +e
  timeout "$timeout_seconds" "${sanitized_env[@]}" GH_TOKEN=dummy "$execd" >"$forbidden_out" 2>"$forbidden_err"
  forbidden_rc=$?
  set -e
  evidence_files+=("$TEST_ID/forbidden-env.stdout.log" "$TEST_ID/forbidden-env.stderr.json")
  if ((forbidden_rc == 4)) && timeout 10 jq -e '.error == "forbidden_environment" and .key == "GH_TOKEN"' "$forbidden_err" >/dev/null 2>&1; then
    add_check forbidden_environment pass "A dummy forbidden key was rejected with exit 4 and forbidden_environment."
  else
    add_check forbidden_environment fail "The dummy forbidden environment key was not rejected as specified."
  fi

  start_out="$tm_dir/no-args.stdout.log"; start_err="$tm_dir/no-args.stderr.json"
  set +e
  timeout "$timeout_seconds" "${sanitized_env[@]}" "$execd" >"$start_out" 2>"$start_err"
  start_rc=$?
  set -e
  evidence_files+=("$TEST_ID/no-args.stdout.log" "$TEST_ID/no-args.stderr.json")
  if ((start_rc == 4)) && timeout 10 jq -e '.error == "not_provisioned"' "$start_err" >/dev/null 2>&1; then
    add_check normal_start_refusal pass "Normal start refused unprovisioned execution with exit 4."
  else
    add_check normal_start_refusal fail "Normal start did not refuse with exit 4 and not_provisioned."
  fi
else
  add_check zero_capacity_self_check not_runnable "The execd binary was not built."
  add_check forbidden_environment not_runnable "The execd binary was not built."
  add_check normal_start_refusal not_runnable "The execd binary was not built."
fi

tree_file="$tm_dir/execd-cargo-tree.txt"
set +e
timeout "$timeout_seconds" cargo tree -p buzz-ci-execd --edges normal --manifest-path "$broker_dir/Cargo.toml" >"$tree_file" 2>&1
tree_rc=$?
set -e
evidence_files+=("$TEST_ID/execd-cargo-tree.txt")
if ((tree_rc != 0)); then
  add_check dependency_posture not_runnable "cargo tree failed."
else
  dependency_text=$(<"$tree_file")
  banned_pattern='(^|[[:space:]├└─])(tokio|reqwest|hyper|rustls|native-tls|openssl|ring|secp256k1|ed25519|rsa|ssh2|curl|ureq|nostr)([[:space:]]|$)'
  tree_packages=()
  while IFS= read -r line; do
    if [[ $line =~ (^|[[:space:]─])([A-Za-z0-9_-]+)[[:space:]]+v[0-9] ]]; then
      tree_packages+=("${BASH_REMATCH[2]}")
    fi
  done <"$tree_file"
  if [[ ${#tree_packages[@]} -eq 2 && ${tree_packages[0]} == buzz-ci-execd && ${tree_packages[1]} == buzz-ci-broker-protocol && $dependency_text == *"buzz-ci-broker-protocol"* ]] \
    && ! timeout 10 grep -Eiq "$banned_pattern" "$tree_file"; then
    add_check dependency_posture pass "Normal tree contains only buzz-ci-broker-protocol; no network, TLS, HTTP, Nostr, or key crate was found."
  else
    add_check dependency_posture fail "Unexpected or security-sensitive normal dependencies appear in the execd tree."
  fi
fi

scan_file="$tm_dir/static-capability-scan.txt"
relay_file="$tm_dir/relay-key-name-readback.txt"
set +e
timeout "$timeout_seconds" grep -RInE 'std::net|std::process::Command|tokio|reqwest|hyper' "$broker_dir/crates/buzz-ci-execd/src" >"$scan_file" 2>&1
capability_hits=$?
timeout "$timeout_seconds" grep -RInE 'BUZZ_RELAY_PRIVATE_KEY|BUZZ_PRIVATE_KEY|NOSTR_PRIVATE_KEY|BUZZ_AUTH_TAG' "$broker_dir/crates/buzz-ci-execd/src" >"$relay_file" 2>&1
relay_hits=$?
set -e
evidence_files+=("$TEST_ID/static-capability-scan.txt" "$TEST_ID/relay-key-name-readback.txt")
direct_key_access=0
if timeout "$timeout_seconds" grep -RInE 'var(_os)?[[:space:]]*\([[:space:]]*"(BUZZ_RELAY_PRIVATE_KEY|BUZZ_PRIVATE_KEY|NOSTR_PRIVATE_KEY|BUZZ_AUTH_TAG)' "$broker_dir/crates/buzz-ci-execd/src" >/dev/null 2>&1; then
  direct_key_access=1
fi
if ((capability_hits == 1 && direct_key_access == 0)); then
  if ((relay_hits == 0)); then
    add_check static_capability_scan pass "No network, process-launch, HTTP, or direct relay-key access exists; relay key names occur only in the name-only denylist."
  else
    add_check static_capability_scan pass "No network, process-launch, HTTP, or relay-key access pattern exists."
  fi
else
  add_check static_capability_scan fail "The execd source contains a forbidden capability or direct relay-key access pattern."
fi

protocol_tree="$tm_dir/protocol-cargo-tree.txt"
set +e
timeout "$timeout_seconds" cargo tree -p buzz-ci-broker-protocol --edges normal --manifest-path "$broker_dir/Cargo.toml" >"$protocol_tree" 2>&1
protocol_rc=$?
set -e
evidence_files+=("$TEST_ID/protocol-cargo-tree.txt")
protocol_packages=()
while IFS= read -r line; do
  if [[ $line =~ (^|[[:space:]─])([A-Za-z0-9_-]+)[[:space:]]+v[0-9] ]]; then
    protocol_packages+=("${BASH_REMATCH[2]}")
  fi
done <"$protocol_tree"
if ((protocol_rc == 0)) && [[ ${#protocol_packages[@]} -eq 1 && ${protocol_packages[0]} == buzz-ci-broker-protocol ]]; then
  add_check protocol_zero_dependencies pass "buzz-ci-broker-protocol has zero normal dependencies."
elif ((protocol_rc != 0)); then
  add_check protocol_zero_dependencies not_runnable "cargo tree for broker-protocol failed."
else
  add_check protocol_zero_dependencies fail "buzz-ci-broker-protocol has one or more normal dependencies."
fi

harness=/etc/buzzci/harness.env
sudo_cmd=()
if [[ -n ${SUITE_SUDO+x} ]]; then
  read -r -a sudo_cmd <<<"$SUITE_SUDO"
elif timeout 5 sudo -n true >/dev/null 2>&1; then
  sudo_cmd=(sudo -n)
fi
if [[ ! -e $harness ]]; then
  add_check broker_ipc_unreachable not_runnable "Substrate wiring has not published /etc/buzzci/harness.env."
elif ((${#sudo_cmd[@]} == 0)); then
  add_check broker_ipc_unreachable not_runnable "Root harness readback requires SUITE_SUDO or passwordless sudo."
else
  set +e
  harness_text=$(timeout "$timeout_seconds" "${sudo_cmd[@]}" cat "$harness" 2>/dev/null)
  harness_rc=$?
  set -e
  execd_socket=$(printf '%s\n' "$harness_text" | timeout 10 awk -F= '$1=="BUZZ_CI_EXECD_SOCKET"{print substr($0,index($0,"=")+1); exit}')
  if ((harness_rc != 0)) || [[ -z $execd_socket ]]; then
    add_check broker_ipc_unreachable fail "The root harness is unreadable or omits BUZZ_CI_EXECD_SOCKET."
  else
    ipc_file="$tm_dir/ipc-permissions.txt"
    set +e
    timeout "$timeout_seconds" stat -Lc '%n mode=%a uid=%u gid=%g type=%F' "$execd_socket" >"$ipc_file" 2>&1
    ipc_rc=$?
    set -e
    evidence_files+=("$TEST_ID/ipc-permissions.txt")
    if ((ipc_rc == 0)) && [[ ! -w $execd_socket ]]; then
      add_check broker_ipc_unreachable pass "The published execd socket is unwritable by this account."
    else
      add_check broker_ipc_unreachable fail "This account can write the published execd socket, or the socket path is invalid."
    fi
  fi
fi

if ((saw_fail)); then emit_result fail false "The broker posture has one or more failed controls." 1; fi
if ((saw_not_runnable)); then emit_result not_runnable false "Implemented broker controls passed, but substrate IPC isolation is not yet runnable." 3; fi
emit_result pass true "The broker is keyless, content-blind, dependency-minimal, and unreachable from this account." 0
