#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-05
TITLE='Implement the pre-start Docker-API policy proxy between a distinct executor account and runtime account'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
candidate=''; candidate_dir=''; evidence_dir=''; plan=0
checks=(); evidence=(); preconditions=(
  'buzz-ci-policy-proxy source, Cargo workspace, and pinned act route census exist in BUZZ_CI_PROXY_DIR or candidate-dir'
  'bash, coreutils, jq, and cargo are installed; evidence-dir is writable'
  'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'
)
failed=0; unrunnable=0
usage() { printf 'usage: %s --candidate <full-sha> --candidate-dir <path> --evidence-dir <path> [--plan]\n' "$0" >&2; exit 4; }
while (($#)); do case $1 in --candidate) (($#>=2))||usage; candidate=$2; shift 2;; --candidate-dir) (($#>=2))||usage; candidate_dir=$2; shift 2;; --evidence-dir) (($#>=2))||usage; evidence_dir=$2; shift 2;; --plan) plan=1; shift;; *) usage;; esac; done
add_check() { local name=$1 status=$2 detail=$3; checks+=("$(timeout "$TIMEOUT_SECONDS" jq -cn --arg n "$name" --arg s "$status" --arg d "$detail" '{name:$n,status:$s,detail:$d}')"); [[ $status != fail ]]||failed=1; [[ $status != not_runnable ]]||unrunnable=1; }
emit() { local status=$1 summary=$2 pass_json=false cj ej pj; [[ $status == pass ]]&&pass_json=true; cj=$(printf '%s\n' "${checks[@]}"|timeout "$TIMEOUT_SECONDS" jq -sc '.'); ej=$(printf '%s\n' "${evidence[@]}"|timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n") | map(select(length > 0))'); pj=$(printf '%s\n' "${preconditions[@]}"|timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n") | map(select(length > 0))'); timeout "$TIMEOUT_SECONDS" jq -cn --arg id "$TEST_ID" --arg title "$TITLE" --arg status "$status" --arg summary "$summary" --argjson pass "$pass_json" --argjson checks "$cj" --argjson files "$ej" --argjson pre "$pj" '{test_id:$id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$files,preconditions:$pre}'; }
if ((plan)); then
  add_check policy_proxy_crate_tests plan 'Run the bounded buzz-ci-policy-proxy crate tests.'
  add_check closed_route_census plan 'Prove the pinned act census contains exactly 13 required routes and the parser is closed.'
  add_check request_rebuild_and_forced_policy plan 'Prove create/exec bodies are rebuilt and force no network, read-only root, and CapDrop ALL.'
  add_check unsafe_classes_refused plan 'Prove host networking, socket mounts, attach/logs/exec-start/archive, build, and pull are refused or disabled by Phase-1 policy.'
  add_check live_route_mediation plan 'Verify every recorded request class was mediated and unknown routes were refused.'
  emit plan 'Planned static and live Docker-API mediation checks; no checks executed.'; exit 0
fi
[[ $candidate =~ ^[0-9a-f]{40}$ && -n $candidate_dir && -n $evidence_dir ]]||usage
if [[ -z ${SUITE_SUDO+x} ]]; then if timeout 5 sudo -n true >/dev/null 2>&1; then SUITE_SUDO='sudo -n'; else SUITE_SUDO=''; fi; fi
read -r -a sudo_cmd <<<"$SUITE_SUDO"
read_harness() {
  if ((${#sudo_cmd[@]})); then
    timeout "$TIMEOUT_SECONDS" "${sudo_cmd[@]}" cat /etc/buzzci/harness.env
  else
    return 3
  fi
}
read_harness_key(){ local key=$1; printf '%s\n' "$harness_text" | timeout "$TIMEOUT_SECONDS" awk -F= -v key="$key" '$1==key{print substr($0,index($0,"=")+1); exit}'; }
proxy_dir=${BUZZ_CI_PROXY_DIR:-$candidate_dir}; out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"||exit 4
cargo_log=$out_dir/cargo-test.log
set +e; CARGO_TARGET_DIR=$proxy_dir/target timeout "$TIMEOUT_SECONDS" cargo test --manifest-path "$proxy_dir/Cargo.toml" -p buzz-ci-policy-proxy >"$cargo_log" 2>&1; rc=$?; set -e
evidence+=("$TEST_ID/cargo-test.log"); if ((rc==0)); then add_check policy_proxy_crate_tests pass 'buzz-ci-policy-proxy tests completed with zero failures.'; else add_check policy_proxy_crate_tests fail "cargo test exited $rc; see cargo-test.log."; fi

route_rs=$proxy_dir/crates/buzz-ci-policy-proxy/src/route.rs; policy_rs=$proxy_dir/crates/buzz-ci-policy-proxy/src/policy.rs; transport_rs=$proxy_dir/crates/buzz-ci-policy-proxy/src/transport.rs; census=$proxy_dir/crates/buzz-ci-policy-proxy/tests/fixtures/act-v0.2.89-minimal-shell-routes.json
route_proof=$out_dir/static-route-proof.txt
if [[ -f $route_rs && -f $policy_rs && -f $transport_rs && -f $census ]]; then
  timeout "$TIMEOUT_SECONDS" grep -nE 'closed route table|Container(Create|Start|Attach|Logs)|Exec(Create|Start)|Archive|ImagePull|Build|ForbiddenFamily|NetworkMode|ReadonlyRootfs|CapDrop|socket|canonical' "$route_rs" "$policy_rs" >"$route_proof" 2>&1||true
  timeout "$TIMEOUT_SECONDS" jq '{act_version,required_routes:(.routes|length),routes,must_refuse}' "$census" >>"$route_proof"
  evidence+=("$TEST_ID/static-route-proof.txt")
  if timeout "$TIMEOUT_SECONDS" jq -e '.act_version=="v0.2.89" and (.routes|length)==13 and all(.routes[];.required==true)' "$census" >/dev/null && timeout "$TIMEOUT_SECONDS" grep -Fq 'method/path is not in the closed route table' "$route_rs"; then add_check closed_route_census pass 'Pinned v0.2.89 census has exactly 13 required routes and unknown method/path pairs fail closed.'; else add_check closed_route_census fail 'The pinned 13-route census or closed-parser refusal is absent.'; fi
  rebuild_missing=''; for pin in 'CanonicalCreate' 'CanonicalExec' 'NetworkMode' 'ReadonlyRootfs' 'CapDrop'; do timeout "$TIMEOUT_SECONDS" grep -Fq "$pin" "$policy_rs"||rebuild_missing+=" $pin"; done
  if [[ -z $rebuild_missing ]] && timeout "$TIMEOUT_SECONDS" grep -Fq '"none"' "$policy_rs" && timeout "$TIMEOUT_SECONDS" grep -Fq '"ALL"' "$policy_rs"; then add_check request_rebuild_and_forced_policy pass 'Static policy rebuilds canonical create/exec requests and forces network none, read-only root, and CapDrop ALL.'; else add_check request_rebuild_and_forced_policy fail "Canonical request rebuild proof is incomplete:$rebuild_missing"; fi
  refusal_missing=''; for pin in 'NetworkMode' 'host' 'socket' 'ImagePull' 'Build'; do timeout "$TIMEOUT_SECONDS" grep -Fq "$pin" "$route_rs" "$policy_rs"||refusal_missing+=" $pin"; done
  transport_block=$(timeout "$TIMEOUT_SECONDS" sed -n '/if matches!(/,/return Err(ConnectionFailure::before_upstream/p' "$transport_rs")
  for pin in 'DockerRoute::ContainerAttach' 'DockerRoute::ContainerLogs' 'DockerRoute::ExecStart' 'DockerRoute::Archive'; do
    [[ $transport_block == *"$pin"* ]] || refusal_missing+=" $pin"
  done
  transport_refusal_line=$(timeout "$TIMEOUT_SECONDS" grep -nF 'Docker stream/archive routes are disabled until bounded mediation is proven' "$transport_rs" | head -n 1 || true)
  [[ -n $transport_refusal_line ]] || refusal_missing+=' transport_refusal_message'
  transport_test_line=$(timeout "$TIMEOUT_SECONDS" grep -nF 'archive_and_hijack_grants_do_not_enable_forwarding' "$transport_rs" | head -n 1 || true)
  [[ -n $transport_test_line ]] || refusal_missing+=' archive_and_hijack_grants_do_not_enable_forwarding'
  printf 'transport refusal: %s\ntransport test: %s\n' "$transport_block" "$transport_test_line" >>"$route_proof"
  if [[ -z $refusal_missing ]]; then
    add_check unsafe_classes_refused pass "transport.rs:${transport_refusal_line%%:*} refuses ContainerAttach, ContainerLogs, ExecStart, and Archive before forwarding; transport.rs:${transport_test_line%%:*} has archive_and_hijack_grants_do_not_enable_forwarding."
  else
    add_check unsafe_classes_refused fail "Transport-layer unsafe-class refusal proof is incomplete:$refusal_missing"
  fi
else
  printf 'missing route.rs, policy.rs, transport.rs, or census fixture\n' >"$route_proof"; evidence+=("$TEST_ID/static-route-proof.txt")
  add_check closed_route_census fail 'Proxy checkout is missing the closed route parser or pinned census fixture.'
  add_check request_rebuild_and_forced_policy fail 'Proxy checkout is missing canonical request policy source.'
  add_check unsafe_classes_refused fail 'Proxy checkout is missing unsafe-class refusal source.'
fi

if [[ ! -e /etc/buzzci/harness.env ]]; then
  add_check live_route_mediation not_runnable 'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'
else
  harness_text=''
  if ! harness_text=$(read_harness 2>/dev/null); then
    if ((${#sudo_cmd[@]} == 0)); then
      add_check live_route_mediation not_runnable 'harness.env unreadable without sudo'
    else
      add_check live_route_mediation fail 'Published harness.env is not root-readable.'
    fi
  else
  state_root=$(read_harness_key BUZZ_CI_LEASE_STATE_ROOT 2>/dev/null||true)
  lease_dir=''; [[ -n $state_root && -d $state_root ]] && for entry in "$state_root"/*; do [[ -d $entry ]]&&{ lease_dir=$entry; break; }; done
  decisions=$lease_dir/proxy/decisions.jsonl; live=$out_dir/live-route-mediation.txt
  if [[ -z $state_root || ! -d $state_root || -z $lease_dir || ! -f $decisions ]]; then
    printf 'state_root=%s lease_dir=%s decisions=%s\n' "$state_root" "$lease_dir" "$decisions" >"$live"; evidence+=("$TEST_ID/live-route-mediation.txt")
    add_check live_route_mediation fail 'harness.env exists but the lease state root or proxy decisions.jsonl is missing.'
  else
    timeout "$TIMEOUT_SECONDS" jq -c '{schema_version,sequence,route,verdict,reason,request_hash,method:(.method//.request.method),target:(.target//.request.target)}' "$decisions" >"$live" 2>&1||true; evidence+=("$TEST_ID/live-route-mediation.txt")
    known=$(timeout "$TIMEOUT_SECONDS" jq -sc --slurpfile c "$census" '
      def norm: sub("^/v[0-9.]+";"");
      def matches_template($actual;$template):
        ($template|gsub("\\{digest\\}|\\{name\\}|\\{container_id\\}|\\{exec_id\\}|\\{path\\}";"[^/?]+")|"^"+. +"$") as $re | ($actual|test($re));
      all(.[]; . as $d | (($d.method//.request.method//"") as $m | ($d.target//.request.target//""|norm) as $t | any($c[0].routes[]; .method==$m and matches_template($t;.target))) or (($d.verdict//"")|ascii_downcase|test("refus|deny")))
    ' "$decisions" 2>/dev/null&&printf yes||printf no)
    schema_ok=$(timeout "$TIMEOUT_SECONDS" jq -s -e 'length>0 and all(.[]; ((.schema_version|type)=="number" or (.schema_version|type)=="string") and (.sequence|type)=="number" and ((.route//"")|type)=="string" and ((.verdict//"")|type)=="string" and ((.reason//"")|type)=="string" and ((.request_hash//"")|type)=="string" and ((.route//"")|length)>0 and ((.verdict//"")|length)>0 and ((.reason//"")|length)>0 and ((.request_hash//"")|length)>0)' "$decisions" >/dev/null 2>&1&&printf yes||printf no)
    monotonic=$(timeout "$TIMEOUT_SECONDS" jq -s -e '([.[].sequence] | length>0 and (map(select(type=="number")) | length == length) and . == (sort | unique))' "$decisions" >/dev/null 2>&1&&printf yes||printf no)
    unknown_refused=$(timeout "$TIMEOUT_SECONDS" jq -s -e 'any(.[]; ((.route//"")|ascii_downcase|test("unknown|forbidden")) and ((.verdict//"")|ascii_downcase|test("refus|deny")))' "$decisions" >/dev/null 2>&1&&printf yes||printf no)
    if [[ $known == yes && $schema_ok == yes && $monotonic == yes && $unknown_refused == yes ]]; then add_check live_route_mediation pass 'Every recorded request maps to the pinned census or a refusal, decisions carry the published schema fields in sequence order, and an unknown route was refused.'; else add_check live_route_mediation fail 'Live decisions contain an unknown admitted route, lack the published schema fields or sequence order, or do not prove an unknown-route refusal.'; fi
  fi
  fi
fi
if ((failed)); then emit fail 'One or more Docker-API mediation checks failed.'; exit 1; fi
if ((unrunnable)); then emit not_runnable 'Static checks ran; live policy-proxy evidence is not runnable on this host.'; exit 3; fi
emit pass 'All Docker-API mediation checks passed.'
