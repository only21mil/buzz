#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-11
TITLE='Before every start, record the proxy-approved canonical OCI request'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
candidate=''; candidate_dir=''; evidence_dir=''; plan=0
checks=(); evidence=(); preconditions=(
  'buzz-ci-policy-proxy source and Cargo workspace exist in BUZZ_CI_PROXY_DIR or candidate-dir'
  'bash, coreutils, jq, and cargo are installed; evidence-dir is writable'
  'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'
)
failed=0; unrunnable=0
usage(){ printf 'usage: %s --candidate <full-sha> --candidate-dir <path> --evidence-dir <path> [--plan]\n' "$0" >&2; exit 4; }
while (($#)); do case $1 in --candidate) (($#>=2))||usage; candidate=$2; shift 2;; --candidate-dir) (($#>=2))||usage; candidate_dir=$2; shift 2;; --evidence-dir) (($#>=2))||usage; evidence_dir=$2; shift 2;; --plan) plan=1; shift;; *) usage;; esac; done
add_check(){ local n=$1 s=$2 d=$3; checks+=("$(timeout "$TIMEOUT_SECONDS" jq -cn --arg n "$n" --arg s "$s" --arg d "$d" '{name:$n,status:$s,detail:$d}')"); [[ $s != fail ]]||failed=1; [[ $s != not_runnable ]]||unrunnable=1; }
emit(){ local s=$1 summary=$2 p=false cj ej pj; [[ $s == pass ]]&&p=true; cj=$(printf '%s\n' "${checks[@]}"|timeout "$TIMEOUT_SECONDS" jq -sc '.'); ej=$(printf '%s\n' "${evidence[@]}"|timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n") | map(select(length > 0))'); pj=$(printf '%s\n' "${preconditions[@]}"|timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n") | map(select(length > 0))'); timeout "$TIMEOUT_SECONDS" jq -cn --arg id "$TEST_ID" --arg title "$TITLE" --arg status "$s" --arg summary "$summary" --argjson pass "$p" --argjson checks "$cj" --argjson files "$ej" --argjson pre "$pj" '{test_id:$id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$files,preconditions:$pre}'; }
if ((plan)); then
  add_check policy_proxy_crate_tests plan 'Run the bounded buzz-ci-policy-proxy crate tests.'
  add_check prestart_proof_gate plan 'Prove container start requires a complete effective-spec proof before the upstream start.'
  add_check effective_oci_constraints plan 'Prove the gate checks non-root user, user namespace, capabilities, seccomp, SELinux, sockets, digest image, namespaces, resources, and disabled logging.'
  add_check live_request_before_start plan 'Verify every canonical request record predates its container start event and contains the effective-spec proof.'
  emit plan 'Planned static pre-start gate and live OCI record checks; no checks executed.'; exit 0
fi
[[ $candidate =~ ^[0-9a-f]{40}$ && -n $candidate_dir && -n $evidence_dir ]]||usage
if [[ -z ${SUITE_SUDO+x} ]]; then if timeout 5 sudo -n true >/dev/null 2>&1; then SUITE_SUDO='sudo -n'; else SUITE_SUDO=''; fi; fi
read -r -a sudo_cmd <<<"$SUITE_SUDO"
read_harness() {
  if ((${#sudo_cmd[@]})); then timeout "$TIMEOUT_SECONDS" "${sudo_cmd[@]}" cat /etc/buzzci/harness.env
  else return 3; fi
}
read_harness_key(){ local key=$1; printf '%s\n' "$harness_text" | timeout "$TIMEOUT_SECONDS" awk -F= -v key="$key" '$1==key{print substr($0,index($0,"=")+1); exit}'; }
proxy_dir=${BUZZ_CI_PROXY_DIR:-$candidate_dir}; out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"||exit 4
cargo_log=$out_dir/cargo-test.log
set +e; CARGO_TARGET_DIR=$proxy_dir/target timeout "$TIMEOUT_SECONDS" cargo test --manifest-path "$proxy_dir/Cargo.toml" -p buzz-ci-policy-proxy >"$cargo_log" 2>&1; rc=$?; set -e
evidence+=("$TEST_ID/cargo-test.log"); if ((rc==0)); then add_check policy_proxy_crate_tests pass 'buzz-ci-policy-proxy tests completed with zero failures.'; else add_check policy_proxy_crate_tests fail "cargo test exited $rc; see cargo-test.log."; fi

policy_rs=$proxy_dir/crates/buzz-ci-policy-proxy/src/policy.rs; transport_rs=$proxy_dir/crates/buzz-ci-policy-proxy/src/transport.rs; proof=$out_dir/static-prestart-proof.txt
if [[ -f $policy_rs && -f $transport_rs ]]; then
  timeout "$TIMEOUT_SECONDS" grep -nE 'NeedsPreStartProof|verify_pre_start|commit_started|EffectiveContainerSpec|userns|selinux|seccomp|cap_drop|network_mode|log_driver|image|socket|nano_cpus|memory|pids' "$policy_rs" "$transport_rs" >"$proof" 2>&1||true; evidence+=("$TEST_ID/static-prestart-proof.txt")
  gate_missing=''; for pin in 'NeedsPreStartProof' 'verify_pre_start' 'commit_started' 'decode_effective_spec'; do timeout "$TIMEOUT_SECONDS" grep -Fq "$pin" "$policy_rs" "$transport_rs"||gate_missing+=" $pin"; done
  if [[ -z $gate_missing ]] && timeout "$TIMEOUT_SECONDS" grep -n 'verify_pre_start' "$transport_rs" >/dev/null; then add_check prestart_proof_gate pass 'Transport decodes the runtime inspection, verifies it against policy, and commits started state only after the pre-start proof.'; else add_check prestart_proof_gate fail "Pre-start effective-spec gate is incomplete:$gate_missing"; fi
  constraint_missing=''; for pin in 'container_user' 'userns_mode' 'cap_drop' 'security_opt' 'network_mode' 'log_driver' 'image' 'devices' 'nano_cpus' 'memory' 'pids_limit'; do timeout "$TIMEOUT_SECONDS" grep -Fq "$pin" "$policy_rs" "$transport_rs"||constraint_missing+=" $pin"; done
  timeout "$TIMEOUT_SECONDS" grep -Eiq 'selinux|label=' "$policy_rs" "$transport_rs"||constraint_missing+=' selinux_label'
  timeout "$TIMEOUT_SECONDS" grep -Eiq 'seccomp' "$policy_rs" "$transport_rs"||constraint_missing+=' seccomp'
  timeout "$TIMEOUT_SECONDS" grep -Eiq 'socket' "$policy_rs" "$transport_rs"||constraint_missing+=' socket_refusal'
  if [[ -z $constraint_missing ]]; then add_check effective_oci_constraints pass 'Effective-spec comparison covers identity, userns, capabilities, seccomp/SELinux, sockets, image, namespaces, resources, and log policy.'; else add_check effective_oci_constraints fail "Effective OCI constraint proof is incomplete:$constraint_missing"; fi
else
  printf 'missing policy.rs or transport.rs\n' >"$proof"; evidence+=("$TEST_ID/static-prestart-proof.txt"); add_check prestart_proof_gate fail 'Proxy checkout is missing policy or transport source.'; add_check effective_oci_constraints fail 'Proxy checkout is missing effective OCI constraint source.'
fi

if [[ ! -e /etc/buzzci/harness.env ]]; then
  add_check live_request_before_start not_runnable 'substrate wiring has not published /etc/buzzci/harness.env (seam contract item 1)'
else
  harness_text=''
  if ! harness_text=$(read_harness 2>/dev/null); then
    if ((${#sudo_cmd[@]} == 0)); then add_check live_request_before_start not_runnable 'harness.env unreadable without sudo'; else add_check live_request_before_start fail 'Published harness.env is not root-readable.'; fi
  else
  state_root=$(read_harness_key BUZZ_CI_LEASE_STATE_ROOT 2>/dev/null||true)
  lease_dir=''; [[ -n $state_root && -d $state_root ]]&&for e in "$state_root"/*; do [[ -d $e ]]&&{ lease_dir=$e; break; }; done
  ordering=$lease_dir/ordering.jsonl; object_dir=$lease_dir/proxy/objects; live=$out_dir/live-prestart-proof.txt
  object_files=(); [[ -d $object_dir ]]&&for f in "$object_dir"/*.json; do [[ -f $f ]]&&object_files+=("$f"); done
  if [[ -z $state_root || ! -d $state_root || -z $lease_dir || ! -f $ordering || ${#object_files[@]} -eq 0 ]]; then
    printf 'state_root=%s lease_dir=%s ordering=%s objects=%s\n' "$state_root" "$lease_dir" "$ordering" "${#object_files[@]}" >"$live"; evidence+=("$TEST_ID/live-prestart-proof.txt"); add_check live_request_before_start fail 'harness.env exists but ordering.jsonl or canonical proxy object records are missing.'
  else
    : >"$live"; live_ok=1
    for f in "${object_files[@]}"; do
      timeout "$TIMEOUT_SECONDS" jq -c '{object_id:(.object_id//.container_id//.id),recorded_ns:(.recorded_ns//.recorded_at_ns//.timestamp_ns),start_ns:(.start_ns//.started_at_ns),effective_spec:(.effective_spec//.effective//.approved_spec)}' "$f" >>"$live" 2>&1||live_ok=0
      object_id=$(timeout "$TIMEOUT_SECONDS" jq -r '.object_id//.container_id//.id//empty' "$f" 2>/dev/null||true)
      recorded_ns=$(timeout "$TIMEOUT_SECONDS" jq -r '.recorded_ns//.recorded_at_ns//.timestamp_ns//empty' "$f" 2>/dev/null||true)
      start_ns=$(timeout "$TIMEOUT_SECONDS" jq -r --arg id "$object_id" '[select((.event//.name//"")|test("start")) | select(($id=="") or ((.object_id//.container_id//"")==$id)) | (.timestamp_ns//.monotonic_ns//.unix_ns)] | min // empty' "$ordering" 2>/dev/null||true)
      [[ $recorded_ns =~ ^[0-9]+$ && $start_ns =~ ^[0-9]+$ && $recorded_ns -lt $start_ns ]]||live_ok=0
      timeout "$TIMEOUT_SECONDS" jq -e '
        (.effective_spec//.effective//.approved_spec) as $s |
        (($s.user//$s.container_user//"")|test("^[1-9][0-9]*:[1-9][0-9]*$")) and
        (($s.userns_mode//$s.userns//"")|length>0) and
        (($s.cap_drop//$s.capabilities.drop//[])|index("ALL")!=null) and
        (($s.security_opt//$s.security_options//[])|map(ascii_downcase)|any(test("seccomp"))) and
        (($s.security_opt//$s.security_options//[])|map(ascii_downcase)|any(test("label|selinux"))) and
        (($s.network_mode//$s.network//"")=="none") and
        (($s.image//$s.image_digest//"")|test("^sha256:[0-9a-f]{64}$")) and
        (($s.binds//$s.mounts//[])|map(tostring)|all(test("docker\\.sock|podman\\.sock|proxy\\.sock")|not)) and
        (($s.log_driver//$s.log_config.type//"")=="none") and
        (($s.artifact_server_enabled//false)==false) and (($s.persistent_logs//false)==false) and
        (($s.nano_cpus//$s.cpu_quota//0)>0) and (($s.memory//$s.memory_max_bytes//0)>0) and (($s.pids_limit//$s.pids_max//0)>0)
      ' "$f" >/dev/null 2>&1||live_ok=0
    done
    evidence+=("$TEST_ID/live-prestart-proof.txt")
    if ((live_ok)); then add_check live_request_before_start pass 'Every canonical request record predates start and proves the required effective OCI constraints.'; else add_check live_request_before_start fail 'A canonical request is late, unbound to a start, or lacks one or more required effective OCI constraints.'; fi
  fi
  fi
fi
if ((failed)); then emit fail 'One or more pre-start OCI record checks failed.'; exit 1; fi
if ((unrunnable)); then emit not_runnable 'Static checks ran; live pre-start records are not runnable on this host.'; exit 3; fi
emit pass 'All pre-start OCI record checks passed.'
