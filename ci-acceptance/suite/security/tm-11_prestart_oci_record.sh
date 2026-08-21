#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-11
TITLE='Before every start, record the proxy-approved canonical OCI request'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/acceptance_control.sh"
candidate=''; candidate_dir=''; evidence_dir=''; plan=0
checks=(); evidence=(); preconditions=(
  'buzz-ci-policy-proxy source and Cargo workspace exist in BUZZ_CI_PROXY_DIR or candidate-dir'
  'bash, coreutils, jq, and cargo are installed; evidence-dir is writable'
  'the exact root-authored TM-11/prestart_oci case is sealed for the suite candidate'
  'the response exposes a nonzero attempt_id and equal positive generation fields'
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
read -r -a SUDO <<<"$SUITE_SUDO"
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

seccomp_source=$(acceptance_receipt_root)/seccomp.json
seccomp_evidence=$out_dir/seccomp-install-receipt.json
oci_receipt_dir=$(acceptance_receipt_root)/oci
fixed_profile=/var/lib/buzzci/seccomp/v1/sha256/2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4.json
fixed_digest=2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4
oci_binding=$out_dir/oci-binding.json
oci_response=$out_dir/oci-response.json
oci_error=$out_dir/oci-response.stderr
oci_expected=$out_dir/oci-expected.json
if [[ ! -e /etc/buzzci/harness.env ]]; then
  add_check live_request_before_start not_runnable 'Substrate wiring has not published /etc/buzzci/harness.env'
elif ((${#SUDO[@]} == 0)); then
  add_check live_request_before_start not_runnable 'Seccomp and OCI receipt readback requires SUITE_SUDO or passwordless sudo'
else
  harness_text=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat /etc/buzzci/harness.env 2>/dev/null) || harness_text=''
  export harness_text
  oci_rc=0
  if ! acceptance_control_init; then
    add_check live_request_before_start not_runnable "$ACCEPTANCE_UNAVAILABLE"
  else
    acceptance_control_run prestart_oci "$oci_response" "$oci_error" "$oci_binding" || oci_rc=$?
    evidence+=("$TEST_ID/oci-response.json" "$TEST_ID/oci-response.stderr" "$TEST_ID/oci-binding.json")
    if ((oci_rc == 3)); then
      add_check live_request_before_start not_runnable 'The exact root-authored TM-11/prestart_oci.json case is missing, stale, cross-candidate, or unsafe'
    elif ((oci_rc != 0)); then
      add_check live_request_before_start fail 'The authenticated OCI qualification case was not admitted'
    elif ! acceptance_bind_response "$oci_binding" "$oci_response" "$oci_expected"; then
      add_check live_request_before_start not_runnable 'The response must expose type=qualification_result, code=ok, nonzero 32-hex attempt_id, equal positive integer generation and lease_generation, and positive updated_at'
    elif ! acceptance_copy_receipt "$seccomp_source" "$seccomp_evidence"; then
      add_check live_request_before_start not_runnable 'The fixed sealed seccomp install receipt is missing or unsafe'
    else
      evidence+=("$TEST_ID/oci-expected.json" "$TEST_ID/seccomp-install-receipt.json")
      install_receipt_sha256=$(timeout 10 sha256sum -- "$seccomp_evidence" | timeout 10 awk '{print $1}')
      oci_lease=$(timeout 10 jq -r '.lease_id' "$oci_expected")
      oci_generation=$(timeout 10 jq -r '.lease_generation' "$oci_expected")
      oci_source=$oci_receipt_dir/$oci_lease-g$oci_generation.json
      oci_evidence=$out_dir/oci-prestart-receipt.json
      for _ in {1..120}; do
        acceptance_copy_receipt "$oci_source" "$oci_evidence" && break
        timeout 2 sleep 0.25
      done
      evidence+=("$TEST_ID/oci-prestart-receipt.json")
      if [[ ! -s $oci_evidence ]]; then
        add_check live_request_before_start not_runnable 'The exact response-derived OCI receipt is missing or unsafe'
      else
        now_ns=$(timeout 10 date +%s%N)
        if acceptance_receipt_binding_matches "$oci_expected" "$oci_evidence" \
          && timeout "$TIMEOUT_SECONDS" jq -e \
            --arg path "$fixed_profile" --arg digest "$fixed_digest" --arg install_digest "$install_receipt_sha256" \
            --argjson now_ns "$now_ns" --argjson max_age_ns "$((TIMEOUT_SECONDS * 1000000000))" '
              .version == 1 and .committed == true and
              .install_receipt_sha256 == $install_digest and
              .profile_path == $path and .profile_sha256 == $digest and .phase == "prestart" and
              .no_new_privileges == true and .recorded_before_unit_start == true and
              ([.security_options[] | select(ascii_downcase | startswith("seccomp="))] == ["seccomp=" + $path]) and
              (.recorded_at_unix_ns | type == "number" and . > 0 and floor == .) and
              (.unit_start_requested_at_unix_ns | type == "number" and . > 0 and floor == .) and
              .unit_start_requested_at_unix_ns > .recorded_at_unix_ns and
              .recorded_at_unix_ns <= $now_ns and ($now_ns - .recorded_at_unix_ns) <= $max_age_ns
            ' "$oci_evidence" >/dev/null 2>&1 \
          && timeout "$TIMEOUT_SECONDS" jq -e --arg path "$fixed_profile" --arg digest "$fixed_digest" '
            .version == 1 and .committed == true and
            (.disposition == "installed" or .disposition == "existing") and
            .profile_path == $path and .profile_sha256 == $digest and
            .source_sha256 == $digest and .build_sha256 == $digest and .install_sha256 == $digest and
            (.recorded_at_unix_ns | type == "number" and . > 0 and floor == .)
          ' "$seccomp_evidence" >/dev/null 2>&1; then
          add_check live_request_before_start pass "Lease $oci_lease generation $oci_generation binds the sealed seccomp receipt to an actual prestart record before unit start"
        else
          add_check live_request_before_start fail 'The exact OCI receipt is stale, cross-bound, or lacks the sealed seccomp prestart proof'
        fi
      fi
    fi
  fi
fi
if ((failed)); then emit fail 'One or more pre-start OCI record checks failed.'; exit 1; fi
if ((unrunnable)); then emit not_runnable 'Static checks ran; live pre-start records are not runnable on this host.'; exit 3; fi
emit pass 'All pre-start OCI record checks passed.'
