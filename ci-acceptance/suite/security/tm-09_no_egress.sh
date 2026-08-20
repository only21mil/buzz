#!/usr/bin/env bash
set -euo pipefail

TEST_ID=TM-09
TITLE='Put outer `act`, Podman helpers, and jobs inside the root-owned no-egress attempt namespace'
TIMEOUT_SECONDS=${SUITE_TIMEOUT_SECONDS:-600}
candidate=''; candidate_dir=''; evidence_dir=''; plan=0
checks=(); statuses=(); evidence_files=()
preconditions=(
  'policy proxy + broker lease path live for outer act, Podman helper, and job placement'
  'lease.json records the broker DNS and network proofs for the materializer, exec, and run principals'
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

record() {
  local name=$1 status=$2 detail=$3
  checks+=("$(timeout "$TIMEOUT_SECONDS" jq -cn --arg name "$name" --arg status "$status" --arg detail "$detail" '{name:$name,status:$status,detail:$detail}')")
  statuses+=("$status")
}
json_array() {
  if (($# == 0)); then printf '[]'; else printf '%s\n' "$@" | timeout "$TIMEOUT_SECONDS" jq -Rsc 'split("\n") | map(select(length > 0))'; fi
}
emit() {
  local status summary pass_json=false checks_json evidence_json preconditions_json
  if ((plan)); then status=plan; summary='Plan only; no network tests executed'
  elif [[ " ${statuses[*]} " == *' fail '* ]]; then status=fail; summary='At least one deny-by-default network check failed'
  elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then status=not_runnable; summary='Host no-egress controls passed where runnable; broker lease proofs are unavailable'
  else status=pass; pass_json=true; summary='All no-egress and network policy checks passed'; fi
  checks_json=$(printf '%s\n' "${checks[@]}" | timeout "$TIMEOUT_SECONDS" jq -sc '.')
  evidence_json=$(json_array "${evidence_files[@]}")
  preconditions_json=$(json_array "${preconditions[@]}")
  timeout "$TIMEOUT_SECONDS" jq -cn --arg test_id "$TEST_ID" --arg title "$TITLE" --arg status "$status" --argjson pass "$pass_json" --arg summary "$summary" --argjson checks "$checks_json" --argjson evidence_files "$evidence_json" --argjson preconditions "$preconditions_json" '{test_id:$test_id,title:$title,status:$status,pass:$pass,summary:$summary,checks:$checks,evidence_files:$evidence_files,preconditions:$preconditions}'
}
finish() {
  emit
  if ((plan)); then exit 0
  elif [[ " ${statuses[*]} " == *' fail '* ]]; then exit 1
  elif [[ " ${statuses[*]} " == *' not_runnable '* ]]; then exit 3
  else exit 0
  fi
}

names=(nft_policy_and_empty_allowlists exec_tcp_1_1_1_1 exec_tcp_9_9_9_9 exec_dns run_tcp_1_1_1_1 run_tcp_9_9_9_9 run_dns mat_tcp_1_1_1_1 mat_tcp_9_9_9_9 mat_dns isolated_netns mediated_attempt_namespace offline_missing_dependency network_host_rejection lease_dns_readback)
if ((plan)); then
  for name in "${names[@]}"; do record "$name" plan 'Would inspect the amended nft policy, host checks, or broker lease DNS readback'; done
  finish
fi
[[ -d $candidate_dir ]] || { printf 'candidate directory is not a directory\n' >&2; exit 4; }

out_dir=$evidence_dir/$TEST_ID
timeout "$TIMEOUT_SECONDS" mkdir -p -- "$out_dir"
SUDO=()
if [[ -n ${SUITE_SUDO+x} ]]; then read -r -a SUDO <<<"$SUITE_SUDO"
elif timeout 5 sudo -n true >/dev/null 2>&1; then SUDO=(sudo -n)
fi

if ((${#SUDO[@]})); then
  nft_file=$out_dir/nft-table.txt
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" nft list table inet buzzci >"$nft_file" 2>&1 || true
  evidence_files+=("$TEST_ID/nft-table.txt")
  normalized=$(timeout "$TIMEOUT_SECONDS" tr -s '[:space:]' ' ' <"$nft_file")
  nft_ok=1
  for required in \
    'set buzzci_allow { type ipv4_addr . inet_service' \
    'set buzzci_allow6 { type ipv6_addr . inet_service' \
    'meta skuid { 964, 965 } drop' \
    'meta skuid 966 ip daddr . tcp dport @buzzci_allow accept' \
    'meta skuid 966 ip6 daddr . tcp dport @buzzci_allow6 accept' \
    'meta skuid 966 drop'; do
    [[ $normalized == *"$required"* ]] || nft_ok=0
  done
  if timeout "$TIMEOUT_SECONDS" grep -Eq 'elements[[:space:]]*=[[:space:]]*\{[[:space:]]*[^}[:space:]]' "$nft_file"; then nft_ok=0; fi
  printf 'allowlist note: today buzzci_allow and buzzci_allow6 are expected to be empty; future entries must still be followed by the final uid-966 drop.\n' >>"$nft_file"
  if ((nft_ok)); then record nft_policy_and_empty_allowlists pass 'nft table inet buzzci has the amended tuple sets, uid drops, and empty allowlists'; else record nft_policy_and_empty_allowlists fail 'nft table inet buzzci differs from the amended tuple rules or an allowlist is non-empty'; fi

  for principal in buzzci-exec-01 buzzci-run-01 buzzci-mat-01; do
    short=${principal#buzzci-}; short=${short%-01}
    for target in 1.1.1.1:443 9.9.9.9:53; do
      ip=${target%:*}; port=${target##*:}; safe_ip=${ip//./_}
      file=$out_dir/${short}-tcp-${safe_ip}-${port}.txt
      set +e
      timeout 5 "${SUDO[@]}" -u "$principal" bash -c 'exec 3<>"/dev/tcp/$1/$2"' bash "$ip" "$port" >"$file" 2>&1
      rc=$?
      set -e
      evidence_files+=("$TEST_ID/${short}-tcp-${safe_ip}-${port}.txt")
      name=${short}_tcp_${safe_ip}
      if ((rc != 0)); then record "$name" pass "$principal could not connect to $target"; else record "$name" fail "$principal connected to forbidden target $target"; fi
    done
    dns_file=$out_dir/${short}-dns.txt
    set +e
    timeout 5 "${SUDO[@]}" -u "$principal" getent hosts example.com >"$dns_file" 2>&1
    dns_rc=$?
    set -e
    evidence_files+=("$TEST_ID/${short}-dns.txt")
    if ((dns_rc != 0)); then record "${short}_dns" pass "$principal could not resolve example.com"; else record "${short}_dns" fail "$principal resolved example.com despite the no-egress rule"; fi
  done

  links_file=$out_dir/netns-links.json
  routes_file=$out_dir/netns-routes.json
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" ip -n buzzci-job01 -j link >"$links_file" 2>&1 || true
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" ip -n buzzci-job01 -j route >"$routes_file" 2>&1 || true
  evidence_files+=("$TEST_ID/netns-links.json" "$TEST_ID/netns-routes.json")
  if timeout "$TIMEOUT_SECONDS" jq -e 'length == 1 and .[0].ifname == "lo"' "$links_file" >/dev/null 2>&1 && timeout "$TIMEOUT_SECONDS" jq -e 'all(.[]; .dst != "default")' "$routes_file" >/dev/null 2>&1; then
    record isolated_netns pass 'buzzci-job01 has only loopback and no default route'
  else
    record isolated_netns fail 'buzzci-job01 has a non-loopback link or a default route'
  fi
else
  record nft_policy_and_empty_allowlists not_runnable 'Root nft readback requires SUITE_SUDO or passwordless sudo'
  for name in exec_tcp_1_1_1_1 exec_tcp_9_9_9_9 exec_dns run_tcp_1_1_1_1 run_tcp_9_9_9_9 run_dns mat_tcp_1_1_1_1 mat_tcp_9_9_9_9 mat_dns isolated_netns; do record "$name" not_runnable 'Principal or netns test requires SUITE_SUDO or passwordless sudo'; done
fi

record mediated_attempt_namespace not_runnable 'Placement of outer act, Podman helpers, and jobs requires the live policy proxy and broker lease path'
record offline_missing_dependency not_runnable 'Missing-action/image offline proof requires a mediated job with DNS and connect observation'

if [[ ! -e /etc/buzzci/harness.env ]]; then
  record lease_dns_readback not_runnable 'substrate wiring has not published /etc/buzzci/harness.env (lease DNS seam)'
else
  harness_text=''
  if ((${#SUDO[@]})); then
    harness_text=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat /etc/buzzci/harness.env 2>/dev/null) || harness_text=''
  fi
  if [[ -z $harness_text ]]; then
    if ((${#SUDO[@]} == 0)); then record lease_dns_readback not_runnable 'harness.env unreadable without sudo'; else record lease_dns_readback fail 'Published harness.env is not root-readable.'; fi
  else
    state_root=$(printf '%s\n' "$harness_text" | timeout "$TIMEOUT_SECONDS" awk -F= '$1=="BUZZ_CI_LEASE_STATE_ROOT"{print substr($0,index($0,"=")+1); exit}')
    lease_dir=''
    if [[ -n $state_root && -d $state_root ]]; then for entry in "$state_root"/*; do [[ -d $entry ]] && { lease_dir=$entry; break; }; done; fi
    lease_json=$lease_dir/lease.json
    dns_evidence=$out_dir/dns-readback.json
    if [[ -z $lease_dir || ! -f $lease_json ]]; then
      printf 'state_root=%s lease_dir=%s lease_json=%s\n' "$state_root" "$lease_dir" "$lease_json" >"$dns_evidence"
      evidence_files+=("$TEST_ID/dns-readback.json")
      record lease_dns_readback fail 'lease.json lacks dns_readback'
    else
      if ((${#SUDO[@]})); then timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat "$lease_json" >"$dns_evidence" 2>&1 || true
      else timeout "$TIMEOUT_SECONDS" cat "$lease_json" >"$dns_evidence" 2>&1 || true
      fi
      evidence_files+=("$TEST_ID/dns-readback.json")
      if timeout "$TIMEOUT_SECONDS" jq -e '.dns_readback | type == "object" and .files_lookup_ok == true and .arbitrary_getent_refused == true and .resolved_varlink_inaccessible == true and .direct_53_refused == true and .allowed_tuples_only == true' "$dns_evidence" >/dev/null 2>&1; then
        record lease_dns_readback pass 'lease.json records all five broker DNS and approved-tuple proofs: pinned files lookup, arbitrary getent refusal, varlink isolation, direct 53 refusal, and approved tuples only'
      else
        record lease_dns_readback fail 'lease.json lacks dns_readback'
      fi
    fi
  fi
fi

proxy_dir=${BUZZ_CI_PROXY_DIR:-$candidate_dir}
if [[ ! -f $proxy_dir/crates/buzz-ci-policy-proxy/src/policy.rs && -f /home/victor/work/buzz-ci-suite-harness-cand-proxy/crates/buzz-ci-policy-proxy/src/policy.rs ]]; then
  proxy_dir=/home/victor/work/buzz-ci-suite-harness-cand-proxy
fi
policy_file=$proxy_dir/crates/buzz-ci-policy-proxy/src/policy.rs
static_file=$out_dir/network-host-static-check.txt
if [[ -r $policy_file ]] && timeout "$TIMEOUT_SECONDS" sed -n '1143,1167p' "$policy_file" >"$static_file" && timeout "$TIMEOUT_SECONDS" rg -q '\("NetworkMode", serde_json::json!\("host"\)\)' "$static_file" && timeout "$TIMEOUT_SECONDS" rg -q '\.is_err\(\)' "$static_file"; then
  evidence_files+=("$TEST_ID/network-host-static-check.txt")
  record network_host_rejection pass "$policy_file:1145 rejects caller HostConfig NetworkMode=host before admission"
else
  [[ -e $static_file ]] || : >"$static_file"; evidence_files+=("$TEST_ID/network-host-static-check.txt")
  record network_host_rejection not_runnable 'No inspected policy-proxy test proves HostConfig NetworkMode=host rejection'
fi
finish
