#!/usr/bin/env bash
set -euo pipefail

CASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ACCEPTANCE_DIR=$(cd -- "$CASE_DIR/.." && pwd -P)
PLAN=$ACCEPTANCE_DIR/substrate/qualification-cases.plan
EXPECTATIONS=$CASE_DIR/expectations.tsv
TEMPLATES=$CASE_DIR/templates
failed=0
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/buzzci-qualification-cases.XXXXXX")
trap 'rm -rf -- "$temp_dir"' EXIT

pass() { printf '%s: pass\n' "$1"; }
fail() { printf '%s: FAIL\n' "$1"; failed=1; }

template_shape() {
  local file=$1 directive=$2 case_name=$3
  timeout 10 jq -e --arg directive "$directive" --arg case_name "$case_name" '
    def token_exact: type == "string" and test("^@[A-Z][A-Z0-9_]*@$");
    def oid: (keys | sort) == ["algorithm","hex"] and (.algorithm == "sha1" or .algorithm == "sha256") and (.hex | token_exact);
    def host: (keys | sort) == ["broker_build_identity","host_profile_digest","integrated_candidate_sha","suite_identity"] and
      (.integrated_candidate_sha | oid) and (.broker_build_identity | token_exact) and
      (.host_profile_digest | token_exact) and (.suite_identity | token_exact);
    def job: (keys | sort) == ["base_oid","isolation_profile_digest","manifest_digest","request_digest","source_oid","test_identity"] and
      (.request_digest | token_exact) and (.manifest_digest | token_exact) and
      (.isolation_profile_digest | token_exact) and (.source_oid | oid) and
      (.base_oid | oid) and (.test_identity | token_exact);
    (.version == "qualification_v1") and
    ((keys | sort) == (if $directive == "teardown_failure" then ["admission","directive","permit","version"] else ["admission","permit","version"] end)) and
    ((.directive // "none") == $directive) and
    ((.permit | keys | sort) == ["authorized_by","expires_at","fixture_identity","fixture_job","fixture_signer","host","nonce","not_before"]) and
    (.permit.authorized_by | token_exact) and (.permit.host | host) and (.permit.fixture_job | job) and
    (.permit.fixture_identity | token_exact) and (.permit.fixture_signer | token_exact) and
    (.permit.nonce | token_exact) and (.permit.not_before | token_exact) and (.permit.expires_at | token_exact) and
    ((.admission | keys | sort) == ["fixture_identity","fixture_job","host","nonce","signer","trust_class"]) and
    (.admission.host | host) and (.admission.fixture_job | job) and
    (.admission.fixture_identity | token_exact) and (.admission.signer | token_exact) and (.admission.nonce | token_exact) and
    (if $case_name == "unaccepted" then .admission.trust_class == "unaccepted" else .admission.trust_class == "qualification_fixture" end) and
    (if $case_name == "external_fork" then
       .permit.host == .admission.host and
       (.permit.fixture_job | del(.source_oid)) == (.admission.fixture_job | del(.source_oid)) and
       .permit.fixture_job.source_oid != .admission.fixture_job.source_oid and
       .permit.fixture_identity == .admission.fixture_identity and .permit.fixture_signer == .admission.signer and .permit.nonce == .admission.nonce
     elif $case_name == "unauthorized_signer" then
       .permit.host == .admission.host and .permit.fixture_job == .admission.fixture_job and
       .permit.fixture_identity == .admission.fixture_identity and .permit.fixture_signer != .admission.signer and .permit.nonce == .admission.nonce
     else
       .permit.host == .admission.host and .permit.fixture_job == .admission.fixture_job and
       .permit.fixture_identity == .admission.fixture_identity and .permit.fixture_signer == .admission.signer and .permit.nonce == .admission.nonce
     end)
  ' "$file" >/dev/null
}

awk -F '\t' 'NF && $1 !~ /^#/ {print $1 "/" $2}' "$PLAN" | sort >"$temp_dir/planned"
find "$TEMPLATES" -type f -name '*.json' -printf '%P\n' | sed 's/\.json$//' | sort >"$temp_dir/templates"
if cmp -s "$temp_dir/planned" "$temp_dir/templates"; then pass coverage; else fail coverage; diff -u "$temp_dir/planned" "$temp_dir/templates" || true; fi

if [[ $(wc -l <"$temp_dir/templates") -eq 41 ]] \
  && [[ -z $(find "$TEMPLATES" -type l -print -quit) ]] \
  && [[ -z $(find "$TEMPLATES" -type f -size +64k -print -quit) ]]; then
  pass artifact_posture
else
  fail artifact_posture
fi

awk -F '\t' 'NF && $1 !~ /^#/ {print $1 "/" $2}' "$EXPECTATIONS" | sort >"$temp_dir/expected"
if cmp -s "$temp_dir/planned" "$temp_dir/expected"; then pass expectations; else fail expectations; diff -u "$temp_dir/planned" "$temp_dir/expected" || true; fi

if [[ $(sort "$temp_dir/planned" | uniq -d | wc -l) -eq 0 ]] \
  && awk -F '\t' 'NF && $1 !~ /^#/ {if ($1 !~ /^TM-[0-9][0-9]$/ || $2 !~ /^[a-z0-9][a-z0-9_-]*$/ || ($3 != "none" && $3 != "teardown_failure")) exit 1}' "$PLAN"; then
  pass plan_shape
else
  fail plan_shape
fi

while IFS=$'\t' read -r test_id case_name directive; do
  [[ -n $test_id && $test_id != \#* ]] || continue
  if ! template_shape "$TEMPLATES/$test_id/$case_name.json" "$directive" "$case_name"; then
    printf 'invalid template: %s/%s\n' "$test_id" "$case_name"
    failed=1
  fi
done <"$PLAN"
if ((failed == 0)); then pass template_content; else printf 'template_content: FAIL\n'; fi

if timeout 10 jq -s -e '.[0].permit.nonce == .[1].permit.nonce' \
    "$TEMPLATES/TM-16/attempt_1.json" "$TEMPLATES/TM-16/replay.json" >/dev/null \
  && timeout 10 jq -s -e '
    (.[0].permit | del(.nonce)) == (.[1].permit | del(.nonce)) and
    (.[0].admission | del(.nonce)) == (.[1].admission | del(.nonce)) and
    .[0].permit.nonce != .[1].permit.nonce and .[0].admission.nonce != .[1].admission.nonce
  ' "$TEMPLATES/TM-16/concurrency_primary.json" "$TEMPLATES/TM-16/concurrency_overflow.json" >/dev/null; then
  pass controller_relationships
else
  fail controller_relationships
fi

if timeout 10 jq -s -e '
  all(.[];
    .permit.host.integrated_candidate_sha == {"algorithm":"sha1","hex":"@INTEGRATED_CANDIDATE_SHA1@"} and
    .permit.host == .admission.host and .permit.fixture_job == .admission.fixture_job and
    .permit.fixture_identity == .admission.fixture_identity and
    .permit.fixture_signer == .admission.signer and .permit.nonce == .admission.nonce)
' "$TEMPLATES/TM-09/dns_readback.json" "$TEMPLATES/TM-11/prestart_oci.json" >/dev/null; then
  pass receipt_case_bindings
else
  fail receipt_case_bindings
fi

if timeout 10 jq -e . "$CASE_DIR"/schema/*.json "$CASE_DIR"/fixtures/hostile/*.json >/dev/null \
  && while IFS= read -r file; do timeout 10 jq -e . "$file" >/dev/null || exit 1; done < <(find "$TEMPLATES" -type f -name '*.json' -print | sort); then
  pass json_parse
else
  fail json_parse
fi

if template_shape "$CASE_DIR/fixtures/hostile/unknown-directive.json" none normal >/dev/null 2>&1 \
  || template_shape "$CASE_DIR/fixtures/hostile/concrete-authority.json" none normal >/dev/null 2>&1 \
  || template_shape "$CASE_DIR/fixtures/hostile/missing-fixture-job.json" none normal >/dev/null 2>&1; then
  fail hostile_templates
else
  pass hostile_templates
fi

if timeout 10 jq -e --argjson now 100 '
  ([.. | strings | select(contains("@"))] | length) == 0 and
  (.permit.not_before | type) == "number" and (.permit.expires_at | type) == "number" and
  .permit.not_before <= $now and $now < .permit.expires_at
' "$CASE_DIR/fixtures/hostile/stale-sealed.json" >/dev/null 2>&1; then
  fail stale_case
else
  pass stale_case
fi

if timeout 10 jq -e --arg candidate 2222222222222222222222222222222222222222 --argjson now 100 '
  .version == "qualification_v1" and
  .permit.host == .admission.host and .permit.fixture_job == .admission.fixture_job and
  .permit.fixture_identity == .admission.fixture_identity and
  .permit.fixture_signer == .admission.signer and .permit.nonce == .admission.nonce and
  .permit.host.integrated_candidate_sha == {"algorithm":"sha1","hex":$candidate} and
  .permit.not_before <= $now and $now < .permit.expires_at
' "$CASE_DIR/fixtures/hostile/cross-candidate-sealed.json" >/dev/null 2>&1; then
  fail cross_candidate_case
elif ! timeout 10 jq -e --arg candidate 1111111111111111111111111111111111111111 --argjson now 100 '
  .permit.host.integrated_candidate_sha == {"algorithm":"sha1","hex":$candidate} and
  .permit.host == .admission.host and .permit.not_before <= $now and $now < .permit.expires_at
' "$CASE_DIR/fixtures/hostile/cross-candidate-sealed.json" >/dev/null 2>&1; then
  fail cross_candidate_fixture_control
else
  pass cross_candidate_case
fi

if timeout 10 jq -e '.code == "ok" and .conclusion != "success" and .broker_state == "quarantined"' \
    "$CASE_DIR/fixtures/hostile/teardown-green-response.json" >/dev/null 2>&1 \
  || timeout 10 jq -s -e 'all(.[]; .event != "publish")' \
    "$CASE_DIR/fixtures/hostile/teardown-publish-ordering.jsonl" >/dev/null 2>&1; then
  fail teardown_hostiles
else
  pass teardown_hostiles
fi

if awk -F '\t' 'NF && $1 !~ /^#/ && $3 == "teardown_failure" {if ($6 !~ /no publish/ || $6 !~ /no green/) exit 1; n++} END {exit !(n == 2)}' "$EXPECTATIONS"; then
  pass teardown_expectations
else
  fail teardown_expectations
fi

if ((failed == 0)); then
  printf 'qualification cases selftest: GREEN\n'
  exit 0
fi
printf 'qualification cases selftest: RED\n'
exit 1
