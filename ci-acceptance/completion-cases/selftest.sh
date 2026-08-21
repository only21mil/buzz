#!/usr/bin/env bash
set -euo pipefail

CASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$CASE_DIR/../.." && pwd -P)
FIXTURE_DIR=$CASE_DIR/fixtures
failed=0
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/buzzci-completion-cases.XXXXXX")
trap 'rm -rf -- "$temp_dir"' EXIT

pass() { printf '%s: pass\n' "$1"; }
fail() { printf '%s: FAIL\n' "$1"; failed=1; }

find "$FIXTURE_DIR" -type f -name '*.json' -printf '%f\n' | sort >"$temp_dir/actual-cases"
printf '%s\n' \
  claimed-success-failed-root-receipts.json \
  completion-after-cancel.json \
  second-completion-after-terminal.json \
  signer-mismatch.json \
  stale-lease.json \
  wrong-generation.json >"$temp_dir/expected-cases"
if cmp -s "$temp_dir/expected-cases" "$temp_dir/actual-cases"; then pass coverage; else fail coverage; fi

if [[ -z $(find "$FIXTURE_DIR" -type l -print -quit) ]] \
  && [[ -z $(find "$FIXTURE_DIR" -type f -size +64k -print -quit) ]] \
  && while IFS= read -r file; do timeout 10 jq -e . "$file" >/dev/null || exit 1; done < <(find "$FIXTURE_DIR" -type f -name '*.json' -print | sort); then
  pass immutable_fixture_posture
else
  fail immutable_fixture_posture
fi

if timeout 10 jq -s -e '
  def exact_token: type == "string" and test("^@[A-Z][A-Z0-9_]*@$");
  def binding_keys: ["attempt_id","base_oid","broker_build_identity","host_profile_digest","integrated_candidate_sha","isolation_profile_digest","job_identity","lease_generation","lease_id","manifest_digest","nonce","request_digest","signer_pubkey","source_oid","suite_identity"];
  all(.[];
    .version == "completion_acceptance_v1" and .wire_schema == "unbound" and
    (.case_binding | keys | sort) == binding_keys and
    (.receipt_binding | keys | sort) == binding_keys and
    (.case_binding == .receipt_binding) and
    ([.case_binding[] | exact_token] | all) and
    (.root_receipts | keys | sort) == ["evidence_verdict","receipt_set_digest","teardown_verdict"] and
    (.root_receipts.receipt_set_digest | exact_token) and
    (.root_receipts.evidence_verdict == "passed" or .root_receipts.evidence_verdict == "failed") and
    (.root_receipts.teardown_verdict == "passed" or .root_receipts.teardown_verdict == "failed") and
    (.before.state_digest | exact_token) and (.expected.after_state_digest | exact_token) and
    (.stimulus.phase == "prepare" or .stimulus.phase == "commit") and
    (.before.publish_count == 0) and (.expected.publish == false))
' "$FIXTURE_DIR"/*.json >/dev/null; then
  pass exact_case_receipt_bindings
else
  fail exact_case_receipt_bindings
fi

if timeout 10 jq -s -e '
  def decision:
    if .before.lifecycle == "terminal" or .before.lifecycle == "cancelled" then "refuse"
    elif .stimulus.lease_relation != "current" then "refuse"
    elif .stimulus.generation_relation != "current" then "refuse"
    elif .stimulus.signer_authentication != "verified" then "refuse"
    elif .stimulus.phase == "commit" and .before.lifecycle != "completion_prepared" then "refuse"
    elif .stimulus.phase == "commit" and
      (.root_receipts.evidence_verdict != "passed" or .root_receipts.teardown_verdict != "passed") then "quarantine"
    elif .stimulus.phase == "prepare" then "prepare"
    else "refuse" end;
  all(.[]; decision == .expected.decision)
' "$FIXTURE_DIR"/*.json >/dev/null; then
  pass mock_controller_decisions
else
  fail mock_controller_decisions
fi

if timeout 10 jq -s -e '
  [.[] | select(.expected.decision == "refuse")] as $refused |
  ($refused | length) == 5 and
  all($refused[];
    .expected.after_lifecycle == .before.lifecycle and
    .expected.after_state_digest == .before.state_digest and
    .expected.publish == false) and
  ([.[] | select(.case_name == "wrong_generation" and .stimulus.generation_relation == "wrong")] | length) == 1 and
  ([.[] | select(.case_name == "stale_lease" and .stimulus.lease_relation == "stale")] | length) == 1 and
  ([.[] | select(.case_name == "second_completion_after_terminal" and .before.lifecycle == "terminal")] | length) == 1 and
  ([.[] | select(.case_name == "completion_after_cancel" and .before.lifecycle == "cancelled")] | length) == 1 and
  ([.[] | select(.case_name == "signer_mismatch" and .stimulus.signer_authentication == "mismatch")] | length) == 1
' "$FIXTURE_DIR"/*.json >/dev/null; then
  pass refusal_zero_state_change
else
  fail refusal_zero_state_change
fi

if timeout 10 jq -s -e '
  [.[] | select(.case_name == "claimed_success_failed_root_receipts")] | length == 1 and
  (.[0] | .stimulus.claimed_conclusion == "success" and
    .stimulus.phase == "commit" and .before.lifecycle == "completion_prepared" and
    .root_receipts.evidence_verdict == "failed" and .root_receipts.teardown_verdict == "failed" and
    .expected.decision == "quarantine" and
    .expected.after_lifecycle == "quarantined" and
    .expected.after_state_digest != .before.state_digest and
    .expected.publish == false)
' "$FIXTURE_DIR/claimed-success-failed-root-receipts.json" >/dev/null; then
  pass failed_root_receipts_quarantine
else
  fail failed_root_receipts_quarantine
fi

(
  cd -- "$REPO_ROOT"
  sha256sum -c "$CASE_DIR/anchors.sha256" >/dev/null
) && pass frozen_v1_4_anchors || fail frozen_v1_4_anchors

sed -n 's/^pub const \(KIND_CI_[A-Z_]*\): u32 = \([0-9][0-9]*\);$/\1\t\2/p' \
  "$REPO_ROOT/crates/buzz-core/src/kind.rs" >"$temp_dir/all-ci-kinds"
if cmp -s "$CASE_DIR/relay-kinds.tsv" "$temp_dir/all-ci-kinds"; then
  pass frozen_relay_kinds
else
  fail frozen_relay_kinds
fi

if ((failed == 0)); then
  printf 'completion cases selftest: GREEN\n'
  exit 0
fi
printf 'completion cases selftest: RED\n'
exit 1
