#!/usr/bin/env bash
# Shared qualification-control helpers for TM-06, TM-07, and TM-12 through TM-17.
# Callers provide TEST_ID, TIMEOUT_SECONDS, candidate, harness_text, and SUDO.
# Assign the sourced candidate contract so standalone ShellCheck can verify it;
# every caller replaces this default while parsing its required --candidate.
candidate=${candidate-}

acceptance_receipt_root() {
  printf '%s' /var/lib/buzzci/activation/receipts
}

acceptance_env_get() {
  local key=$1
  # shellcheck disable=SC2154 # harness_text is assigned by every sourcing TM script.
  printf '%s\n' "$harness_text" | timeout "$TIMEOUT_SECONDS" awk -F= -v key="$key" \
    '$1==key{print substr($0,index($0,"=")+1); exit}'
}

acceptance_control_init() {
  local ctl_stat ctl_owner ctl_group ctl_mode ctl_kind root_stat root_owner root_group root_mode root_kind
  local case_dir case_dir_stat case_dir_owner case_dir_group case_dir_mode case_dir_kind
  ACCEPTANCE_CTL=$(acceptance_env_get BUZZ_CI_ACCEPTANCE_CTL)
  QUALIFICATION_CASE_ROOT=$(acceptance_env_get BUZZ_CI_QUALIFICATION_CASE_ROOT)
  # shellcheck disable=SC2034 # consumed by the sourcing TM script.
  ACCEPTANCE_UNAVAILABLE=''

  if ((${#SUDO[@]} == 0)); then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE='Qualification case readback and the buzzci-ctl invocation require SUITE_SUDO or passwordless sudo'
    return 3
  fi
  if [[ ! $ACCEPTANCE_CTL == /* || ! -x $ACCEPTANCE_CTL ]]; then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE='harness.env lacks an absolute executable BUZZ_CI_ACCEPTANCE_CTL'
    return 3
  fi
  ctl_stat=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -c '%U %G %a %F' -- "$ACCEPTANCE_CTL" 2>/dev/null) || return 3
  read -r ctl_owner ctl_group ctl_mode ctl_kind <<<"$ctl_stat"
  if [[ $ctl_owner != root || $ctl_group != buzzci-ctl || $ctl_mode != 750 || $ctl_kind != 'regular file' ]]; then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE='BUZZ_CI_ACCEPTANCE_CTL is not the root:buzzci-ctl mode 0750 regular binary'
    return 3
  fi
  if [[ ! $QUALIFICATION_CASE_ROOT == /* ]] \
    || ! timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" test -d "$QUALIFICATION_CASE_ROOT"; then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE='harness.env lacks an absolute readable BUZZ_CI_QUALIFICATION_CASE_ROOT'
    return 3
  fi
  root_stat=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -c '%U %G %a %F' -- "$QUALIFICATION_CASE_ROOT" 2>/dev/null) || return 3
  read -r root_owner root_group root_mode root_kind <<<"$root_stat"
  if [[ $root_owner != root || $root_group != root || $root_mode != 755 || $root_kind != directory ]]; then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE='BUZZ_CI_QUALIFICATION_CASE_ROOT is not a root:root mode 0755 directory'
    return 3
  fi
  case_dir=$QUALIFICATION_CASE_ROOT/$TEST_ID
  case_dir_stat=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -c '%U %G %a %F' -- "$case_dir" 2>/dev/null) || return 3
  read -r case_dir_owner case_dir_group case_dir_mode case_dir_kind <<<"$case_dir_stat"
  if [[ $case_dir_owner != root || $case_dir_group != root || $case_dir_mode != 755 || $case_dir_kind != directory ]]; then
    # shellcheck disable=SC2034
    ACCEPTANCE_UNAVAILABLE="Qualification case directory for $TEST_ID is not root:root mode 0755"
    return 3
  fi
}

acceptance_case_path() {
  local case_name=$1
  [[ $case_name =~ ^[a-z0-9][a-z0-9_-]*$ ]] || return 4
  printf '%s/%s/%s.json' "$QUALIFICATION_CASE_ROOT" "$TEST_ID" "$case_name"
}

# Invoke one root-authored qualification case. The JSON bytes are never parsed,
# copied, or rebuilt by the suite; the exact file is streamed to the closed
# acceptance control on stdin. Returns 3 for a missing/unsafe fixture, otherwise
# the control's status.
acceptance_control_run() {
  local case_name=$1 output=$2 error=$3 binding_output=${4:-}
  local case_file stat_line owner group mode kind size now case_sha256
  case_file=$(acceptance_case_path "$case_name") || return $?
  stat_line=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -c '%U|%G|%a|%F|%s' -- "$case_file" 2>/dev/null) || return 3
  IFS='|' read -r owner group mode kind size <<<"$stat_line"
  [[ $owner == root && $group == root && $mode == 444 && $kind == 'regular file' && $size =~ ^[1-9][0-9]*$ && $size -le 65536 ]] || return 3

  now=$(timeout 10 date +%s)
  [[ $now =~ ^[1-9][0-9]*$ ]] || return 3
  # Do not invoke the control for an unsigned template, malformed binding, or
  # stale positive case. The one expired negative is deliberately structurally
  # valid and expired so ActivationController, rather than the client, refuses it.
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" jq -e --arg candidate "$candidate" --arg case_name "$case_name" --arg test_id "$TEST_ID" --argjson now "$now" --argjson run_bound "$TIMEOUT_SECONDS" '
    def hex32: type == "string" and test("^[0-9a-f]{64}$") and . != ("0" * 64);
    def oid: type == "object" and
      ((.algorithm == "sha1" and (.hex | type == "string" and test("^[0-9a-f]{40}$") and . != ("0" * 40))) or
       (.algorithm == "sha256" and (.hex | hex32)));
    .version == "qualification_v1" and
    ([.. | strings | select(contains("@"))] | length) == 0 and
    .permit.host.integrated_candidate_sha == {"algorithm":"sha1","hex":$candidate} and
    (.permit.authorized_by | hex32) and (.permit.host.integrated_candidate_sha | oid) and
    (.permit.host.broker_build_identity | hex32) and (.permit.host.host_profile_digest | hex32) and (.permit.host.suite_identity | hex32) and
    (.permit.fixture_job.request_digest | hex32) and (.permit.fixture_job.manifest_digest | hex32) and
    (.permit.fixture_job.isolation_profile_digest | hex32) and (.permit.fixture_job.source_oid | oid) and
    (.permit.fixture_job.base_oid | oid) and (.permit.fixture_job.test_identity | hex32) and
    (.permit.fixture_identity | hex32) and (.permit.fixture_signer | hex32) and (.permit.nonce | hex32) and
    (.permit.not_before | type) == "number" and (.permit.expires_at | type) == "number" and
    .permit.not_before < .permit.expires_at and
    (if $case_name == "expired" then .permit.expires_at <= $now
     elif $case_name == "rate_limit" then $now < .permit.not_before and .permit.expires_at > ($now + $run_bound)
     else .permit.not_before <= $now and .permit.expires_at > ($now + $run_bound) end) and
    (if $test_id == "TM-06" and $case_name == "teardown_failure" or $test_id == "TM-14" and $case_name == "teardown_failure"
     then .directive == "teardown_failure" else has("directive") | not end) and
    (if $case_name == "unaccepted" then .admission.trust_class == "unaccepted" else .admission.trust_class == "qualification_fixture" end) and
    (if $case_name == "external_fork" then
       .permit.host == .admission.host and
       (.permit.fixture_job | del(.source_oid)) == (.admission.fixture_job | del(.source_oid)) and
       .permit.fixture_job.source_oid != .admission.fixture_job.source_oid and
       .permit.fixture_identity == .admission.fixture_identity and .permit.fixture_signer == .admission.signer and .permit.nonce == .admission.nonce
     elif $case_name == "unauthorized_signer" then
       .permit.host == .admission.host and .permit.fixture_job == .admission.fixture_job and
       .permit.fixture_identity == .admission.fixture_identity and .permit.fixture_signer != .admission.signer and .permit.nonce == .admission.nonce
     else .permit.host == .admission.host and .permit.fixture_job == .admission.fixture_job and
       .permit.fixture_identity == .admission.fixture_identity and .permit.fixture_signer == .admission.signer and .permit.nonce == .admission.nonce
     end)
  ' "$case_file" >/dev/null 2>&1 || return 3

  if [[ -n $binding_output ]]; then
    case_sha256=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" sha256sum -- "$case_file" 2>/dev/null | timeout 10 awk '{print $1}') || return 3
    [[ $case_sha256 =~ ^[0-9a-f]{64}$ ]] || return 3
    if ! timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" jq -c --arg case_sha256 "$case_sha256" '
      {
        schema: "buzz-ci-qualification-binding-v1",
        case_sha256: $case_sha256,
        integrated_candidate: {
          algorithm: .permit.host.integrated_candidate_sha.algorithm,
          bytes: .permit.host.integrated_candidate_sha.hex
        },
        broker_build_identity: .permit.host.broker_build_identity,
        host_profile_digest: .permit.host.host_profile_digest,
        suite_identity: .permit.host.suite_identity,
        fixture_signer: .permit.fixture_signer,
        request_digest: .permit.fixture_job.request_digest,
        manifest_digest: .permit.fixture_job.manifest_digest,
        isolation_profile_digest: .permit.fixture_job.isolation_profile_digest,
        source: {algorithm: .permit.fixture_job.source_oid.algorithm, bytes: .permit.fixture_job.source_oid.hex},
        base: {algorithm: .permit.fixture_job.base_oid.algorithm, bytes: .permit.fixture_job.base_oid.hex},
        job_identity: .permit.fixture_job.test_identity,
        fixture_identity: .permit.fixture_identity,
        nonce: .permit.nonce,
        not_before: .permit.not_before,
        expires_at: .permit.expires_at
      }
    ' "$case_file" >"$binding_output"; then
      rm -f -- "$binding_output"
      return 3
    fi
  fi

  set +e
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cat -- "$case_file" 2>>"$error" \
    | timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" -u buzzci-ctl "$ACCEPTANCE_CTL" >"$output" 2>>"$error"
  local pipe_status=("${PIPESTATUS[@]}")
  set -e
  ((pipe_status[0] == 0)) || return 3
  if ((pipe_status[1] == 3)) && {
    acceptance_error_is broker_unavailable "$output" "$error" \
      || acceptance_error_is transport_failure "$output" "$error" \
      || acceptance_error_is invalid_broker_response "$output" "$error" \
      || acceptance_error_is not_provisioned "$output" "$error" \
      || acceptance_error_is reconciling "$output" "$error" \
      || acceptance_error_is storage_unavailable "$output" "$error"
  }; then
    return 3
  fi
  # A policy/capacity/replay response is a real server verdict, not an
  # unavailable harness. Normalize its transport exit so callers can inspect
  # the stable error without confusing it with not_runnable.
  if ((pipe_status[1] == 3)); then return 1; fi
  return "${pipe_status[1]}"
}

# Bind a successful authenticated controller response to the public case fields.
# The result is the exact receipt identity expected by the live evidence checks.
acceptance_bind_response() {
  local binding_file=$1 response_file=$2 expected_file=$3
  timeout "$TIMEOUT_SECONDS" jq -e -s '
    .[0] as $binding | .[1] as $response |
    $binding.schema == "buzz-ci-qualification-binding-v1" and
    $response.type == "qualification_result" and $response.code == "ok" and
    ($response.attempt_id | type == "string" and test("^[0-9a-f]{32}$") and . != ("0" * 32)) and
    ($response.generation | type == "number" and . > 0 and floor == .) and
    ($response.lease_generation | type == "number" and . > 0 and floor == .) and
    $response.generation == $response.lease_generation and
    ($response.updated_at | type == "number" and . > 0 and floor == .) and
    $response.attempt_id == ($binding.fixture_identity[0:32])
  ' "$binding_file" "$response_file" >/dev/null 2>&1 || return 1
  timeout "$TIMEOUT_SECONDS" jq -c -s '
    .[0] + {
      lease_id: .[1].attempt_id,
      lease_generation: .[1].lease_generation,
      controller_generation: .[1].generation,
      controller_updated_at: .[1].updated_at
    }
  ' "$binding_file" "$response_file" >"$expected_file"
}

# Copy one exact root-owned durable receipt without accepting links or loose modes.
acceptance_copy_receipt() {
  local source=$1 destination=$2 stat_line owner group mode kind size
  stat_line=$(timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" stat -c '%U|%G|%a|%F|%s' -- "$source" 2>/dev/null) || return 3
  IFS='|' read -r owner group mode kind size <<<"$stat_line"
  [[ $owner == root && $group == root && $mode == 600 && $kind == 'regular file' \
    && $size =~ ^[1-9][0-9]*$ && $size -le 65536 ]] || return 3
  timeout "$TIMEOUT_SECONDS" "${SUDO[@]}" cp -- "$source" "$destination" 2>/dev/null || return 3
}

# Compare every public authority, job, and lease coordinate. Extra receipt fields
# remain available to the caller for its evidence-specific checks.
acceptance_receipt_binding_matches() {
  local expected_file=$1 receipt_file=$2
  timeout "$TIMEOUT_SECONDS" jq -e -s '
    .[0] as $expected | .[1].binding as $actual |
    ($actual | {
      integrated_candidate,
      broker_build_identity,
      host_profile_digest,
      suite_identity,
      fixture_signer,
      request_digest,
      manifest_digest,
      isolation_profile_digest,
      source,
      base,
      job_identity,
      fixture_identity,
      nonce,
      lease_id,
      lease_generation
    }) == ($expected | {
      integrated_candidate,
      broker_build_identity,
      host_profile_digest,
      suite_identity,
      fixture_signer,
      request_digest,
      manifest_digest,
      isolation_profile_digest,
      source,
      base,
      job_identity,
      fixture_identity,
      nonce,
      lease_id,
      lease_generation
    })
  ' "$expected_file" "$receipt_file" >/dev/null 2>&1
}

acceptance_error_is() {
  local expected=$1 output=$2 error=$3
  timeout 10 jq -e --arg expected "$expected" '.error == $expected or .code == $expected' "$output" >/dev/null 2>&1 \
    || timeout 10 jq -e --arg expected "$expected" '.error == $expected or .code == $expected' "$error" >/dev/null 2>&1
}
