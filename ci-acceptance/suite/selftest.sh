#!/usr/bin/env bash
set -euo pipefail

SUITE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "$SUITE_DIR/.." && pwd -P)"
SHA=1111111111111111111111111111111111111111
PASS_DIR="$SUITE_DIR/fixtures/security-pass"
PROBE_BIN="$ROOT/fixtures/mock-buzz"
failed=0
temp_dir=$(mktemp -d "$SUITE_DIR/.selftest.XXXXXX")
cleanup() {
  rm -rf -- "$temp_dir"
}
trap cleanup EXIT

mapfile -t scripts < <(find "$SUITE_DIR" -type f -name '*.sh' -print | sort)
printf 'syntax: checking %d suite shell scripts\n' "${#scripts[@]}"
for script in "${scripts[@]}"; do
  if bash -n "$script"; then
    printf 'syntax: ok %s\n' "${script#"$ROOT/"}"
  else
    printf 'syntax: FAIL %s\n' "${script#"$ROOT/"}"
    failed=1
  fi
done

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck_log="$temp_dir/shellcheck.log"
  set +e
  shellcheck -S warning "${scripts[@]}" >"$shellcheck_log" 2>&1
  shellcheck_rc=$?
  set -e
  if ((shellcheck_rc == 0)); then
    printf 'shellcheck: pass\n'
  else
    printf 'shellcheck: FAIL (exit %d)\n' "$shellcheck_rc"
    tail -n 20 "$shellcheck_log"
    failed=1
  fi
else
  printf 'shellcheck: absent (not a failure)\n'
fi

run_suite_case() {
  local name=$1
  shift
  local output="$temp_dir/$name.out"
  local error="$temp_dir/$name.err"
  local evidence="$temp_dir/$name-evidence"
  local rc
  set +e
  SUITE_SECURITY_DIR="$PASS_DIR" \
    "$SUITE_DIR/run_suite.sh" \
      --candidate "$SHA" --candidate-dir "$ROOT" --evidence-root "$evidence" \
      --probe-bin "$PROBE_BIN" --selftest-mock "$@" >"$output" 2>"$error"
  rc=$?
  set -e
  RUN_CASE_RC=$rc
  RUN_CASE_OUTPUT=$output
  RUN_CASE_ERROR=$error
  RUN_CASE_EVIDENCE=$evidence
}

plan_output="$temp_dir/plan.out"
plan_error="$temp_dir/plan.err"
set +e
SUITE_SECURITY_DIR="$PASS_DIR" "$SUITE_DIR/run_suite.sh" \
  --plan --candidate "$SHA" --candidate-dir "$ROOT" --evidence-root "$temp_dir/plan-evidence" \
  --probe-bin "$PROBE_BIN" --selftest-mock >"$plan_output" 2>"$plan_error"
plan_rc=$?
set -e
if ((plan_rc == 0)) \
  && jq -e '(.mode == "plan") and ((.security.tests | length) == 17) and ((.probes.probes | length) == 6)' \
  "$plan_output" >/dev/null 2>&1; then
  printf 'plan: pass\n'
else
  printf 'plan: FAIL (exit %d)\n' "$plan_rc"
  tail -n 20 "$plan_error"
  failed=1
fi

run_suite_case full
if ((RUN_CASE_RC == 0)) \
  && jq -e '.green == true and .security.passed == 17 and .probes.passed_runs == 12' \
    "$RUN_CASE_OUTPUT" >/dev/null 2>&1 \
  && jq -e -s 'length == 17 and all(.[]; .executor == "selftest-mock")' \
    "$RUN_CASE_EVIDENCE/$SHA/security.jsonl" >/dev/null 2>&1 \
  && jq -e -s 'length == 12 and all(.[]; .executor == "selftest-mock")' \
    "$RUN_CASE_EVIDENCE/$SHA/probe.jsonl" >/dev/null 2>&1; then
  printf 'full mock suite: pass\n'
else
  printf 'full mock suite: FAIL (exit %d)\n' "$RUN_CASE_RC"
  tail -n 20 "$RUN_CASE_ERROR"
  cat "$RUN_CASE_OUTPUT"
  failed=1
fi

for case_name in not_runnable fail garbage candidate_mismatch; do
  case_output="$temp_dir/$case_name.out"
  case_error="$temp_dir/$case_name.err"
  case_evidence="$temp_dir/$case_name-evidence"
  set +e
  SUITE_SECURITY_DIR="$PASS_DIR" SUITE_FIXTURE_CASE="$case_name" SUITE_FIXTURE_BAD_ID=TM-05 \
    "$SUITE_DIR/run_suite.sh" \
      --candidate "$SHA" --candidate-dir "$ROOT" --evidence-root "$case_evidence" \
      --probe-bin "$PROBE_BIN" --selftest-mock >"$case_output" 2>"$case_error"
  case_rc=$?
  set -e
  if ((case_rc == 1)) && jq -e '.green == false' "$case_output" >/dev/null 2>&1; then
    printf 'negative %s: pass\n' "$case_name"
  else
    printf 'negative %s: FAIL (exit %d)\n' "$case_name" "$case_rc"
    tail -n 20 "$case_error"
    cat "$case_output"
    failed=1
  fi
done

missing_dir="$temp_dir/security-missing"
mkdir -p -- "$missing_dir"
cp -a -- "$PASS_DIR/." "$missing_dir/"
rm -f -- "$missing_dir/tm-09_fixture.sh"
set +e
SUITE_SECURITY_DIR="$missing_dir" "$SUITE_DIR/run_suite.sh" \
  --candidate "$SHA" --candidate-dir "$ROOT" --evidence-root "$temp_dir/missing-evidence" \
  --probe-bin "$PROBE_BIN" --selftest-mock >"$temp_dir/missing.out" 2>"$temp_dir/missing.err"
missing_rc=$?
set -e
if ((missing_rc == 1)) && jq -e '.green == false and (.failed | index("TM-09") != null)' \
  "$temp_dir/missing.out" >/dev/null 2>&1; then
  printf 'negative missing runner: pass\n'
else
  printf 'negative missing runner: FAIL (exit %d)\n' "$missing_rc"
  tail -n 20 "$temp_dir/missing.err"
  cat "$temp_dir/missing.out"
  failed=1
fi

set +e
"$SUITE_DIR/probes_bridge.sh" \
  --candidate "$SHA" --candidate-dir "$ROOT" --evidence-dir "$temp_dir/guard-evidence" \
  --probe-bin "$PROBE_BIN" >"$temp_dir/guard.out" 2>"$temp_dir/guard.err"
guard_rc=$?
set -e
if ((guard_rc == 2)) && grep -q 'refusing probe mock' "$temp_dir/guard.err"; then
  printf 'probe mock guard: pass\n'
else
  printf 'probe mock guard: FAIL (exit %d)\n' "$guard_rc"
  cat "$temp_dir/guard.err"
  failed=1
fi

if ((failed == 0)); then
  printf 'suite selftest: GREEN\n'
  exit 0
fi
printf 'suite selftest: RED\n'
exit 1
