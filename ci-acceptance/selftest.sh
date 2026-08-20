#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SHA=1111111111111111111111111111111111111111
failed=0
temp_dir="$(mktemp -d "$ROOT/.selftest.XXXXXX")"
cleanup() {
  rm -rf -- "$temp_dir"
}
trap cleanup EXIT

mapfile -t scripts < <(find "$ROOT" -type f \( -name '*.sh' -o -name 'mock-buzz*' \) -print | sort)
printf 'syntax: checking %d shell scripts\n' "${#scripts[@]}"
for script in "${scripts[@]}"; do
  if bash -n "$script"; then
    printf 'syntax: ok %s\n' "${script#"$ROOT"/}"
  else
    printf 'syntax: FAIL %s\n' "${script#"$ROOT"/}"
    failed=1
  fi
done

if command -v shellcheck >/dev/null 2>&1; then
  printf 'shellcheck: %s\n' "$(shellcheck --version | head -n 1)"
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

mock_summary="$temp_dir/mock-summary.json"
mock_stderr="$temp_dir/mock-stderr.log"
set +e
BUZZ_CI_BIN="$ROOT/fixtures/mock-buzz" BUZZ_CI_SHA="$SHA" BUZZ_CI_RESULTS_FILE="$temp_dir/mock-results.jsonl" BUZZ_CI_SUMMARY_FILE="$mock_summary" "$ROOT/probes/run_probes.sh" >"$mock_summary" 2>"$mock_stderr"
mock_rc=$?
set -e
if ((mock_rc == 0)) && jq -e '.all_pass == true' "$mock_summary" >/dev/null 2>&1; then
  printf 'mock suite: pass (all probes passed twice)\n'
else
  printf 'mock suite: FAIL (exit %d)\n' "$mock_rc"
  tail -n 20 "$mock_stderr"
  cat "$mock_summary"
  failed=1
fi

broken_summary="$temp_dir/broken-summary.json"
broken_stderr="$temp_dir/broken-stderr.log"
set +e
BUZZ_CI_BIN="$ROOT/fixtures/mock-buzz-broken" BUZZ_CI_SHA="$SHA" BUZZ_CI_RESULTS_FILE="$temp_dir/broken-results.jsonl" BUZZ_CI_SUMMARY_FILE="$broken_summary" "$ROOT/probes/run_probes.sh" >"$broken_summary" 2>"$broken_stderr"
broken_rc=$?
set -e
if ((broken_rc != 0)) && jq -e '.all_pass == false' "$broken_summary" >/dev/null 2>&1; then
  printf 'negative suite: pass (broken mock was rejected)\n'
else
  printf 'negative suite: FAIL (exit %d)\n' "$broken_rc"
  tail -n 20 "$broken_stderr"
  cat "$broken_summary"
  failed=1
fi

suite_output="$temp_dir/suite-output.log"
suite_error="$temp_dir/suite-error.log"
set +e
"$ROOT/suite/selftest.sh" >"$suite_output" 2>"$suite_error"
suite_rc=$?
set -e
if ((suite_rc == 0)) && grep -q 'suite selftest: GREEN' "$suite_output"; then
  printf 'suite orchestrator: pass\n'
else
  printf 'suite orchestrator: FAIL (exit %d)\n' "$suite_rc"
  tail -n 20 "$suite_error"
  tail -n 20 "$suite_output"
  failed=1
fi

if ((failed == 0)); then
  printf 'selftest: GREEN\n'
  exit 0
fi
printf 'selftest: RED\n'
exit 1
