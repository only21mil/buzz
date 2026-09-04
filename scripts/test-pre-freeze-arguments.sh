#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
subject="$repo_root/scripts/pre-freeze.sh"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

fixture="$tmp/repo"
runtime="$tmp/runtime"
mkdir -p "$fixture/scripts" "$fixture/bin" "$runtime"
cp "$subject" "$fixture/scripts/pre-freeze.sh"

cat > "$fixture/bin/cargo" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == "fmt --all -- --check" ]]; then
    exit "${FAKE_CARGO_FMT_STATUS:-0}"
fi
printf 'unexpected cargo invocation: %s\n' "$*" >&2
exit 99
SH
chmod 700 "$fixture/scripts/pre-freeze.sh" "$fixture/bin/cargo"

git -C "$fixture" init -q
git -C "$fixture" config user.name test
git -C "$fixture" config user.email test@example.com
git -C "$fixture" add scripts/pre-freeze.sh bin/cargo
git -C "$fixture" commit -qm fixture
fixture_head=$(git -C "$fixture" rev-parse HEAD)
git -C "$fixture" update-ref refs/remotes/buzz/main "$fixture_head"

receipt="$fixture/pre-freeze-receipt.json"
output="$tmp/output"
error="$tmp/error"
status=0

run_subject() {
    rm -f -- "$receipt" "$output" "$error"
    if (
        cd "$fixture"
        TMPDIR="$runtime" scripts/pre-freeze.sh "$@"
    ) >"$output" 2>"$error"; then
        status=0
    else
        status=$?
    fi
}

assert_no_receipt_or_runtime_files() {
    [[ ! -e "$receipt" ]] || {
        printf '%s\n' 'argument-only invocation wrote a receipt' >&2
        exit 1
    }
    if find "$runtime" -mindepth 1 -print -quit | grep -q .; then
        printf '%s\n' 'argument-only invocation created gate runtime files' >&2
        exit 1
    fi
}

run_subject --help
[[ "$status" -eq 0 ]]
grep -Fq 'Usage: scripts/pre-freeze.sh' "$output"
assert_no_receipt_or_runtime_files

run_subject -h
[[ "$status" -eq 0 ]]
grep -Fq 'Usage: scripts/pre-freeze.sh' "$output"
assert_no_receipt_or_runtime_files

run_subject --unknown
[[ "$status" -eq 2 ]]
grep -Fq 'unknown argument: --unknown' "$error"
grep -Fq 'Usage: scripts/pre-freeze.sh' "$error"
assert_no_receipt_or_runtime_files

run_subject --base
[[ "$status" -eq 2 ]]
grep -Fq -- '--base requires a ref' "$error"
assert_no_receipt_or_runtime_files

run_subject --base --full
[[ "$status" -eq 2 ]]
grep -Fq -- '--base requires a ref' "$error"
assert_no_receipt_or_runtime_files

run_subject --base ''
[[ "$status" -eq 2 ]]
grep -Fq -- '--base requires a ref' "$error"
assert_no_receipt_or_runtime_files

rm -f -- "$receipt" "$output" "$error"
if (
    cd "$fixture"
    TMPDIR="$runtime" FAKE_CARGO_FMT_STATUS=9 scripts/pre-freeze.sh
) >"$output" 2>"$error"; then
    status=0
else
    status=$?
fi
[[ "$status" -eq 1 ]]
[[ -f "$receipt" ]]
python3 - "$receipt" "$fixture_head" <<'PY'
import json
import sys

path, expected_head = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    receipt = json.load(stream)
expected = {
    "source": "pre-freeze",
    "head_sha": expected_head,
    "base_sha": expected_head,
    "overall": "FAIL",
}
for field, value in expected.items():
    if receipt.get(field) != value:
        raise SystemExit(f"unexpected {field}: {receipt.get(field)!r}")
checks = {check["name"]: check for check in receipt["checks"]}
if checks.get("clean-tree", {}).get("status") != "PASS":
    raise SystemExit("clean-tree result missing or invalid")
if checks.get("rust-format", {}).get("status") != "FAIL":
    raise SystemExit("rust-format failure missing from receipt")
if checks["rust-format"].get("exit_code") != 9:
    raise SystemExit("rust-format exit code was not preserved")
PY

if find "$runtime" -mindepth 1 -print -quit | grep -q .; then
    printf '%s\n' 'final gate left runtime files behind' >&2
    exit 1
fi
