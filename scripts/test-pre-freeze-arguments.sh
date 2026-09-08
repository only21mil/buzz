#!/usr/bin/env bash
# Hermetic harness for scripts/pre-freeze.sh: argument handling and the
# retained-evidence receipt contract (issue #142). It runs the real script in a
# throwaway repository with a fake cargo, so no workspace gate executes.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
subject="$repo_root/scripts/pre-freeze.sh"
evidence_tool="$repo_root/scripts/protected-ci-receipt.py"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp" "${shm_root:-}"' EXIT
shm_root=""

fixture="$tmp/repo"
runtime="$tmp/runtime"
evidence="$tmp/evidence"
mkdir -p "$fixture/scripts" "$fixture/bin" "$runtime"
mkdir -m 700 "$evidence"
cp "$subject" "$fixture/scripts/pre-freeze.sh"
cp "$evidence_tool" "$fixture/scripts/protected-ci-receipt.py"

cat > "$fixture/bin/cargo" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == "fmt --all -- --check" ]]; then
    exit "${FAKE_CARGO_FMT_STATUS:-0}"
fi
printf 'unexpected cargo invocation: %s\n' "$*" >&2
exit 99
SH
chmod 700 "$fixture/scripts/pre-freeze.sh" "$fixture/scripts/protected-ci-receipt.py" "$fixture/bin/cargo"

git -C "$fixture" init -q
git -C "$fixture" config user.name test
git -C "$fixture" config user.email test@example.com
git -C "$fixture" add scripts/pre-freeze.sh scripts/protected-ci-receipt.py bin/cargo
git -C "$fixture" commit -qm fixture
fixture_head=$(git -C "$fixture" rev-parse HEAD)
git -C "$fixture" update-ref refs/remotes/buzz/main "$fixture_head"

output="$tmp/output"
error="$tmp/error"
status=0

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

# run_subject [--no-root] <arguments...>: run the fixture script with the
# evidence root exported unless --no-root is given.
run_subject() {
    local -a environment=(TMPDIR="$runtime" BUZZ_EVIDENCE_ROOT="$evidence")
    if [[ "${1-}" == --no-root ]]; then
        environment=(TMPDIR="$runtime")
        shift
    fi
    rm -f -- "$output" "$error"
    if (
        cd "$fixture"
        env -u BUZZ_EVIDENCE_ROOT "${environment[@]}" scripts/pre-freeze.sh "$@"
    ) >"$output" 2>"$error"; then
        status=0
    else
        status=$?
    fi
}

receipts_in_evidence() {
    find "$evidence" -mindepth 1 -maxdepth 1 -name 'pre-freeze-receipt-*.json' -type f
}

assert_no_receipt_or_runtime_files() {
    if [[ -n "$(receipts_in_evidence)" ]]; then
        fail 'argument-only invocation wrote a receipt'
    fi
    if find "$runtime" -mindepth 1 -print -quit | grep -q .; then
        fail 'argument-only invocation created gate runtime files'
    fi
}

assert_checkout_untouched() {
    local porcelain
    porcelain=$(git -C "$fixture" status --porcelain --untracked-files=all)
    [[ -z "$porcelain" ]] || fail "gate wrote inside the checkout: $porcelain"
}

assert_evidence_root_clean() {
    # Only published receipts may remain: no temporary files, no stray names.
    local stray
    stray=$(find "$evidence" -mindepth 1 ! -name 'pre-freeze-receipt-*.json' \
        ! -name 'fixed.json' ! -name 'clean-tree.json')
    [[ -z "$stray" ]] || fail "evidence root holds unexpected entries: $stray"
}

# assert_fail_receipt <path>: the receipt records the fake rust-format failure.
assert_fail_receipt() {
    local receipt=$1
    [[ -f "$receipt" && ! -L "$receipt" ]] || fail "receipt is missing: $receipt"
    [[ "$(stat -c %a "$receipt")" == 600 ]] || fail "receipt is not mode 0600: $receipt"
    [[ "$(stat -c %h "$receipt")" == 1 ]] || fail "receipt has extra links: $receipt"
    python3 - "$receipt" "$fixture_head" <<'PY'
import json
import sys

path, expected_head = sys.argv[1:]
with open(path, "rb") as stream:
    raw = stream.read()
receipt = json.loads(raw)
canonical = (json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
if raw != canonical:
    raise SystemExit("receipt is not canonical JSON plus LF")
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
}

# --- argument handling: no receipt, no runtime files, no evidence root needed ---

run_subject --no-root --help
[[ "$status" -eq 0 ]] || fail '--help exit status'
grep -Fq 'Usage: scripts/pre-freeze.sh' "$output"
grep -Fq -- '--receipt <path>' "$output"
grep -Fq 'BUZZ_EVIDENCE_ROOT' "$output"
assert_no_receipt_or_runtime_files

run_subject --no-root -h
[[ "$status" -eq 0 ]] || fail '-h exit status'
grep -Fq 'Usage: scripts/pre-freeze.sh' "$output"
assert_no_receipt_or_runtime_files

run_subject --no-root --unknown
[[ "$status" -eq 2 ]] || fail '--unknown exit status'
grep -Fq 'unknown argument: --unknown' "$error"
grep -Fq 'Usage: scripts/pre-freeze.sh' "$error"
assert_no_receipt_or_runtime_files

run_subject --no-root --base
[[ "$status" -eq 2 ]] || fail '--base exit status'
grep -Fq -- '--base requires a ref' "$error"
assert_no_receipt_or_runtime_files

run_subject --no-root --base --full
[[ "$status" -eq 2 ]] || fail '--base --full exit status'
grep -Fq -- '--base requires a ref' "$error"
assert_no_receipt_or_runtime_files

run_subject --no-root --base ''
[[ "$status" -eq 2 ]] || fail "--base '' exit status"
grep -Fq -- '--base requires a ref' "$error"
assert_no_receipt_or_runtime_files

run_subject --no-root --receipt
[[ "$status" -eq 2 ]] || fail '--receipt exit status'
grep -Fq -- '--receipt requires a path' "$error"
assert_no_receipt_or_runtime_files

# --- evidence root contract: refused before any gate runs ---

run_subject --no-root
[[ "$status" -eq 2 ]] || fail 'missing BUZZ_EVIDENCE_ROOT exit status'
grep -Fq 'BUZZ_EVIDENCE_ROOT must name the absolute retained-evidence directory' "$error"
assert_no_receipt_or_runtime_files
assert_checkout_untouched

run_subject --receipt "$fixture/pre-freeze-receipt.json"
[[ "$status" -eq 2 ]] || fail 'in-checkout --receipt exit status'
grep -Fq 'evidence root must be outside the checkout' "$error"
[[ ! -e "$fixture/pre-freeze-receipt.json" ]] || fail 'in-checkout receipt was written'
assert_no_receipt_or_runtime_files
assert_checkout_untouched

run_subject --receipt relative/receipt.json
[[ "$status" -eq 2 ]] || fail 'relative --receipt exit status'
grep -Fq -- '--receipt must be an absolute path' "$error"
assert_no_receipt_or_runtime_files

mkdir "$tmp/shared"
chmod 755 "$tmp/shared"
run_subject --receipt "$tmp/shared/receipt.json"
[[ "$status" -eq 2 ]] || fail 'shared-parent --receipt exit status'
grep -Fq 'evidence root must be a caller-owned mode-0700 directory' "$error"
[[ ! -e "$tmp/shared/receipt.json" ]] || fail 'receipt was written under a shared parent'
assert_no_receipt_or_runtime_files

chmod 755 "$evidence"
run_subject
[[ "$status" -eq 2 ]] || fail 'mode-0755 BUZZ_EVIDENCE_ROOT exit status'
grep -Fq 'evidence root must be a caller-owned mode-0700 directory' "$error"
chmod 700 "$evidence"
assert_no_receipt_or_runtime_files

ln -s "$evidence" "$tmp/evidence-link"
BUZZ_EVIDENCE_ROOT_LINK="$tmp/evidence-link"
rm -f -- "$output" "$error"
if (cd "$fixture" && TMPDIR="$runtime" BUZZ_EVIDENCE_ROOT="$BUZZ_EVIDENCE_ROOT_LINK" scripts/pre-freeze.sh) >"$output" 2>"$error"; then
    fail 'symlinked BUZZ_EVIDENCE_ROOT was accepted'
fi
grep -Fq 'evidence root must not be a symlink' "$error"
assert_no_receipt_or_runtime_files

# --- a real gate run: FAIL receipt published under the evidence root ---

rm -f -- "$output" "$error"
if (
    cd "$fixture"
    TMPDIR="$runtime" BUZZ_EVIDENCE_ROOT="$evidence" FAKE_CARGO_FMT_STATUS=9 scripts/pre-freeze.sh
) >"$output" 2>"$error"; then
    status=0
else
    status=$?
fi
[[ "$status" -eq 1 ]] || fail "gate run exit status $status: $(cat "$error")"
receipt=$(receipts_in_evidence)
[[ -n "$receipt" && "$(printf '%s\n' "$receipt" | wc -l)" -eq 1 ]] || fail 'expected exactly one receipt'
grep -Fq "Receipt: $receipt (FAIL)" "$output"
assert_fail_receipt "$receipt"
assert_checkout_untouched
assert_evidence_root_clean
if find "$runtime" -mindepth 1 -print -quit | grep -q .; then
    fail 'final gate left runtime files behind'
fi

# --- clean-tree gate: a receipt-named file inside the checkout is dirty ---

# The default name carries a one-second UTC stamp, so this run names its
# receipt explicitly instead of racing the previous run's stamp.
printf '{}\n' > "$fixture/pre-freeze-receipt.json"
run_subject --receipt "$evidence/clean-tree.json"
[[ "$status" -eq 1 ]] || fail 'stray receipt clean-tree exit status'
grep -Fq 'dirty: ?? pre-freeze-receipt.json' "$error"
grep -Fq 'worktree must have clean porcelain (except generated build output)' "$error"
rm -f -- "$fixture/pre-freeze-receipt.json"
python3 - "$evidence/clean-tree.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    receipt = json.load(stream)
checks = {check["name"]: check for check in receipt["checks"]}
if receipt.get("overall") != "FAIL" or checks.get("clean-tree", {}).get("status") != "FAIL":
    raise SystemExit("clean-tree failure was not recorded")
PY

# --- explicit --receipt is create-only ---

fixed="$evidence/fixed.json"
run_subject --receipt "$fixed"
[[ "$status" -eq 1 ]] || fail 'explicit --receipt gate exit status'
[[ -f "$fixed" ]] || fail 'explicit --receipt was not written'
[[ "$(stat -c %a "$fixed")" == 600 ]] || fail 'explicit receipt is not mode 0600'
fixed_sha=$(sha256sum "$fixed" | cut -d' ' -f1)
run_subject --receipt "$fixed"
[[ "$status" -eq 2 ]] || fail 'second --receipt run was not refused'
grep -Fq "receipt already exists: $fixed" "$error"
[[ "$(sha256sum "$fixed" | cut -d' ' -f1)" == "$fixed_sha" ]] || fail 'existing receipt was replaced'
assert_evidence_root_clean

# --- EXDEV: TMPDIR on another filesystem than the evidence root ---

if [[ -d /dev/shm && -w /dev/shm ]] && [[ "$(stat -c %d /dev/shm)" != "$(stat -c %d "$tmp")" ]]; then
    shm_root=$(mktemp -d /dev/shm/buzz-pre-freeze-evidence.XXXXXX)
    chmod 700 "$shm_root"
    rm -f -- "$output" "$error"
    if (
        cd "$fixture"
        TMPDIR="$runtime" BUZZ_EVIDENCE_ROOT="$shm_root" FAKE_CARGO_FMT_STATUS=9 scripts/pre-freeze.sh
    ) >"$output" 2>"$error"; then
        status=0
    else
        status=$?
    fi
    [[ "$status" -eq 1 ]] || fail "cross-filesystem gate run exit status $status: $(cat "$error")"
    shm_receipt=$(find "$shm_root" -mindepth 1 -maxdepth 1 -name 'pre-freeze-receipt-*.json' -type f)
    [[ -n "$shm_receipt" ]] || fail 'cross-filesystem receipt was not written'
    assert_fail_receipt "$shm_receipt"
    [[ -z "$(find "$shm_root" -mindepth 1 ! -name 'pre-freeze-receipt-*.json')" ]] || \
        fail 'cross-filesystem run left temporary files in the evidence root'
    if find "$runtime" -mindepth 1 -print -quit | grep -q .; then
        fail 'cross-filesystem run left runtime files behind'
    fi
else
    printf '%s\n' 'note: /dev/shm shares a filesystem with the fixture; EXDEV placement not exercised'
fi

printf '%s\n' 'PASS: pre-freeze argument and receipt contract'
