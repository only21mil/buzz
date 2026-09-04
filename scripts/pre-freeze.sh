#!/usr/bin/env bash

# Run the local gates that must be green before a Buzz candidate is frozen.
# The command list intentionally follows .github/workflows/ci.yml and Justfile.

set -u -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
RECEIPT_PATH="$REPO_ROOT/pre-freeze-receipt.json"
RECORDS_FILE=""
DIFF_PATHS_FILE=""

HEAD_SHA=""
BASE_SHA=""
BASE_INPUT=""
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OVERALL_FAILED=0
FULL_CLIPPY=0
RUN_TESTS=0

declare -a TOUCHED_PATHS=()
declare -a CRATE_PACKAGES=()

cleanup() {
    rm -f -- "$RECORDS_FILE"
    if [[ -n "$DIFF_PATHS_FILE" ]]; then
        rm -f -- "$DIFF_PATHS_FILE"
    fi
}

join_command() {
    local rendered=""
    local argument
    for argument in "$@"; do
        printf -v argument '%q' "$argument"
        rendered+="${rendered:+ }$argument"
    done
    printf '%s' "$rendered"
}

record_result() {
    local name="$1"
    local command="$2"
    local exit_code="$3"
    local duration_ms="$4"
    printf '%s\t%s\t%s\t%s\n' "$name" "$command" "$exit_code" "$duration_ms" >> "$RECORDS_FILE"
}

record_skip() {
    record_result "$1" "$2" 0 0
}

now_ms() {
    local now
    now="$(date +%s%N)"
    printf '%s' "$((now / 1000000))"
}

run_check() {
    local name="$1"
    local command="$2"
    shift 2
    local started
    local finished
    local duration_ms
    local exit_code

    printf '\n==> %s\n%s\n' "$name" "$command"
    started="$(now_ms)"
    "$@"
    exit_code=$?
    finished="$(now_ms)"
    duration_ms=$((finished - started))
    record_result "$name" "$command" "$exit_code" "$duration_ms"
    if ((exit_code != 0)); then
        OVERALL_FAILED=1
        printf 'FAIL: %s (exit %s, %sms)\n' "$name" "$exit_code" "$duration_ms" >&2
        return 1
    fi
    printf 'PASS: %s (%sms)\n' "$name" "$duration_ms"
    return 0
}

write_receipt() {
    local process_status="$1"
    local overall="FAIL"
    local receipt_tmp

    if ((process_status == 0 && OVERALL_FAILED == 0)); then
        overall="PASS"
    fi

    receipt_tmp="$(mktemp "${TMPDIR:-/tmp}/buzz-pre-freeze-receipt.XXXXXX")" || return 1
    if ! python3 - "$receipt_tmp" "$RECEIPT_PATH" "$HEAD_SHA" "$BASE_SHA" "$TIMESTAMP" "$RECORDS_FILE" "$overall" <<'PY'
import json
import os
import sys

tmp_path, output_path, head_sha, base_sha, timestamp, records_path, overall = sys.argv[1:]
checks = []
with open(records_path, encoding="utf-8") as records:
    for line in records:
        name, command, exit_code, duration_ms = line.rstrip("\n").split("\t", 3)
        exit_number = int(exit_code)
        checks.append(
            {
                "name": name,
                "command": command,
                "exit_code": exit_number,
                "duration_ms": int(duration_ms),
                "status": "PASS" if exit_number == 0 else "FAIL",
            }
        )

receipt = {
    "schema_version": 1,
    "source": "pre-freeze",
    "repository": "only21mil/buzz",
    "head_sha": head_sha,
    "base_sha": base_sha,
    "timestamp": timestamp,
    "checks": checks,
    "overall": overall,
}
with open(tmp_path, "w", encoding="utf-8") as output:
    json.dump(receipt, output, indent=2, sort_keys=True)
    output.write("\n")
os.replace(tmp_path, output_path)
PY
    then
        rm -f -- "$receipt_tmp"
        return 1
    fi
    rm -f -- "$receipt_tmp"
    printf '\nReceipt: %s (%s)\n' "$RECEIPT_PATH" "$overall"
    return 0
}

finish() {
    local process_status=$?
    if ! write_receipt "$process_status"; then
        process_status=1
    fi
    cleanup
    exit "$process_status"
}

usage() {
    cat <<'USAGE'
Usage: scripts/pre-freeze.sh [--base <ref>] [--full] [--test]

  --base <ref>  Compare against this commit/ref. Defaults to merge-base with
                refs/remotes/buzz/main.
  --full        Run workspace-wide clippy (and workspace-wide tests with --test).
  --test        Run cargo test for the touched workspace crates.
USAGE
}

while (($# > 0)); do
    case "$1" in
        --base)
            if (($# < 2)) || [[ -z "$2" || "$2" == -* ]]; then
                printf '%s\n' '--base requires a ref' >&2
                exit 2
            fi
            BASE_INPUT="$2"
            shift 2
            ;;
        --full)
            FULL_CLIPPY=1
            shift
            ;;
        --test)
            RUN_TESTS=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ! RECORDS_FILE="$(mktemp "${TMPDIR:-/tmp}/buzz-pre-freeze-records.XXXXXX")"; then
    printf '%s\n' 'could not create pre-freeze records file' >&2
    exit 1
fi
trap finish EXIT

cd -- "$REPO_ROOT" || exit 1
export PATH="$REPO_ROOT/bin:$PATH"

resolve_refs() {
    local base_expression
    local resolved

    HEAD_SHA="$(git rev-parse --verify 'HEAD^{commit}')" || return 1
    git rev-parse --verify 'refs/remotes/buzz/main^{commit}' >/dev/null || return 1
    if [[ -n "$BASE_INPUT" ]]; then
        if [[ "$BASE_INPUT" == -* ]]; then
            printf '%s\n' 'base refs may not start with -' >&2
            return 1
        fi
        base_expression="${BASE_INPUT}^{commit}"
        resolved="$(git rev-parse --verify "$base_expression")" || return 1
    else
        resolved="$(git merge-base HEAD refs/remotes/buzz/main)" || return 1
    fi
    BASE_SHA="$resolved"
    return 0
}

if ! resolve_refs; then
    record_result \
        "refs-resolution" \
        "git rev-parse --verify HEAD^{commit}; git rev-parse --verify refs/remotes/buzz/main^{commit}; git merge-base HEAD refs/remotes/buzz/main" \
        1 \
        0
    OVERALL_FAILED=1
    exit 1
fi

is_generated_untracked_path() {
    case "$1" in
        pre-freeze-receipt.json|\
        target|target/*|\
        dist|dist/*|\
        build|build/*|\
        .cache|.cache/*|\
        node_modules|node_modules/*|\
        desktop/node_modules|desktop/node_modules/*|\
        desktop/target|desktop/target/*|\
        desktop/dist|desktop/dist/*|\
        desktop/src-tauri/target|desktop/src-tauri/target/*|\
        web/node_modules|web/node_modules/*|\
        web/dist|web/dist/*|\
        mobile/.dart_tool|mobile/.dart_tool/*|\
        mobile/build|mobile/build/*)
            return 0
            ;;
    esac
    return 1
}

check_clean_tree() {
    local status_file
    local entry
    local path
    local status_code
    local dirty=0

    status_file="$(mktemp "${TMPDIR:-/tmp}/buzz-pre-freeze-status.XXXXXX")" || return 1
    if ! git status --porcelain=v1 --untracked-files=all -z > "$status_file"; then
        rm -f -- "$status_file"
        return 1
    fi
    while IFS= read -r -d '' entry; do
        if [[ "${entry:2:1}" == ' ' ]]; then
            status_code="${entry:0:2}"
            path="${entry:3}"
        else
            status_code=""
            path="$entry"
        fi
        if [[ "$status_code" == '??' ]] && is_generated_untracked_path "$path"; then
            continue
        fi
        printf 'dirty: %s\n' "$entry" >&2
        dirty=1
    done < "$status_file"
    rm -f -- "$status_file"
    if ((dirty != 0)); then
        printf '%s\n' 'worktree must have clean porcelain (except generated build output and pre-freeze-receipt.json)' >&2
        return 1
    fi
    return 0
}

if ! run_check \
    "clean-tree" \
    "git status --porcelain=v1 --untracked-files=all -z (build directories and pre-freeze-receipt.json excepted)" \
    check_clean_tree; then
    exit 1
fi

if ! run_check "rust-format" "cargo fmt --all -- --check" cargo fmt --all -- --check; then
    exit 1
fi

collect_touched_paths() {
    local path
    DIFF_PATHS_FILE="$(mktemp "${TMPDIR:-/tmp}/buzz-pre-freeze-diff.XXXXXX")" || return 1
    if ! git diff --name-only --no-renames -z "$BASE_SHA" "$HEAD_SHA" -- > "$DIFF_PATHS_FILE"; then
        return 1
    fi
    while IFS= read -r -d '' path; do
        TOUCHED_PATHS+=("$path")
    done < "$DIFF_PATHS_FILE"
    return 0
}

crate_package_name() {
    local crate_dir="$1"
    local manifest="$REPO_ROOT/crates/$crate_dir/Cargo.toml"
    if [[ ! -f "$manifest" ]]; then
        return 1
    fi
    awk '
        /^\[package\]$/ { in_package = 1; next }
        /^\[/ { in_package = 0 }
        in_package && $0 ~ /^[[:space:]]*name[[:space:]]*=/ {
            line = $0
            sub(/^[^=]*=[[:space:]]*/, "", line)
            gsub(/["[:space:]]/, "", line)
            print line
            exit
        }
    ' "$manifest"
}

append_crate_package() {
    local package="$1"
    local existing
    for existing in "${CRATE_PACKAGES[@]}"; do
        if [[ "$existing" == "$package" ]]; then
            return 0
        fi
    done
    CRATE_PACKAGES+=("$package")
}

sort_crate_packages() {
    if ((${#CRATE_PACKAGES[@]} > 1)); then
        mapfile -t CRATE_PACKAGES < <(printf '%s\n' "${CRATE_PACKAGES[@]}" | sort -u)
    fi
}

classify_touched_paths() {
    local path
    local crate_dir
    local package
    local needs_workspace=0
    local has_unclassified=0

    for path in "${TOUCHED_PATHS[@]}"; do
        case "$path" in
            crates/*/*)
                crate_dir="${path#crates/}"
                crate_dir="${crate_dir%%/*}"
                package="$(crate_package_name "$crate_dir")" || package=""
                if [[ -n "$package" ]]; then
                    append_crate_package "$package"
                else
                    needs_workspace=1
                fi
                ;;
            Cargo.toml|Cargo.lock|rust-toolchain|rust-toolchain.*|deny.toml|.cargo/*|.github/workflows/ci.yml|Justfile|justfile|migrations/*|schema/*|Dockerfile|examples/*|scripts/run-tests.sh)
                needs_workspace=1
                ;;
        esac
    done

    if ((${#TOUCHED_PATHS[@]} == 0)); then
        has_unclassified=1
    fi

    if ((FULL_CLIPPY != 0 || needs_workspace != 0)); then
        return 2
    fi
    if ((has_unclassified != 0 || ${#CRATE_PACKAGES[@]} == 0)); then
        return 0
    fi
    return 1
}

if ! collect_touched_paths; then
    record_result "touched-paths" "git diff --name-only --no-renames -z $BASE_SHA $HEAD_SHA" 1 0
    OVERALL_FAILED=1
    exit 1
fi

clippy_mode=0
classify_touched_paths
classify_status=$?
if ((classify_status == 2)); then
    clippy_mode=2
elif ((classify_status == 1)); then
    clippy_mode=1
fi
sort_crate_packages

if ((clippy_mode == 2)); then
    if ! run_check \
        "rust-clippy" \
        "cargo clippy --workspace --all-targets -- -D warnings" \
        cargo clippy --workspace --all-targets -- -D warnings; then
        exit 1
    fi
elif ((clippy_mode == 1)); then
    clippy_args=(cargo clippy)
    clippy_display=(cargo clippy)
    for package in "${CRATE_PACKAGES[@]}"; do
        clippy_args+=( -p "$package" )
        clippy_display+=( -p "$package" )
    done
    clippy_args+=( --all-targets -- -D warnings )
    clippy_display+=( --all-targets -- -D warnings )
    clippy_command="$(join_command "${clippy_display[@]}")"
    if ! run_check "rust-clippy" "$clippy_command" "${clippy_args[@]}"; then
        exit 1
    fi
else
    record_skip "rust-clippy" "skipped: no workspace crates changed versus base (use --full for workspace clippy)"
    printf '%s\n' 'SKIP: rust-clippy (no workspace crates changed; use --full for workspace clippy)'
fi

desktop_ui_touched=0
desktop_tauri_touched=0
web_touched=0
mobile_touched=0
for path in "${TOUCHED_PATHS[@]}"; do
    case "$path" in
        desktop/src-tauri/*|desktop/src-tauri)
            desktop_tauri_touched=1
            ;;
        desktop/*|desktop)
            desktop_ui_touched=1
            ;;
        web/*|web)
            web_touched=1
            ;;
        mobile/*|mobile)
            mobile_touched=1
            ;;
        pnpm-lock.yaml)
            desktop_ui_touched=1
            web_touched=1
            ;;
        scripts/check-file-sizes-core.mjs|scripts/check-file-sizes-core.test.mjs)
            desktop_ui_touched=1
            web_touched=1
            mobile_touched=1
            ;;
        scripts/check-px-text-core.mjs|scripts/check-pubkey-truncation-core.mjs)
            desktop_ui_touched=1
            ;;
        scripts/check-android-google-free.py|scripts/test-check-android-google-free.sh|scripts/mobile-*|scripts/*mobile*|scripts/*android*)
            mobile_touched=1
            ;;
        .github/workflows/ci.yml)
            desktop_ui_touched=1
            desktop_tauri_touched=1
            web_touched=1
            mobile_touched=1
            ;;
    esac
done

if ((desktop_ui_touched != 0)); then
    if ! run_check "desktop-ci-format" "just desktop-check" just desktop-check; then
        exit 1
    fi
fi
if ((desktop_tauri_touched != 0)); then
    if ! run_check \
        "desktop-tauri-format" \
        "just desktop-tauri-fmt-check" \
        just desktop-tauri-fmt-check; then
        exit 1
    fi
    if ! run_check \
        "desktop-tauri-clippy" \
        "just desktop-tauri-clippy" \
        just desktop-tauri-clippy; then
        exit 1
    fi
fi
if ((web_touched != 0)); then
    if ! run_check "web-ci-format" "just web-check" just web-check; then
        exit 1
    fi
fi
if ((mobile_touched != 0)); then
    if ! run_check "mobile-ci-format" "just mobile-check" just mobile-check; then
        exit 1
    fi
fi

check_lineage() {
    local main_now
    main_now="$(git rev-parse --verify 'refs/remotes/buzz/main^{commit}')" || return 1
    if ! git merge-base --is-ancestor "$BASE_SHA" "$HEAD_SHA"; then
        printf 'HEAD %s is not a descendant of base %s\n' "$HEAD_SHA" "$BASE_SHA" >&2
        return 1
    fi
    if [[ "$main_now" != "$BASE_SHA" ]]; then
        printf 'WARNING: refs/remotes/buzz/main moved: base=%s current-main=%s\n' "$BASE_SHA" "$main_now" >&2
        return 1
    fi
    return 0
}

if ! run_check \
    "base-lineage" \
    "git merge-base --is-ancestor $BASE_SHA $HEAD_SHA && test \$(git rev-parse --verify refs/remotes/buzz/main^{commit}) = $BASE_SHA" \
    check_lineage; then
    exit 1
fi

if ((RUN_TESTS != 0)); then
    if ((FULL_CLIPPY != 0)); then
        if ! run_check "rust-tests" "cargo test --workspace" cargo test --workspace; then
            exit 1
        fi
    elif ((${#CRATE_PACKAGES[@]} > 0)); then
        test_args=(cargo test)
        test_display=(cargo test)
        for package in "${CRATE_PACKAGES[@]}"; do
            test_args+=( -p "$package" )
            test_display+=( -p "$package" )
        done
        test_command="$(join_command "${test_display[@]}")"
        if ! run_check "rust-tests" "$test_command" "${test_args[@]}"; then
            exit 1
        fi
    else
        record_skip "rust-tests" "skipped: no workspace crates changed versus base"
        printf '%s\n' 'SKIP: rust-tests (no workspace crates changed)'
    fi
fi

exit 0
