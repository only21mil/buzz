#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "verify-android-fork-release-unsigned-apk: $*" >&2
  exit 1
}

[[ "$#" -eq 4 ]] || \
  fail "usage: $0 <apk> <dependency-manifest> <version-name> <version-code>"
readonly apk="$1"
readonly dependencies="$2"
readonly expected_version_name="$3"
readonly expected_version_code="$4"

[[ -f "$apk" && -s "$apk" ]] || fail "APK is missing or empty"
[[ -f "$dependencies" && -s "$dependencies" ]] || fail "dependency manifest is missing or empty"
[[ "$expected_version_code" =~ ^[1-9][0-9]*$ ]] || fail "version code must be positive"
for tool in apksigner apkanalyzer; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

if apksigner verify "$apk" >/dev/null 2>&1; then
  fail "unsigned handoff APK unexpectedly has a valid signature"
fi
[[ "$(apkanalyzer manifest application-id "$apk")" == "xyz.block.buzz.mobile" ]] || \
  fail "APK package is not xyz.block.buzz.mobile"
[[ "$(apkanalyzer manifest version-name "$apk")" == "$expected_version_name" ]] || \
  fail "APK version name does not match"
[[ "$(apkanalyzer manifest version-code "$apk")" == "$expected_version_code" ]] || \
  fail "APK version code does not match"
[[ "$(apkanalyzer manifest debuggable "$apk")" == "false" ]] || fail "release APK is debuggable"
[[ "$(apkanalyzer manifest permissions "$apk" | grep -cx 'android.permission.POST_NOTIFICATIONS')" -eq 1 ]] || \
  fail "APK must request POST_NOTIFICATIONS exactly once"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repo_root
python3 "$repo_root/scripts/check-android-google-free.py" \
  --apk "$apk" --dependency-manifest "$dependencies"

printf 'Verified unsigned Android release handoff: sha256=%s version=%s (%s).\n' \
  "$(sha256sum "$apk" | awk '{print $1}')" \
  "$expected_version_name" "$expected_version_code"
