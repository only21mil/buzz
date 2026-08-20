#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "verify-android-fork-release-apk: $*" >&2
  exit 1
}

[[ "$#" -eq 5 ]] || \
  fail "usage: $0 <apk> <dependency-manifest> <version-name> <version-code> <cert-sha256>"
readonly apk="$1"
readonly dependencies="$2"
readonly expected_version_name="$3"
readonly expected_version_code="$4"
expected_cert="$(printf '%s' "$5" | tr '[:upper:]' '[:lower:]' | tr -d ':[:space:]')"
readonly expected_cert

[[ -f "$apk" && -s "$apk" ]] || fail "APK is missing or empty"
[[ -f "$dependencies" && -s "$dependencies" ]] || fail "dependency manifest is missing or empty"
[[ "$expected_version_code" =~ ^[1-9][0-9]*$ ]] || fail "version code must be positive"
[[ "$expected_cert" =~ ^[0-9a-f]{64}$ ]] || fail "certificate fingerprint must be 64 hex characters"
for tool in apksigner apkanalyzer zipalign; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

if ! signer_output="$(apksigner verify --verbose --print-certs "$apk" 2>&1)"; then
  fail "APK signature verification failed"
fi
readonly signer_output
mapfile -t signer_digests < <(
  printf '%s\n' "$signer_output" |
    awk '/Signer #[0-9]+ certificate SHA-256 digest: / {
           sub(/.*certificate SHA-256 digest: /, "")
           print
         }' |
    tr '[:upper:]' '[:lower:]' | sed 's/[:[:space:]]//g' | sort -u
)
[[ "${#signer_digests[@]}" -eq 1 ]] || fail "APK must have exactly one signing certificate"
[[ "${signer_digests[0]}" == "$expected_cert" ]] || fail "APK signer does not match the pinned certificate"
zipalign -c -P 16 4 "$apk" >/dev/null || fail "APK is not zip-aligned"

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

printf 'Verified Android release APK: sha256=%s cert=%s version=%s (%s).\n' \
  "$(sha256sum "$apk" | awk '{print $1}')" "$expected_cert" \
  "$expected_version_name" "$expected_version_code"
