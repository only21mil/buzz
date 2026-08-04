#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "validate-android-release-keystore: $*" >&2
  exit 1
}

: "${BUZZ_ANDROID_RELEASE_KEYSTORE_PATH:?missing keystore path}"
: "${BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD:?missing keystore password}"
: "${BUZZ_ANDROID_RELEASE_KEY_ALIAS:?missing key alias}"
: "${BUZZ_ANDROID_RELEASE_KEY_PASSWORD:?missing key password}"
: "${BUZZ_ANDROID_RELEASE_CERT_SHA256:?missing pinned certificate fingerprint}"
: "${RUNNER_TEMP:?missing runner-private temporary directory}"

readonly keystore="$BUZZ_ANDROID_RELEASE_KEYSTORE_PATH"
expected_cert="$(
  printf '%s' "$BUZZ_ANDROID_RELEASE_CERT_SHA256" |
    tr '[:upper:]' '[:lower:]' | tr -d ':[:space:]'
)"
readonly expected_cert
[[ "$expected_cert" =~ ^[0-9a-f]{64}$ ]] || fail "pinned certificate must be 64 hex characters"
[[ "$keystore" = /* ]] || fail "keystore path must be absolute"
[[ -f "$keystore" && ! -L "$keystore" && -s "$keystore" ]] || \
  fail "keystore must be a nonempty regular file, not a symlink"
[[ "$(stat -c '%u' "$keystore")" == "$(id -u)" ]] || fail "keystore owner is not the runner user"
[[ "$(stat -c '%a' "$keystore")" == "600" ]] || fail "keystore mode must be 0600"

validation_root="$(mktemp -d "$RUNNER_TEMP/buzz-release-key-validation.XXXXXX")"
readonly validation_root
chmod 700 "$validation_root"
cleanup() {
  rm -rf -- "$validation_root"
}
trap cleanup EXIT

mkdir "$validation_root/payload"
printf 'validation\n' >"$validation_root/payload/marker"
jar --create --file "$validation_root/validation.jar" \
  -C "$validation_root/payload" . >/dev/null 2>&1 || fail "could not create signing probe"

keytool -list \
  -keystore "$keystore" \
  -storepass:env BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD \
  -alias "$BUZZ_ANDROID_RELEASE_KEY_ALIAS" >/dev/null 2>&1 || \
  fail "keystore, store password, or alias validation failed"
jarsigner \
  -keystore "$keystore" \
  -storepass:env BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD \
  -keypass:env BUZZ_ANDROID_RELEASE_KEY_PASSWORD \
  "$validation_root/validation.jar" "$BUZZ_ANDROID_RELEASE_KEY_ALIAS" >/dev/null 2>&1 || \
  fail "private-key password validation failed"
keytool -exportcert \
  -keystore "$keystore" \
  -storepass:env BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD \
  -alias "$BUZZ_ANDROID_RELEASE_KEY_ALIAS" \
  -file "$validation_root/certificate.der" >/dev/null 2>&1 || \
  fail "could not export the public certificate"

actual_cert="$(sha256sum "$validation_root/certificate.der" | awk '{print $1}')"
readonly actual_cert
[[ "$actual_cert" == "$expected_cert" ]] || fail "keystore certificate does not match the pinned fingerprint"
printf 'Validated Android release keystore certificate SHA-256 %s.\n' "$actual_cert"
