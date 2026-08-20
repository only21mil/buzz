#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "sign-android-fork-release-apk: $*" >&2
  exit 1
}

[[ "$#" -eq 2 ]] || fail "usage: $0 <unsigned-apk> <signed-apk>"
readonly unsigned_apk="$1"
readonly signed_apk="$2"
: "${HOST_NETWORK_NAMESPACE:?missing host network namespace identity}"
: "${RUNNER_TEMP:?missing runner-private temporary directory}"
: "${GITHUB_RUN_ID:?missing workflow run id}"
: "${GITHUB_RUN_ATTEMPT:?missing workflow run attempt}"
: "${BUZZ_ANDROID_RELEASE_KEYSTORE_BASE64:?missing protected keystore}"
: "${BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD:?missing keystore password}"
: "${BUZZ_ANDROID_RELEASE_KEY_ALIAS:?missing key alias}"
: "${BUZZ_ANDROID_RELEASE_KEY_PASSWORD:?missing key password}"
: "${BUZZ_ANDROID_RELEASE_CERT_SHA256:?missing pinned certificate fingerprint}"

[[ "$(id -u)" -eq 0 ]] || fail "signing must run as root inside an isolated network namespace"
current_network_namespace="$(readlink /proc/self/ns/net)"
readonly current_network_namespace
[[ "$current_network_namespace" != "$HOST_NETWORK_NAMESPACE" ]] || \
  fail "signing is still in the host network namespace"
mapfile -t network_interfaces < <(
  awk -F: 'NR > 2 { gsub(/[[:space:]]/, "", $1); print $1 }' /proc/net/dev | sort
)
[[ "${#network_interfaces[@]}" -eq 1 && "${network_interfaces[0]}" == "lo" ]] || \
  fail "isolated namespace contains a non-loopback network interface"
if awk 'NR > 1 && $2 == "00000000" { found = 1 } END { exit !found }' /proc/net/route; then
  fail "isolated namespace contains an IPv4 default route"
fi

for tool in apksigner jar jarsigner keytool sha256sum zipalign; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
[[ "$unsigned_apk" = /* && -f "$unsigned_apk" && ! -L "$unsigned_apk" && -s "$unsigned_apk" ]] || \
  fail "unsigned APK must be a nonempty absolute regular file, not a symlink"
[[ "$signed_apk" = /* && ! -e "$signed_apk" && ! -L "$signed_apk" ]] || \
  fail "signed APK output must be a new absolute path"
[[ -d "$(dirname "$signed_apk")" && ! -L "$(dirname "$signed_apk")" ]] || \
  fail "signed APK output directory must be an existing directory, not a symlink"
if apksigner verify "$unsigned_apk" >/dev/null 2>&1; then
  fail "input APK is already signed"
fi
[[ "${SUDO_UID:-}" =~ ^[0-9]+$ && "${SUDO_GID:-}" =~ ^[0-9]+$ ]] || \
  fail "signing requires the invoking runner identity"

readonly signing_dir="$RUNNER_TEMP/buzz-android-signing-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
[[ ! -e "$signing_dir" ]] || fail "signing directory already exists"
cleanup() {
  rm -rf -- "$signing_dir"
}
trap cleanup EXIT
umask 077
mkdir -m 700 "$signing_dir"
readonly keystore="$signing_dir/release.jks"
printf '%s' "$BUZZ_ANDROID_RELEASE_KEYSTORE_BASE64" | base64 --decode > "$keystore" || \
  fail "protected Android keystore is not valid base64"
chmod 600 "$keystore"
[[ -s "$keystore" ]] || fail "protected Android keystore is empty"

export BUZZ_ANDROID_RELEASE_KEYSTORE_PATH="$keystore"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repo_root
"$repo_root/scripts/validate-android-release-keystore.sh"

readonly aligned_apk="$signing_dir/app-release-aligned.apk"
readonly isolated_signed_apk="$signing_dir/app-release-signed.apk"
zipalign -P 16 -f 4 "$unsigned_apk" "$aligned_apk"
apksigner sign \
  --ks "$keystore" \
  --ks-key-alias "$BUZZ_ANDROID_RELEASE_KEY_ALIAS" \
  --ks-pass env:BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD \
  --key-pass env:BUZZ_ANDROID_RELEASE_KEY_PASSWORD \
  --v4-signing-enabled false \
  --out "$isolated_signed_apk" \
  "$aligned_apk"
apksigner verify --verbose --print-certs "$isolated_signed_apk" >/dev/null
install -m 600 "$isolated_signed_apk" "$signed_apk"
chown "$SUDO_UID:$SUDO_GID" "$signed_apk"

printf 'Signed Android release APK with network namespace %s isolated from host %s.\n' \
  "$current_network_namespace" "$HOST_NETWORK_NAMESPACE"
