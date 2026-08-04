#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repo_root
readonly metadata="$repo_root/scripts/android-fork-release-metadata.py"
readonly tag_workflow="$repo_root/.github/workflows/android-fork-release-tag.yml"
readonly apk_workflow="$repo_root/.github/workflows/android-fork-release-apk.yml"
readonly gradle_build="$repo_root/mobile/android/app/build.gradle.kts"
readonly validator="$repo_root/scripts/validate-android-release-keystore.sh"
readonly publisher="$repo_root/scripts/publish-android-fork-release-candidate.sh"
test_root="$(mktemp -d)"
readonly test_root
trap 'rm -rf "$test_root"' EXIT

fail() {
  echo "test-android-fork-release-contract: $*" >&2
  exit 1
}

expected='{"candidate_number":1,"tag":"only21mil-android-v0.1.0-rc.1","version":"0.1.0","version_code":1000100001,"version_name":"0.1.0-only21mil.rc.1"}'
[[ "$(python3 "$metadata" only21mil-android-v0.1.0-rc.1)" == "$expected" ]] || \
  fail "first fork release metadata changed"
for invalid in \
  mobile-v0.1.0-rc.1 \
  only21mil-android-v00.1.0-rc.1 \
  only21mil-android-v0.1.0-rc.0 \
  only21mil-android-v0.1.0-rc.1000 \
  only21mil-android-v100.0.0-rc.1; do
  if python3 "$metadata" "$invalid" >/dev/null 2>&1; then
    fail "invalid release tag passed: $invalid"
  fi
done

mkdir "$test_root/bin"
cat >"$test_root/bin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}:${2:-}" in
  api:repos/only21mil/buzz/git/ref/heads/main)
    printf '%s\n' "$TEST_TARGET_SHA"
    ;;
  api:repos/only21mil/buzz/commits/*)
    printf '%s\n' "$TEST_TARGET_SHA"
    ;;
  api:repos/only21mil/buzz/git/ref/tags/*)
    if [[ "$*" == *'--silent'* ]]; then
      exit "${TEST_TAG_EXISTS:-1}"
    elif [[ "$*" == *'.object.type'* ]]; then
      printf 'tag\n'
    else
      printf '%s\n' "$TEST_TAG_OBJECT_SHA"
    fi
    ;;
  api:--paginate)
    [[ "${TEST_LIST_FAIL:-false}" != "true" ]] || exit 2
    printf '%s' "${TEST_EXISTING_TAGS:-}"
    ;;
  api:--method)
    case "${4:-}" in
      repos/only21mil/buzz/git/tags)
        printf '%s\n' "$*" >>"$TEST_GH_CALLS"
        printf '%s\n' "$TEST_TAG_OBJECT_SHA"
        ;;
      repos/only21mil/buzz/git/refs)
        printf '%s\n' "$*" >>"$TEST_GH_CALLS"
        ;;
      *) exit 2 ;;
    esac
    ;;
  api:repos/only21mil/buzz/git/tags/*)
    printf '%s\n' "$TEST_TARGET_SHA"
    ;;
  *)
    echo "unexpected gh call: $*" >&2
    exit 2
    ;;
esac
GH
chmod +x "$test_root/bin/gh"
export PATH="$test_root/bin:$PATH"
export GITHUB_REPOSITORY=only21mil/buzz
export TEST_TARGET_SHA=1111111111111111111111111111111111111111
export TEST_TAG_OBJECT_SHA=2222222222222222222222222222222222222222
export TEST_GH_CALLS="$test_root/gh-calls"

"$publisher" only21mil-android-v0.1.0-rc.1 "$TEST_TARGET_SHA" >/dev/null
grep -Fq -- '-f tag=only21mil-android-v0.1.0-rc.1' "$TEST_GH_CALLS" || \
  fail "publisher did not create the requested annotated tag"
grep -Fq -- '-f ref=refs/tags/only21mil-android-v0.1.0-rc.1' "$TEST_GH_CALLS" || \
  fail "publisher did not create the immutable tag ref"
if TEST_LIST_FAIL=true "$publisher" only21mil-android-v0.1.0-rc.1 "$TEST_TARGET_SHA" >/dev/null 2>&1; then
  fail "publisher continued after tag inventory failed"
fi
if TEST_TARGET_SHA=3333333333333333333333333333333333333333 \
  "$publisher" only21mil-android-v0.1.0-rc.1 \
  1111111111111111111111111111111111111111 >/dev/null 2>&1; then
  fail "publisher accepted a moved main branch"
fi
if TEST_EXISTING_TAGS=$'refs/tags/only21mil-android-v0.1.0-rc.1\ttag\t4444444444444444444444444444444444444444\n' \
  "$publisher" only21mil-android-v0.1.0-rc.1 "$TEST_TARGET_SHA" >/dev/null 2>&1; then
  fail "publisher reused a candidate number or Android version code"
fi
if GITHUB_REPOSITORY=attacker/buzz \
  "$publisher" only21mil-android-v0.1.0-rc.1 "$TEST_TARGET_SHA" >/dev/null 2>&1; then
  fail "publisher accepted the wrong repository"
fi

for workflow in "$tag_workflow" "$apk_workflow"; do
  grep -Fq 'github.repository' "$workflow" || fail "workflow does not bind repository identity"
  grep -Fq 'only21mil/buzz' "$workflow" || fail "workflow is not fork-bound"
  grep -Fq 'refs/heads/main' "$workflow" || fail "workflow is not dispatch-ref-bound"
  grep -Fq 'environment: android-release' "$workflow" || fail "workflow lacks protected environment"
  grep -Fq 'actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10' "$workflow" || \
    fail "workflow checkout action is not pinned"
  grep -Fq 'persist-credentials: false' "$workflow" || fail "checkout persists credentials"
  if grep -Eq '^  (pull_request|push|release):' "$workflow"; then
    fail "fork release workflows must be manual only"
  fi
done

grep -Fq 'permissions:' "$tag_workflow" || fail "tag workflow lacks explicit permissions"
grep -Fq 'contents: write' "$tag_workflow" || fail "tag workflow cannot publish its one tag"
grep -Fq 'contents: read' "$apk_workflow" || fail "APK workflow exceeds read-only repository access"
grep -Fq 'cache-disabled: true' "$apk_workflow" || fail "release Gradle cache is enabled"
if grep -Eq 'actions/cache|gh release|play-store|google-play|fastlane|BUZZ_ANDROID_UPLOAD_' "$apk_workflow"; then
  fail "APK workflow contains a cache, public release/store path, or Block upload-key path"
fi
grep -Fq 'BUZZ_ANDROID_RELEASE_SIGNING: direct-release' "$apk_workflow" || \
  fail "APK workflow does not select the explicit fork signing mode"
grep -Fq 'scripts/verify-android-fork-release-ref.sh' "$apk_workflow" || \
  fail "APK workflow does not verify immutable source"
[[ "$(grep -Fc 'scripts/verify-android-fork-release-ref.sh' "$apk_workflow")" -eq 2 ]] || \
  fail "APK workflow must re-read source before staging"
grep -Fq 'scripts/verify-android-fork-release-apk.sh' "$apk_workflow" || \
  fail "APK workflow does not verify the built release APK"
grep -Fq 'scripts/write-android-fork-release-provenance.py' "$apk_workflow" || \
  fail "APK workflow does not write provenance"
grep -Fq 'if: always()' "$apk_workflow" || fail "signing cleanup is not unconditional"
grep -Fq 'if: success()' "$apk_workflow" || fail "artifact upload is not success-only"
grep -Fq 'retention-days: 3' "$apk_workflow" || fail "release artifact retention changed"
cleanup_line="$(grep -n 'Remove and prove absence of signing material' "$apk_workflow" | cut -d: -f1)"
upload_line="$(grep -n 'Upload verified APK and provenance' "$apk_workflow" | cut -d: -f1)"
(( cleanup_line < upload_line )) || fail "artifact upload occurs before signing cleanup"

for variable in \
  BUZZ_ANDROID_RELEASE_KEYSTORE_PATH \
  BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD \
  BUZZ_ANDROID_RELEASE_KEY_ALIAS \
  BUZZ_ANDROID_RELEASE_KEY_PASSWORD; do
  grep -Fq "$variable" "$gradle_build" || fail "Gradle is missing $variable"
done
grep -Fq 'direct-release' "$gradle_build" || fail "Gradle lacks the direct-release mode"
grep -Fq 'must not be combined with ' "$gradle_build" || \
  fail "Gradle does not reject mixed signing lineages"
grep -Fq 'BUZZ_ANDROID_UPLOAD_* credentials.' "$gradle_build" || \
  fail "Gradle mixed-lineage rejection does not name Block upload credentials"

grep -Fq -- '-storepass:env BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD' "$validator" || \
  fail "validator does not keep the store password out of argv"
grep -Fq -- '-keypass:env BUZZ_ANDROID_RELEASE_KEY_PASSWORD' "$validator" || \
  fail "validator does not keep the key password out of argv"
grep -Fq 'BUZZ_ANDROID_RELEASE_CERT_SHA256' "$validator" || \
  fail "validator does not require a separately pinned public certificate"

bash -n \
  "$repo_root/scripts/publish-android-fork-release-candidate.sh" \
  "$repo_root/scripts/verify-android-fork-release-ref.sh" \
  "$repo_root/scripts/validate-android-release-keystore.sh" \
  "$repo_root/scripts/verify-android-fork-release-apk.sh"
python3 -m py_compile \
  "$metadata" \
  "$repo_root/scripts/write-android-fork-release-provenance.py"

echo "Android fork release contract tests passed"
