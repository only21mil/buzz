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

# Exercise the trusted verifier against a real local remote. The verifier under
# test is committed on main before any source tag is fetched.
verify_remote="$test_root/verify-remote.git"
verify_author="$test_root/verify-author"
verify_trusted="$test_root/verify-trusted"
git init --quiet --bare "$verify_remote"
git init --quiet --initial-branch=main "$verify_author"
git -C "$verify_author" config user.name "Release Contract"
git -C "$verify_author" config user.email "release-contract@example.invalid"
mkdir "$verify_author/scripts"
cp "$metadata" "$verify_author/scripts/android-fork-release-metadata.py"
cp "$repo_root/scripts/verify-android-fork-release-ref.sh" "$verify_author/scripts/"
printf 'trusted release policy\n' >"$verify_author/policy"
git -C "$verify_author" add scripts policy
git -C "$verify_author" commit --quiet -m "trusted policy"
verified_sha="$(git -C "$verify_author" rev-parse HEAD)"
git -C "$verify_author" tag -a only21mil-android-v0.1.0-rc.1 -m "candidate one"
git -C "$verify_author" remote add origin "$verify_remote"
git -C "$verify_author" push --quiet origin main only21mil-android-v0.1.0-rc.1
git --git-dir="$verify_remote" symbolic-ref HEAD refs/heads/main
git clone --quiet --no-tags "$verify_remote" "$verify_trusted"
GITHUB_REPOSITORY=only21mil/buzz \
  "$verify_trusted/scripts/verify-android-fork-release-ref.sh" \
  only21mil-android-v0.1.0-rc.1 "$verified_sha" >/dev/null
if GITHUB_REPOSITORY=only21mil/buzz \
  "$verify_trusted/scripts/verify-android-fork-release-ref.sh" \
  only21mil-android-v0.1.0-rc.1 0000000000000000000000000000000000000000 \
  >/dev/null 2>&1; then
  fail "trusted verifier accepted a mismatched peeled commit SHA"
fi
git -C "$verify_author" tag only21mil-android-v0.1.1-rc.1 "$verified_sha"
git -C "$verify_author" push --quiet origin only21mil-android-v0.1.1-rc.1
if GITHUB_REPOSITORY=only21mil/buzz \
  "$verify_trusted/scripts/verify-android-fork-release-ref.sh" \
  only21mil-android-v0.1.1-rc.1 "$verified_sha" >/dev/null 2>&1; then
  fail "trusted verifier accepted a lightweight source tag"
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
grep -Fxq '  group: android-fork-release-tag-publication' "$tag_workflow" || \
  fail "tag publication is not serialized through one global concurrency group"
if sed -n '/^concurrency:/,/^permissions:/p' "$tag_workflow" | grep -Fq 'inputs.source_tag'; then
  fail "tag publication concurrency is still partitioned by input tag"
fi

grep -Fq 'contents: read' "$apk_workflow" || fail "APK workflow exceeds read-only repository access"
grep -Fq 'cache-disabled: true' "$apk_workflow" || fail "release Gradle cache is enabled"
if grep -Eq 'actions/cache|gh release|play-store|google-play|fastlane' "$apk_workflow"; then
  fail "APK workflow contains a cache, public release, or store path"
fi

extract_job() {
  python3 - "$apk_workflow" "$1" <<'PY'
import pathlib
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
header = f"  {sys.argv[2]}:"
try:
    start = lines.index(header)
except ValueError:
    raise SystemExit(f"missing workflow job {sys.argv[2]}")
end = next(
    (index for index in range(start + 1, len(lines)) if lines[index].startswith("  ") and not lines[index].startswith("    ") and lines[index].endswith(":")),
    len(lines),
)
print("\n".join(lines[start:end]))
PY
}

verify_job="$(extract_job verify-source)"
build_job="$(extract_job build-unsigned)"
sign_job="$(extract_job sign)"

# These are literal GitHub Actions expressions inspected as text.
# shellcheck disable=SC2016
grep -Fq 'ref: ${{ github.sha }}' <<<"$verify_job" || \
  fail "trusted verifier is not pinned to the reviewed main dispatch SHA"
grep -Fq 'path: trusted-release' <<<"$verify_job" || \
  fail "trusted verifier lacks a separate trusted-release checkout"
grep -Fq 'trusted-release/scripts/verify-android-fork-release-ref.sh' <<<"$verify_job" || \
  fail "source tag is not verified by trusted-main code"
grep -Fq 'needs: verify-source' <<<"$build_job" || \
  fail "source checkout can start before trusted verification"
# shellcheck disable=SC2016
grep -Fq 'ref: ${{ needs.verify-source.outputs.source_sha }}' <<<"$build_job" || \
  fail "source checkout is not pinned to the verified peeled commit"
if grep -Fq 'inputs.source_tag' <<<"$build_job"; then
  fail "source checkout still consumes the untrusted tag name"
fi
if grep -Fq 'secrets.' <<<"$build_job"; then
  fail "networked source build receives a secret"
fi
if grep -Fq 'environment: android-release' <<<"$build_job"; then
  fail "networked source build enters the protected signing environment"
fi
grep -Fq 'BUZZ_ANDROID_RELEASE_SIGNING: external' <<<"$build_job" || \
  fail "networked build does not select the unsigned external seam"
grep -Fq 'trusted-release/scripts/verify-android-fork-release-unsigned-apk.sh' <<<"$build_job" || \
  fail "networked build does not reject a signed handoff"
grep -Fq 'actions/upload-artifact@' <<<"$build_job" || \
  fail "unsigned build lacks a job-boundary artifact handoff"

grep -Fq 'needs: [verify-source, build-unsigned]' <<<"$sign_job" || \
  fail "protected signing can start before verification and unsigned handoff"
grep -Fq 'environment: android-release' <<<"$sign_job" || \
  fail "signing job lacks the protected environment"
# shellcheck disable=SC2016
grep -Fq 'ref: ${{ github.sha }}' <<<"$sign_job" || \
  fail "signing policy is not pinned to trusted main"
grep -Fq 'path: trusted-release' <<<"$sign_job" || \
  fail "signing job lacks a separate trusted-release checkout"
# shellcheck disable=SC2016
if grep -Fq 'ref: ${{ inputs.source_tag }}' <<<"$sign_job"; then
  fail "signing job checks out source-tag code"
fi
grep -Fq 'actions/download-artifact@' <<<"$sign_job" || \
  fail "signing job does not receive the unsigned handoff"
grep -Fq 'sudo --preserve-env=' <<<"$sign_job" || fail "signing is not elevated for network isolation"
grep -Fq 'unshare --net --' <<<"$sign_job" || fail "signing lacks an isolated network namespace"
grep -Fq 'trusted-release/scripts/sign-android-fork-release-apk.sh' <<<"$sign_job" || \
  fail "protected secrets are not consumed solely by trusted-main signing code"
download_line="$(grep -n 'Receive unsigned build handoff' "$apk_workflow" | cut -d: -f1)"
secret_line="$(grep -n 'BUZZ_ANDROID_RELEASE_KEYSTORE_BASE64:.*secrets\.' "$apk_workflow" | cut -d: -f1)"
(( download_line < secret_line )) || fail "signing key is exposed before unsigned artifact handoff"
[[ "$(grep -Fc 'environment: android-release' "$apk_workflow")" -eq 1 ]] || \
  fail "protected signing environment is attached outside the signing job"
[[ "$(grep -Fc 'scripts/verify-android-fork-release-ref.sh' "$apk_workflow")" -eq 2 ]] || \
  fail "trusted source verification is not repeated before signing"
grep -Fq 'if: always()' <<<"$sign_job" || fail "signing cleanup proof is not unconditional"
grep -Fq 'retention-days: 3' <<<"$sign_job" || fail "release artifact retention changed"

readonly unsigned_verifier="$repo_root/scripts/verify-android-fork-release-unsigned-apk.sh"
mkdir "$test_root/apk-bin"
cat >"$test_root/apk-bin/apksigner" <<'APK_SIGNER'
#!/usr/bin/env bash
exit 0
APK_SIGNER
cat >"$test_root/apk-bin/apkanalyzer" <<'APK_ANALYZER'
#!/usr/bin/env bash
exit 0
APK_ANALYZER
chmod +x "$test_root/apk-bin/apksigner" "$test_root/apk-bin/apkanalyzer"
printf 'signed apk fixture\n' >"$test_root/signed-fixture.apk"
printf 'dependency fixture\n' >"$test_root/dependencies.tsv"
if PATH="$test_root/apk-bin:$PATH" \
  "$unsigned_verifier" "$test_root/signed-fixture.apk" "$test_root/dependencies.tsv" \
  0.1.0-only21mil.rc.1 1000100001 >/dev/null 2>&1; then
  fail "unsigned handoff verifier accepted an APK with a valid signature"
fi

readonly signer="$repo_root/scripts/sign-android-fork-release-apk.sh"
# The command substitution is an exact source-code assertion, not executable shell.
# shellcheck disable=SC2016
grep -Fq '[[ "$(id -u)" -eq 0 ]]' "$signer" || fail "signer does not require root isolation"
grep -Fq 'current_network_namespace' "$signer" || fail "signer does not compare network namespaces"
grep -Fq '/proc/net/dev' "$signer" || fail "signer does not reject non-loopback interfaces"
grep -Fq '/proc/net/route' "$signer" || fail "signer does not reject a default route"
grep -Fq 'apksigner sign' "$signer" || fail "trusted signer does not use apksigner"
grep -Fq -- '--ks-pass env:BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD' "$signer" || \
  fail "signer exposes the keystore password in argv"
grep -Fq -- '--key-pass env:BUZZ_ANDROID_RELEASE_KEY_PASSWORD' "$signer" || \
  fail "signer exposes the key password in argv"
if HOST_NETWORK_NAMESPACE="$(readlink /proc/self/ns/net)" \
  RUNNER_TEMP="$test_root" GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 \
  BUZZ_ANDROID_RELEASE_KEYSTORE_BASE64=invalid \
  BUZZ_ANDROID_RELEASE_KEYSTORE_PASSWORD=invalid \
  BUZZ_ANDROID_RELEASE_KEY_ALIAS=invalid \
  BUZZ_ANDROID_RELEASE_KEY_PASSWORD=invalid \
  BUZZ_ANDROID_RELEASE_CERT_SHA256=0000000000000000000000000000000000000000000000000000000000000000 \
  "$signer" /missing/unsigned.apk "$test_root/signed.apk" >/dev/null 2>&1; then
  fail "signer ran without root network-namespace isolation"
fi

grep -Fq 'setOf("upload-keystore", "external")' "$gradle_build" || \
  fail "Gradle no longer exposes the pre-existing unsigned external seam"
if grep -Eq 'direct-release|BUZZ_ANDROID_RELEASE_KEYSTORE_|BUZZ_ANDROID_RELEASE_KEY_ALIAS|BUZZ_ANDROID_RELEASE_KEY_PASSWORD' "$gradle_build"; then
  fail "Gradle still contains the persistent fork signing-key seam"
fi

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
  "$repo_root/scripts/verify-android-fork-release-apk.sh" \
  "$repo_root/scripts/verify-android-fork-release-unsigned-apk.sh" \
  "$repo_root/scripts/sign-android-fork-release-apk.sh"
python3 -m py_compile \
  "$metadata" \
  "$repo_root/scripts/write-android-fork-release-provenance.py"

echo "Android fork release contract tests passed"
