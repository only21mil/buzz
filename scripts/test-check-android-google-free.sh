#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/scripts/check-android-google-free.py"
workflow="$repo_root/.github/workflows/ci.yml"
gradle_build="$repo_root/mobile/android/app/build.gradle.kts"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "$*" >&2
  exit 1
}

write_clean_manifest() {
  cat > "$1" <<'EOF'
component	debugRuntimeClasspath	androidx.core:core:1.17.0
component	profileRuntimeClasspath	androidx.core:core:1.17.0
component	releaseRuntimeClasspath	androidx.core:core:1.17.0
configuration	debugRuntimeClasspath
configuration	profileRuntimeClasspath
configuration	releaseRuntimeClasspath
EOF
}

make_apk() {
  local output="$1"
  local entry_name="$2"
  local entry_content="$3"
  local root="$tmp/apk-root"
  rm -rf "$root"
  rm -f "$output"
  mkdir -p "$root/$(dirname "$entry_name")"
  printf '%s' "$entry_content" > "$root/$entry_name"
  (
    cd "$root"
    zip -q "$output" "$entry_name"
  )
}

manifest="$tmp/dependencies.tsv"
apk="$tmp/app.apk"
write_clean_manifest "$manifest"
make_apk "$apk" classes.dex 'Lxyz/block/buzz/mobile/MainActivity;'
"$checker" --apk "$apk" --dependency-manifest "$manifest" > "$tmp/pass-output"
grep -Fq 'Android Google SDK-free check passed' "$tmp/pass-output" || fail "clean fixture did not pass"

for group in com.google.android.gms com.google.firebase com.google.mlkit; do
  write_clean_manifest "$manifest"
  sed -i "1s#androidx.core:core:1.17.0#$group:forbidden:1.0#" "$manifest"
  if "$checker" --apk "$apk" --dependency-manifest "$manifest" > "$tmp/output" 2>&1; then
    fail "forbidden dependency group passed: $group"
  fi
  grep -Fq "$group:forbidden:1.0" "$tmp/output" || fail "dependency failure did not name $group"
done

write_clean_manifest "$manifest"
for marker in com/google/android/gms com/google/firebase com/google/mlkit; do
  make_apk "$apk" classes.dex "L$marker/Forbidden;"
  if "$checker" --apk "$apk" --dependency-manifest "$manifest" > "$tmp/output" 2>&1; then
    fail "forbidden APK class passed: $marker"
  fi
  grep -Fq "$marker/" "$tmp/output" || fail "APK failure did not name $marker"
done

make_apk "$apk" assets/com.google.mlkit/model.bin 'opaque-model'
if "$checker" --apk "$apk" --dependency-manifest "$manifest" > "$tmp/output" 2>&1; then
  fail "forbidden APK asset path passed"
fi
grep -Fq 'assets/com.google.mlkit/model.bin' "$tmp/output" || fail "asset failure did not name entry"

make_apk "$apk" assets/mlkit_barcode_models/model.tflite 'opaque-model'
if "$checker" --apk "$apk" --dependency-manifest "$manifest" > "$tmp/output" 2>&1; then
  fail "ML Kit model asset path passed"
fi
grep -Fq 'assets/mlkit_barcode_models/model.tflite' "$tmp/output" || \
  fail "ML Kit asset failure did not name entry"

make_apk "$apk" classes.dex 'Lxyz/block/buzz/mobile/MainActivity;'
grep -v $'configuration\tprofileRuntimeClasspath' "$manifest" > "$tmp/missing.tsv"
if "$checker" --apk "$apk" --dependency-manifest "$tmp/missing.tsv" > "$tmp/output" 2>&1; then
  fail "missing runtime configuration passed"
fi
grep -Fq 'missing configurations: profileRuntimeClasspath' "$tmp/output" || \
  fail "missing-configuration failure was not explicit"

printf 'not an apk' > "$tmp/not-an-apk"
if "$checker" --apk "$tmp/not-an-apk" --dependency-manifest "$manifest" > "$tmp/output" 2>&1; then
  fail "malformed APK passed"
fi
grep -Fq 'cannot open APK' "$tmp/output" || fail "malformed APK failure was not explicit"

# Keep the executable gate and its inputs wired together. This contract runs in
# the always-on changes job, so removing JVM coverage or any half of the
# dependency/APK check fails before the path-filtered mobile job can be skipped.
awk '/^  mobile:$/,/^  security:$/' "$workflow" > "$tmp/mobile-job.yml"
grep -Fq 'uses: gradle/actions/setup-gradle@9c971963bec38e04b3d30dcc455b5382be2fdbfb # v6.3.0' \
  "$tmp/mobile-job.yml" || fail "mobile CI must use the reviewed setup-gradle revision"
[[ "$(grep -Fc 'uses: gradle/actions/setup-gradle@' "$tmp/mobile-job.yml")" == "1" ]] || \
  fail "mobile CI must declare exactly one setup-gradle action"
grep -Fq "gradle-version: '8.14.5'" "$tmp/mobile-job.yml" || \
  fail "mobile CI must install the Android project's pinned Gradle version"
[[ "$(grep -Fc 'gradle-version:' "$tmp/mobile-job.yml")" == "1" ]] || \
  fail "mobile CI must declare exactly one Gradle version"
grep -Fq "gradle -p mobile/android \\" "$tmp/mobile-job.yml" || \
  fail "mobile CI must invoke the installed Gradle distribution"
if grep -Fq 'gradlew' "$tmp/mobile-job.yml"; then
  fail "mobile CI must not invoke the ignored, untracked Gradle wrapper"
fi
grep -Fq ':app:testDebugUnitTest' "$tmp/mobile-job.yml" || fail "mobile CI must run Android JVM tests"
grep -Fq ':app:writeBuzzRuntimeDependencyManifest' "$tmp/mobile-job.yml" || \
  fail "mobile CI must resolve the canonical runtime dependency manifest"
grep -Fq 'scripts/check-android-google-free.py' "$tmp/mobile-job.yml" || \
  fail "mobile CI must run the APK/dependency guard"
grep -Fq -- '--apk mobile/build/app/outputs/flutter-apk/app-debug.apk' "$tmp/mobile-job.yml" || \
  fail "mobile CI guard must scan the APK it just built"
grep -Fq -- '--dependency-manifest mobile/build/app/reports/buzz-runtime-dependencies.tsv' \
  "$tmp/mobile-job.yml" || fail "mobile CI guard must scan the generated dependency manifest"
for configuration in debugRuntimeClasspath profileRuntimeClasspath releaseRuntimeClasspath; do
  grep -Fq "\"$configuration\"" "$gradle_build" || \
    fail "Gradle manifest must cover $configuration"
done
grep -Fq 'lines.sorted()' "$gradle_build" || fail "Gradle dependency manifest must be canonical"
grep -Fq 'configuration.incoming.resolutionResult' "$gradle_build" || \
  fail "Gradle dependency manifest must inspect the component graph"
if grep -Eq '\.resolve\(|resolvedConfiguration|artifactView|incoming\.files' "$gradle_build"; then
  fail "Gradle dependency manifest must not resolve multi-variant artifacts"
fi

echo "Android Google SDK-free guard tests passed"
