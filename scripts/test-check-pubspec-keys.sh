#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/scripts/check-pubspec-keys.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "$*" >&2
  exit 1
}

expect_pass() {
  local name="$1" file="$2"
  python3 "$checker" --pubspec "$file" > "$tmp/$name.out" 2>&1 \
    || fail "$name: expected pass, got failure: $(cat "$tmp/$name.out")"
}

expect_fail() {
  local name="$1" file="$2" pattern="$3"
  if python3 "$checker" --pubspec "$file" > "$tmp/$name.out" 2>&1; then
    fail "$name: expected failure, got pass"
  fi
  grep -q "$pattern" "$tmp/$name.out" \
    || fail "$name: failure missed '$pattern': $(cat "$tmp/$name.out")"
}

write_clean_manifest() {
  cat > "$1" <<'EOF'
name: buzz
environment:
  sdk: ^3.11.4

dependencies:
  flutter:
    sdk: flutter
  characters: ^1.4.0
  flutter_zxing: ^2.3.0
  image: ^4.8.0

dev_dependencies:
  flutter_test:
    sdk: flutter

flutter:
  uses-material-design: true
  fonts:
    - family: Inter
      fonts:
        - asset: assets/fonts/InterVariable.ttf
        - asset: assets/fonts/InterVariable-Italic.ttf
          style: italic
    - family: GeistMono
      fonts:
        - asset: assets/fonts/GeistMono-Variable.ttf
        - asset: assets/fonts/GeistMono-Italic-Variable.ttf
          style: italic
EOF
}

# 1. Clean manifest passes, including repeated `- asset:` sibling items.
write_clean_manifest "$tmp/clean.yaml"
expect_pass "clean" "$tmp/clean.yaml"

# 2. The MW-2 hazard: a duplicate `image` key with no conflict marker fails.
write_clean_manifest "$tmp/dup-image.yaml"
python3 - "$tmp/dup-image.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path).read()
text = text.replace("  image: ^4.8.0\n", "  image: ^4.8.0\n  image: ^4.9.0\n")
open(path, "w").write(text)
PY
expect_fail "dup-image" "$tmp/dup-image.yaml" "duplicate key 'image'"

# 3. A duplicate nested key fails.
write_clean_manifest "$tmp/dup-nested.yaml"
python3 - "$tmp/dup-nested.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path).read()
text = text.replace("  fonts:\n", "  fonts:\n  fonts:\n")
open(path, "w").write(text)
PY
expect_fail "dup-nested" "$tmp/dup-nested.yaml" "duplicate key 'fonts'"

# 4. A prohibited ML Kit dependency fails before resolution.
write_clean_manifest "$tmp/mlkit.yaml"
python3 - "$tmp/mlkit.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path).read()
text = text.replace(
    "  image: ^4.8.0\n",
    "  image: ^4.8.0\n  google_mlkit_selfie_segmentation: ^0.1.0\n",
)
open(path, "w").write(text)
PY
expect_fail "mlkit" "$tmp/mlkit.yaml" "prohibited mlkit dependency"

# 5. A Firebase dependency fails too.
write_clean_manifest "$tmp/firebase.yaml"
python3 - "$tmp/firebase.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path).read()
text = text.replace(
    "  image: ^4.8.0\n",
    "  image: ^4.8.0\n  firebase_core: ^3.0.0\n",
)
open(path, "w").write(text)
PY
expect_fail "firebase" "$tmp/firebase.yaml" "prohibited firebase dependency"

# 6. Tab indentation fails.
write_clean_manifest "$tmp/tab.yaml"
printf '\tbad: true\n' >> "$tmp/tab.yaml"
expect_fail "tab" "$tmp/tab.yaml" "tab indentation"

# 7. The real manifest passes.
expect_pass "real-pubspec" "$repo_root/mobile/pubspec.yaml"

echo "Pubspec manifest guard unit tests passed: 7 cases"
