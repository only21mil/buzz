#!/usr/bin/env bash
# Pure-bash fixtures for fix-appimage.sh root metadata symlink normalization.

set -euo pipefail

fail() {
  echo "Error: $*" >&2
  exit 1
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixer="${FIX_APPIMAGE_FIXER:-$script_dir/fix-appimage.sh}"
[[ -x "$fixer" ]] || fail "fixer is not executable: $fixer"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

run_pass_fixture() {
  local appdir="$workdir/pass/squashfs-root"
  local original_appdir="$workdir/build/Buzz.AppDir"
  local icon_suffix="usr/share/icons/hicolor/128x128/apps/buzz-desktop.png"
  local desktop_suffix="usr/share/applications/Buzz.desktop"
  local icon_target="$original_appdir/$icon_suffix"
  local desktop_target="$original_appdir/$desktop_suffix"
  local log="$workdir/pass.log"
  local line_count

  mkdir -p \
    "$appdir/usr/share/icons/hicolor/128x128/apps" \
    "$appdir/usr/share/applications" \
    "$original_appdir"
  printf 'fixture icon\n' > "$appdir/$icon_suffix"
  printf '[Desktop Entry]\nName=Buzz\n' > "$appdir/$desktop_suffix"

  # Four allowlisted links prove the whole set is normalized, not only
  # .DirIcon: two absolute icon links, one absolute desktop link, and one
  # already-relative desktop link.
  ln -s "$icon_target" "$appdir/.DirIcon"
  ln -s "$icon_target" "$appdir/buzz-desktop.png"
  ln -s "$desktop_target" "$appdir/Buzz.desktop"
  ln -s "$desktop_suffix" "$appdir/Relative.desktop"

  if ! "$fixer" --normalize-root-symlinks "$appdir" >"$log" 2>&1; then
    cat "$log" >&2
    fail "expected the internal absolute-link fixture to pass"
  fi

  line_count="$(grep -c '^AppImage root metadata symlink: ' "$log" || true)"
  [[ "$line_count" -eq 4 ]] || {
    cat "$log" >&2
    fail "expected exactly one observability line per root metadata link (got $line_count)"
  }

  grep -Fq -- ".DirIcon -> $icon_target (rewritten)" "$log" || fail ".DirIcon was not reported as rewritten"
  grep -Fq -- "buzz-desktop.png -> $icon_target (rewritten)" "$log" || fail "root icon was not reported as rewritten"
  grep -Fq -- "Buzz.desktop -> $desktop_target (rewritten)" "$log" || fail "root desktop was not reported as rewritten"
  grep -Fq -- "Relative.desktop -> $desktop_suffix (skipped-relative)" "$log" || fail "relative root desktop was not reported as skipped"

  [[ "$(readlink -- "$appdir/.DirIcon")" == "$icon_suffix" ]] || fail ".DirIcon was not rebased to its internal suffix"
  [[ "$(readlink -- "$appdir/buzz-desktop.png")" == "$icon_suffix" ]] || fail "root icon was not rebased to its internal suffix"
  [[ "$(readlink -- "$appdir/Buzz.desktop")" == "$desktop_suffix" ]] || fail "root desktop was not rebased to its internal suffix"
  [[ "$(readlink -- "$appdir/Relative.desktop")" == "$desktop_suffix" ]] || fail "relative root desktop was modified"
  [[ "$(realpath -e -- "$appdir/.DirIcon")" == "$appdir/$icon_suffix" ]] || fail ".DirIcon does not resolve inside squashfs-root"
  [[ "$(realpath -e -- "$appdir/buzz-desktop.png")" == "$appdir/$icon_suffix" ]] || fail "root icon does not resolve inside squashfs-root"
  [[ "$(realpath -e -- "$appdir/Buzz.desktop")" == "$appdir/$desktop_suffix" ]] || fail "root desktop does not resolve inside squashfs-root"

  cat "$log"
}

run_outside_fixture() {
  local appdir="$workdir/outside/squashfs-root"
  local outside_target="$workdir/outside-file.png"
  local log="$workdir/outside.log"

  mkdir -p "$appdir" "$workdir/outside"
  printf 'outside\n' > "$outside_target"
  ln -s "$outside_target" "$appdir/.DirIcon"

  if "$fixer" --normalize-root-symlinks "$appdir" >"$log" 2>&1; then
    cat "$log" >&2
    fail "expected an absolute target outside the original AppDir to fail closed"
  fi
  grep -Fq -- '.DirIcon -> ' "$log" || fail "outside-target failure did not report .DirIcon"
  grep -Fq -- '(failed):' "$log" || fail "outside-target failure did not report failed outcome"
  [[ "$(readlink -- "$appdir/.DirIcon")" == "$outside_target" ]] || fail "external target was rewritten"
}

run_mapped_outside_fixture() {
  local appdir="$workdir/mapped-outside/squashfs-root"
  local original_appdir="$workdir/mapped-build/Buzz.AppDir"
  local outside_target="$workdir/mapped-outside-file.png"
  local log="$workdir/mapped-outside.log"

  mkdir -p "$appdir" "$original_appdir"
  printf 'outside\n' > "$outside_target"
  ln -s "$outside_target" "$appdir/escape-target"
  ln -s "$original_appdir/escape-target" "$appdir/.DirIcon"

  if "$fixer" --normalize-root-symlinks "$appdir" >"$log" 2>&1; then
    cat "$log" >&2
    fail "expected a mapped suffix resolving outside squashfs-root to fail closed"
  fi
  grep -Fq -- 'target resolves outside extracted AppDir' "$log" || {
    cat "$log" >&2
    fail "mapped outside-target failure did not identify the escape"
  }
  [[ "$(readlink -- "$appdir/.DirIcon")" == "$original_appdir/escape-target" ]] || fail "mapped external target was rewritten"
}

run_missing_fixture() {
  local appdir="$workdir/missing/squashfs-root"
  local original_appdir="$workdir/missing-build/Buzz.AppDir"
  local missing_target="$original_appdir/usr/share/icons/missing.png"
  local log="$workdir/missing.log"

  mkdir -p "$appdir" "$original_appdir"
  ln -s "$missing_target" "$appdir/buzz-desktop.png"

  if "$fixer" --normalize-root-symlinks "$appdir" >"$log" 2>&1; then
    cat "$log" >&2
    fail "expected an unmappable internal suffix to fail closed"
  fi
  grep -Fq -- 'internal suffix does not resolve in extracted AppDir' "$log" || {
    cat "$log" >&2
    fail "missing internal suffix failure was not reported"
  }
  [[ "$(readlink -- "$appdir/buzz-desktop.png")" == "$missing_target" ]] || fail "missing target was rewritten"
}

run_pass_fixture
run_outside_fixture
run_mapped_outside_fixture
run_missing_fixture

echo "fix-appimage.sh root metadata symlink fixtures passed"
