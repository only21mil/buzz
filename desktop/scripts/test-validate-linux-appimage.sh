#!/usr/bin/env bash
# Focused static fixtures for validate-linux-appimage.sh. No app build needed.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
validator="$script_dir/validate-linux-appimage.sh"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

base="$workdir/base"
mkdir -p \
  "$base/apprun-hooks" \
  "$base/usr/bin" \
  "$base/usr/lib/x-test-linux-gnu/gio/modules" \
  "$base/usr/lib/x-test-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders" \
  "$base/usr/lib/x-test-linux-gnu/gtk-3.0/3.0.0/immodules" \
  "$base/usr/lib/x-test-linux-gnu/webkit2gtk-4.1" \
  "$base/usr/share/applications" \
  "$base/usr/share/glib-2.0/schemas" \
  "$base/usr/share/icons/hicolor/128x128/apps"

cp /bin/true "$base/AppRun"
cp /bin/true "$base/AppRun.wrapped"
cp /bin/true "$base/usr/lib/libwebkit2gtk-4.1.so.0"
cp /bin/true "$base/usr/lib/x-test-linux-gnu/webkit2gtk-4.1/WebKitNetworkProcess"
cp /bin/true "$base/usr/lib/x-test-linux-gnu/webkit2gtk-4.1/WebKitWebProcess"
cp /bin/true "$base/usr/lib/x-test-linux-gnu/gio/modules/libgiognutls.so"
touch "$base/usr/lib/x-test-linux-gnu/gtk-3.0/3.0.0/immodules/im-test.so"
touch "$base/usr/lib/x-test-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-test.so"
ln -s x-test-linux-gnu/gtk-3.0/3.0.0/immodules/im-test.so "$base/usr/lib/im-test.so"
ln -s x-test-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-test.so \
  "$base/usr/lib/libpixbufloader-test.so"

cat > "$base/usr/lib/x-test-linux-gnu/gtk-3.0/3.0.0/immodules.cache" <<'EOF'
# synthetic GTK cache
"im-test.so"
"test" "Test" "gtk30" "/usr/share/locale" ""
EOF
cat > "$base/usr/lib/x-test-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache" <<'EOF'
# synthetic GDK pixbuf cache
"libpixbufloader-test.so"
"test" 0 "gdk-pixbuf" "Test" "LGPL"
EOF
cat > "$base/apprun-hooks/linuxdeploy-plugin-gtk.sh" <<'EOF'
#!/usr/bin/env bash
export GTK_PATH="$APPDIR/usr/lib/x-test-linux-gnu/gtk-3.0"
export GTK_IM_MODULE_FILE="$APPDIR/usr/lib/x-test-linux-gnu/gtk-3.0/3.0.0/immodules.cache"
export GDK_PIXBUF_MODULE_FILE="$APPDIR/usr/lib/x-test-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache"
export GIO_EXTRA_MODULES="$APPDIR/usr/lib/x-test-linux-gnu/gio/modules"
export GSETTINGS_SCHEMA_DIR="$APPDIR/usr/share/glib-2.0/schemas"
EOF
printf 'synthetic schemas\n' > "$base/usr/share/glib-2.0/schemas/gschemas.compiled"
printf '[Desktop Entry]\nName=Buzz\n' > "$base/usr/share/applications/Buzz.desktop"
printf 'png\n' > "$base/usr/share/icons/hicolor/128x128/apps/buzz-desktop.png"
ln -s usr/share/applications/Buzz.desktop "$base/Buzz.desktop"
ln -s usr/share/icons/hicolor/128x128/apps/buzz-desktop.png "$base/buzz-desktop.png"
ln -s usr/share/icons/hicolor/128x128/apps/buzz-desktop.png "$base/.DirIcon"

fake_appimage="$workdir/fake.AppImage"
cat > "$fake_appimage" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1-}" == '--appimage-extract' ]]
cp -a "$FAKE_APPDIR_SOURCE" squashfs-root
EOF
chmod +x "$fake_appimage"

case_dir() {
  local name="$1"
  local destination="$workdir/$name"
  mkdir "$destination"
  cp -a "$base/." "$destination/"
  printf '%s\n' "$destination"
}

expect_pass() {
  local fixture="$1"
  if ! FAKE_APPDIR_SOURCE="$fixture" "$validator" "$fake_appimage" >"$workdir/pass.log" 2>&1; then
    cat "$workdir/pass.log" >&2
    echo "Expected validator success" >&2
    exit 1
  fi
}

expect_fail() {
  local fixture="$1"
  local expected="$2"
  if FAKE_APPDIR_SOURCE="$fixture" "$validator" "$fake_appimage" >"$workdir/fail.log" 2>&1; then
    echo "Expected validator failure containing: $expected" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" "$workdir/fail.log"; then
    cat "$workdir/fail.log" >&2
    echo "Validator failure did not contain: $expected" >&2
    exit 1
  fi
}

expect_pass "$base"

missing_cache="$(case_dir missing-cache)"
rm "$missing_cache/usr/lib/x-test-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache"
expect_fail "$missing_cache" "expected exactly one GDK pixbuf loaders cache, found 0"

absolute_webkit="$(case_dir absolute-webkit)"
printf '\0/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitNetworkProcess\0' >> \
  "$absolute_webkit/usr/lib/libwebkit2gtk-4.1.so.0"
expect_fail "$absolute_webkit" "still contains host-absolute helper lookup"

missing_helper="$(case_dir missing-helper)"
rm "$missing_helper/usr/lib/x-test-linux-gnu/webkit2gtk-4.1/WebKitNetworkProcess"
expect_fail "$missing_helper" "expected exactly one WebKitNetworkProcess helper, found 0"

broken_link="$(case_dir broken-link)"
ln -sfn /build/Buzz.desktop "$broken_link/Buzz.desktop"
expect_fail "$broken_link" "root symlink must be relative"

broken_dir_icon="$(case_dir broken-dir-icon)"
ln -sfn /build/buzz-desktop.png "$broken_dir_icon/.DirIcon"
expect_fail "$broken_dir_icon" "root symlink must be relative"

echo "validate-linux-appimage.sh fixtures passed"
