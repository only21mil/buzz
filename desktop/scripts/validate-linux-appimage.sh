#!/usr/bin/env bash
# Validate the runtime-critical GTK/WebKit contents of one Tauri AppImage.
# Extraction uses the AppImage runtime's --appimage-extract path and never FUSE.

set -euo pipefail

fail() {
  echo "Error: $*" >&2
  exit 1
}

if [[ $# -ne 1 ]]; then
  fail "usage: $0 <path-to.AppImage>"
fi

for command in find grep readelf realpath strings; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

[[ -f "$1" ]] || fail "AppImage not found: $1"
[[ -x "$1" ]] || fail "AppImage is not executable: $1"
appimage="$(realpath "$1")"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

extract_log="$workdir/extract.log"
if ! (cd "$workdir" && "$appimage" --appimage-extract >"$extract_log" 2>&1); then
  echo "AppImage extraction output:" >&2
  tail -n 80 "$extract_log" >&2 || true
  fail "could not extract $appimage with --appimage-extract"
fi

appdir="$workdir/squashfs-root"
[[ -d "$appdir" ]] || fail "extraction did not create squashfs-root"

for launcher in AppRun AppRun.wrapped; do
  [[ -f "$appdir/$launcher" ]] || fail "missing root launcher: $launcher"
  [[ -x "$appdir/$launcher" ]] || fail "root launcher is not executable: $launcher"
done

# Gate every root metadata symlink that the packaged AppImage exposes.
mapfile -d '' -t root_links < <(
  find "$appdir" -maxdepth 1 -type l \
    \( -name '.DirIcon' -o -name '*.desktop' -o -name '*.png' \) -print0 | sort -z
)
[[ ${#root_links[@]} -gt 0 ]] || fail "no root desktop/icon symlinks were bundled"
desktop_link_count=0
icon_link_count=0
for link in "${root_links[@]}"; do
  case "$link" in
    *.desktop) ((desktop_link_count += 1)) ;;
    *.png) ((icon_link_count += 1)) ;;
  esac
  target="$(readlink "$link")"
  [[ "$target" != /* ]] || fail "root symlink must be relative: ${link#"$appdir/"} -> $target"
  resolved="$(realpath -e "$link" 2>/dev/null)" || \
    fail "root symlink does not resolve: ${link#"$appdir/"} -> $target"
  case "$resolved" in
    "$appdir"/*) ;;
    *) fail "root symlink escapes AppDir: ${link#"$appdir/"} -> $target" ;;
  esac
done
[[ $desktop_link_count -gt 0 ]] || fail "no root .desktop symlink was bundled"
[[ $icon_link_count -gt 0 ]] || fail "no root .png icon symlink was bundled"

find_exactly_one() {
  local description="$1"
  shift
  local -a matches=()
  mapfile -d '' -t matches < <(find "$appdir" "$@" -print0 | sort -z)
  if [[ ${#matches[@]} -ne 1 ]]; then
    fail "expected exactly one $description, found ${#matches[@]}"
  fi
  printf '%s\n' "${matches[0]}"
}

gtk_cache="$(find_exactly_one 'GTK immodules cache' -type f -path '*/gtk-3.0/*/immodules.cache')"
pixbuf_cache="$(find_exactly_one 'GDK pixbuf loaders cache' -type f -path '*/gdk-pixbuf-2.0/*/loaders.cache')"

validate_module_cache() {
  local label="$1"
  local cache="$2"
  local entry entry_count=0

  [[ -s "$cache" ]] || fail "$label cache is empty: ${cache#"$appdir/"}"
  while IFS= read -r entry; do
    entry="${entry#\"}"
    entry="${entry%%\"*}"
    [[ -n "$entry" ]] || continue
    ((entry_count += 1))
    [[ "$entry" != /* ]] || fail "$label cache contains a host-absolute module: $entry"
    if [[ ! -e "$(dirname "$cache")/$entry" && ! -e "$appdir/usr/lib/$entry" ]]; then
      fail "$label cache entry does not resolve inside AppDir: $entry"
    fi
  done < <(grep -E '^"[^"[:space:]]+\.so[^"[:space:]]*"[[:space:]]*$' "$cache" || true)

  [[ $entry_count -gt 0 ]] || fail "$label cache contains no relative .so module entries"
}

validate_module_cache "GTK immodules" "$gtk_cache"
validate_module_cache "GDK pixbuf loaders" "$pixbuf_cache"

gtk_hook="$(find_exactly_one 'linuxdeploy GTK AppRun hook' -type f -path '*/apprun-hooks/linuxdeploy-plugin-gtk.sh')"
[[ -s "$gtk_hook" ]] || fail "linuxdeploy GTK AppRun hook is empty"

require_hook_export() {
  local name="$1"
  local expected_path="$2"
  local appdir_reference="\\\$APPDIR|\\\$\\{APPDIR\\}"
  local -a exports=()
  mapfile -t exports < <(grep -E "^export[[:space:]]+$name=" "$gtk_hook" || true)
  [[ ${#exports[@]} -eq 1 ]] || \
    fail "GTK AppRun hook must export $name exactly once; found ${#exports[@]}"
  grep -Eq "$appdir_reference" <<<"${exports[0]}" || \
    fail "GTK AppRun hook export $name is not rooted at \$APPDIR"
  [[ "${exports[0]}" == *"$expected_path"* ]] || \
    fail "GTK AppRun hook export $name does not reference $expected_path"
}

gtk_cache_rel="${gtk_cache#"$appdir/"}"
pixbuf_cache_rel="${pixbuf_cache#"$appdir/"}"
require_hook_export GTK_IM_MODULE_FILE "$gtk_cache_rel"
require_hook_export GDK_PIXBUF_MODULE_FILE "$pixbuf_cache_rel"
require_hook_export GTK_PATH 'gtk-3.0'

gio_module="$(find_exactly_one 'bundled GIO TLS module (libgiognutls)' -type f -path '*/gio/modules/libgiognutls.so')"
[[ -s "$gio_module" ]] || fail "bundled GIO TLS module is empty: ${gio_module#"$appdir/"}"
gio_dir_rel="$(dirname "${gio_module#"$appdir/"}")"
require_hook_export GIO_EXTRA_MODULES "$gio_dir_rel"

schemas="$appdir/usr/share/glib-2.0/schemas/gschemas.compiled"
[[ -s "$schemas" ]] || fail "missing compiled GSettings schemas: usr/share/glib-2.0/schemas/gschemas.compiled"
require_hook_export GSETTINGS_SCHEMA_DIR 'usr/share/glib-2.0/schemas'

webkit_lib="$(find_exactly_one 'bundled WebKitGTK 4.1 shared library' -type f -name 'libwebkit2gtk-4.1.so*')"
network_helper="$(find_exactly_one 'WebKitNetworkProcess helper' -type f -name WebKitNetworkProcess)"
web_helper="$(find_exactly_one 'WebKitWebProcess helper' -type f -name WebKitWebProcess)"

[[ "$(basename "$(dirname "$network_helper")")" == 'webkit2gtk-4.1' ]] || \
  fail "WebKitNetworkProcess is not in a webkit2gtk-4.1 helper directory"
[[ "$(dirname "$network_helper")" == "$(dirname "$web_helper")" ]] || \
  fail "WebKit process helpers are not colocated"

elf_identity() {
  local file="$1"
  local header
  header="$(readelf -h "$file" 2>/dev/null)" || return 1
  awk -F: '
    /^[[:space:]]*Class:/ || /^[[:space:]]*Data:/ || /^[[:space:]]*Machine:/ {
      value = $2
      sub(/^[[:space:]]+/, "", value)
      printf "%s|", value
    }
  ' <<<"$header"
}

if ! webkit_identity="$(elf_identity "$webkit_lib")"; then
  fail "bundled WebKitGTK library is not a readable ELF: ${webkit_lib#"$appdir/"}"
fi
[[ -n "$webkit_identity" ]] || fail "bundled WebKitGTK library is not a readable ELF: ${webkit_lib#"$appdir/"}"

mapfile -d '' -t webkit_helpers < <(
  find "$(dirname "$network_helper")" -maxdepth 1 -type f -name 'WebKit*Process' -print0 | sort -z
)
for helper in "${webkit_helpers[@]}"; do
  [[ -x "$helper" ]] || fail "WebKit helper is not executable: ${helper#"$appdir/"}"
  if ! helper_identity="$(elf_identity "$helper")"; then
    fail "WebKit helper is not a readable ELF: ${helper#"$appdir/"}"
  fi
  [[ "$helper_identity" == "$webkit_identity" ]] || \
    fail "WebKit helper ELF does not match bundled WebKitGTK library: ${helper#"$appdir/"}"
done

bad_lookup="$(
  strings -a "$webkit_lib" | \
    grep -E -m1 '/usr/lib/([^/[:space:]]+/)*webkit2gtk-4[.]1(/[^[:space:]]*)?' || true
)"
[[ -z "$bad_lookup" ]] || \
  fail "bundled WebKitGTK library still contains host-absolute helper lookup '$bad_lookup'; linuxdeploy GTK rewrite did not complete"

echo "Validated AppImage GTK/WebKit runtime: $appimage"
