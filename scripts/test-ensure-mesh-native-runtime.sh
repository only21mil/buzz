#!/usr/bin/env bash
# No native build: both cargo metadata and runtime preparation are fixtures.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP="$(mktemp -d)"
trap 'rm -rf -- "$TEMP"' EXIT
FIXTURE="$TEMP/worktree with spaces"
mkdir -p "$FIXTURE/scripts" "$FIXTURE/bin" "$TEMP/runtime"
cp "$ROOT/scripts/ensure-mesh-native-runtime.sh" "$FIXTURE/scripts/"
export TEST_MESH_ROOT="$TEMP/mesh" TEST_RUNTIME="$TEMP/runtime"
cat > "$FIXTURE/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import json, os
print(json.dumps({'packages': [{'name': 'mesh-llm-sdk', 'version': '1.0',
    'manifest_path': os.environ['TEST_MESH_ROOT'] + '/sdk/crate/Cargo.toml'}]}))
PY
STUB
mkdir -p "$TEMP/mesh/sdk/crate"
# The script resolves the SDK crate directory two levels upward.
mkdir -p "$TEMP/mesh/scripts"
cat > "$TEMP/mesh/scripts/ci-prepare-native-runtime.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$TEST_RUNTIME"
STUB
chmod +x "$FIXTURE/bin/cargo" "$TEMP/mesh/scripts/ci-prepare-native-runtime.sh"
printf 'payload\n' > "$TEMP/runtime/library"
export MESH_LLM_NATIVE_RUNTIME_CACHE_DIR="$TEMP/cache"
export MESH_LLM_NATIVE_RUNTIME_OUT_DIR="$TEMP/out"
write_manifest() {
  python3 - "$TEST_RUNTIME/manifest.json" "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1], 'w') as output:
    json.dump({'runtime': {'mesh_version': sys.argv[2], 'id': sys.argv[3]}}, output)
PY
}
write_manifest '1.0' 'runtime-cpu'
bash "$FIXTURE/scripts/ensure-mesh-native-runtime.sh" cpu > "$TEMP/stdout"
cmp "$TEMP/runtime/library" "$TEMP/cache/1.0/runtime-cpu/library"
[[ "$(cat "$TEMP/stdout")" == "$TEMP/cache" ]]
mkdir -p "$TEMP/keep"
printf 'do not remove\n' > "$TEMP/keep/sentinel"
for bad in '..' '../keep' '/absolute' '' $'line\nbreak'; do
  for field in version id; do
    if [[ "$field" == version ]]; then
      write_manifest "$bad" 'runtime-cpu'
    else
      write_manifest '1.0' "$bad"
    fi
    # An empty version deliberately retains the existing "unknown" fallback.
    [[ "$field" == version && -z "$bad" ]] && continue
    if bash "$FIXTURE/scripts/ensure-mesh-native-runtime.sh" cpu > "$TEMP/stdout" 2> "$TEMP/stderr"; then
      printf 'unexpectedly accepted %s=%q\n' "$field" "$bad" >&2
      exit 1
    fi
    grep -q 'Invalid native runtime path component' "$TEMP/stderr"
    [[ -f "$TEMP/keep/sentinel" ]]
  done
done
printf 'PASS: runtime cache paths and workspace spaces\n'
