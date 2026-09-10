#!/bin/bash
# Fixed unsigned app qualification derived from ci.yml:desktop-build-macos. No publishing step.
set -euo pipefail
test "$(id -u)" = 590
test "$(uname -sm)" = 'Darwin arm64'
source bin/activate-hermit
just desktop-install-ci
target=$(rustc -vV | sed -n 's|host: ||p')
test "$target" = aarch64-apple-darwin
mkdir -p desktop/src-tauri/binaries
for sidecar in buzz-acp buzz-agent buzz-backend-kubernetes buzz-dev-mcp git-credential-nostr buzz; do
    touch "desktop/src-tauri/binaries/$sidecar-$target"
done
mesh_rev=$(/usr/bin/python3 -I -c '
import re
from pathlib import Path
packages = re.split(r"(?m)^\[\[package\]\]\s*$", Path("Cargo.lock").read_text())
matches = [p for p in packages if re.search(r"(?m)^name = \"mesh-llm-sdk\"$", p)]
if len(matches) != 1:
    raise SystemExit("exactly one mesh package required")
sources = re.findall(r"(?m)^source = \"git\+https://github.com/Mesh-LLM/mesh-llm\.git[^\"\n]*#([0-9a-f]{40})\"$", matches[0])
if len(sources) != 1:
    raise SystemExit("exactly one pinned public mesh source required")
print(sources[0])')
[[ "$mesh_rev" =~ ^[0-9a-f]{40}$ ]]
cargo fetch --manifest-path desktop/src-tauri/Cargo.toml
mesh_root=$(find "$CARGO_HOME/git/checkouts" -path "*/${mesh_rev:0:7}" -type d -name "${mesh_rev:0:7}" | head -1)
test -n "$mesh_root"
export LLAMA_STAGE_BACKEND=metal
export LLAMA_STAGE_BUILD_DIR="$PWD/.cache/mesh-llama/build-stage-abi-metal"
export CMAKE_OSX_DEPLOYMENT_TARGET=10.15
export MACOSX_DEPLOYMENT_TARGET=10.15
export CMAKE_POLICY_VERSION_MINIMUM=3.5
export SKIPPY_LLAMA_AUTO_BUILD=0
"$mesh_root/scripts/prepare-llama.sh" pinned
"$mesh_root/scripts/build-llama.sh" -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15
cd desktop
# .app only avoids DMG Finder automation. Signing/updater secrets are absent.
# The trusted override disables project signing/notarization and updater output.
pnpm tauri build --bundles app --config '{"bundle":{"createUpdaterArtifacts":false,"macOS":{"signingIdentity":null}}}'
