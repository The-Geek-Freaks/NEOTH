#!/usr/bin/env bash
# build_example_plugins.sh — compile NEOTH example WASM plugins.
#
# Usage:
#   bash SRC/scripts/build_example_plugins.sh
#
# On Windows with MSVC, wrap cargo via the cargo-msvc.ps1 script:
#   powershell.exe -ExecutionPolicy Bypass -File scripts\cargo-msvc.ps1 \
#       build --manifest-path SRC/examples/wasm_plugins/echo/Cargo.toml \
#             --target wasm32-unknown-unknown --release
#
# Outputs (relative to repo root):
#   SRC/examples/wasm_plugins/echo/plugin.wasm
#   SRC/examples/wasm_plugins/recall_summariser/plugin.wasm
#
# These .wasm files are loaded by the neothd integration tests under
# --features wasm-plugin-host.  The tests are NOT gated on the files
# existing (they embed equivalent hand-crafted WAT bytes); the real .wasm
# files are for operator validation and plugin-dev reference.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLES_DIR="$REPO_ROOT/SRC/examples/wasm_plugins"
TARGET="wasm32-unknown-unknown"

echo "==> Checking for $TARGET target..."
if ! rustup target list --installed 2>/dev/null | grep -q "$TARGET"; then
    echo "    Installing $TARGET via rustup..."
    rustup target add "$TARGET"
fi

build_plugin() {
    local name="$1"
    local manifest="$EXAMPLES_DIR/$name/Cargo.toml"
    local out_name
    out_name="$(grep '^name' "$manifest" | head -1 | sed 's/.*= *"\(.*\)"/\1/' | tr '-' '_').wasm"
    local dest="$EXAMPLES_DIR/$name/plugin.wasm"

    echo "==> Building $name..."
    cargo build \
        --manifest-path "$manifest" \
        --target "$TARGET" \
        --release \
        2>&1

    local wasm_path
    wasm_path="$(dirname "$manifest")/target/$TARGET/release/$out_name"

    # Fallback: cargo may put artifacts under the workspace target dir.
    if [ ! -f "$wasm_path" ]; then
        wasm_path="$REPO_ROOT/SRC/target/$TARGET/release/$out_name"
    fi

    if [ ! -f "$wasm_path" ]; then
        echo "ERROR: could not locate compiled .wasm for $name"
        echo "  Searched: $(dirname "$manifest")/target/$TARGET/release/$out_name"
        echo "  and:      $REPO_ROOT/SRC/target/$TARGET/release/$out_name"
        exit 1
    fi

    cp "$wasm_path" "$dest"
    echo "    => $dest ($(wc -c < "$dest") bytes)"
}

build_plugin echo
build_plugin recall_summariser

echo ""
echo "==> All example plugins built."
echo "    Activate with: neoth plugin enable echo"
echo "    Activate with: neoth plugin enable recall-summariser"
