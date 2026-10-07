#!/usr/bin/env bash
# W2328 R8 hosted-only builder: exact committed debug CLI + host cdylib.
set -euo pipefail
: "${EXPECTED_HEAD:?exact source head required}"; : "${BRIDGE_CARGO_SHA256:?required}"
: "${BRIDGE_LIB_SHA256:?required}"; : "${BRIDGE_HEADER_SHA256:?required}"
: "${CANONICAL_PROTOCOL_SHA256:?required}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"
stage="${1:?fresh stage required}"; repo="$(git rev-parse --show-toplevel)"
bridge="$repo/bridges/companion-native"; protocol="$repo/SRC/neothd/src/daemon/companion_protocol.rs"
[[ "$(git rev-parse HEAD)" == "$EXPECTED_HEAD" && ! -e "$stage" ]] || { echo 'invalid source/stage custody' >&2; exit 64; }
sha() { sha256sum "$1" | awk '{print toupper($1)}'; }
verify() { [[ "$2" =~ ^[0-9A-Fa-f]{64}$ && -f "$1" && "$(sha "$1")" == "${2^^}" ]] || { echo "protected source mismatch: $1" >&2; exit 65; }; }
verify "$bridge/Cargo.toml" "$BRIDGE_CARGO_SHA256"; verify "$bridge/src/lib.rs" "$BRIDGE_LIB_SHA256"
verify "$bridge/include/neoth_companion_bridge.h" "$BRIDGE_HEADER_SHA256"; verify "$protocol" "$CANONICAL_PROTOCOL_SHA256"
lock="$(sha "$repo/SRC/Cargo.lock")"; cargo build --manifest-path "$bridge/Cargo.toml" --locked
cargo build --manifest-path "$repo/SRC/Cargo.toml" --locked --package neoth --bin neoth
[[ "$(sha "$repo/SRC/Cargo.lock")" == "$lock" ]] || { echo 'SRC Cargo.lock changed' >&2; exit 66; }
lib="$bridge/target/debug/libneoth_companion_bridge.so"; bin="$repo/SRC/target/debug/neoth"
[[ -f "$lib" && -x "$bin" ]] || { echo 'host artifacts missing' >&2; exit 67; }
symbols=(neoth_companion_bridge_new neoth_companion_pair_start neoth_companion_reconnect_start neoth_companion_chat_start neoth_companion_operation_poll neoth_companion_operation_cancel neoth_companion_operation_free neoth_companion_bridge_free neoth_companion_chat_start_v2 neoth_companion_operation_poll_v2)
for symbol in "${symbols[@]}"; do nm -D --defined-only "$lib" | awk '{print $3}' | grep -Fx "$symbol" >/dev/null || { echo "required ABI symbol absent: $symbol" >&2; exit 68; }; done
mkdir -p "$stage"; cp "$lib" "$stage/libneoth_companion_bridge.so"; cp "$bin" "$stage/neoth"
printf '{"schema":"neoth.wave2328.host-interop-build.r2.v1","source_head":"%s","profile":"debug","artifacts":{"neoth_sha256":"%s","bridge_sha256":"%s"},"required_symbols":["neoth_companion_bridge_new","neoth_companion_pair_start","neoth_companion_reconnect_start","neoth_companion_chat_start","neoth_companion_operation_poll","neoth_companion_operation_cancel","neoth_companion_operation_free","neoth_companion_bridge_free","neoth_companion_chat_start_v2","neoth_companion_operation_poll_v2"]}\n' "$EXPECTED_HEAD" "$(sha "$stage/neoth")" "$(sha "$stage/libneoth_companion_bridge.so")" > "$stage/host-interop-manifest.json"
