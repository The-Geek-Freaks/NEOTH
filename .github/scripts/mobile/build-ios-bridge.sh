#!/usr/bin/env bash
# Future hosted-run helper. This file is never invoked by the candidate author.
set -euo pipefail
: "${BRIDGE_CARGO_SHA256:?workflow input required}"
: "${BRIDGE_LIB_SHA256:?workflow input required}"
: "${BRIDGE_HEADER_SHA256:?workflow input required}"
: "${CANONICAL_PROTOCOL_SHA256:?workflow input required}"

repo_root="$(git rev-parse --show-toplevel)"; bridge="$repo_root/bridges/companion-native"; protocol="$repo_root/SRC/neothd/src/daemon/companion_protocol.rs"; source_lock="$repo_root/SRC/Cargo.lock"; stage="${1:?native staging root required}"
sha256() { shasum -a 256 "$1" | awk '{print toupper($1)}'; }
uppercase() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }
require_hash() { local path="$1" expected="$2" actual expected_upper; [[ "$expected" =~ ^[0-9A-Fa-f]{64}$ && -f "$path" ]] || { echo "invalid hash or missing source: $path" >&2; exit 64; }; actual="$(sha256 "$path")"; expected_upper="$(uppercase "$expected")"; [[ "$actual" == "$expected_upper" ]] || { echo "source SHA-256 mismatch: $path expected=$expected_upper actual=$actual" >&2; exit 65; }; }
[[ "$GITHUB_REF" == "refs/heads/main" && "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]] || { echo "producer source provenance rejected" >&2; exit 66; }
require_hash "$bridge/Cargo.toml" "$BRIDGE_CARGO_SHA256"; require_hash "$bridge/src/lib.rs" "$BRIDGE_LIB_SHA256"; require_hash "$bridge/include/neoth_companion_bridge.h" "$BRIDGE_HEADER_SHA256"; require_hash "$protocol" "$CANONICAL_PROTOCOL_SHA256"
[[ -f "$repo_root/SRC/vendor/peeroxide/Cargo.toml" && -f "$source_lock" ]] || { echo "bridge prerequisites missing" >&2; exit 67; }
src_lock_before="$(sha256 "$source_lock")"; if [[ ! -f "$bridge/Cargo.lock" ]]; then cargo generate-lockfile --manifest-path "$bridge/Cargo.toml"; fi; [[ -f "$bridge/Cargo.lock" ]] || { echo "standalone bridge Cargo.lock missing" >&2; exit 68; }; cargo test --manifest-path "$bridge/Cargo.toml" --locked; [[ "$(sha256 "$source_lock")" == "$src_lock_before" ]] || { echo "SRC/Cargo.lock changed during bridge test" >&2; exit 69; }
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do rustup target add "$target"; cargo build --manifest-path "$bridge/Cargo.toml" --locked --release --target "$target"; done
device="$bridge/target/aarch64-apple-ios/release/libneoth_companion_bridge.a"; sim_arm="$bridge/target/aarch64-apple-ios-sim/release/libneoth_companion_bridge.a"; sim_x64="$bridge/target/x86_64-apple-ios/release/libneoth_companion_bridge.a"
[[ -f "$device" && -f "$sim_arm" && -f "$sim_x64" ]] || { echo "iOS static library output missing" >&2; exit 70; }; [[ "$(sha256 "$source_lock")" == "$src_lock_before" ]] || { echo "SRC/Cargo.lock changed during iOS build" >&2; exit 71; }
mkdir -p "$stage/ios/simulator"; lipo -create "$sim_arm" "$sim_x64" -output "$stage/ios/simulator/libneoth_companion_bridge.a"
cp "$bridge/Cargo.lock" "$stage/bridge-Cargo.lock"
xcodebuild -create-xcframework -library "$device" -headers "$bridge/include" -library "$stage/ios/simulator/libneoth_companion_bridge.a" -headers "$bridge/include" -output "$stage/ios/NEOTHCompanionBridge.xcframework"
[[ -f "$stage/ios/NEOTHCompanionBridge.xcframework/Info.plist" ]] || { echo "XCFramework manifest missing" >&2; exit 72; }
files='[]'; while IFS= read -r relative; do files="$(jq -c --arg p "$relative" --arg h "$(sha256 "$stage/$relative")" '. + [{relative_path:$p,sha256:$h}]' <<< "$files")"; done < <(cd "$stage" && find ios/NEOTHCompanionBridge.xcframework -type f -print | LC_ALL=C sort)
jq -n --arg head "$GITHUB_SHA" --arg lock "$(sha256 "$bridge/Cargo.lock")" --arg cargo "$(uppercase "$BRIDGE_CARGO_SHA256")" --arg lib "$(uppercase "$BRIDGE_LIB_SHA256")" --arg header "$(uppercase "$BRIDGE_HEADER_SHA256")" --arg protocol "$(uppercase "$CANONICAL_PROTOCOL_SHA256")" --arg src_lock "$src_lock_before" --argjson files "$files" '{schema:"neoth.mobile-native-artifact-manifest.v1",platform:"ios",source:{head:$head,bridge_cargo_sha256:$cargo,bridge_lib_sha256:$lib,bridge_header_sha256:$header,canonical_protocol_sha256:$protocol,bridge_cargo_lock_sha256:$lock,src_cargo_lock_sha256:$src_lock},files:$files}' > "$stage/ios-native-manifest.json"
