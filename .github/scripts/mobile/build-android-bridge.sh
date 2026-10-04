#!/usr/bin/env bash
# Future hosted-run helper. This file is never invoked by the candidate author.
set -euo pipefail

: "${BRIDGE_CARGO_SHA256:?workflow input required}"
: "${BRIDGE_LIB_SHA256:?workflow input required}"
: "${BRIDGE_HEADER_SHA256:?workflow input required}"
: "${CANONICAL_PROTOCOL_SHA256:?workflow input required}"
: "${ANDROID_NDK_HOME:?Android NDK root required}"

repo_root="$(git rev-parse --show-toplevel)"
bridge="$repo_root/bridges/companion-native"
protocol="$repo_root/SRC/neothd/src/daemon/companion_protocol.rs"
source_lock="$repo_root/SRC/Cargo.lock"
stage="${1:?native staging root required}"

sha256() { sha256sum "$1" | awk '{print toupper($1)}'; }
require_hash() {
  local path="$1" expected="$2" actual
  [[ "$expected" =~ ^[0-9A-Fa-f]{64}$ ]] || { echo "invalid expected SHA-256 for $path" >&2; exit 64; }
  [[ -f "$path" ]] || { echo "missing required source: $path" >&2; exit 65; }
  actual="$(sha256 "$path")"
  [[ "$actual" == "${expected^^}" ]] || { echo "source SHA-256 mismatch: $path expected=${expected^^} actual=$actual" >&2; exit 66; }
}

[[ "$GITHUB_REF" == "refs/heads/main" ]] || { echo "manual producer accepts main only" >&2; exit 67; }
[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]] || { echo "checked-out source does not equal dispatch SHA" >&2; exit 68; }
require_hash "$bridge/Cargo.toml" "$BRIDGE_CARGO_SHA256"
require_hash "$bridge/src/lib.rs" "$BRIDGE_LIB_SHA256"
require_hash "$bridge/include/neoth_companion_bridge.h" "$BRIDGE_HEADER_SHA256"
require_hash "$protocol" "$CANONICAL_PROTOCOL_SHA256"
[[ -f "$repo_root/SRC/vendor/peeroxide/Cargo.toml" && -f "$source_lock" ]] || { echo "bridge prerequisites missing" >&2; exit 69; }

src_lock_before="$(sha256 "$source_lock")"
if [[ ! -f "$bridge/Cargo.lock" ]]; then cargo generate-lockfile --manifest-path "$bridge/Cargo.toml"; fi
[[ -f "$bridge/Cargo.lock" ]] || { echo "standalone bridge Cargo.lock was not created" >&2; exit 70; }
cargo test --manifest-path "$bridge/Cargo.toml" --locked
[[ "$(sha256 "$source_lock")" == "$src_lock_before" ]] || { echo "SRC/Cargo.lock changed during bridge test" >&2; exit 71; }

toolchain="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
[[ -x "$toolchain/bin/aarch64-linux-android21-clang" ]] || { echo "NDK clang toolchain is incomplete" >&2; exit 72; }
mkdir -p "$stage/android"
targets=("aarch64-linux-android:arm64-v8a:aarch64-linux-android21-clang" "armv7-linux-androideabi:armeabi-v7a:armv7a-linux-androideabi21-clang" "x86_64-linux-android:x86_64:x86_64-linux-android21-clang")
for item in "${targets[@]}"; do
  IFS=: read -r target abi linker <<< "$item"
  rustup target add "$target"
  target_key="${target^^}"; target_key="${target_key//-/_}"
  export "CARGO_TARGET_${target_key}_LINKER=$toolchain/bin/$linker"
  cargo build --manifest-path "$bridge/Cargo.toml" --locked --release --target "$target"
  output="$bridge/target/$target/release/libneoth_companion_bridge.so"
  [[ -f "$output" ]] || { echo "Android bridge output missing: $output" >&2; exit 73; }
  mkdir -p "$stage/android/$abi"
  cp "$output" "$stage/android/$abi/libneoth_companion_bridge.so"
done
[[ "$(sha256 "$source_lock")" == "$src_lock_before" ]] || { echo "SRC/Cargo.lock changed during Android build" >&2; exit 74; }
cp "$bridge/Cargo.lock" "$stage/bridge-Cargo.lock"

jq -n \
  --arg head "$GITHUB_SHA" --arg lock "$(sha256 "$bridge/Cargo.lock")" \
  --arg cargo "${BRIDGE_CARGO_SHA256^^}" --arg lib "${BRIDGE_LIB_SHA256^^}" \
  --arg header "${BRIDGE_HEADER_SHA256^^}" --arg protocol "${CANONICAL_PROTOCOL_SHA256^^}" \
  --arg src_lock "$src_lock_before" \
  --arg a64 "$(sha256 "$stage/android/arm64-v8a/libneoth_companion_bridge.so")" \
  --arg arm "$(sha256 "$stage/android/armeabi-v7a/libneoth_companion_bridge.so")" \
  --arg x64 "$(sha256 "$stage/android/x86_64/libneoth_companion_bridge.so")" \
  '{schema:"neoth.mobile-native-artifact-manifest.v1",platform:"android",source:{head:$head,bridge_cargo_sha256:$cargo,bridge_lib_sha256:$lib,bridge_header_sha256:$header,canonical_protocol_sha256:$protocol,bridge_cargo_lock_sha256:$lock,src_cargo_lock_sha256:$src_lock},files:[{relative_path:"android/arm64-v8a/libneoth_companion_bridge.so",sha256:$a64},{relative_path:"android/armeabi-v7a/libneoth_companion_bridge.so",sha256:$arm},{relative_path:"android/x86_64/libneoth_companion_bridge.so",sha256:$x64}]}' > "$stage/android-native-manifest.json"
