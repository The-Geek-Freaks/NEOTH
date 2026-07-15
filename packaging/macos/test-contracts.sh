#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly BUILDER="$SCRIPT_DIR/build-packages.sh"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

expect_fail_contains() {
  local pattern=$1
  shift
  local output
  if output=$("$@" 2>&1); then
    fail "command unexpectedly succeeded: $*"
  fi
  grep -F -- "$pattern" <<<"$output" >/dev/null ||
    fail "failure did not contain '$pattern': $output"
}

bash -n "$BUILDER" "$SCRIPT_DIR/uninstall-neoth.sh" "$0"
diff -u <(sed 's/\r$//' "$SCRIPT_DIR/fixtures/expected-layout.txt") <("$BUILDER" --print-layout)
"$BUILDER" --help >/dev/null
grep -F 'NEOTH-${version}-${target}.pkg' "$BUILDER" >/dev/null || fail "stable PKG asset name drifted"
grep -F 'NEOTH-${version}-${target}.dmg' "$BUILDER" >/dev/null || fail "stable DMG asset name drifted"
grep -F 'neoth-v${version}-${target}.tar.gz' "$BUILDER" >/dev/null || fail "signed portable asset name drifted"
grep -F '"sha256": "$checksum"' "$BUILDER" >/dev/null || fail "machine-readable checksum sidecar is missing"
grep -F '"$dmg_root/NEOTH.app"' "$BUILDER" >/dev/null || fail "DMG must expose NEOTH.app at top level"
grep -A2 -F '<key>LSEnvironment</key>' "$SCRIPT_DIR/Info.plist.in" | grep -F '<key>NEOTH_PRODUCT_LAUNCHER</key>' >/dev/null ||
  fail "macOS app launch must enter product-launcher mode"
grep -A1 -F '<key>NEOTH_PRODUCT_LAUNCHER</key>' "$SCRIPT_DIR/Info.plist.in" | grep -F '<string>1</string>' >/dev/null ||
  fail "macOS product-launcher environment must be exact"
grep -A1 -F '<key>CFBundleExecutable</key>' "$SCRIPT_DIR/Info.plist.in" | grep -F '<string>neothd-gui</string>' >/dev/null ||
  fail "macOS app must retain the signed native GUI executable"
grep -F 'plutil -extract LSEnvironment.NEOTH_PRODUCT_LAUNCHER raw' "$BUILDER" >/dev/null ||
  fail "macOS builder must verify the staged and final product-launcher contract"
if "$BUILDER" --unknown >/dev/null 2>&1; then
  fail "unknown arguments must fail"
fi
if grep -E -- '/\.neoth|HOME.*\.neoth|~/\.neoth' "$SCRIPT_DIR/build-packages.sh" "$SCRIPT_DIR/uninstall-neoth.sh" >/dev/null; then
  fail "installer and uninstaller must not address user state"
fi
if "$BUILDER" --bundle nowhere --version 1.0.0 --arch arm64 --validate-only --require-signing >/dev/null 2>&1; then
  fail "required signing must fail without identities"
fi
if "$BUILDER" --bundle nowhere --version 1.0.0 --arch arm64 --validate-only \
  --application-identity app --installer-identity installer --require-notarization >/dev/null 2>&1; then
  fail "required notarization must fail without a keychain profile"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/neoth-macos-contracts.XXXXXX")"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fixture="$work/neoth-v1.0.0-aarch64-apple-darwin"
fake_bin="$work/bin"
mkdir -p "$fixture" "$fake_bin"
for name in neoth neothd neothd-gui neoth-migrate neoth-relay neoth-keet-bridge; do
  cat >"$fixture/$name" <<'EOF'
#!/usr/bin/env sh
if [ -n "${EXEC_LOG:-}" ]; then
  printf '%s\n' "$(basename "$0")" >>"$EXEC_LOG"
fi
printf '%s\n' 'neoth component 1.0.0'
EOF
  chmod 0755 "$fixture/$name"
done
for name in README.md LICENSE-MIT LICENSE-APACHE THIRD_PARTY_LICENSES freedom.yaml.example import-manifest.example.yaml; do
  printf 'fixture %s\n' "$name" >"$fixture/$name"
done
cat >"$fake_bin/lipo" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "${FAKE_ARCH:-arm64}"
EOF
chmod 0755 "$fake_bin/lipo"

PATH="$fake_bin:$PATH" "$BUILDER" --bundle "$fixture" --version 1.0.0 --arch arm64 --validate-only >/dev/null
if FAKE_ARCH=x86_64 PATH="$fake_bin:$PATH" "$BUILDER" --bundle "$fixture" --version 1.0.0 --arch arm64 --validate-only >/dev/null 2>&1; then
  fail "a mismatched Mach-O architecture must fail"
fi
rm "$fixture/neoth-keet-bridge"
if PATH="$fake_bin:$PATH" "$BUILDER" --bundle "$fixture" --version 1.0.0 --arch arm64 --validate-only >/dev/null 2>&1; then
  fail "a missing Keet companion must fail"
fi

# A preflight receipt is minted only by the runtime/architecture/version path.
# Its consume path verifies exact bytes and must not execute product code while
# signing identities are available.
printf 'fixture neoth-keet-bridge\n' >"$fixture/neoth-keet-bridge"
cat >"$fixture/neoth-keet-bridge" <<'EOF'
#!/usr/bin/env sh
if [ -n "${EXEC_LOG:-}" ]; then
  printf '%s\n' "$(basename "$0")" >>"$EXEC_LOG"
fi
printf '%s\n' '1.0.0'
EOF
chmod 0755 "$fixture/neoth-keet-bridge"
receipt="$work/preflight.receipt"
exec_log="$work/executed-products.log"
EXEC_LOG="$exec_log" PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$fixture" --version 1.0.0 --arch arm64 --validate-only \
  --write-preflight-receipt "$receipt" >/dev/null
[[ $(wc -l <"$exec_log") -eq 5 ]] || fail "preflight must execute all five versioned products"

: >"$exec_log"
expect_fail_contains '--source-date-epoch must be an integer' \
  env EXEC_LOG="$exec_log" PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$fixture" --version 1.0.0 --arch arm64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$receipt"
[[ ! -s $exec_log ]] || fail "receipt consume path executed a product binary"

expect_fail_contains 'preflight receipt must be a regular, non-symlink file' \
  env PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$fixture" --version 1.0.0 --arch arm64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$work/missing.receipt"

tampered="$work/tampered/neoth-v1.0.0-aarch64-apple-darwin"
mkdir -p "$(dirname "$tampered")"
cp -R "$fixture" "$tampered"
printf 'tamper\n' >>"$tampered/README.md"
expect_fail_contains 'preflight receipt does not match version, target, architecture, or bundle bytes' \
  env PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$tampered" --version 1.0.0 --arch arm64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$receipt"

stale_receipt="$work/stale.receipt"
sed 's/^version 1\.0\.0$/version 1.0.1/' "$receipt" >"$stale_receipt"
expect_fail_contains 'preflight receipt does not match version, target, architecture, or bundle bytes' \
  env PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$fixture" --version 1.0.0 --arch arm64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$stale_receipt"

version_bundle="$work/version/neoth-v1.0.1-aarch64-apple-darwin"
mkdir -p "$(dirname "$version_bundle")"
cp -R "$fixture" "$version_bundle"
expect_fail_contains 'preflight receipt does not match version, target, architecture, or bundle bytes' \
  env PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$version_bundle" --version 1.0.1 --arch arm64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$receipt"

target_bundle="$work/target/neoth-v1.0.0-x86_64-apple-darwin"
mkdir -p "$(dirname "$target_bundle")"
cp -R "$fixture" "$target_bundle"
expect_fail_contains 'preflight receipt does not match version, target, architecture, or bundle bytes' \
  env FAKE_ARCH=x86_64 PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$target_bundle" --version 1.0.0 --arch x86_64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$receipt"

printf 'macOS packaging contract checks passed\n'
