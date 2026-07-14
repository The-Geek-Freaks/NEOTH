#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly BUILDER="$SCRIPT_DIR/build-packages.sh"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

bash -n "$BUILDER" "$SCRIPT_DIR/uninstall-neoth.sh" "$0"
diff -u "$SCRIPT_DIR/fixtures/expected-layout.txt" <("$BUILDER" --print-layout)
"$BUILDER" --help >/dev/null
grep -F 'NEOTH-${version}-${target}.pkg' "$BUILDER" >/dev/null || fail "stable PKG asset name drifted"
grep -F 'NEOTH-${version}-${target}.dmg' "$BUILDER" >/dev/null || fail "stable DMG asset name drifted"
grep -F 'neoth-v${version}-${target}.tar.gz' "$BUILDER" >/dev/null || fail "signed portable asset name drifted"
grep -F '"sha256": "$checksum"' "$BUILDER" >/dev/null || fail "machine-readable checksum sidecar is missing"
grep -F '"$dmg_root/NEOTH.app"' "$BUILDER" >/dev/null || fail "DMG must expose NEOTH.app at top level"
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
printf '%s\n' 'neoth component 1.0.0'
EOF
  chmod 0755 "$fixture/$name"
done
for name in README.md LICENSE-MIT LICENSE-APACHE freedom.yaml.example import-manifest.example.yaml; do
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

printf 'macOS packaging contract checks passed\n'
