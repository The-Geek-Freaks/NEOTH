#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
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

bash -n "$BUILDER" "$0"
diff -u <(sed 's/\r$//' "$SCRIPT_DIR/fixtures/expected-layout.txt") <("$BUILDER" --print-layout)
"$BUILDER" --help >/dev/null
grep -F 'NEOTH-${version}-${target}.deb' "$BUILDER" >/dev/null || fail "stable DEB asset name drifted"
grep -F 'NEOTH-${version}-${target}.rpm' "$BUILDER" >/dev/null || fail "stable RPM asset name drifted"
grep -F '"sha256": "$checksum"' "$BUILDER" >/dev/null || fail "machine-readable checksum sidecar is missing"
grep -Fx 'Exec=/usr/bin/neothd-gui --product-launcher' "$SCRIPT_DIR/neoth.desktop" >/dev/null ||
  fail "desktop launch must honor the saved GUI/CLI product preference"
if grep -Fx 'Exec=/usr/bin/neothd-gui' "$SCRIPT_DIR/neoth.desktop" >/dev/null; then
  fail "generic desktop launch must not force GUI"
fi
if "$BUILDER" --unknown >/dev/null 2>&1; then
  fail "unknown arguments must fail"
fi
if grep -E -- '/\.neoth|HOME.*\.neoth|~/\.neoth' "$SCRIPT_DIR/build-packages.sh" "$SCRIPT_DIR/neoth.desktop" >/dev/null; then
  fail "package payload must not address user state"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/neoth-linux-contracts.XXXXXX")"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fixture="$work/neoth-v1.0.0-x86_64-unknown-linux-gnu"
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
mkdir -p "$fixture/self-knowledge/wiki" "$fixture/self-knowledge/obsidian"
printf '%s\n' '{"schema_version":1,"product":"NEOTH","release_version":"1.0.0","files":[{"path":"graph.json"}]}' \
  >"$fixture/self-knowledge/manifest.json"
printf '%s\n' '{"nodes":[{"id":"neoth"}],"links":[]}' >"$fixture/self-knowledge/graph.json"
printf '%s\n' '# Wiki' >"$fixture/self-knowledge/wiki/index.md"
printf '%s\n' '# Vault' >"$fixture/self-knowledge/obsidian/index.md"
cat >"$fake_bin/readelf" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'ELF Header:' "  Machine:                           ${FAKE_MACHINE:-Advanced Micro Devices X86-64}"
EOF
chmod 0755 "$fake_bin/readelf"

PATH="$fake_bin:$PATH" "$BUILDER" --bundle "$fixture" --version 1.0.0 --arch x86_64 --validate-only >/dev/null
newline_path="$fixture/self-knowledge/wiki/"$'bad\nname.md'
printf 'bad path\n' >"$newline_path"
expect_fail_contains 'self-knowledge path contains a newline' \
  env PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$fixture" --version 1.0.0 --arch x86_64 --validate-only
rm -f -- "$newline_path"
if FAKE_MACHINE=AArch64 PATH="$fake_bin:$PATH" "$BUILDER" --bundle "$fixture" --version 1.0.0 --arch x86_64 --validate-only >/dev/null 2>&1; then
  fail "a mismatched ELF architecture must fail"
fi

receipt="$work/preflight.receipt"
exec_log="$work/executed-products.log"
EXEC_LOG="$exec_log" PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$fixture" --version 1.0.0 --arch x86_64 --validate-only \
  --write-preflight-receipt "$receipt" >/dev/null
[[ $(wc -l <"$exec_log") -eq 5 ]] || fail "preflight must execute all five versioned products"

: >"$exec_log"
expect_fail_contains '--source-date-epoch must be an integer' \
  env EXEC_LOG="$exec_log" PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$fixture" --version 1.0.0 --arch x86_64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$receipt"
[[ ! -s $exec_log ]] || fail "receipt consume path executed a product binary"

expect_fail_contains 'preflight receipt must be a regular, non-symlink file' \
  env PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$fixture" --version 1.0.0 --arch x86_64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$work/missing.receipt"

tampered="$work/tampered/neoth-v1.0.0-x86_64-unknown-linux-gnu"
mkdir -p "$(dirname "$tampered")"
cp -R "$fixture" "$tampered"
printf 'tamper\n' >>"$tampered/README.md"
expect_fail_contains 'preflight receipt does not match version, target, architecture, or bundle bytes' \
  env PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$tampered" --version 1.0.0 --arch x86_64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$receipt"

stale_receipt="$work/stale.receipt"
sed 's/^version 1\.0\.0$/version 1.0.1/' "$receipt" >"$stale_receipt"
expect_fail_contains 'preflight receipt does not match version, target, architecture, or bundle bytes' \
  env PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$fixture" --version 1.0.0 --arch x86_64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$stale_receipt"

version_bundle="$work/version/neoth-v1.0.1-x86_64-unknown-linux-gnu"
mkdir -p "$(dirname "$version_bundle")"
cp -R "$fixture" "$version_bundle"
expect_fail_contains 'preflight receipt does not match version, target, architecture, or bundle bytes' \
  env PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$version_bundle" --version 1.0.1 --arch x86_64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$receipt"

target_bundle="$work/target/neoth-v1.0.0-aarch64-unknown-linux-gnu"
mkdir -p "$(dirname "$target_bundle")"
cp -R "$fixture" "$target_bundle"
expect_fail_contains 'preflight receipt does not match version, target, architecture, or bundle bytes' \
  env FAKE_MACHINE=AArch64 PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$target_bundle" --version 1.0.0 --arch aarch64 --output "$work/output" \
  --source-date-epoch invalid --preflight-receipt "$receipt"

printf '%s\n' '#!/usr/bin/env sh' "printf '%s\\n' '9.9.9'" >"$fixture/neoth-relay"
chmod 0755 "$fixture/neoth-relay"
if PATH="$fake_bin:$PATH" "$BUILDER" --bundle "$fixture" --version 1.0.0 --arch x86_64 --validate-only >/dev/null 2>&1; then
  fail "a mismatched component version must fail"
fi

printf 'linux packaging contract checks passed\n'
