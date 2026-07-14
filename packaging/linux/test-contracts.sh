#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly BUILDER="$SCRIPT_DIR/build-packages.sh"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

bash -n "$BUILDER" "$0"
diff -u "$SCRIPT_DIR/fixtures/expected-layout.txt" <("$BUILDER" --print-layout)
"$BUILDER" --help >/dev/null
grep -F 'NEOTH-${version}-${target}.deb' "$BUILDER" >/dev/null || fail "stable DEB asset name drifted"
grep -F 'NEOTH-${version}-${target}.rpm' "$BUILDER" >/dev/null || fail "stable RPM asset name drifted"
grep -F '"sha256": "$checksum"' "$BUILDER" >/dev/null || fail "machine-readable checksum sidecar is missing"
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
printf '%s\n' 'neoth component 1.0.0'
EOF
  chmod 0755 "$fixture/$name"
done
for name in README.md LICENSE-MIT LICENSE-APACHE freedom.yaml.example import-manifest.example.yaml; do
  printf 'fixture %s\n' "$name" >"$fixture/$name"
done
cat >"$fake_bin/readelf" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'ELF Header:' "  Machine:                           ${FAKE_MACHINE:-Advanced Micro Devices X86-64}"
EOF
chmod 0755 "$fake_bin/readelf"

PATH="$fake_bin:$PATH" "$BUILDER" --bundle "$fixture" --version 1.0.0 --arch x86_64 --validate-only >/dev/null
if FAKE_MACHINE=AArch64 PATH="$fake_bin:$PATH" "$BUILDER" --bundle "$fixture" --version 1.0.0 --arch x86_64 --validate-only >/dev/null 2>&1; then
  fail "a mismatched ELF architecture must fail"
fi

printf '%s\n' '#!/usr/bin/env sh' "printf '%s\\n' '9.9.9'" >"$fixture/neoth-relay"
chmod 0755 "$fixture/neoth-relay"
if PATH="$fake_bin:$PATH" "$BUILDER" --bundle "$fixture" --version 1.0.0 --arch x86_64 --validate-only >/dev/null 2>&1; then
  fail "a mismatched component version must fail"
fi

printf 'linux packaging contract checks passed\n'
