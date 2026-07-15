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
  fail "macOS builder must verify the built and final product-launcher contract"
grep -F '<string>@BUNDLE_VERSION@</string>' "$SCRIPT_DIR/Info.plist.in" >/dev/null ||
  fail "CFBundleVersion must use the PackageKit-safe mapped version"
grep -F -- '--version "$bundle_version"' "$BUILDER" >/dev/null ||
  fail "PackageKit receipt version must equal the mapped app bundle version"
grep -F 'ditto "$app" "$pkg_root/Applications/NEOTH.app"' "$BUILDER" >/dev/null ||
  fail "PKG must carry the complete signed app at its live PackageKit path"
grep -F -- '--scripts "$pkg_scripts"' "$BUILDER" >/dev/null ||
  fail "PKG must embed ownership preinstall and postinstall scripts"
grep -F -- '--component-plist "$pkg_component_plist"' "$BUILDER" >/dev/null ||
  fail "PKG must pin its live bundle component contract"
grep -A1 -F '<key>BundleHasStrictIdentifier</key>' "$BUILDER" | grep -F '<true/>' >/dev/null ||
  fail "PKG live app must require its strict bundle identifier"
grep -A1 -F '<key>BundleIsRelocatable</key>' "$BUILDER" | grep -F '<false/>' >/dev/null ||
  fail "PKG live app must be non-relocatable"
grep -A1 -F '<key>BundleOverwriteAction</key>' "$BUILDER" | grep -F '<string>upgrade</string>' >/dev/null ||
  fail "PKG live app must use PackageKit's native upgrade contract"
grep -A1 -F '<key>RootRelativeBundlePath</key>' "$BUILDER" | grep -F '<string>Applications/NEOTH.app</string>' >/dev/null ||
  fail "PKG component must own the live NEOTH.app path"
grep -F -- '--ownership recommended' "$BUILDER" >/dev/null ||
  fail "PKG must declare PackageKit ownership normalization"
grep -F 'neoth-package-ownership.plist' "$BUILDER" >/dev/null ||
  fail "app bundle ownership receipt is missing"
receipt_line=$(grep -nF 'ownership_receipt="$resources_dir/neoth-package-ownership.plist"' "$BUILDER" | cut -d: -f1)
sign_line=$(grep -nF 'codesign --force --sign "$application_identity" --options runtime --timestamp \' "$BUILDER" | tail -1 | cut -d: -f1)
if [[ -z $receipt_line || -z $sign_line ]] || ((receipt_line >= sign_line)); then
  fail "ownership receipt must be embedded before the app is signed"
fi
if grep -F 'pkg_stage_name=' "$BUILDER" >/dev/null ||
  grep -F '/bin/mv "$stage" "$live"' "$BUILDER" >/dev/null ||
  grep -F 'NEOTH-PKG-COMMIT-V1' "$BUILDER" >/dev/null; then
  fail "hidden carrier-stage/backup/marker architecture returned"
fi
release_workflow="$SCRIPT_DIR/../../.github/workflows/release.yml"
grep -F 'Native PKG install, reinstall and removal smoke' "$release_workflow" >/dev/null ||
  fail "release workflow must describe same-version coverage honestly as reinstall"
grep -F 'pkgutil --files io.github.the-geek-freaks.neoth' "$release_workflow" >/dev/null ||
  fail "release workflow must inspect the installed PackageKit receipt"
grep -F 'pkgutil --payload-files "$PKG"' "$release_workflow" >/dev/null ||
  fail "release workflow must inspect the uninstalled PackageKit payload"
grep -F 'lsbom -s "$PKG_EXPANDED/Bom"' "$release_workflow" >/dev/null ||
  fail "release workflow must inspect the exact PackageKit BOM"
grep -F '"$PKG_EXPANDED/Payload/Applications/NEOTH.app"' "$release_workflow" >/dev/null ||
  fail "release workflow must compare installed app bytes with the expanded payload"
if grep -F 'pkgutil --verify' "$release_workflow" >/dev/null; then
  fail "release workflow must not call the obsolete undocumented pkgutil --verify command"
fi
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

# Parse only the definition prefix and prove the PKG writer is an actual shell
# function, not text accidentally captured inside another heredoc.
builder_definitions="$work/builder-definitions.sh"
awk '/^bundle=$/ { exit } { print }' "$BUILDER" >"$builder_definitions"
bash -c 'source "$1"; declare -F write_pkg_install_scripts >/dev/null' _ "$builder_definitions" ||
  fail "PKG install-script writer is not a real top-level shell function"

declare -a bundle_version_cases=(
  '0.1.0=1.0.99'
  '1.0.0-alpha.1=100.0.1'
  '1.0.0-beta.1=100.0.33'
  '1.0.0-beta.2=100.0.34'
  '1.0.0-rc.1=100.0.65'
  '1.0.0=100.0.99'
  '1.0.1-alpha.0=100.1.0'
  '1.1.0-beta.1=101.0.33'
  '2.0.0=200.0.99'
  '99.99.99=9999.99.99'
  '99.99.99-rc.31=9999.99.95'
)
for version_case in "${bundle_version_cases[@]}"; do
  semver=${version_case%%=*}
  expected=${version_case#*=}
  actual=$(bash -c 'source "$1"; macos_bundle_version "$2"' _ \
    "$builder_definitions" "$semver")
  [[ $actual == "$expected" ]] ||
    fail "macOS bundle-version mapping drifted for $semver: $actual != $expected"
done
expect_fail_contains 'require alpha.N, beta.N, or rc.N' \
  bash -c 'source "$1"; macos_bundle_version "$2"' _ \
  "$builder_definitions" 1.0.0-preview.1
expect_fail_contains 'N in 0..31' \
  bash -c 'source "$1"; macos_bundle_version "$2"' _ \
  "$builder_definitions" 1.0.0-beta.32
expect_fail_contains 'major, minor, and patch in 0..99' \
  bash -c 'source "$1"; macos_bundle_version "$2"' _ \
  "$builder_definitions" 1.100.0
expect_fail_contains 'major, minor, and patch in 0..99' \
  bash -c 'source "$1"; macos_bundle_version "$2"' _ \
  "$builder_definitions" 100.0.0
expect_fail_contains 'major, minor, and patch in 0..99' \
  bash -c 'source "$1"; macos_bundle_version "$2"' _ \
  "$builder_definitions" 1.0.100
expect_fail_contains 'major or minor to be nonzero' \
  bash -c 'source "$1"; macos_bundle_version "$2"' _ \
  "$builder_definitions" 0.0.1

extract_builder_heredoc() {
  local marker=$1
  awk -v marker="$marker" '
    !copy && index($0, "<<" sprintf("%c", 39) marker sprintf("%c", 39)) { copy=1; next }
    copy && $0 == marker { exit }
    copy { print }
  ' "$BUILDER"
}

# Execute the exact generated script bodies against an isolated target volume.
# The tool doubles let these checks prove signer/receipt/owner decisions without
# trusting or executing any candidate application.
pkg_scripts="$work/pkg-scripts"
pkg_target="$work/pkg-target"
applications="$pkg_target/Applications"
live_app="$applications/NEOTH.app"
bin_root="$pkg_target/usr/local/bin"
fake_tools="$work/pkg-tools"
execution_sentinel="$work/candidate-executed.log"
mkdir -p "$pkg_scripts" "$applications" "$fake_tools"

cat >"$fake_tools/codesign" <<'EOF'
#!/bin/sh
case "$1" in
  --verify) exit "${FAKE_CODESIGN_VERIFY_STATUS:-0}" ;;
  -dv)
    printf 'TeamIdentifier=%s\n' "${FAKE_TEAM_ID:-NEOTHTEAM1}" >&2
    ;;
  -d)
    [ "${2:-}" = -r- ] || exit 64
    printf 'designated => %s\n' "${FAKE_REQUIREMENT:-identifier neoth and anchor apple generic}" >&2
    ;;
  *) exit 64 ;;
esac
EOF
cat >"$fake_tools/plutil" <<'EOF'
#!/bin/sh
[ "$1" = -extract ] && [ "$3" = raw ] && [ "$4" = -o ] && [ "$5" = - ] || exit 64
key=$2
file=$6
awk -v needle="<key>$key</key>" '
  index($0, needle) {
    if (getline <= 0) exit 1
    gsub(/^[[:space:]]*<(string|integer)>/, "")
    gsub(/<\/(string|integer)>[[:space:]]*$/, "")
    print
    found=1
    exit
  }
  END { if (!found) exit 1 }
' "$file"
EOF
cat >"$fake_tools/stat" <<'EOF'
#!/bin/sh
[ "$1" = -f ] || exit 64
format=$2
path=$3
owner=${FAKE_STAT_OWNER:-$(id -u)}
if [ "$format" = %u ]; then
  printf '%s\n' "$owner"
  exit 0
fi
[ "$format" = '%u %Sp' ] || exit 64
if [ -d "$path" ]; then
  mode=drwxr-xr-x
else
  mode=-rw-r--r--
fi
if [ -n "${FAKE_WRITABLE_PATH:-}" ] && [ "$path" = "$FAKE_WRITABLE_PATH" ]; then
  mode=-rw-rw-r--
fi
printf '%s %s\n' "$owner" "$mode"
EOF
cat >"$fake_tools/shasum" <<'EOF'
#!/bin/sh
if [ "${1:-}" = -a ] && [ "${2:-}" = 256 ]; then
  shift 2
fi
if command -v sha256sum >/dev/null 2>&1; then
  exec sha256sum "$@"
fi
exec /usr/bin/shasum -a 256 "$@"
EOF
chmod 0755 "$fake_tools"/*

expected_requirement='identifier neoth and anchor apple generic'
expected_requirement_sha256=$(printf '%s' "$expected_requirement" |
  "$fake_tools/shasum" -a 256 | awk '{print $1}')
expected_owner_uid=$(id -u)

write_test_script() {
  local marker=$1
  local destination=$2
  local require_signature=$3
  {
    printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      'export LC_ALL=C' \
      "require_signature=$require_signature" \
      "expected_bundle_id='io.github.the-geek-freaks.neoth'" \
      "expected_release_version='1.0.0'" \
      "expected_bundle_version='100.0.99'" \
      "expected_team_id='NEOTHTEAM1'" \
      "expected_requirement_sha256='$expected_requirement_sha256'" \
      "expected_owner_uid='$expected_owner_uid'" \
      "expected_target_volume='$pkg_target'" \
      "codesign_tool='$fake_tools/codesign'" \
      "find_tool='$(command -v find)'" \
      "plutil_tool='$fake_tools/plutil'" \
      "readlink_tool='$(command -v readlink)'" \
      "shasum_tool='$fake_tools/shasum'" \
      "stat_tool='$fake_tools/stat'"
    extract_builder_heredoc "$marker"
  } >"$destination"
  chmod 0755 "$destination"
}

write_test_script NEOTH_PKG_PREINSTALL "$pkg_scripts/preinstall" 1
write_test_script NEOTH_PKG_PREINSTALL "$pkg_scripts/preinstall-unsigned" 0
write_test_script NEOTH_PKG_POSTINSTALL "$pkg_scripts/postinstall" 1
bash -n "$pkg_scripts/preinstall" "$pkg_scripts/preinstall-unsigned" "$pkg_scripts/postinstall"

preinstall_body=$(extract_builder_heredoc NEOTH_PKG_PREINSTALL)
if grep -F '"$live/Contents/MacOS/neoth"' <<<"$preinstall_body" >/dev/null ||
  grep -E '/bin/(mv|rm).*\$live' <<<"$preinstall_body" >/dev/null; then
  fail "preinstall must never execute, move, or remove an old live candidate"
fi

make_app() {
  local destination=$1
  local verifier_status=$2
  local receipt_bundle_id=$3
  local release_version=$4
  local bundle_version=${5:-100.0.99}
  rm -rf "$destination"
  mkdir -p "$destination/Contents/MacOS" "$destination/Contents/Resources/self-knowledge"
  cat >"$destination/Contents/Info.plist" <<EOF
<plist><dict>
<key>CFBundleIdentifier</key>
<string>io.github.the-geek-freaks.neoth</string>
<key>CFBundleExecutable</key>
<string>neothd-gui</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleVersion</key>
<string>$bundle_version</string>
<key>NEOTHReleaseVersion</key>
<string>$release_version</string>
</dict></plist>
EOF
  cat >"$destination/Contents/Resources/neoth-package-ownership.plist" <<EOF
<plist><dict>
<key>schema_version</key>
<integer>1</integer>
<key>product</key>
<string>NEOTH</string>
<key>bundle_id</key>
<string>$receipt_bundle_id</string>
<key>install_profile</key>
<string>native-pkg</string>
<key>release_version</key>
<string>$release_version</string>
</dict></plist>
EOF
  printf '%s\n' '{"schema_version":1,"product":"NEOTH","release_version":"1.0.0"}' \
    >"$destination/Contents/Resources/self-knowledge/manifest.json"
  cat >"$destination/Contents/MacOS/neoth" <<EOF
#!/bin/sh
if [ -n "\${EXECUTION_SENTINEL:-}" ]; then
  printf 'executed\n' >>"\$EXECUTION_SENTINEL"
fi
exit $verifier_status
EOF
  chmod 0755 "$destination/Contents/MacOS/neoth"
  for name in neothd neothd-gui neoth-migrate neoth-relay neoth-keet-bridge; do
    printf '%s\n' '#!/bin/sh' 'exit 0' >"$destination/Contents/MacOS/$name"
    chmod 0755 "$destination/Contents/MacOS/$name"
  done
  printf '%s\n' '#!/bin/sh' 'exit 0' >"$destination/Contents/Resources/uninstall-neoth.sh"
  chmod 0755 "$destination/Contents/Resources/uninstall-neoth.sh"
}

install_command_links() {
  rm -rf "$bin_root"
  mkdir -p "$bin_root"
  for name in neoth neothd neothd-gui neoth-migrate neoth-relay neoth-keet-bridge; do
    ln -s "/Applications/NEOTH.app/Contents/MacOS/$name" "$bin_root/$name" 2>/dev/null || return 1
  done
  ln -s '/Applications/NEOTH.app/Contents/Resources/uninstall-neoth.sh' "$bin_root/neoth-uninstall" 2>/dev/null
}

# Fresh install: no legacy path is touched and no candidate is executed.
expect_fail_contains 'may only be installed on the root volume' \
  "$pkg_scripts/preinstall" package destination "$work/other-volume"
EXECUTION_SENTINEL="$execution_sentinel" \
  "$pkg_scripts/preinstall" package destination "$pkg_target"
[[ ! -e $execution_sentinel ]] || fail "fresh preinstall executed a product binary"

# A valid signed package-owned app may be replaced, but preinstall still never
# executes it. Its receipt release is bound to its own Info.plist so N -> N+1
# can be authorized without pretending this local same-version test proves it.
make_app "$live_app" 0 io.github.the-geek-freaks.neoth 0.9.0
EXECUTION_SENTINEL="$execution_sentinel" \
  "$pkg_scripts/preinstall" package destination "$pkg_target"
[[ ! -e $execution_sentinel ]] || fail "preinstall executed the existing package-owned app"

# A foreign exit-0 app is rejected by metadata and never gains authority from
# its behavior.
make_app "$live_app" 0 io.example.foreign 1.0.0
expect_fail_contains 'unexpected bundle_id' \
  env EXECUTION_SENTINEL="$execution_sentinel" \
  "$pkg_scripts/preinstall" package destination "$pkg_target"
[[ ! -e $execution_sentinel ]] || fail "preinstall executed a foreign exit-0 app"

make_app "$live_app" 0 io.github.the-geek-freaks.neoth 1.0.0
receipt="$live_app/Contents/Resources/neoth-package-ownership.plist"
sed 's#<string>1\.0\.0</string>#<string>0.9.0</string>#' "$receipt" >"$receipt.tmp"
mv "$receipt.tmp" "$receipt"
expect_fail_contains 'ownership receipt does not match Info.plist release' \
  env EXECUTION_SENTINEL="$execution_sentinel" \
  "$pkg_scripts/preinstall" package destination "$pkg_target"
make_app "$live_app" 0 io.github.the-geek-freaks.neoth 1.0.0
expect_fail_contains 'not owned by the package owner' \
  env FAKE_STAT_OWNER=999999 EXECUTION_SENTINEL="$execution_sentinel" \
  "$pkg_scripts/preinstall" package destination "$pkg_target"
expect_fail_contains 'group/world-writable' \
  env FAKE_WRITABLE_PATH="$live_app/Contents/Resources/neoth-package-ownership.plist" \
  EXECUTION_SENTINEL="$execution_sentinel" \
  "$pkg_scripts/preinstall" package destination "$pkg_target"
expect_fail_contains 'Team ID is not the pinned NEOTH Team ID' \
  env FAKE_TEAM_ID=FOREIGN001 EXECUTION_SENTINEL="$execution_sentinel" \
  "$pkg_scripts/preinstall" package destination "$pkg_target"
expect_fail_contains 'designated requirement is not the pinned NEOTH requirement' \
  env FAKE_REQUIREMENT='identifier foreign and anchor apple generic' \
  EXECUTION_SENTINEL="$execution_sentinel" \
  "$pkg_scripts/preinstall" package destination "$pkg_target"
[[ ! -e $execution_sentinel ]] || fail "a rejected existing app was executed"

expect_fail_contains 'unsigned NEOTH prerelease packages cannot replace' \
  env EXECUTION_SENTINEL="$execution_sentinel" \
  "$pkg_scripts/preinstall-unsigned" package destination "$pkg_target"
[[ ! -e $execution_sentinel ]] || fail "unsigned legacy rejection executed the candidate"

mkdir -p "$bin_root"
printf '%s\n' foreign >"$bin_root/neoth"
expect_fail_contains 'refusing to replace foreign command path' \
  "$pkg_scripts/preinstall" package destination "$pkg_target"
rm -f "$bin_root/neoth"
if ln -s /tmp/foreign-neoth "$bin_root/neoth" 2>/dev/null && [[ -L $bin_root/neoth ]]; then
  expect_fail_contains 'refusing to replace foreign command link' \
    "$pkg_scripts/preinstall" package destination "$pkg_target"
  rm -f "$bin_root/neoth"
fi

# Postinstall only executes the new payload after exact receipt, owner, signer,
# and command-link authorization. Its nonzero status is left for PackageKit to
# roll back on a real macOS install.
make_app "$live_app" 0 io.github.the-geek-freaks.neoth 1.0.0
if install_command_links && [[ -L $bin_root/neoth ]]; then
  EXECUTION_SENTINEL="$execution_sentinel" \
    "$pkg_scripts/postinstall" package destination "$pkg_target"
  [[ -s $execution_sentinel ]] || fail "postinstall did not run the authorized new verifier"
  rm -f "$execution_sentinel"
  make_app "$live_app" 0 io.example.foreign 1.0.0
  expect_fail_contains 'unexpected bundle_id' \
    env EXECUTION_SENTINEL="$execution_sentinel" \
    "$pkg_scripts/postinstall" package destination "$pkg_target"
  [[ ! -e $execution_sentinel ]] || fail "postinstall executed a new payload before receipt authorization"
  make_app "$live_app" 0 io.github.the-geek-freaks.neoth 1.0.0 1.0.0
  expect_fail_contains 'unexpected CFBundleVersion' \
    env EXECUTION_SENTINEL="$execution_sentinel" \
    "$pkg_scripts/postinstall" package destination "$pkg_target"
  [[ ! -e $execution_sentinel ]] || fail "postinstall executed a payload with a false PackageKit version"
  make_app "$live_app" 42 io.github.the-geek-freaks.neoth 1.0.0
  if EXECUTION_SENTINEL="$execution_sentinel" \
    "$pkg_scripts/postinstall" package destination "$pkg_target" >/dev/null 2>&1; then
    fail "postinstall accepted a new payload rejected by native self-knowledge verification"
  fi
else
  printf 'note: local filesystem cannot create symlinks; native macOS CI runs postinstall link execution checks\n'
fi

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
mkdir -p "$fixture/self-knowledge/wiki" "$fixture/self-knowledge/obsidian"
printf '%s\n' '{"schema_version":1,"product":"NEOTH","release_version":"1.0.0","files":[{"path":"graph.json"}]}' \
  >"$fixture/self-knowledge/manifest.json"
printf '%s\n' '{"nodes":[{"id":"neoth"}],"links":[]}' >"$fixture/self-knowledge/graph.json"
printf '%s\n' '# Wiki' >"$fixture/self-knowledge/wiki/index.md"
printf '%s\n' '# Vault' >"$fixture/self-knowledge/obsidian/index.md"
cat >"$fake_bin/lipo" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "${FAKE_ARCH:-arm64}"
EOF
chmod 0755 "$fake_bin/lipo"
cat >"$fake_bin/shasum" <<'EOF'
#!/usr/bin/env sh
if [ "$1" = -a ] && [ "$2" = 256 ]; then
  shift 2
fi
sha256sum "$@"
EOF
chmod 0755 "$fake_bin/shasum"

PATH="$fake_bin:$PATH" "$BUILDER" --bundle "$fixture" --version 1.0.0 --arch arm64 --validate-only >/dev/null
newline_path="$fixture/self-knowledge/wiki/"$'bad\nname.md'
printf 'bad path\n' >"$newline_path"
expect_fail_contains 'self-knowledge path contains a newline' \
  env PATH="$fake_bin:$PATH" "$BUILDER" \
  --bundle "$fixture" --version 1.0.0 --arch arm64 --validate-only
rm -f -- "$newline_path"
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
