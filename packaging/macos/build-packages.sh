#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly BINARIES=(neoth neothd neothd-gui neoth-migrate neoth-relay neoth-keet-bridge)
readonly VERSIONED_BINARIES=(neoth neothd neoth-migrate neoth-relay neoth-keet-bridge)
readonly SUPPORT_FILES=(README.md LICENSE-MIT LICENSE-APACHE THIRD_PARTY_LICENSES freedom.yaml.example import-manifest.example.yaml)
readonly BUNDLE_ID=io.github.the-geek-freaks.neoth

usage() {
  cat <<'EOF'
Usage:
  build-packages.sh --bundle DIR --version X.Y.Z --arch x86_64|arm64 \
    --output DIR --source-date-epoch UNIX_EPOCH [signing/notary options] \
    [--preflight-receipt FILE]
  build-packages.sh --bundle DIR --version X.Y.Z --arch x86_64|arm64 \
    --validate-only --write-preflight-receipt FILE
  build-packages.sh --print-layout

Signing options:
  --application-identity NAME   Developer ID Application identity
  --installer-identity NAME     Developer ID Installer identity
  --require-signing             Fail unless both identities are usable

Notarization options:
  --notary-profile NAME         notarytool keychain profile
  --notary-keychain PATH        explicit keychain containing the profile
  --require-notarization        Fail unless signing and credentials are usable

The corresponding NEOTH_* environment variables are also accepted. Passing
identities enables signing; passing complete notary credentials enables
notarization. Required modes never fall back to unsigned artifacts.

Key-isolation options:
  --write-preflight-receipt FILE
      Validate architecture and execute version probes, then bind every input
      byte to FILE. Only valid with --validate-only.
  --preflight-receipt FILE
      Verify the bound input bytes without executing any bundled product.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

write_sidecars() {
  local artifact=$1
  local format=$2
  local checksum basename signed notarized
  basename=$(basename "$artifact")
  checksum=$(shasum -a 256 "$artifact" | awk '{print $1}')
  signed=false
  notarized=false
  ((do_signing)) && signed=true
  ((do_notarization)) && notarized=true
  printf '%s  %s\n' "$checksum" "$basename" >"$artifact.sha256"
  cat >"$artifact.json" <<EOF
{
  "schema_version": 1,
  "product": "NEOTH",
  "name": "$basename",
  "version": "$version",
  "target": "$target",
  "architecture": "$arch",
  "format": "$format",
  "sha256": "$checksum",
  "trust": {
    "developer_id_signed": $signed,
    "apple_notarized": $notarized
  }
}
EOF
  touch -h -t "$timestamp" "$artifact.sha256" "$artifact.json"
}

capture_version() {
  local executable=$1
  local capture pid watchdog status
  capture="$(mktemp "${TMPDIR:-/tmp}/neoth-version.XXXXXX")"
  "$executable" --version >"$capture" 2>&1 &
  pid=$!
  (
    sleeper=
    trap 'if [[ -n $sleeper ]]; then kill "$sleeper" 2>/dev/null || true; fi; exit 0' TERM INT
    sleep 15 &
    sleeper=$!
    wait "$sleeper" || exit 0
    kill -TERM "$pid" 2>/dev/null || exit 0
    sleep 1
    kill -KILL "$pid" 2>/dev/null || true
  ) </dev/null >/dev/null 2>&1 &
  watchdog=$!
  if wait "$pid"; then
    status=0
  else
    status=$?
  fi
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  cat "$capture"
  rm -f "$capture"
  return "$status"
}

emit_preflight_receipt() {
  local name checksum
  printf '%s\n' 'NEOTH-MACOS-PREFLIGHT-V1'
  printf 'version %s\n' "$version"
  printf 'target %s\n' "$target"
  printf 'architecture %s\n' "$arch"
  for name in "${BINARIES[@]}" "${SUPPORT_FILES[@]}"; do
    checksum=$(shasum -a 256 "$bundle/$name" | awk '{print $1}')
    printf '%s  %s\n' "$checksum" "$name"
  done
}

write_preflight_receipt_file() {
  local destination=$1
  local parent temporary
  [[ ! -e $destination ]] || die "preflight receipt already exists: $destination"
  parent=$(dirname "$destination")
  [[ -d $parent ]] || die "preflight receipt directory not found: $parent"
  temporary=$(mktemp "$parent/.release-preflight.XXXXXX")
  if ! (umask 077; emit_preflight_receipt >"$temporary"); then
    rm -f "$temporary"
    die "could not write preflight receipt"
  fi
  mv "$temporary" "$destination"
}

verify_preflight_receipt_file() {
  local receipt=$1
  local temporary
  [[ -f $receipt && ! -L $receipt ]] ||
    die "preflight receipt must be a regular, non-symlink file: $receipt"
  temporary=$(mktemp "${TMPDIR:-/tmp}/neoth-preflight-verify.XXXXXX")
  emit_preflight_receipt >"$temporary"
  if ! cmp -s "$temporary" "$receipt"; then
    rm -f "$temporary"
    die "preflight receipt does not match version, target, architecture, or bundle bytes"
  fi
  rm -f "$temporary"
}

print_layout() {
  cat <<'EOF'
/Applications/NEOTH.app/Contents/MacOS/neoth
/Applications/NEOTH.app/Contents/MacOS/neothd
/Applications/NEOTH.app/Contents/MacOS/neothd-gui
/Applications/NEOTH.app/Contents/MacOS/neoth-migrate
/Applications/NEOTH.app/Contents/MacOS/neoth-relay
/Applications/NEOTH.app/Contents/MacOS/neoth-keet-bridge
/Applications/NEOTH.app/Contents/Info.plist
/Applications/NEOTH.app/Contents/Resources/README.md
/Applications/NEOTH.app/Contents/Resources/LICENSE-MIT
/Applications/NEOTH.app/Contents/Resources/LICENSE-APACHE
/Applications/NEOTH.app/Contents/Resources/THIRD_PARTY_LICENSES
/Applications/NEOTH.app/Contents/Resources/examples/freedom.yaml.example
/Applications/NEOTH.app/Contents/Resources/examples/import-manifest.example.yaml
/Applications/NEOTH.app/Contents/Resources/uninstall-neoth.sh
/usr/local/bin/neoth
/usr/local/bin/neothd
/usr/local/bin/neothd-gui
/usr/local/bin/neoth-migrate
/usr/local/bin/neoth-relay
/usr/local/bin/neoth-keet-bridge
/usr/local/bin/neoth-uninstall
EOF
}

bundle=
version=
arch=
output=
source_date_epoch=${SOURCE_DATE_EPOCH:-}
application_identity=${NEOTH_APPLICATION_IDENTITY:-}
installer_identity=${NEOTH_INSTALLER_IDENTITY:-}
notary_profile=${NEOTH_NOTARY_PROFILE:-}
notary_keychain=${NEOTH_NOTARY_KEYCHAIN:-}
require_signing=0
require_notarization=0
validate_only=0
write_preflight_receipt=
preflight_receipt=

while (($#)); do
  case "$1" in
    --bundle | --version | --arch | --output | --source-date-epoch | \
      --application-identity | --installer-identity | --notary-profile | \
      --notary-keychain | --write-preflight-receipt | --preflight-receipt)
      (($# >= 2)) || die "$1 requires a value"
      case "$1" in
        --bundle) bundle=$2 ;;
        --version) version=$2 ;;
        --arch) arch=$2 ;;
        --output) output=$2 ;;
        --source-date-epoch) source_date_epoch=$2 ;;
        --application-identity) application_identity=$2 ;;
        --installer-identity) installer_identity=$2 ;;
        --notary-profile) notary_profile=$2 ;;
        --notary-keychain) notary_keychain=$2 ;;
        --write-preflight-receipt) write_preflight_receipt=$2 ;;
        --preflight-receipt) preflight_receipt=$2 ;;
      esac
      shift 2
      ;;
    --require-signing) require_signing=1; shift ;;
    --require-notarization) require_notarization=1; shift ;;
    --validate-only) validate_only=1; shift ;;
    --print-layout)
      (($# == 1)) || die "--print-layout cannot be combined with other arguments"
      print_layout
      exit 0
      ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n $bundle ]] || die "--bundle is required"
[[ -n $version ]] || die "--version is required"
[[ -n $arch ]] || die "--arch is required"
[[ -n $output || $validate_only == 1 ]] || die "--output is required"
[[ -z $write_preflight_receipt || $validate_only == 1 ]] ||
  die "--write-preflight-receipt requires --validate-only"
[[ -z $preflight_receipt || $validate_only == 0 ]] ||
  die "--preflight-receipt cannot be combined with --validate-only"
[[ -z $write_preflight_receipt || -z $preflight_receipt ]] ||
  die "preflight receipt write and consume modes are mutually exclusive"
[[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] ||
  die "invalid semantic version: $version"
IFS=. read -r -a prerelease_parts <<<"${version#*-}"
if [[ $version == *-* ]]; then
  for part in "${prerelease_parts[@]}"; do
    [[ ! $part =~ ^0[0-9]+$ ]] || die "numeric prerelease identifiers must not have leading zeroes"
  done
fi

case "$arch" in
  x86_64) target=x86_64-apple-darwin ;;
  arm64) target=aarch64-apple-darwin ;;
  *) die "unsupported architecture: $arch (expected x86_64 or arm64)" ;;
esac

if [[ -n $application_identity || -n $installer_identity ]]; then
  [[ -n $application_identity && -n $installer_identity ]] ||
    die "application and installer signing identities must be supplied together"
  do_signing=1
else
  do_signing=0
fi
if ((require_signing || require_notarization)) && ((do_signing == 0)); then
  die "required signing needs both --application-identity and --installer-identity"
fi

[[ -z $notary_keychain || -n $notary_profile ]] ||
  die "--notary-keychain requires --notary-profile"
[[ -z $notary_keychain || -f $notary_keychain ]] ||
  die "notary keychain not found: $notary_keychain"
if [[ -n $notary_profile ]]; then
  do_notarization=1
else
  do_notarization=0
fi
if ((require_notarization)) && ((do_notarization == 0)); then
  die "required notarization needs a keychain profile or complete Apple credentials"
fi
if ((do_notarization)) && ((do_signing == 0)); then
  die "notarization requires signed application and installer artifacts"
fi

[[ -d $bundle ]] || die "bundle directory not found: $bundle"
bundle="$(cd "$bundle" && pwd -P)"
[[ $(basename "$bundle") == "neoth-v${version}-${target}" ]] ||
  die "bundle directory must be named neoth-v${version}-${target}"

need_cmd lipo
if [[ -n $write_preflight_receipt || -n $preflight_receipt ]]; then
  need_cmd cmp
  need_cmd shasum
fi
for name in "${BINARIES[@]}"; do
  path="$bundle/$name"
  [[ -f $path && ! -L $path && -s $path && -x $path ]] ||
    die "missing regular non-empty executable: $name"
  binary_archs="$(lipo -archs "$path" 2>/dev/null)" || die "$name is not a readable Mach-O executable"
  [[ $binary_archs == "$arch" ]] || die "$name architecture is '$binary_archs', expected '$arch'"
done
for name in "${SUPPORT_FILES[@]}"; do
  [[ -f $bundle/$name && ! -L $bundle/$name && -s $bundle/$name ]] ||
    die "missing regular non-empty release file: $name"
done
if [[ -n $preflight_receipt ]]; then
  verify_preflight_receipt_file "$preflight_receipt"
else
  for name in "${VERSIONED_BINARIES[@]}"; do
    version_output="$(capture_version "$bundle/$name")" ||
      die "$name --version failed or timed out"
    tr -cs '0-9A-Za-z.+-' '\n' <<<"$version_output" | grep -Fqx -- "$version" ||
      die "$name version does not equal $version"
  done
fi

if ((validate_only)); then
  if [[ -n $write_preflight_receipt ]]; then
    write_preflight_receipt_file "$write_preflight_receipt"
  fi
  printf 'validated %s (%s, %s)\n' "$bundle" "$version" "$arch"
  exit 0
fi

[[ $source_date_epoch =~ ^[0-9]+$ ]] || die "--source-date-epoch must be an integer"
((source_date_epoch >= 315532800)) || die "--source-date-epoch must be 1980-01-01 or later"

for command in cmp codesign date ditto find hdiutil install lipo mktemp pkgbuild pkgutil plutil shasum tar touch xcrun; do
  need_cmd "$command"
done
if ((do_signing)); then
  need_cmd security
  security find-identity -v -p codesigning | grep -F -- "$application_identity" >/dev/null ||
    die "application signing identity is unavailable: $application_identity"
  security find-certificate -a -c "$installer_identity" -Z | grep -Eq '^SHA-(1|256) hash:' ||
    die "installer signing identity is unavailable: $installer_identity"
fi

mkdir -p "$output"
output="$(cd "$output" && pwd -P)"
app_final="$output/NEOTH-${version}-${target}.app"
pkg_final="$output/NEOTH-${version}-${target}.pkg"
dmg_final="$output/NEOTH-${version}-${target}.dmg"
portable_final="$output/neoth-v${version}-${target}.tar.gz"
for artifact in "$app_final" "$portable_final" "$portable_final.sha256" "$portable_final.json" \
  "$pkg_final" "$pkg_final.sha256" "$pkg_final.json" \
  "$dmg_final" "$dmg_final.sha256" "$dmg_final.json"; do
  [[ ! -e $artifact ]] || die "output already exists: $artifact"
done

work="$(mktemp -d "$output/.packaging-macos.XXXXXX")"
dmg_mount=
cleanup() {
  if [[ -n ${dmg_mount:-} && -d $dmg_mount ]]; then
    hdiutil detach -quiet -force "$dmg_mount" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$work/artifacts"
app_output="$work/artifacts/$(basename "$app_final")"
pkg_output="$work/artifacts/$(basename "$pkg_final")"
dmg_output="$work/artifacts/$(basename "$dmg_final")"
portable_output="$work/artifacts/$(basename "$portable_final")"
app="$work/NEOTH.app"
macos_dir="$app/Contents/MacOS"
resources_dir="$app/Contents/Resources"
examples_dir="$resources_dir/examples"
mkdir -p "$macos_dir" "$examples_dir"

for name in "${BINARIES[@]}"; do
  install -m 0755 "$bundle/$name" "$macos_dir/$name"
done
for name in README.md LICENSE-MIT LICENSE-APACHE THIRD_PARTY_LICENSES; do
  install -m 0644 "$bundle/$name" "$resources_dir/$name"
done
for name in freedom.yaml.example import-manifest.example.yaml; do
  install -m 0644 "$bundle/$name" "$examples_dir/$name"
done
install -m 0755 "$SCRIPT_DIR/uninstall-neoth.sh" "$resources_dir/uninstall-neoth.sh"

version_without_build=${version%%+*}
numeric_version=${version_without_build%%-*}
sed -e "s/@NUMERIC_VERSION@/$numeric_version/g" -e "s/@RELEASE_VERSION@/$version/g" \
  "$SCRIPT_DIR/Info.plist.in" >"$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" >/dev/null

timestamp="$(date -u -r "$source_date_epoch" '+%Y%m%d%H%M.%S')"
find "$app" -exec touch -h -t "$timestamp" {} +

if ((do_signing)); then
  for name in "${BINARIES[@]}"; do
    entitlements="$SCRIPT_DIR/entitlements.plist"
    if [[ $name == neoth ]]; then
      # The desktop release enables Wasmtime; hardened runtime needs the
      # narrow JIT entitlement or signed WASM plugins cannot execute.
      entitlements="$SCRIPT_DIR/entitlements-jit.plist"
    fi
    codesign --force --sign "$application_identity" --options runtime --timestamp \
      --entitlements "$entitlements" "$macos_dir/$name"
  done
  codesign --force --sign "$application_identity" --options runtime --timestamp \
    --entitlements "$SCRIPT_DIR/entitlements.plist" "$app"
  codesign --verify --strict --verbose=2 "$app"
fi

notary_args=()
if [[ -n $notary_profile ]]; then
  notary_args+=(--keychain-profile "$notary_profile")
  [[ -z $notary_keychain ]] || notary_args+=(--keychain "$notary_keychain")
fi
notarize() {
  local artifact=$1
  xcrun notarytool submit "$artifact" "${notary_args[@]}" --wait
}

if ((do_notarization)); then
  app_zip="$work/NEOTH-${version}-${arch}.zip"
  ditto -c -k --sequesterRsrc --keepParent "$app" "$app_zip"
  notarize "$app_zip"
  xcrun stapler staple "$app"
  xcrun stapler validate "$app"
fi

# Rebuild the canonical portable archive from the signed leaf executables.
# The unsigned matrix tarball is an internal package input only and is never
# promoted to the public release on macOS.
portable_parent="$work/portable"
portable_root="$portable_parent/neoth-v${version}-${target}"
mkdir -p "$portable_root"
for name in "${BINARIES[@]}"; do
  install -m 0755 "$macos_dir/$name" "$portable_root/$name"
done
for name in "${SUPPORT_FILES[@]}"; do
  install -m 0644 "$bundle/$name" "$portable_root/$name"
done
find "$portable_root" -exec touch -h -t "$timestamp" {} +
COPYFILE_DISABLE=1 tar -C "$portable_parent" -czf "$portable_output" "$(basename "$portable_root")"
portable_verify="$work/portable-verify"
mkdir -p "$portable_verify"
tar -xzf "$portable_output" -C "$portable_verify"
for name in "${BINARIES[@]}"; do
  cmp -s "$macos_dir/$name" "$portable_verify/$(basename "$portable_root")/$name" ||
    die "portable archive changed signed executable $name"
  if ((do_signing)); then
    codesign --verify --strict --verbose=2 "$portable_verify/$(basename "$portable_root")/$name"
  fi
done
write_sidecars "$portable_output" portable-tar

pkg_root="$work/pkg-root"
mkdir -p "$pkg_root/Applications" "$pkg_root/usr/local/bin"
ditto "$app" "$pkg_root/Applications/NEOTH.app"
for name in "${BINARIES[@]}"; do
  ln -s "/Applications/NEOTH.app/Contents/MacOS/$name" "$pkg_root/usr/local/bin/$name"
done
ln -s '/Applications/NEOTH.app/Contents/Resources/uninstall-neoth.sh' "$pkg_root/usr/local/bin/neoth-uninstall"
find "$pkg_root" -exec touch -h -t "$timestamp" {} +

pkg_args=(--root "$pkg_root" --identifier "$BUNDLE_ID" --version "$numeric_version" --install-location /)
if ((do_signing)); then
  pkg_args+=(--sign "$installer_identity" --timestamp)
fi
pkgbuild "${pkg_args[@]}" "$pkg_output"
if ((do_signing)); then
  pkgutil --check-signature "$pkg_output" >/dev/null
fi
if ((do_notarization)); then
  notarize "$pkg_output"
  xcrun stapler staple "$pkg_output"
  xcrun stapler validate "$pkg_output"
fi
write_sidecars "$pkg_output" pkg

dmg_root="$work/dmg-root"
mkdir -p "$dmg_root"
ditto "$app" "$dmg_root/NEOTH.app"
install -m 0644 "$pkg_output" "$dmg_root/$(basename "$pkg_output")"
ln -s /Applications "$dmg_root/Applications"
find "$dmg_root" -exec touch -h -t "$timestamp" {} +
hdiutil create -quiet -fs HFS+ -format UDZO -volname "NEOTH $version" -srcfolder "$dmg_root" "$dmg_output"
if ((do_signing)); then
  codesign --force --sign "$application_identity" --timestamp "$dmg_output"
  codesign --verify --verbose=2 "$dmg_output"
fi
if ((do_notarization)); then
  notarize "$dmg_output"
  xcrun stapler staple "$dmg_output"
  xcrun stapler validate "$dmg_output"
fi

ditto "$app" "$app_output"
for name in "${BINARIES[@]}"; do
  [[ -x $app_output/Contents/MacOS/$name ]] || die "built app is missing executable $name"
done
for name in README.md LICENSE-MIT LICENSE-APACHE THIRD_PARTY_LICENSES; do
  [[ -s $app_output/Contents/Resources/$name ]] || die "built app is missing $name"
done
for name in freedom.yaml.example import-manifest.example.yaml; do
  [[ -s $app_output/Contents/Resources/examples/$name ]] || die "built app is missing example $name"
done
plutil -lint "$app_output/Contents/Info.plist" >/dev/null
[[ $(plutil -extract CFBundleIdentifier raw -o - "$app_output/Contents/Info.plist") == "$BUNDLE_ID" ]] ||
  die "built app bundle identifier drifted"
pkg_payload="$(pkgutil --payload-files "$pkg_output" | sed 's#^\./##')"
while IFS= read -r required_path; do
  grep -Fqx -- "${required_path#/}" <<<"$pkg_payload" || die "built PKG is missing $required_path"
done < <(print_layout)
if ((do_notarization)); then
  xcrun stapler validate "$app_output"
fi

dmg_mount="$work/dmg-mount"
mkdir -p "$dmg_mount"
hdiutil attach -quiet -nobrowse -readonly -mountpoint "$dmg_mount" "$dmg_output"
[[ -d $dmg_mount/NEOTH.app ]] || die "built DMG is missing NEOTH.app"
[[ -s $dmg_mount/$(basename "$pkg_output") ]] || die "built DMG is missing its native PKG"
[[ -L $dmg_mount/Applications && $(readlink "$dmg_mount/Applications") == /Applications ]] ||
  die "built DMG is missing its Applications link"
hdiutil detach -quiet "$dmg_mount"
dmg_mount=
write_sidecars "$dmg_output" dmg
for artifact in "$app_output" \
  "$portable_output" "$portable_output.sha256" "$portable_output.json" \
  "$pkg_output" "$pkg_output.sha256" "$pkg_output.json" \
  "$dmg_output" "$dmg_output.sha256" "$dmg_output.json"; do
  mv "$artifact" "$output/"
done
printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
  "$app_final" \
  "$portable_final" "$portable_final.sha256" "$portable_final.json" \
  "$pkg_final" "$pkg_final.sha256" "$pkg_final.json" \
  "$dmg_final" "$dmg_final.sha256" "$dmg_final.json"
