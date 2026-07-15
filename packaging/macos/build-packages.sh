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

# Apple compares CFBundleVersion as at most three numeric components. Preserve
# SemVer precedence without pretending that arbitrary prerelease identifiers
# have a native ordering: unsupported native-PKG versions fail closed.
macos_bundle_version() {
  local semver=$1
  local core prerelease major minor patch stage sequence slot

  core=${semver%%-*}
  IFS=. read -r major minor patch <<<"$core"
  ((major <= 99 && minor <= 99 && patch <= 99)) ||
    die "macOS native package versions require major, minor, and patch in 0..99: $semver"
  ((major > 0 || minor > 0)) ||
    die "macOS native package versions require major or minor to be nonzero: $semver"

  if [[ $semver != *-* ]]; then
    slot=99
  else
    prerelease=${semver#*-}
    if [[ ! $prerelease =~ ^(alpha|beta|rc)\.(0|[1-9]|[12][0-9]|3[01])$ ]]; then
      die "macOS native prereleases require alpha.N, beta.N, or rc.N with N in 0..31: $semver"
    fi
    stage=${BASH_REMATCH[1]}
    sequence=${BASH_REMATCH[2]}
    case "$stage" in
      alpha) slot=$sequence ;;
      beta) slot=$((32 + sequence)) ;;
      rc) slot=$((64 + sequence)) ;;
    esac
  fi

  printf '%d.%d.%d\n' "$((major * 100 + minor))" "$patch" "$slot"
}

write_pkg_install_scripts() {
  local scripts_dir=$1
  local require_signature=$2
  local expected_team_id=$3
  local expected_requirement_sha256=$4
  mkdir -p "$scripts_dir"

  {
    printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      'export LC_ALL=C' \
      "require_signature=$require_signature" \
      "expected_bundle_id='$BUNDLE_ID'" \
      "expected_release_version='$version'" \
      "expected_bundle_version='$bundle_version'" \
      "expected_team_id='$expected_team_id'" \
      "expected_requirement_sha256='$expected_requirement_sha256'" \
      'expected_owner_uid=0' \
      "expected_target_volume='/'" \
      'codesign_tool=/usr/bin/codesign' \
      'find_tool=/usr/bin/find' \
      'plutil_tool=/usr/bin/plutil' \
      'readlink_tool=/usr/bin/readlink' \
      'shasum_tool=/usr/bin/shasum' \
      'stat_tool=/usr/bin/stat'
    cat <<'NEOTH_PKG_PREINSTALL'

die() {
  printf 'NEOTH PKG preinstall: %s\n' "$*" >&2
  exit 1
}

target_volume=${3:-/}
[ "$target_volume" = "$expected_target_volume" ] ||
  die "this package may only be installed on the root volume: $target_volume"
case "$target_volume" in
  /) applications_root=/Applications ;;
  /*) applications_root="${target_volume%/}/Applications" ;;
  *) die "target volume is not absolute: $target_volume" ;;
esac
live="$applications_root/NEOTH.app"
case "$target_volume" in
  /) bin_root=/usr/local/bin ;;
  *) bin_root="${target_volume%/}/usr/local/bin" ;;
esac

require_owned_path() {
  path=$1
  label=$2
  [ ! -L "$path" ] || die "$label must not be a symbolic link: $path"
  [ -f "$path" ] || [ -d "$path" ] || die "$label is not a regular file or directory: $path"
  metadata=$("$stat_tool" -f '%u %Sp' "$path") || die "could not inspect $label: $path"
  owner=${metadata%% *}
  mode=${metadata#* }
  [ "$owner" = "$expected_owner_uid" ] ||
    die "$label is not owned by the package owner: $path"
  case "$mode" in
    ?????w????* | ????????w?*) die "$label is group/world-writable: $path" ;;
  esac
}

plist_value() {
  "$plutil_tool" -extract "$2" raw -o - "$1" 2>/dev/null
}

require_plist_value() {
  file=$1
  key=$2
  expected=$3
  label=$4
  actual=$(plist_value "$file" "$key") || die "$label is missing $key"
  [ "$actual" = "$expected" ] || die "$label has an unexpected $key"
}

verify_app_contract() {
  app=$1
  required_release=$2
  label=$3
  [ -d "$app" ] && [ ! -L "$app" ] || die "$label must be a non-link directory: $app"
  listing=$("$find_tool" "$app" -print) || die "could not inspect $label"
  old_ifs=$IFS
  IFS='
'
  set -f
  for path in $listing; do
    require_owned_path "$path" "$label member"
  done
  set +f
  IFS=$old_ifs

  info="$app/Contents/Info.plist"
  receipt="$app/Contents/Resources/neoth-package-ownership.plist"
  require_owned_path "$info" "$label Info.plist"
  require_owned_path "$receipt" "$label ownership receipt"
  require_plist_value "$info" CFBundleIdentifier "$expected_bundle_id" "$label Info.plist"
  require_plist_value "$info" CFBundleExecutable neothd-gui "$label Info.plist"
  require_plist_value "$info" CFBundlePackageType APPL "$label Info.plist"
  require_plist_value "$receipt" schema_version 1 "$label ownership receipt"
  require_plist_value "$receipt" product NEOTH "$label ownership receipt"
  require_plist_value "$receipt" bundle_id "$expected_bundle_id" "$label ownership receipt"
  require_plist_value "$receipt" install_profile native-pkg "$label ownership receipt"
  receipt_release=$(plist_value "$receipt" release_version) ||
    die "$label ownership receipt is missing release_version"
  info_release=$(plist_value "$info" NEOTHReleaseVersion) ||
    die "$label Info.plist is missing NEOTHReleaseVersion"
  [ -n "$receipt_release" ] && [ "$receipt_release" = "$info_release" ] ||
    die "$label ownership receipt does not match Info.plist release"
  if [ -n "$required_release" ]; then
    [ "$receipt_release" = "$required_release" ] ||
      die "$label release does not match the package release"
  fi
  for name in neoth neothd neothd-gui neoth-migrate neoth-relay neoth-keet-bridge; do
    require_owned_path "$app/Contents/MacOS/$name" "$label executable $name"
  done
  require_owned_path "$app/Contents/Resources/self-knowledge/manifest.json" \
    "$label self-knowledge manifest"
}

verify_exact_signature() {
  app=$1
  label=$2
  "$codesign_tool" --verify --deep --strict --verbose=2 "$app" ||
    die "$label signature verification failed"
  details=$("$codesign_tool" -dv --verbose=4 "$app" 2>&1) ||
    die "$label signer identity could not be read"
  team=$(printf '%s\n' "$details" | /usr/bin/sed -n 's/^TeamIdentifier=//p' | /usr/bin/tail -n 1)
  [ "$team" = "$expected_team_id" ] || die "$label Team ID is not the pinned NEOTH Team ID"
  requirement_output=$("$codesign_tool" -d -r- "$app" 2>&1) ||
    die "$label designated requirement could not be read"
  requirement=$(printf '%s\n' "$requirement_output" |
    /usr/bin/sed -n 's/^designated => //p' | /usr/bin/tail -n 1)
  [ -n "$requirement" ] || die "$label designated requirement is missing"
  requirement_sha256=$(printf '%s' "$requirement" | "$shasum_tool" -a 256 | /usr/bin/awk '{print $1}')
  [ "$requirement_sha256" = "$expected_requirement_sha256" ] ||
    die "$label designated requirement is not the pinned NEOTH requirement"
}

verify_command_links() {
  [ ! -L "$bin_root" ] || die "command directory must not be a symbolic link: $bin_root"
  if [ -e "$bin_root" ] && [ ! -d "$bin_root" ]; then
    die "command directory is not a directory: $bin_root"
  fi
  for name in neoth neothd neothd-gui neoth-migrate neoth-relay neoth-keet-bridge; do
    path="$bin_root/$name"
    expected="/Applications/NEOTH.app/Contents/MacOS/$name"
    if [ -e "$path" ] || [ -L "$path" ]; then
      [ -L "$path" ] || die "refusing to replace foreign command path: $path"
      [ "$("$readlink_tool" "$path")" = "$expected" ] ||
        die "refusing to replace foreign command link: $path"
      owner=$("$stat_tool" -f '%u' "$path") || die "could not inspect command link: $path"
      [ "$owner" = "$expected_owner_uid" ] || die "refusing to replace foreign-owned command link: $path"
    fi
  done
  path="$bin_root/neoth-uninstall"
  expected=/Applications/NEOTH.app/Contents/Resources/uninstall-neoth.sh
  if [ -e "$path" ] || [ -L "$path" ]; then
    [ -L "$path" ] || die "refusing to replace foreign command path: $path"
    [ "$("$readlink_tool" "$path")" = "$expected" ] ||
      die "refusing to replace foreign command link: $path"
    owner=$("$stat_tool" -f '%u' "$path") || die "could not inspect command link: $path"
    [ "$owner" = "$expected_owner_uid" ] || die "refusing to replace foreign-owned command link: $path"
  fi
}

if [ -L "$applications_root" ] || [ ! -d "$applications_root" ]; then
  die "Applications directory must be a non-link directory: $applications_root"
fi
if [ -e "$live" ] || [ -L "$live" ]; then
  [ "$require_signature" -eq 1 ] ||
    die 'unsigned NEOTH prerelease packages cannot replace an existing or legacy NEOTH.app; use the documented migration/uninstall flow first'
  verify_app_contract "$live" '' 'existing NEOTH.app' ||
    die 'existing NEOTH.app is not an exact package-owned installation; use the documented migration/uninstall flow first'
  verify_exact_signature "$live" 'existing NEOTH.app' ||
    die 'existing NEOTH.app is not signed by the pinned NEOTH release identity; use the documented migration/uninstall flow first'
fi
verify_command_links
NEOTH_PKG_PREINSTALL
  } >"$scripts_dir/preinstall"

  {
    printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      'export LC_ALL=C' \
      "require_signature=$require_signature" \
      "expected_bundle_id='$BUNDLE_ID'" \
      "expected_release_version='$version'" \
      "expected_bundle_version='$bundle_version'" \
      "expected_team_id='$expected_team_id'" \
      "expected_requirement_sha256='$expected_requirement_sha256'" \
      'expected_owner_uid=0' \
      "expected_target_volume='/'" \
      'codesign_tool=/usr/bin/codesign' \
      'find_tool=/usr/bin/find' \
      'plutil_tool=/usr/bin/plutil' \
      'readlink_tool=/usr/bin/readlink' \
      'shasum_tool=/usr/bin/shasum' \
      'stat_tool=/usr/bin/stat'
    cat <<'NEOTH_PKG_POSTINSTALL'

die() {
  printf 'NEOTH PKG postinstall: %s\n' "$*" >&2
  exit 1
}

target_volume=${3:-/}
[ "$target_volume" = "$expected_target_volume" ] ||
  die "this package may only be installed on the root volume: $target_volume"
case "$target_volume" in
  /) applications_root=/Applications ;;
  /*) applications_root="${target_volume%/}/Applications" ;;
  *) die "target volume is not absolute: $target_volume" ;;
esac
live="$applications_root/NEOTH.app"
case "$target_volume" in
  /) bin_root=/usr/local/bin ;;
  *) bin_root="${target_volume%/}/usr/local/bin" ;;
esac

require_owned_path() {
  path=$1
  label=$2
  [ ! -L "$path" ] || die "$label must not be a symbolic link: $path"
  [ -f "$path" ] || [ -d "$path" ] || die "$label is not a regular file or directory: $path"
  metadata=$("$stat_tool" -f '%u %Sp' "$path") || die "could not inspect $label: $path"
  owner=${metadata%% *}
  mode=${metadata#* }
  [ "$owner" = "$expected_owner_uid" ] || die "$label is not owned by the package owner: $path"
  case "$mode" in
    ?????w????* | ????????w?*) die "$label is group/world-writable: $path" ;;
  esac
}

plist_value() {
  "$plutil_tool" -extract "$2" raw -o - "$1" 2>/dev/null
}

require_plist_value() {
  file=$1
  key=$2
  expected=$3
  label=$4
  actual=$(plist_value "$file" "$key") || die "$label is missing $key"
  [ "$actual" = "$expected" ] || die "$label has an unexpected $key"
}

verify_new_payload() {
  app=$1
  [ -d "$app" ] && [ ! -L "$app" ] || die "installed NEOTH.app must be a non-link directory"
  listing=$("$find_tool" "$app" -print) || die 'could not inspect installed NEOTH.app'
  old_ifs=$IFS
  IFS='
'
  set -f
  for path in $listing; do
    require_owned_path "$path" 'installed NEOTH.app member'
  done
  set +f
  IFS=$old_ifs

  info="$app/Contents/Info.plist"
  receipt="$app/Contents/Resources/neoth-package-ownership.plist"
  require_plist_value "$info" CFBundleIdentifier "$expected_bundle_id" 'installed Info.plist'
  require_plist_value "$info" CFBundleExecutable neothd-gui 'installed Info.plist'
  require_plist_value "$info" CFBundlePackageType APPL 'installed Info.plist'
  require_plist_value "$info" CFBundleVersion "$expected_bundle_version" 'installed Info.plist'
  require_plist_value "$info" NEOTHReleaseVersion "$expected_release_version" 'installed Info.plist'
  require_plist_value "$receipt" schema_version 1 'installed ownership receipt'
  require_plist_value "$receipt" product NEOTH 'installed ownership receipt'
  require_plist_value "$receipt" bundle_id "$expected_bundle_id" 'installed ownership receipt'
  require_plist_value "$receipt" install_profile native-pkg 'installed ownership receipt'
  require_plist_value "$receipt" release_version "$expected_release_version" 'installed ownership receipt'
  for name in neoth neothd neothd-gui neoth-migrate neoth-relay neoth-keet-bridge; do
    require_owned_path "$app/Contents/MacOS/$name" "installed executable $name"
  done
  require_owned_path "$app/Contents/Resources/self-knowledge/manifest.json" \
    'installed self-knowledge manifest'
}

verify_exact_signature() {
  app=$1
  "$codesign_tool" --verify --deep --strict --verbose=2 "$app" ||
    die 'installed NEOTH.app signature verification failed'
  details=$("$codesign_tool" -dv --verbose=4 "$app" 2>&1) ||
    die 'installed NEOTH.app signer identity could not be read'
  team=$(printf '%s\n' "$details" | /usr/bin/sed -n 's/^TeamIdentifier=//p' | /usr/bin/tail -n 1)
  [ "$team" = "$expected_team_id" ] || die 'installed NEOTH.app Team ID is not pinned'
  requirement_output=$("$codesign_tool" -d -r- "$app" 2>&1) ||
    die 'installed NEOTH.app designated requirement could not be read'
  requirement=$(printf '%s\n' "$requirement_output" |
    /usr/bin/sed -n 's/^designated => //p' | /usr/bin/tail -n 1)
  [ -n "$requirement" ] || die 'installed NEOTH.app designated requirement is missing'
  requirement_sha256=$(printf '%s' "$requirement" | "$shasum_tool" -a 256 | /usr/bin/awk '{print $1}')
  [ "$requirement_sha256" = "$expected_requirement_sha256" ] ||
    die 'installed NEOTH.app designated requirement is not pinned'
}

verify_installed_command_links() {
  [ -d "$bin_root" ] && [ ! -L "$bin_root" ] || die 'installed command directory is invalid'
  for name in neoth neothd neothd-gui neoth-migrate neoth-relay neoth-keet-bridge; do
    path="$bin_root/$name"
    expected="/Applications/NEOTH.app/Contents/MacOS/$name"
    [ -L "$path" ] || die "installed command link is missing: $path"
    [ "$("$readlink_tool" "$path")" = "$expected" ] || die "installed command link is wrong: $path"
    owner=$("$stat_tool" -f '%u' "$path") || die "could not inspect installed command link: $path"
    [ "$owner" = "$expected_owner_uid" ] || die "installed command link has the wrong owner: $path"
  done
  path="$bin_root/neoth-uninstall"
  [ -L "$path" ] || die "installed command link is missing: $path"
  [ "$("$readlink_tool" "$path")" = '/Applications/NEOTH.app/Contents/Resources/uninstall-neoth.sh' ] ||
    die "installed command link is wrong: $path"
  owner=$("$stat_tool" -f '%u' "$path") || die "could not inspect installed command link: $path"
  [ "$owner" = "$expected_owner_uid" ] || die "installed command link has the wrong owner: $path"
}

# PackageKit has already placed the strict, non-relocatable component at its
# live path. Validate only those new bytes. Returning nonzero delegates rollback
# to PackageKit; this script never executes, moves, or removes an old candidate.
verify_new_payload "$live"
if [ "$require_signature" -eq 1 ]; then
  verify_exact_signature "$live"
fi
verify_installed_command_links
"$live/Contents/MacOS/neoth" --output json self-knowledge verify \
  --snapshot "$live/Contents/Resources/self-knowledge" >/dev/null
NEOTH_PKG_POSTINSTALL
  } >"$scripts_dir/postinstall"

  chmod 0755 "$scripts_dir/preinstall" "$scripts_dir/postinstall"
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
  local name checksum path relative
  printf '%s\n' 'NEOTH-MACOS-PREFLIGHT-V1'
  printf 'version %s\n' "$version"
  printf 'target %s\n' "$target"
  printf 'architecture %s\n' "$arch"
  for name in "${BINARIES[@]}" "${SUPPORT_FILES[@]}"; do
    checksum=$(shasum -a 256 "$bundle/$name" | awk '{print $1}')
    printf '%s  %s\n' "$checksum" "$name"
  done
  while IFS= read -r path; do
    relative=${path#"$bundle/"}
    checksum=$(shasum -a 256 "$path" | awk '{print $1}')
    printf '%s  %s\n' "$checksum" "$relative"
  done < <(find "$bundle/self-knowledge" -type f -print | LC_ALL=C sort)
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
/Applications/NEOTH.app/Contents/Resources/neoth-package-ownership.plist
/Applications/NEOTH.app/Contents/Resources/self-knowledge/manifest.json
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
numeric_version=${version%%-*}
bundle_version=$(macos_bundle_version "$version")

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
need_cmd find
if [[ -n $write_preflight_receipt || -n $preflight_receipt ]]; then
  need_cmd cmp
  need_cmd shasum
  need_cmd sort
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
snapshot="$bundle/self-knowledge"
[[ -d $snapshot && ! -L $snapshot && -s $snapshot/manifest.json && ! -L $snapshot/manifest.json ]] ||
  die "missing regular self-knowledge snapshot and manifest"
[[ -z $(find "$snapshot" -type l -print -quit) ]] ||
  die "self-knowledge snapshot must not contain symlinks"
[[ -z $(find "$snapshot" ! -type f ! -type d -print -quit) ]] ||
  die "self-knowledge snapshot contains a non-file/non-directory entry"
while IFS= read -r -d '' path; do
  [[ $path != *$'\n'* && $path != *$'\r'* ]] ||
    die "self-knowledge path contains a newline"
done < <(find "$snapshot" -print0)
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

for command in awk chmod cmp codesign date diff ditto find hdiutil install lipo lsbom mktemp pkgbuild pkgutil plutil sed shasum sort tail tar touch xcrun; do
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
ditto "$snapshot" "$resources_dir/self-knowledge"
install -m 0755 "$SCRIPT_DIR/uninstall-neoth.sh" "$resources_dir/uninstall-neoth.sh"

sed -e "s/@NUMERIC_VERSION@/$numeric_version/g" \
  -e "s/@BUNDLE_VERSION@/$bundle_version/g" \
  -e "s/@RELEASE_VERSION@/$version/g" \
  "$SCRIPT_DIR/Info.plist.in" >"$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" >/dev/null
[[ $(plutil -extract CFBundleVersion raw -o - "$app/Contents/Info.plist") == "$bundle_version" ]] ||
  die "app PackageKit bundle-version contract drifted"
[[ $(plutil -extract LSEnvironment.NEOTH_PRODUCT_LAUNCHER raw -o - "$app/Contents/Info.plist") == 1 ]] ||
  die "app product-launcher environment contract drifted"
ownership_receipt="$resources_dir/neoth-package-ownership.plist"
cat >"$ownership_receipt" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>schema_version</key>
  <integer>1</integer>
  <key>product</key>
  <string>NEOTH</string>
  <key>bundle_id</key>
  <string>$BUNDLE_ID</string>
  <key>install_profile</key>
  <string>native-pkg</string>
  <key>release_version</key>
  <string>$version</string>
</dict>
</plist>
EOF
plutil -lint "$ownership_receipt" >/dev/null

timestamp="$(date -u -r "$source_date_epoch" '+%Y%m%d%H%M.%S')"
find "$app" -exec touch -h -t "$timestamp" {} +

expected_team_id=UNSIGNED
expected_requirement_sha256=UNSIGNED
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
  codesign --verify --deep --strict --verbose=2 "$app"
  signature_details=$(codesign -dv --verbose=4 "$app" 2>&1) ||
    die "could not read the signed app identity"
  expected_team_id=$(sed -n 's/^TeamIdentifier=//p' <<<"$signature_details" | tail -n 1)
  [[ $expected_team_id =~ ^[A-Z0-9]{10}$ ]] ||
    die "signed app has no exact 10-character Team ID"
  requirement_output=$(codesign -d -r- "$app" 2>&1) ||
    die "could not read the signed app designated requirement"
  designated_requirement=$(sed -n 's/^designated => //p' <<<"$requirement_output" | tail -n 1)
  [[ -n $designated_requirement ]] || die "signed app has no designated requirement"
  expected_requirement_sha256=$(printf '%s' "$designated_requirement" | shasum -a 256 | awk '{print $1}')
  [[ $expected_requirement_sha256 =~ ^[0-9a-f]{64}$ ]] ||
    die "signed app designated requirement digest is invalid"
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
ditto "$snapshot" "$portable_root/self-knowledge"
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
diff -qr "$snapshot" "$portable_verify/$(basename "$portable_root")/self-knowledge" >/dev/null ||
  die "portable archive changed or omitted self-knowledge payload"
write_sidecars "$portable_output" portable-tar

pkg_root="$work/pkg-root"
pkg_scripts="$work/pkg-scripts"
pkg_component_plist="$work/pkg-components.plist"
mkdir -p "$pkg_root/Applications" "$pkg_root/usr/local/bin"
# PackageKit owns the live, strict component. Its BOM and receipt therefore
# describe the files operators actually run; rollback is PackageKit's job.
ditto "$app" "$pkg_root/Applications/NEOTH.app"
for name in "${BINARIES[@]}"; do
  ln -s "/Applications/NEOTH.app/Contents/MacOS/$name" "$pkg_root/usr/local/bin/$name"
done
ln -s '/Applications/NEOTH.app/Contents/Resources/uninstall-neoth.sh' "$pkg_root/usr/local/bin/neoth-uninstall"
find "$pkg_root" -exec touch -h -t "$timestamp" {} +
write_pkg_install_scripts \
  "$pkg_scripts" \
  "$do_signing" \
  "$expected_team_id" \
  "$expected_requirement_sha256"
find "$pkg_scripts" -exec touch -h -t "$timestamp" {} +
cat >"$pkg_component_plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>BundleHasStrictIdentifier</key>
    <true/>
    <key>BundleIsRelocatable</key>
    <false/>
    <key>BundleIsVersionChecked</key>
    <true/>
    <key>BundleOverwriteAction</key>
    <string>upgrade</string>
    <key>RootRelativeBundlePath</key>
    <string>Applications/NEOTH.app</string>
  </dict>
</array>
</plist>
EOF
plutil -lint "$pkg_component_plist" >/dev/null
touch -h -t "$timestamp" "$pkg_component_plist"

pkg_args=(--root "$pkg_root" --scripts "$pkg_scripts" --component-plist "$pkg_component_plist" --identifier "$BUNDLE_ID" --version "$bundle_version" --install-location / --ownership recommended)
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
pkg_verify="$work/pkg-verify"
pkgutil --expand-full "$pkg_output" "$pkg_verify"
diff -qr \
  "$snapshot" \
  "$pkg_verify/Payload/Applications/NEOTH.app/Contents/Resources/self-knowledge" >/dev/null ||
  die "built PKG changed or omitted self-knowledge payload"
[[ -x $pkg_verify/Scripts/preinstall && -x $pkg_verify/Scripts/postinstall ]] ||
  die "built PKG omitted executable ownership install scripts"
cmp -s \
  "$ownership_receipt" \
  "$pkg_verify/Payload/Applications/NEOTH.app/Contents/Resources/neoth-package-ownership.plist" ||
  die "built PKG changed or omitted its ownership receipt"
[[ -f $pkg_verify/Bom ]] || die "built PKG has no PackageKit BOM"
pkg_bom_payload=$(lsbom -s "$pkg_verify/Bom" | sed 's#^\./##')
grep -Fqx 'Applications/NEOTH.app/Contents/Info.plist' <<<"$pkg_bom_payload" ||
  die "built PKG BOM does not own the live NEOTH.app"
if grep -F '.NEOTH.app.neoth-pkg-' <<<"$pkg_bom_payload" >/dev/null; then
  die "built PKG BOM still owns a hidden transaction carrier"
fi

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
cmp -s "$ownership_receipt" "$app_output/Contents/Resources/neoth-package-ownership.plist" ||
  die "built app changed or omitted its ownership receipt"
diff -qr "$snapshot" "$app_output/Contents/Resources/self-knowledge" >/dev/null ||
  die "built app changed or omitted self-knowledge payload"
plutil -lint "$app_output/Contents/Info.plist" >/dev/null
[[ $(plutil -extract CFBundleIdentifier raw -o - "$app_output/Contents/Info.plist") == "$BUNDLE_ID" ]] ||
  die "built app bundle identifier drifted"
[[ $(plutil -extract CFBundleVersion raw -o - "$app_output/Contents/Info.plist") == "$bundle_version" ]] ||
  die "built app PackageKit bundle version drifted"
[[ $(plutil -extract LSEnvironment.NEOTH_PRODUCT_LAUNCHER raw -o - "$app_output/Contents/Info.plist") == 1 ]] ||
  die "built app product-launcher environment contract drifted"
pkg_payload="$(pkgutil --payload-files "$pkg_output" | sed 's#^\./##')"
if grep -F '.NEOTH.app.neoth-pkg-' <<<"$pkg_payload" >/dev/null; then
  die "built PKG payload still owns a hidden transaction carrier"
fi
while IFS= read -r required_path; do
  grep -Fqx -- "${required_path#/}" <<<"$pkg_payload" || die "built PKG is missing $required_path"
  grep -Fqx -- "${required_path#/}" <<<"$pkg_bom_payload" || die "built PKG BOM is missing $required_path"
done < <(print_layout)
if ((do_notarization)); then
  xcrun stapler validate "$app_output"
fi

dmg_mount="$work/dmg-mount"
mkdir -p "$dmg_mount"
hdiutil attach -quiet -nobrowse -readonly -mountpoint "$dmg_mount" "$dmg_output"
[[ -d $dmg_mount/NEOTH.app ]] || die "built DMG is missing NEOTH.app"
[[ -s $dmg_mount/$(basename "$pkg_output") ]] || die "built DMG is missing its native PKG"
cmp -s "$ownership_receipt" "$dmg_mount/NEOTH.app/Contents/Resources/neoth-package-ownership.plist" ||
  die "built DMG changed or omitted the app ownership receipt"
diff -qr "$snapshot" "$dmg_mount/NEOTH.app/Contents/Resources/self-knowledge" >/dev/null ||
  die "built DMG changed or omitted self-knowledge payload"
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
