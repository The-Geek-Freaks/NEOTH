#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly BINARIES=(neoth neothd neothd-gui neoth-migrate neoth-relay neoth-keet-bridge)
readonly VERSIONED_BINARIES=(neoth neothd neoth-migrate neoth-relay neoth-keet-bridge)
readonly SUPPORT_FILES=(README.md LICENSE-MIT LICENSE-APACHE THIRD_PARTY_LICENSES freedom.yaml.example import-manifest.example.yaml)

usage() {
  cat <<'EOF'
Usage:
  build-packages.sh --bundle DIR --version X.Y.Z --arch x86_64|aarch64 \
    --output DIR --source-date-epoch UNIX_EPOCH [--preflight-receipt FILE]
  build-packages.sh --bundle DIR --version X.Y.Z --arch x86_64|aarch64 \
    --validate-only --write-preflight-receipt FILE
  build-packages.sh --print-layout

Builds a native .deb and .rpm from an extracted, version-bound NEOTH desktop
release bundle. The bundle directory must be named for its Rust target, for
example neoth-v1.0.0-x86_64-unknown-linux-gnu.

The write mode executes version probes and binds every input byte. The consume
mode verifies that receipt without executing any bundled product.
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
  local checksum basename
  basename=$(basename -- "$artifact")
  checksum=$(sha256sum -- "$artifact" | awk '{print $1}')
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
    "native_package_signed": false
  }
}
EOF
  touch --date="@$source_date_epoch" "$artifact.sha256" "$artifact.json"
}

emit_preflight_receipt() {
  local name checksum
  printf '%s\n' 'NEOTH-LINUX-PREFLIGHT-V1'
  printf 'version %s\n' "$version"
  printf 'target %s\n' "$target"
  printf 'architecture %s\n' "$arch"
  for name in "${BINARIES[@]}" "${SUPPORT_FILES[@]}"; do
    checksum=$(sha256sum -- "$bundle/$name" | awk '{print $1}')
    printf '%s  %s\n' "$checksum" "$name"
  done
}

write_preflight_receipt_file() {
  local destination=$1
  local parent temporary
  [[ ! -e $destination ]] || die "preflight receipt already exists: $destination"
  parent=$(dirname -- "$destination")
  [[ -d $parent ]] || die "preflight receipt directory not found: $parent"
  temporary=$(mktemp "$parent/.release-preflight.XXXXXX")
  if ! (umask 077; emit_preflight_receipt >"$temporary"); then
    rm -f -- "$temporary"
    die "could not write preflight receipt"
  fi
  mv -- "$temporary" "$destination"
}

verify_preflight_receipt_file() {
  local receipt=$1
  local temporary
  [[ -f $receipt && ! -L $receipt ]] ||
    die "preflight receipt must be a regular, non-symlink file: $receipt"
  temporary=$(mktemp "${TMPDIR:-/tmp}/neoth-preflight-verify.XXXXXX")
  emit_preflight_receipt >"$temporary"
  if ! cmp -s -- "$temporary" "$receipt"; then
    rm -f -- "$temporary"
    die "preflight receipt does not match version, target, architecture, or bundle bytes"
  fi
  rm -f -- "$temporary"
}

print_layout() {
  cat <<'EOF'
/usr/bin/neoth
/usr/bin/neothd
/usr/bin/neothd-gui
/usr/bin/neoth-migrate
/usr/bin/neoth-relay
/usr/bin/neoth-keet-bridge
/usr/share/applications/neoth.desktop
/usr/share/icons/hicolor/scalable/apps/neoth.svg
/usr/share/doc/neoth/README.md
/usr/share/doc/neoth/LICENSE-MIT
/usr/share/doc/neoth/LICENSE-APACHE
/usr/share/doc/neoth/THIRD_PARTY_LICENSES
/usr/share/doc/neoth/examples/freedom.yaml.example
/usr/share/doc/neoth/examples/import-manifest.example.yaml
EOF
}

bundle=
version=
arch=
output=
source_date_epoch=${SOURCE_DATE_EPOCH:-}
validate_only=0
write_preflight_receipt=
preflight_receipt=

while (($#)); do
  case "$1" in
    --bundle | --version | --arch | --output | --source-date-epoch | \
      --write-preflight-receipt | --preflight-receipt)
      (($# >= 2)) || die "$1 requires a value"
      case "$1" in
        --bundle) bundle=$2 ;;
        --version) version=$2 ;;
        --arch) arch=$2 ;;
        --output) output=$2 ;;
        --source-date-epoch) source_date_epoch=$2 ;;
        --write-preflight-receipt) write_preflight_receipt=$2 ;;
        --preflight-receipt) preflight_receipt=$2 ;;
      esac
      shift 2
      ;;
    --validate-only)
      validate_only=1
      shift
      ;;
    --print-layout)
      (($# == 1)) || die "--print-layout cannot be combined with other arguments"
      print_layout
      exit 0
      ;;
    -h | --help)
      usage
      exit 0
      ;;
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
  x86_64)
    target=x86_64-unknown-linux-gnu
    deb_arch=amd64
    rpm_arch=x86_64
    machine_pattern='Advanced Micro Devices X86-64|X86-64'
    ;;
  aarch64)
    target=aarch64-unknown-linux-gnu
    deb_arch=arm64
    rpm_arch=aarch64
    machine_pattern=AArch64
    ;;
  *) die "unsupported architecture: $arch (expected x86_64 or aarch64)" ;;
esac

[[ -d $bundle ]] || die "bundle directory not found: $bundle"
bundle="$(cd -- "$bundle" && pwd -P)"
[[ $(basename -- "$bundle") == "neoth-v${version}-${target}" ]] ||
  die "bundle directory must be named neoth-v${version}-${target}"

need_cmd readelf
if [[ -n $write_preflight_receipt || -n $preflight_receipt ]]; then
  need_cmd cmp
  need_cmd sha256sum
fi
if [[ -z $preflight_receipt ]]; then
  need_cmd timeout
fi

for name in "${BINARIES[@]}"; do
  path="$bundle/$name"
  [[ -f $path && ! -L $path && -s $path && -x $path ]] ||
    die "missing regular non-empty executable: $name"
  readelf_header="$(readelf -h -- "$path" 2>/dev/null)" || die "$name is not a readable ELF executable"
  grep -Eq "Machine:[[:space:]]*(${machine_pattern})" <<<"$readelf_header" ||
    die "$name does not match requested architecture $arch"
done

for name in "${SUPPORT_FILES[@]}"; do
  [[ -f $bundle/$name && ! -L $bundle/$name && -s $bundle/$name ]] ||
    die "missing regular non-empty release file: $name"
done

if [[ -n $preflight_receipt ]]; then
  verify_preflight_receipt_file "$preflight_receipt"
else
  for name in "${VERSIONED_BINARIES[@]}"; do
    version_output="$(timeout 15 "$bundle/$name" --version 2>&1)" ||
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

need_cmd date
need_cmd cmp
need_cmd cpio
need_cmd dpkg-deb
need_cmd dpkg-shlibdeps
need_cmd du
need_cmd find
need_cmd install
need_cmd rpm
need_cmd rpm2cpio
need_cmd rpmbuild
need_cmd sha256sum
need_cmd tar
need_cmd touch

mkdir -p -- "$output"
output="$(cd -- "$output" && pwd -P)"
deb_version=${version/-/~}
version_without_build=${version%%+*}
rpm_core=${version_without_build%%-*}
if [[ $version_without_build == *-* ]]; then
  rpm_prerelease=${version_without_build#*-}
  rpm_prerelease=${rpm_prerelease//+/.}
  rpm_prerelease=${rpm_prerelease//-/.}
  rpm_release="0.${rpm_prerelease}.1"
else
  rpm_release=1
fi
deb_final="$output/NEOTH-${version}-${target}.deb"
rpm_final="$output/NEOTH-${version}-${target}.rpm"
for artifact in "$deb_final" "$deb_final.sha256" "$deb_final.json" \
  "$rpm_final" "$rpm_final.sha256" "$rpm_final.json"; do
  [[ ! -e $artifact ]] || die "output already exists: $artifact"
done

work="$(mktemp -d "$output/.packaging-linux.XXXXXX")"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p -- "$work/artifacts"
deb_output="$work/artifacts/$(basename -- "$deb_final")"
rpm_output="$work/artifacts/$(basename -- "$rpm_final")"

payload="$work/payload"
doc_dir="$payload/usr/share/doc/neoth"
examples_dir="$doc_dir/examples"
mkdir -p -- "$payload/usr/bin" "$payload/usr/share/applications" \
  "$payload/usr/share/icons/hicolor/scalable/apps" "$examples_dir"

for name in "${BINARIES[@]}"; do
  install -m 0755 -- "$bundle/$name" "$payload/usr/bin/$name"
done
install -m 0644 -- "$SCRIPT_DIR/neoth.desktop" "$payload/usr/share/applications/neoth.desktop"
install -m 0644 -- "$SCRIPT_DIR/neoth.svg" "$payload/usr/share/icons/hicolor/scalable/apps/neoth.svg"
for name in README.md LICENSE-MIT LICENSE-APACHE THIRD_PARTY_LICENSES; do
  install -m 0644 -- "$bundle/$name" "$doc_dir/$name"
done
for name in freedom.yaml.example import-manifest.example.yaml; do
  install -m 0644 -- "$bundle/$name" "$examples_dir/$name"
done

find "$payload" -exec touch --no-dereference --date="@$source_date_epoch" {} +

deb_root="$work/deb-root"
mkdir -p -- "$deb_root"
cp -a -- "$payload/." "$deb_root/"
mkdir -p -- "$deb_root/DEBIAN" "$work/debian"

cat >"$work/debian/control" <<EOF
Source: neoth
Section: utils
Priority: optional
Maintainer: The Geek Freaks <noreply@the-geek-freaks.invalid>

Package: neoth
Architecture: any
Description: Local-first agent runtime and assistant
EOF

shlib_args=()
for name in "${BINARIES[@]}"; do
  shlib_args+=("-e$deb_root/usr/bin/$name")
done
shlib_line="$(cd -- "$work" && dpkg-shlibdeps -O "${shlib_args[@]}")" || die "dpkg-shlibdeps failed"
depends=${shlib_line#shlibs:Depends=}
[[ -n $depends && $depends != "$shlib_line" ]] || die "dpkg-shlibdeps returned no dependency contract"
installed_size="$(du -sk -- "$deb_root/usr" | awk '{print $1}')"

cat >"$deb_root/DEBIAN/control" <<EOF
Package: neoth
Version: $deb_version
Section: utils
Priority: optional
Architecture: $deb_arch
Maintainer: The Geek Freaks <noreply@the-geek-freaks.invalid>
Installed-Size: $installed_size
Depends: $depends
Homepage: https://github.com/The-Geek-Freaks/NEOTH
Description: Local-first agent runtime and assistant
 NEOTH combines a CLI, desktop GUI, migration utility, relay, compatibility
 launcher, and authenticated Keet companion in one version-bound package.
 User state is intentionally outside the package and survives removal.
EOF
find "$deb_root" -exec touch --no-dereference --date="@$source_date_epoch" {} +
SOURCE_DATE_EPOCH=$source_date_epoch dpkg-deb --build --root-owner-group "$deb_root" "$deb_output" >/dev/null
dpkg-deb --info "$deb_output" >/dev/null
[[ $(dpkg-deb -f "$deb_output" Package) == neoth ]] || die "built DEB package name drifted"
[[ $(dpkg-deb -f "$deb_output" Version) == "$deb_version" ]] || die "built DEB version drifted"
[[ $(dpkg-deb -f "$deb_output" Architecture) == "$deb_arch" ]] || die "built DEB architecture drifted"
mapfile -t deb_paths < <(dpkg-deb --fsys-tarfile "$deb_output" | tar -tf - | sed -e 's#^\./#/#' -e '/\/$/d')
while IFS= read -r required_path; do
  printf '%s\n' "${deb_paths[@]}" | grep -Fqx -- "$required_path" ||
    die "built DEB is missing $required_path"
done < <(print_layout)
deb_verify="$work/deb-verify"
mkdir -p -- "$deb_verify"
dpkg-deb -x "$deb_output" "$deb_verify"
for name in "${BINARIES[@]}"; do
  cmp -s -- "$bundle/$name" "$deb_verify/usr/bin/$name" || die "DEB changed binary $name"
done
write_sidecars "$deb_output" deb

rpm_top="$work/rpmbuild"
mkdir -p -- "$rpm_top/BUILD" "$rpm_top/BUILDROOT" "$rpm_top/RPMS" "$rpm_top/SOURCES" "$rpm_top/SPECS" "$rpm_top/SRPMS"
source_root="$rpm_top/SOURCES/neoth-$rpm_core"
mkdir -p -- "$source_root"
cp -a -- "$payload/." "$source_root/"
find "$source_root" -exec touch --no-dereference --date="@$source_date_epoch" {} +
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  -C "$rpm_top/SOURCES" -czf "$rpm_top/SOURCES/neoth-$rpm_core.tar.gz" "neoth-$rpm_core"
changelog_date="$(date -u --date="@$source_date_epoch" '+%a %b %d %Y')"

cat >"$rpm_top/SPECS/neoth.spec" <<EOF
%global debug_package %{nil}
%global __os_install_post %{nil}
Name: neoth
Version: $rpm_core
Release: $rpm_release
Summary: Local-first agent runtime and assistant
License: MIT OR Apache-2.0
URL: https://github.com/The-Geek-Freaks/NEOTH
Source0: %{name}-%{version}.tar.gz
BuildArch: $rpm_arch
AutoReqProv: yes

%description
NEOTH combines a CLI, desktop GUI, migration utility, relay, compatibility
launcher, and authenticated Keet companion in one version-bound package.
User state is intentionally outside the package and survives removal.

%prep
%setup -q

%build

%install
mkdir -p %{buildroot}
cp -a . %{buildroot}/

%files
%defattr(-,root,root,-)
%license %{_docdir}/neoth/LICENSE-MIT
%license %{_docdir}/neoth/LICENSE-APACHE
%license %{_docdir}/neoth/THIRD_PARTY_LICENSES
%doc %{_docdir}/neoth/README.md
%doc %{_docdir}/neoth/examples
%{_bindir}/neoth
%{_bindir}/neothd
%{_bindir}/neothd-gui
%{_bindir}/neoth-migrate
%{_bindir}/neoth-relay
%{_bindir}/neoth-keet-bridge
%{_datadir}/applications/neoth.desktop
%{_datadir}/icons/hicolor/scalable/apps/neoth.svg

%changelog
* $changelog_date The Geek Freaks <noreply@the-geek-freaks.invalid> - $rpm_core-$rpm_release
- Reproducible NEOTH $version native package.
EOF

SOURCE_DATE_EPOCH=$source_date_epoch rpmbuild \
  --target "$rpm_arch" \
  --define "_topdir $rpm_top" \
  --define "_buildhost reproducible.neoth.invalid" \
  --define "_build_id_links none" \
  --define "_binary_payload w9.gzdio" \
  --define "clamp_mtime_to_source_date_epoch 1" \
  --define "source_date_epoch_from_changelog 0" \
  -bb "$rpm_top/SPECS/neoth.spec" >/dev/null

mapfile -t built_rpms < <(find "$rpm_top/RPMS" -type f -name '*.rpm' -print)
((${#built_rpms[@]} == 1)) || die "expected one binary RPM, found ${#built_rpms[@]}"
install -m 0644 -- "${built_rpms[0]}" "$rpm_output"
rpm -qpl "$rpm_output" >/dev/null
[[ $(rpm -qp --qf '%{NAME}' "$rpm_output") == neoth ]] || die "built RPM package name drifted"
[[ $(rpm -qp --qf '%{VERSION}' "$rpm_output") == "$rpm_core" ]] || die "built RPM version drifted"
[[ $(rpm -qp --qf '%{RELEASE}' "$rpm_output") == "$rpm_release" ]] || die "built RPM release drifted"
[[ $(rpm -qp --qf '%{ARCH}' "$rpm_output") == "$rpm_arch" ]] || die "built RPM architecture drifted"
mapfile -t rpm_paths < <(rpm -qpl "$rpm_output")
while IFS= read -r required_path; do
  printf '%s\n' "${rpm_paths[@]}" | grep -Fqx -- "$required_path" ||
    die "built RPM is missing $required_path"
done < <(print_layout)
rpm_verify="$work/rpm-verify"
mkdir -p -- "$rpm_verify"
(cd -- "$rpm_verify" && rpm2cpio "$rpm_output" | cpio -idm --quiet)
for name in "${BINARIES[@]}"; do
  cmp -s -- "$bundle/$name" "$rpm_verify/usr/bin/$name" || die "RPM changed binary $name"
done
write_sidecars "$rpm_output" rpm

for artifact in "$deb_output" "$deb_output.sha256" "$deb_output.json" \
  "$rpm_output" "$rpm_output.sha256" "$rpm_output.json"; do
  mv -- "$artifact" "$output/"
done
printf '%s\n%s\n%s\n%s\n%s\n%s\n' \
  "$deb_final" "$deb_final.sha256" "$deb_final.json" \
  "$rpm_final" "$rpm_final.sha256" "$rpm_final.json"
