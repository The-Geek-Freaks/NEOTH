#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install.sh — NEOTH bootstrap installer for Linux + macOS
# ─────────────────────────────────────────────────────────────────────────────
# Downloads the published `neoth` binary from the GitHub Releases page,
# verifies its SHA256 and mandatory release authenticity via minisign or a
# temporary, digest-pinned cosign bootstrap,
# installs to `~/.local/bin/neoth` (or
# `$NEOTH_INSTALL_DIR` if set), atomically installs every package-owned binary,
# example, legal/support file, and the verified self-knowledge snapshot, then
# prints next steps. The explicitly headless musl archive omits GUI and Keet
# because the standalone Bare runtime is glibc-linked.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.sh | bash
#   NEOTH_VERSION=v1.0.0 ./install.sh                  # pin a specific version
#   NEOTH_INSTALL_DIR=/opt/neoth/bin ./install.sh      # alt install location
#   NEOTH_ALLOW_UNVERIFIED_RECOVERY=1 ./install.sh     # emergency only; loud warning
#
# Release format matches `.github/workflows/release.yml` (hand-rolled —
# OPEN_DECISIONS D-001 rejected cargo-dist):
#   - archive:  neoth-<version>-<target>.tar.gz
#   - checksum: neoth-<version>-<target>.tar.gz.sha256
#   - minisign: neoth-<version>-<target>.tar.gz.minisig
#   - cosign:   neoth-<version>-<target>.tar.gz.cosign.bundle
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail
umask 077
unset TAR_OPTIONS

# ── Config ──────────────────────────────────────────────────────────────────
NEOTH_VERSION="${NEOTH_VERSION:-latest}"
NEOTH_INSTALL_DIR="${NEOTH_INSTALL_DIR:-$HOME/.local/bin}"
NEOTH_ALLOW_UNVERIFIED_RECOVERY="${NEOTH_ALLOW_UNVERIFIED_RECOVERY:-0}"
RELEASES_URL="https://github.com/The-Geek-Freaks/NEOTH/releases"
RELEASES_API_URL="https://api.github.com/repos/The-Geek-Freaks/NEOTH/releases"
PINNED_MINISIGN_PUBKEY="RWQa0n4hqyE1huqkKoU+4aUs+YjbMiWabY4MwnwIafb79dWiSLV7qGBi"
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
# Digests are copied from sigstore/cosign-installer action.yml at the immutable
# source commit recorded in packaging/cosign-bootstrap.json. The downloaded
# verifier lives only in this installer's temporary directory.
COSIGN_BOOTSTRAP_VERSION="v3.0.6"
COSIGN_BOOTSTRAP_LINUX_AMD64_SHA256="c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74"
COSIGN_BOOTSTRAP_LINUX_ARM64_SHA256="bedac92e8c3729864e13d4a17048007cfafa79d5deca993a43a90ffe018ef2b8"
COSIGN_BOOTSTRAP_DARWIN_AMD64_SHA256="4c3e7af8372d3ca3296e62fa56f23fcbb5721cc6ac1827900d398f110d7cd280"
COSIGN_BOOTSTRAP_DARWIN_ARM64_SHA256="5fadd012ae6381a6a29ff86a7d39aa873878852f1073fc90b15995961ecfb084"
COSIGN_VERIFIER=""
MAX_ARCHIVE_BYTES=1073741824
MAX_METADATA_BYTES=16777216
MAX_VERIFIER_BYTES=268435456
MAX_ARCHIVE_ENTRIES=100000
MAX_ARCHIVE_DEPTH=64
MAX_ARCHIVE_MEMBER_BYTES=1073741824
MAX_ARCHIVE_TOTAL_BYTES=8589934592
MAX_ARCHIVE_LISTING_BYTES=67108864
MAX_ARCHIVE_RECORDS=500000
MAX_ARCHIVE_RECORD_BYTES=67108864
MAX_DOWNLOAD_SECONDS=600

# ── Helpers ─────────────────────────────────────────────────────────────────
err() { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || err "missing required command: $1"
}

validate_release_tag() {
    local version="$1" prerelease part
    local -a parts
    if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
        err "invalid release tag (strict SemVer required): $version"
    fi
    if [[ "$version" == *-* ]]; then
        prerelease="${version#*-}"
        IFS='.' read -r -a parts <<< "$prerelease"
        for part in "${parts[@]}"; do
            if [[ "$part" =~ ^[0-9]+$ && ${#part} -gt 1 && "$part" == 0* ]]; then
                err "invalid numeric prerelease identifier with leading zero: $version"
            fi
        done
    fi
}

sha256_file() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        err "neither sha256sum nor shasum found — cannot verify downloaded bytes"
    fi
}

bounded_stream_to_file() {
    local destination="$1" max_bytes="$2" part actual
    part="$destination.part"
    rm -f "$destination" "$part"
    head -c $((max_bytes + 1)) > "$part" || { rm -f "$part"; return 1; }
    actual="$(wc -c < "$part" | tr -d '[:space:]')"
    if [[ ! "$actual" =~ ^[0-9]+$ ]] || [ "$actual" -gt "$max_bytes" ]; then
        rm -f "$part"
        return 1
    fi
    mv "$part" "$destination"
}

download_file() {
    local uri="$1" destination="$2" max_bytes="$3" attempt
    rm -f "$destination" "$destination.part"
    for attempt in 1 2 3; do
        if curl --connect-timeout 20 \
            --max-time "$MAX_DOWNLOAD_SECONDS" \
            --proto '=https' --proto-redir '=https' --max-filesize "$max_bytes" \
            -fsSL "$uri" | bounded_stream_to_file "$destination" "$max_bytes"; then
            return
        fi
        rm -f "$destination" "$destination.part"
        [ "$attempt" = 3 ] || sleep "$attempt"
    done
    return 1
}

resolve_cosign_verifier() {
    local os arch filename expected path got

    if command -v cosign >/dev/null 2>&1; then
        COSIGN_VERIFIER="$(command -v cosign)"
        return
    fi

    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os-$arch" in
        Linux-x86_64)
            filename="cosign-linux-amd64"
            expected="$COSIGN_BOOTSTRAP_LINUX_AMD64_SHA256"
            ;;
        Linux-aarch64|Linux-arm64)
            filename="cosign-linux-arm64"
            expected="$COSIGN_BOOTSTRAP_LINUX_ARM64_SHA256"
            ;;
        Darwin-x86_64)
            filename="cosign-darwin-amd64"
            expected="$COSIGN_BOOTSTRAP_DARWIN_AMD64_SHA256"
            ;;
        Darwin-arm64|Darwin-aarch64)
            filename="cosign-darwin-arm64"
            expected="$COSIGN_BOOTSTRAP_DARWIN_ARM64_SHA256"
            ;;
        *)
            err "no digest-pinned cosign bootstrap for $os-$arch"
            ;;
    esac

    path="$TMP/$filename"
    info "→ downloading digest-pinned cosign $COSIGN_BOOTSTRAP_VERSION verifier"
    if ! download_file \
        "https://github.com/sigstore/cosign/releases/download/$COSIGN_BOOTSTRAP_VERSION/$filename" \
        "$path" "$MAX_VERIFIER_BYTES"; then
        if [ "$NEOTH_ALLOW_UNVERIFIED_RECOVERY" = "1" ]; then
            printf '\nWARNING: NEOTH_ALLOW_UNVERIFIED_RECOVERY=1\n' >&2
            printf 'The digest-pinned cosign verifier could not be downloaded. Authenticity was NOT verified.\n' >&2
            printf 'Use this recovery path only for an archive you authenticated out of band.\n\n' >&2
            COSIGN_VERIFIER=""
            return
        fi
        err "failed to download digest-pinned cosign verifier"
    fi

    got="$(sha256_file "$path")"
    if [ "$got" != "$expected" ]; then
        err "bootstrap cosign SHA256 mismatch: expected $expected, got $got — refusing to execute it"
    fi
    chmod 700 "$path"
    COSIGN_VERIFIER="$path"
    info "✓ digest-pinned cosign verifier ready ($got)"
}

verify_release_authenticity() {
    local archive_path="$1" signature_path="$2" bundle_path="$3"
    local certificate_identity trusted_count
    certificate_identity="https://github.com/The-Geek-Freaks/NEOTH/.github/workflows/release.yml@refs/tags/$VERSION"

    download_file "$BASE_URL/$SIGNATURE" "$signature_path" "$MAX_METADATA_BYTES" \
        || err "failed to download mandatory signature $BASE_URL/$SIGNATURE"

    if command -v minisign >/dev/null 2>&1; then
        info "→ verifying minisign release signature"
        minisign -Vm "$archive_path" -x "$signature_path" \
            -P "$PINNED_MINISIGN_PUBKEY" \
            || err "minisign verification failed — refusing to install"
        trusted_count="$(grep -c '^trusted comment:' "$signature_path" || true)"
        if [ "$trusted_count" != "1" ] \
            || ! grep -Fqx "trusted comment: file:$ARCHIVE" "$signature_path"; then
            err "minisign trusted comment is not bound to file:$ARCHIVE"
        fi
        info "✓ minisign signature verified"
        return
    fi

    resolve_cosign_verifier
    if [ -n "$COSIGN_VERIFIER" ]; then
        download_file "$BASE_URL/$COSIGN_BUNDLE" "$bundle_path" "$MAX_METADATA_BYTES" \
            || err "failed to download $BASE_URL/$COSIGN_BUNDLE"
        info "→ verifying exact cosign workflow identity"
        "$COSIGN_VERIFIER" verify-blob \
            --bundle "$bundle_path" \
            --certificate-identity "$certificate_identity" \
            --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
            "$archive_path" \
            || err "cosign verification failed — refusing to install"
        info "✓ cosign signature verified"
        return
    fi

    if [ "$NEOTH_ALLOW_UNVERIFIED_RECOVERY" = "1" ]; then
        return
    fi

    err "digest-pinned cosign verifier was not available (emergency only: NEOTH_ALLOW_UNVERIFIED_RECOVERY=1)"
}

detect_target() {
    local os arch
    if [ -n "${NEOTH_TARGET:-}" ]; then
        case "$NEOTH_TARGET" in
            x86_64-unknown-linux-gnu|x86_64-unknown-linux-musl|aarch64-unknown-linux-gnu|x86_64-apple-darwin|aarch64-apple-darwin)
                printf '%s\n' "$NEOTH_TARGET"
                return
                ;;
            *) err "unsupported forced target: $NEOTH_TARGET" ;;
        esac
    fi
    os="$(uname -s)"
    arch="$(uname -m)"
    # Matches the build matrix in `.github/workflows/release.yml`.
    case "$os-$arch" in
        Linux-x86_64)  echo "x86_64-unknown-linux-gnu" ;;
        Linux-aarch64) echo "aarch64-unknown-linux-gnu" ;;
        Darwin-arm64)  echo "aarch64-apple-darwin" ;;
        Darwin-x86_64) echo "x86_64-apple-darwin" ;;
        *) err "unsupported platform: $os-$arch (supported targets in release.yml: x86_64-linux-gnu, aarch64-linux-gnu, x86_64-darwin, aarch64-darwin)" ;;
    esac
}

verify_sha256_sidecar() {
    local file="$1" checksum_file="$2" expected_asset="$3"
    local checksum_line_count checksum_line checksum_pattern expected got

    checksum_line_count="$(awk 'END { print NR }' "$checksum_file")"
    [ "$checksum_line_count" = "1" ] \
        || err "checksum sidecar must contain exactly one line"
    IFS= read -r checksum_line < "$checksum_file" || [ -n "$checksum_line" ] \
        || err "checksum sidecar is empty"
    checksum_pattern='^([0-9A-Fa-f]{64})  (.+)$'
    if [[ ! "$checksum_line" =~ $checksum_pattern ]]; then
        err "checksum sidecar must be exactly: <64 hex><two spaces><asset name>"
    fi
    expected="${BASH_REMATCH[1]}"
    [ "${BASH_REMATCH[2]}" = "$expected_asset" ] \
        || err "checksum sidecar names '${BASH_REMATCH[2]}', expected '$expected_asset'"

    got="$(sha256_file "$file")"
    if [ "$got" != "$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')" ]; then
        err "SHA256 mismatch: expected $expected, got $got — refusing to install"
    fi
    info "✓ SHA256 verified ($got)"
}

preflight_tar_archive() {
    local archive="$1" expected_root="$2" destination="$3"
    local names="$TMP/archive.names" verbose="$TMP/archive.verbose"
    local records="$TMP/archive.records" sorted="$TMP/archive.records.sorted"
    local tar_flavor tar_version name metadata normalized type size key parent parent_key unexpected
    local entry_count=0 root_count=0 file_count=0 total_bytes=0
    local record_count=0 record_bytes=0 line_bytes=0
    local -a parts

    tar_version="$(tar --version 2>/dev/null | head -n 1)" \
        || err "could not identify tar implementation"
    case "$tar_version" in
    *"GNU tar"*)
        tar_flavor=gnu
        (
            ulimit -t 120 2>/dev/null || true
            LC_ALL=C tar --numeric-owner --quoting-style=escape --absolute-names -tzf "$archive"
        ) | bounded_stream_to_file "$names" "$MAX_ARCHIVE_LISTING_BYTES" \
            || err "release tar name preflight failed or exceeded its output/CPU ceiling"
        (
            ulimit -t 120 2>/dev/null || true
            LC_ALL=C tar --numeric-owner --quoting-style=escape --absolute-names -tvzf "$archive"
        ) | bounded_stream_to_file "$verbose" "$MAX_ARCHIVE_LISTING_BYTES" \
            || err "release tar metadata preflight failed or exceeded its output/CPU ceiling"
        ;;
    *bsdtar*|*libarchive*)
        tar_flavor=bsd
        (
            ulimit -t 120 2>/dev/null || true
            LC_ALL=C tar --numeric-owner -P -tzf "$archive"
        ) | bounded_stream_to_file "$names" "$MAX_ARCHIVE_LISTING_BYTES" \
            || err "release tar name preflight failed or exceeded its output/CPU ceiling"
        (
            ulimit -t 120 2>/dev/null || true
            LC_ALL=C tar --numeric-owner -P -tvzf "$archive"
        ) | bounded_stream_to_file "$verbose" "$MAX_ARCHIVE_LISTING_BYTES" \
            || err "release tar metadata preflight failed or exceeded its output/CPU ceiling"
        ;;
    *)
        err "unsupported tar implementation (requires GNU tar or bsdtar/libarchive): $tar_version"
        ;;
    esac

    : > "$records"
    exec 3< "$names"
    exec 4< "$verbose"
    while IFS= read -r name <&3 || [ -n "$name" ]; do
        IFS= read -r metadata <&4 || err "release tar name/metadata listing count mismatch"
        if [ "$tar_flavor" = bsd ]; then
            # Native Windows bsdtar writes CRLF; remove exactly the transport
            # CR. Any CR embedded in an archive name remains and is rejected.
            name="${name%$'\r'}"
            metadata="${metadata%$'\r'}"
        fi
        entry_count=$((entry_count + 1))
        [ "$entry_count" -le "$MAX_ARCHIVE_ENTRIES" ] \
            || err "release tar exceeds the $MAX_ARCHIVE_ENTRIES-entry ceiling"
        [ "${#name}" -le 4096 ] || err "release tar member path exceeds 4096 bytes"
        if printf '%s' "$name" | LC_ALL=C grep -q '[^ -~]'; then
            err "release tar paths must be printable ASCII for cross-platform canonicalization"
        fi
        case "$name" in
            *\\*|/*|*//*|*:*) err "unsafe release tar path: $name" ;;
        esac
        [[ ! "$name" =~ ^[A-Za-z]: ]] || err "drive-qualified release tar path: $name"

        type="${metadata:0:1}"
        case "$type" in
            -)
                [[ "$name" != */ ]] || err "regular release tar member ends with '/': $name"
                normalized="$name"
                file_count=$((file_count + 1))
                ;;
            d)
                [[ "$name" == */ ]] || err "release tar directory lacks canonical trailing '/': $name"
                normalized="${name%/}"
                ;;
            *) err "release tar contains a symlink, hardlink, or special member: $name" ;;
        esac
        [ -n "$normalized" ] || err "release tar contains an empty member path"
        IFS='/' read -r -a parts <<< "$normalized"
        [ "${parts[0]}" = "$expected_root" ] \
            || err "release tar member is outside exact root $expected_root: $name"
        [ "${#parts[@]}" -le $((MAX_ARCHIVE_DEPTH + 1)) ] \
            || err "release tar member exceeds depth $MAX_ARCHIVE_DEPTH: $name"
        for part in "${parts[@]}"; do
            [ -n "$part" ] && [ "$part" != "." ] && [ "$part" != ".." ] \
                || err "release tar contains a traversal or empty path segment: $name"
        done

        if [ "$tar_flavor" = gnu ]; then
            size="$(printf '%s\n' "$metadata" | awk '{ print $3 }')"
        else
            size="$(printf '%s\n' "$metadata" | awk '{ print $5 }')"
        fi
        [[ "$size" =~ ^[0-9]+$ ]] || err "could not parse release tar member size: $name"
        if [ "$type" = d ] && [ "$size" != 0 ]; then
            err "release tar directory carries file data: $name"
        fi
        if [ "$type" = - ]; then
            [ "$size" -le "$MAX_ARCHIVE_MEMBER_BYTES" ] \
                || err "release tar member exceeds the $MAX_ARCHIVE_MEMBER_BYTES-byte ceiling: $name"
            [ "$total_bytes" -le $((MAX_ARCHIVE_TOTAL_BYTES - size)) ] \
                || err "release tar exceeds the $MAX_ARCHIVE_TOTAL_BYTES-byte expanded ceiling"
            total_bytes=$((total_bytes + size))
        fi

        key="$(printf '%s' "$normalized" | LC_ALL=C tr '[:upper:]' '[:lower:]')"
        line_bytes=$((${#key} + 4))
        [ "$record_count" -lt "$MAX_ARCHIVE_RECORDS" ] \
            && [ "$record_bytes" -le $((MAX_ARCHIVE_RECORD_BYTES - line_bytes)) ] \
            || err "release tar derived member index exceeds its record/byte ceiling"
        printf '%s\tA%s\n' "$key" "$type" >> "$records"
        record_count=$((record_count + 1))
        record_bytes=$((record_bytes + line_bytes))
        parent="$normalized"
        while [[ "$parent" == */* ]]; do
            parent="${parent%/*}"
            parent_key="$(printf '%s' "$parent" | LC_ALL=C tr '[:upper:]' '[:lower:]')"
            line_bytes=$((${#parent_key} + 3))
            [ "$record_count" -lt "$MAX_ARCHIVE_RECORDS" ] \
                && [ "$record_bytes" -le $((MAX_ARCHIVE_RECORD_BYTES - line_bytes)) ] \
                || err "release tar derived parent index exceeds its record/byte ceiling"
            printf '%s\tI\n' "$parent_key" >> "$records"
            record_count=$((record_count + 1))
            record_bytes=$((record_bytes + line_bytes))
        done
        if [ "$normalized" = "$expected_root" ]; then
            [ "$type" = d ] || err "release tar root is not a directory"
            root_count=$((root_count + 1))
        fi
    done
    if IFS= read -r metadata <&4; then
        err "release tar name/metadata listing count mismatch"
    fi
    exec 3<&-
    exec 4<&-
    [ "$entry_count" -gt 0 ] && [ "$file_count" -gt 0 ] \
        || err "release tar contains no installable files"
    [ "$root_count" = 1 ] || err "release tar must contain exactly one explicit root $expected_root/"

    LC_ALL=C sort -t "$(printf '\t')" -k1,1 "$records" > "$sorted"
    awk -F '\t' '
        function finish() {
            if (actual > 1 || (actual_type == "-" && implicit)) exit 1
        }
        $1 != key { if (NR > 1) finish(); key=$1; actual=0; actual_type=""; implicit=0 }
        $2 == "I" { implicit=1; next }
        { actual++; actual_type=substr($2, 2, 1) }
        END { finish() }
    ' "$sorted" || err "release tar contains duplicates, case-fold collisions, or a file/directory conflict"

    mkdir -m 700 "$destination"
    if [ "$tar_flavor" = gnu ]; then
        tar --extract --gzip --file "$archive" --directory "$destination" \
            --keep-old-files --no-same-owner --no-same-permissions --delay-directory-restore \
            || err "validated release tar extraction failed"
    else
        tar -xzkf "$archive" -C "$destination" --no-same-owner --no-same-permissions \
            || err "validated release tar extraction failed"
    fi
    if ! unexpected="$(find "$destination" -mindepth 1 ! -type f ! -type d -print -quit)"; then
        err "could not inspect the validated release extraction"
    fi
    if [ -n "$unexpected" ]; then
        err "release tar extraction produced a link, reparse, or special member"
    fi
}

preflight_portable_ownership() {
    local root="$1" marker marker_size owned
    if [ ! -e "$root" ] && [ ! -L "$root" ]; then
        return
    fi
    [ -d "$root" ] && [ ! -L "$root" ] \
        || err "portable install root must be a real directory: $root"
    marker="$root/.neoth-portable-install.json"
    # ~/.local/bin is intentionally a shared executable directory. A first
    # install therefore does not claim or inventory unrelated files. Once the
    # native transaction has committed a marker, however, it must remain a
    # bounded regular file and the Rust helper validates its complete identity
    # under the destination lock before replacing any package-owned member.
    if [ ! -e "$marker" ] && [ ! -L "$marker" ]; then
        for owned in neoth neothd neoth-migrate neoth-relay neothd-gui neoth-keet-bridge neoth-support; do
            if [ -e "$root/$owned" ] || [ -L "$root/$owned" ]; then
                err "markerless first install found existing NEOTH target $root/$owned; move/uninstall that legacy target or choose another install directory (unrelated files may remain)"
            fi
        done
        return
    fi
    [ -f "$marker" ] && [ ! -L "$marker" ] && [ -s "$marker" ] \
        || err "portable ownership marker is not a regular non-link file: $marker"
    marker_size="$(wc -c < "$marker" | tr -d '[:space:]')"
    [[ "$marker_size" =~ ^[0-9]+$ ]] && [ "$marker_size" -le 16384 ] \
        || err "portable ownership marker exceeds its 16384-byte ceiling: $marker"
}

# ── Main ────────────────────────────────────────────────────────────────────
require_cmd curl
require_cmd uname
require_cmd mkdir
require_cmd sed
require_cmd awk
require_cmd tr
require_cmd chmod
require_cmd wc
require_cmd grep
require_cmd sort
require_cmd find
require_cmd tar
require_cmd mktemp
require_cmd head

TMP_BASE="${TMPDIR:-/tmp}"
[ -d "$TMP_BASE" ] && [ ! -L "$TMP_BASE" ] || err "temporary root must be a real directory"
TMP="$(mktemp -d "$TMP_BASE/neoth-install.XXXXXXXX")"
[ -d "$TMP" ] && [ ! -L "$TMP" ] && [ -O "$TMP" ] \
    || err "could not create an owner-private installer directory"
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT

TARGET="$(detect_target)"
if [ "$NEOTH_VERSION" = "latest" ]; then
    info "→ resolving latest published release"
    LATEST_PATH="$TMP/latest-release.json"
    download_file "$RELEASES_API_URL/latest" "$LATEST_PATH" "$MAX_METADATA_BYTES" \
        || err "could not download the latest GitHub release metadata"
    VERSION="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$LATEST_PATH" | head -n 1)"
    [ -n "$VERSION" ] || err "could not resolve the latest GitHub release tag"
else
    VERSION="$NEOTH_VERSION"
fi
validate_release_tag "$VERSION"
info "→ detected target: $TARGET"
info "→ version: $VERSION"
info "→ install dir: $NEOTH_INSTALL_DIR"

# Release workflow naming (see .github/workflows/release.yml):
#   neoth-<version>-<target>.tar.gz
#   neoth-<version>-<target>.tar.gz.sha256
#   neoth-<version>-<target>.tar.gz.cosign.bundle  (mandatory without minisign)
BASE_URL="$RELEASES_URL/download/$VERSION"
ARCHIVE="neoth-$VERSION-$TARGET.tar.gz"
CHECKSUM="$ARCHIVE.sha256"
SIGNATURE="$ARCHIVE.minisig"
COSIGN_BUNDLE="$ARCHIVE.cosign.bundle"

info "→ downloading $ARCHIVE"
download_file "$BASE_URL/$ARCHIVE" "$TMP/$ARCHIVE" "$MAX_ARCHIVE_BYTES" \
    || err "failed to download $BASE_URL/$ARCHIVE"
download_file "$BASE_URL/$CHECKSUM" "$TMP/$CHECKSUM" "$MAX_METADATA_BYTES" \
    || err "failed to download $BASE_URL/$CHECKSUM"

verify_sha256_sidecar "$TMP/$ARCHIVE" "$TMP/$CHECKSUM" "$ARCHIVE"
verify_release_authenticity \
    "$TMP/$ARCHIVE" \
    "$TMP/$SIGNATURE" \
    "$TMP/$COSIGN_BUNDLE"

# Release workflow packs into a subdirectory `neoth-<version>-<target>/`.
ARCHIVE_NAME="neoth-$VERSION-$TARGET"
EXTRACTION_ROOT="$TMP/extracted"
info "→ validating and extracting"
preflight_tar_archive "$TMP/$ARCHIVE" "$ARCHIVE_NAME" "$EXTRACTION_ROOT"
BUNDLE_ROOT="$EXTRACTION_ROOT/$ARCHIVE_NAME"
[ -d "$BUNDLE_ROOT" ] && [ ! -L "$BUNDLE_ROOT" ] \
    || err "release archive is missing its exact non-symlink root $ARCHIVE_NAME"
BINARY_SRC="$BUNDLE_ROOT/neoth"
[ -f "$BINARY_SRC" ] && [ ! -L "$BINARY_SRC" ] && [ -x "$BINARY_SRC" ] \
    || err "release archive is missing its executable neoth transaction helper"
KEET_SRC="$BUNDLE_ROOT/neoth-keet-bridge"
GUI_SRC="$BUNDLE_ROOT/neothd-gui"
GUI_REQUIRED=1
KEET_REQUIRED=1
case "$TARGET" in
    *-unknown-linux-musl)
        GUI_REQUIRED=0
        KEET_REQUIRED=0
        # The native closed profile rejects these files in a musl bundle and
        # atomically removes stale copies from an older desktop installation.
        ;;
esac
if [ "$GUI_REQUIRED" = "1" ] && [ ! -f "$GUI_SRC" ]; then
    err "desktop release archive is missing neothd-gui"
fi
if [ "$KEET_REQUIRED" = "1" ] && [ ! -f "$KEET_SRC" ]; then
    err "desktop release archive is missing neoth-keet-bridge"
fi
if [ "$KEET_REQUIRED" = "1" ]; then
    [ -x "$KEET_SRC" ] || err "neoth-keet-bridge in release archive is not executable"
    KEET_VERSION="$("$KEET_SRC" --version)" \
        || err "could not execute neoth-keet-bridge version preflight"
    [ "$KEET_VERSION" = "${VERSION#v}" ] \
        || err "neoth-keet-bridge version $KEET_VERSION does not match release ${VERSION#v}"
fi

SELF_KNOWLEDGE_SRC="$BUNDLE_ROOT/self-knowledge"
[ -d "$SELF_KNOWLEDGE_SRC" ] && [ ! -L "$SELF_KNOWLEDGE_SRC" ] \
    || err "release archive is missing a regular self-knowledge directory"
for required in manifest.json graph.json GRAPH_REPORT.md SOURCE_MANIFEST.json GENERATION_RECEIPT.json; do
    [ -s "$SELF_KNOWLEDGE_SRC/$required" ] && [ ! -L "$SELF_KNOWLEDGE_SRC/$required" ] \
        || err "release archive is missing self-knowledge/$required"
done
[ -d "$SELF_KNOWLEDGE_SRC/wiki" ] && [ -d "$SELF_KNOWLEDGE_SRC/obsidian" ] \
    || err "release archive self-knowledge is missing Wiki or Obsidian exports"
if [ -n "$(find "$SELF_KNOWLEDGE_SRC" -type l -print -quit)" ]; then
    err "release self-knowledge must not contain symlinks"
fi
if ! "$BINARY_SRC" --output json self-knowledge verify \
    --snapshot "$SELF_KNOWLEDGE_SRC" >/dev/null; then
    err "release binary rejected its self-knowledge snapshot"
fi

# The verified helper owns locking, destination-local staging, the durable
# journal, crash recovery, closed member selection, and the final `neoth`
# commit point. The bootstrap never mutates the install root before that lock.
case "$NEOTH_INSTALL_DIR" in
    *$'\n'*|*$'\r'*) err "install directory must not contain a newline" ;;
esac
preflight_portable_ownership "$NEOTH_INSTALL_DIR"
RECEIPT_PATH="$TMP/transaction-receipt.json"
if ! "$BINARY_SRC" --output json internal bundle-transaction apply \
    --bundle-root "$BUNDLE_ROOT" \
    --install-root "$NEOTH_INSTALL_DIR" \
    --expected-version "${VERSION#v}" > "$RECEIPT_PATH"; then
    err "native crash-safe bundle transaction failed"
fi
RECEIPT_SIZE="$(wc -c < "$RECEIPT_PATH" | tr -d '[:space:]')"
[ "$RECEIPT_SIZE" -le 4096 ] && [ "$(awk 'END { print NR }' "$RECEIPT_PATH")" = 1 ] \
    || err "native bundle transaction returned a non-canonical receipt"
IFS= read -r TRANSACTION_RECEIPT < "$RECEIPT_PATH" || [ -n "$TRANSACTION_RECEIPT" ]
EXPECTED_PROFILE=desktop
case "$TARGET" in *-unknown-linux-musl) EXPECTED_PROFILE=headless_musl ;; esac
RECEIPT_PATTERN='^\{"members":[1-9][0-9]*,"profile":"(desktop|headless_musl)","status":"committed","transaction_id":"[0-9a-f]{32}","version":"[^"]+"\}$'
[[ "$TRANSACTION_RECEIPT" =~ $RECEIPT_PATTERN ]] \
    || err "native bundle transaction returned an invalid receipt"
[[ "$TRANSACTION_RECEIPT" == *\"profile\":\"$EXPECTED_PROFILE\"* \
    && "$TRANSACTION_RECEIPT" == *\"version\":\"${VERSION#v}\"* ]] \
    || err "native bundle transaction receipt does not match this release"
[ -s "$NEOTH_INSTALL_DIR/.neoth-portable-install.json" ] \
    && [ ! -L "$NEOTH_INSTALL_DIR/.neoth-portable-install.json" ] \
    || err "native bundle transaction did not commit its portable ownership marker"

GUI_INSTALLED=0
if [ "$GUI_REQUIRED" = "1" ]; then
    GUI_INSTALLED=1
else
    info "→ this Linux server target is CLI-only; build neothd-gui from source for a desktop session"
fi

KEET_INSTALLED=0
if [ "$KEET_REQUIRED" = "1" ]; then
    KEET_INSTALLED=1
else
    info "→ this musl server target omits the glibc-linked Keet companion"
fi

info ""
info "✓ neoth installed: $NEOTH_INSTALL_DIR/neoth"
if [ "$KEET_INSTALLED" = "1" ]; then
    info "✓ Keet companion installed: $NEOTH_INSTALL_DIR/neoth-keet-bridge"
fi
info ""

# Wire a durable user-shell PATH entry idempotently. A piped installer cannot
# mutate its parent shell, so also print the exact current-shell export.
case ":$PATH:" in
    *":$NEOTH_INSTALL_DIR:"*) ;;
    *)
        case "${SHELL:-}" in
            */zsh) PATH_PROFILE="$HOME/.zshrc" ;;
            */bash) PATH_PROFILE="$HOME/.bashrc" ;;
            *) PATH_PROFILE="$HOME/.profile" ;;
        esac
        PATH_MARKER="# NEOTH installer PATH: $NEOTH_INSTALL_DIR"
        touch "$PATH_PROFILE" || err "could not update shell profile $PATH_PROFILE"
        if ! grep -Fqx "$PATH_MARKER" "$PATH_PROFILE"; then
            {
                printf '\n%s\n' "$PATH_MARKER"
                printf 'export PATH=%q:"$PATH"\n' "$NEOTH_INSTALL_DIR"
            } >> "$PATH_PROFILE" || err "could not update shell profile $PATH_PROFILE"
        fi
        info "→ wired $NEOTH_INSTALL_DIR into $PATH_PROFILE"
        info "For this current shell, run:"
        printf '  export PATH=%q:"$PATH"\n' "$NEOTH_INSTALL_DIR"
        info ""
        ;;
esac

info "Next steps:"
if [ "$GUI_INSTALLED" = "1" ]; then
    info "  1. Launch the GUI wizard:      $NEOTH_INSTALL_DIR/neoth gui"
else
    info "  1. Run the CLI wizard:         $NEOTH_INSTALL_DIR/neoth init"
fi
info "  2. Or copy the example config: cp $NEOTH_INSTALL_DIR/neoth-support/freedom.yaml.example ~/.neoth/freedom.yaml"
info "  3. Start the daemon:           $NEOTH_INSTALL_DIR/neoth serve"
if [ "$KEET_INSTALLED" = "1" ]; then
    info "  4. To enable the Keet channel: $NEOTH_INSTALL_DIR/neoth-keet-bridge setup"
fi
