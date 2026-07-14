#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install.sh — NEOTH bootstrap installer for Linux + macOS
# ─────────────────────────────────────────────────────────────────────────────
# Downloads the published `neoth` binary from the GitHub Releases page,
# verifies its SHA256 and mandatory release authenticity via minisign or cosign,
# installs to `~/.local/bin/neoth` (or
# `$NEOTH_INSTALL_DIR` if set), copies `freedom.yaml.example` next to it,
# installs the `neothd` compatibility executable, migration/relay companion
# tools, installs `neothd-gui` on desktop release targets, and prints next steps.
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

# ── Config ──────────────────────────────────────────────────────────────────
NEOTH_VERSION="${NEOTH_VERSION:-latest}"
NEOTH_INSTALL_DIR="${NEOTH_INSTALL_DIR:-$HOME/.local/bin}"
NEOTH_ALLOW_UNVERIFIED_RECOVERY="${NEOTH_ALLOW_UNVERIFIED_RECOVERY:-0}"
RELEASES_URL="https://github.com/The-Geek-Freaks/NEOTH/releases"
RELEASES_API_URL="https://api.github.com/repos/The-Geek-Freaks/NEOTH/releases"
PINNED_MINISIGN_PUBKEY="RWQa0n4hqyE1huqkKoU+4aUs+YjbMiWabY4MwnwIafb79dWiSLV7qGBi"
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"

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

verify_release_authenticity() {
    local archive_path="$1" signature_path="$2" bundle_path="$3"
    local certificate_identity trusted_count
    certificate_identity="https://github.com/The-Geek-Freaks/NEOTH/.github/workflows/release.yml@refs/tags/$VERSION"

    curl -fsSL "$BASE_URL/$SIGNATURE" -o "$signature_path" \
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

    if command -v cosign >/dev/null 2>&1; then
        curl -fsSL "$BASE_URL/$COSIGN_BUNDLE" -o "$bundle_path" \
            || err "failed to download $BASE_URL/$COSIGN_BUNDLE"
        info "→ verifying exact cosign workflow identity"
        cosign verify-blob \
            --bundle "$bundle_path" \
            --certificate-identity "$certificate_identity" \
            --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
            "$archive_path" \
            || err "cosign verification failed — refusing to install"
        info "✓ cosign signature verified"
        return
    fi

    if [ "$NEOTH_ALLOW_UNVERIFIED_RECOVERY" = "1" ]; then
        printf '\nWARNING: NEOTH_ALLOW_UNVERIFIED_RECOVERY=1\n' >&2
        printf 'No minisign or cosign executable is available. Authenticity was NOT verified.\n' >&2
        printf 'Use this recovery path only for an archive you authenticated out of band.\n\n' >&2
        return
    fi

    err "no authenticity verifier found; install minisign or cosign (emergency only: NEOTH_ALLOW_UNVERIFIED_RECOVERY=1)"
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

    if command -v sha256sum >/dev/null 2>&1; then
        got="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        got="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        err "neither sha256sum nor shasum found — cannot verify checksum"
    fi
    if [ "$got" != "$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')" ]; then
        err "SHA256 mismatch: expected $expected, got $got — refusing to install"
    fi
    info "✓ SHA256 verified ($got)"
}

# ── Main ────────────────────────────────────────────────────────────────────
require_cmd curl
require_cmd uname
require_cmd mkdir
require_cmd install
require_cmd sed
require_cmd awk
require_cmd tr

TARGET="$(detect_target)"
if [ "$NEOTH_VERSION" = "latest" ]; then
    info "→ resolving latest published release"
    VERSION="$(curl -fsSL "$RELEASES_API_URL/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
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
#   neoth-<version>-<target>.tar.gz.cosign.bundle  (optional verify)
BASE_URL="$RELEASES_URL/download/$VERSION"
ARCHIVE="neoth-$VERSION-$TARGET.tar.gz"
CHECKSUM="$ARCHIVE.sha256"
SIGNATURE="$ARCHIVE.minisig"
COSIGN_BUNDLE="$ARCHIVE.cosign.bundle"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info "→ downloading $ARCHIVE"
curl -fsSL "$BASE_URL/$ARCHIVE" -o "$TMP/$ARCHIVE" \
    || err "failed to download $BASE_URL/$ARCHIVE"
curl -fsSL "$BASE_URL/$CHECKSUM" -o "$TMP/$CHECKSUM" \
    || err "failed to download $BASE_URL/$CHECKSUM"

verify_sha256_sidecar "$TMP/$ARCHIVE" "$TMP/$CHECKSUM" "$ARCHIVE"
verify_release_authenticity \
    "$TMP/$ARCHIVE" \
    "$TMP/$SIGNATURE" \
    "$TMP/$COSIGN_BUNDLE"

info "→ extracting"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP" || err "tar extraction failed"

# Release workflow packs into a subdirectory `neoth-<version>-<target>/`.
ARCHIVE_NAME="neoth-$VERSION-$TARGET"
BINARY_SRC="$TMP/$ARCHIVE_NAME/neoth"
[ -f "$BINARY_SRC" ] || BINARY_SRC="$TMP/neoth"
[ -f "$BINARY_SRC" ] || err "could not locate neoth binary in extracted archive"
COMPAT_SRC="$TMP/$ARCHIVE_NAME/neothd"
[ -f "$COMPAT_SRC" ] || COMPAT_SRC="$TMP/neothd"
[ -f "$COMPAT_SRC" ] || err "could not locate neothd compatibility launcher in extracted archive"
MIGRATE_SRC="$TMP/$ARCHIVE_NAME/neoth-migrate"
[ -f "$MIGRATE_SRC" ] || MIGRATE_SRC="$TMP/neoth-migrate"
[ -f "$MIGRATE_SRC" ] || err "release archive is missing neoth-migrate"
RELAY_SRC="$TMP/$ARCHIVE_NAME/neoth-relay"
[ -f "$RELAY_SRC" ] || RELAY_SRC="$TMP/neoth-relay"
[ -f "$RELAY_SRC" ] || err "release archive is missing neoth-relay"
GUI_SRC="$TMP/$ARCHIVE_NAME/neothd-gui"
[ -f "$GUI_SRC" ] || GUI_SRC="$TMP/neothd-gui"
GUI_REQUIRED=1
case "$TARGET" in
    *-unknown-linux-musl) GUI_REQUIRED=0 ;;
esac
if [ "$GUI_REQUIRED" = "1" ] && [ ! -f "$GUI_SRC" ]; then
    err "desktop release archive is missing neothd-gui"
fi

# The example config is part of the release contract. A missing source is a
# corrupt artifact and must fail closed instead of silently degrading setup.
EXAMPLE_SRC="$TMP/$ARCHIVE_NAME/freedom.yaml.example"
[ -f "$EXAMPLE_SRC" ] || EXAMPLE_SRC="$TMP/freedom.yaml.example"
[ -f "$EXAMPLE_SRC" ] || err "release archive is missing freedom.yaml.example"
IMPORT_EXAMPLE_SRC="$TMP/$ARCHIVE_NAME/import-manifest.example.yaml"
[ -f "$IMPORT_EXAMPLE_SRC" ] || IMPORT_EXAMPLE_SRC="$TMP/import-manifest.example.yaml"
[ -f "$IMPORT_EXAMPLE_SRC" ] || err "release archive is missing import-manifest.example.yaml"

# Stage the complete payload on the destination filesystem, replace companions
# before the public entrypoint, and roll back in reverse order on any failure.
mkdir -p "$NEOTH_INSTALL_DIR"
case "$NEOTH_INSTALL_DIR" in
    *$'\n'*|*$'\r'*) err "install directory must not contain a newline" ;;
esac

transactional_install() {
    local stage payload backup index name source mode destination
    local -a names sources modes replaced
    stage="$(mktemp -d "$NEOTH_INSTALL_DIR/.neoth-install.XXXXXX")"
    payload="$stage/payload"
    backup="$stage/backup"
    mkdir -p "$payload" "$backup"

    names=("neothd" "neoth-migrate" "neoth-relay")
    sources=("$COMPAT_SRC" "$MIGRATE_SRC" "$RELAY_SRC")
    modes=("0755" "0755" "0755")
    if [ -f "$GUI_SRC" ]; then
        names+=("neothd-gui")
        sources+=("$GUI_SRC")
        modes+=("0755")
    fi
    if [ ! -e "$NEOTH_INSTALL_DIR/freedom.yaml.example" ] && [ ! -L "$NEOTH_INSTALL_DIR/freedom.yaml.example" ]; then
        names+=("freedom.yaml.example")
        sources+=("$EXAMPLE_SRC")
        modes+=("0644")
    fi
    if [ ! -e "$NEOTH_INSTALL_DIR/import-manifest.example.yaml" ] && [ ! -L "$NEOTH_INSTALL_DIR/import-manifest.example.yaml" ]; then
        names+=("import-manifest.example.yaml")
        sources+=("$IMPORT_EXAMPLE_SRC")
        modes+=("0644")
    fi
    # Core is the commit point: it is replaced only after every companion.
    names+=("neoth")
    sources+=("$BINARY_SRC")
    modes+=("0755")

    for index in "${!names[@]}"; do
        name="${names[$index]}"
        source="${sources[$index]}"
        mode="${modes[$index]}"
        destination="$NEOTH_INSTALL_DIR/$name"
        if { [ -e "$destination" ] || [ -L "$destination" ]; } \
            && [ ! -f "$destination" ] && [ ! -L "$destination" ]; then
            rm -rf "$stage"
            err "install target is not a regular file: $destination"
        fi
        if ! install -m "$mode" "$source" "$payload/$name"; then
            rm -rf "$stage"
            err "could not stage $name in $NEOTH_INSTALL_DIR"
        fi
    done

    rollback_replaced() {
        local rollback_index rollback_name rollback_destination rollback_failed=0
        for ((rollback_index=${#replaced[@]} - 1; rollback_index >= 0; rollback_index--)); do
            rollback_name="${replaced[$rollback_index]}"
            rollback_destination="$NEOTH_INSTALL_DIR/$rollback_name"
            rm -f "$rollback_destination" || rollback_failed=1
            if [ -e "$backup/$rollback_name" ] || [ -L "$backup/$rollback_name" ]; then
                mv "$backup/$rollback_name" "$rollback_destination" \
                    || { printf 'error: rollback could not restore %s\n' "$rollback_destination" >&2; rollback_failed=1; }
            fi
        done
        return "$rollback_failed"
    }

    replaced=()
    for name in "${names[@]}"; do
        destination="$NEOTH_INSTALL_DIR/$name"
        if [ -e "$destination" ] || [ -L "$destination" ]; then
            if ! mv "$destination" "$backup/$name"; then
                if ! rollback_replaced; then
                    err "could not back up $destination; rollback backups retained at $backup"
                fi
                rm -rf "$stage"
                err "could not back up $destination"
            fi
        fi
        replaced+=("$name")
        if ! mv "$payload/$name" "$destination"; then
            if ! rollback_replaced; then
                err "could not install $name; rollback backups retained at $backup"
            fi
            rm -rf "$stage"
            err "could not install $name; previous files were restored"
        fi
    done

    rm -rf "$stage"
}

transactional_install

GUI_INSTALLED=0
if [ -f "$GUI_SRC" ]; then
    GUI_INSTALLED=1
else
    info "→ this Linux server target is CLI-only; build neothd-gui from source for a desktop session"
fi

info ""
info "✓ neoth installed: $NEOTH_INSTALL_DIR/neoth"
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
info "  2. Or copy the example config: cp $NEOTH_INSTALL_DIR/freedom.yaml.example ~/.neoth/freedom.yaml"
info "  3. Start the daemon:           $NEOTH_INSTALL_DIR/neoth serve"
