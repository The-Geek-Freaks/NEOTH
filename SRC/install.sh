#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install.sh — NEOTH bootstrap installer for Linux + macOS
# ─────────────────────────────────────────────────────────────────────────────
# Downloads the published `neothd` binary from the GitHub Releases page,
# verifies its SHA256 against the matching `.sha256` checksum file, optionally
# verifies the cosign keyless signature, installs to `~/.local/bin/neothd` (or
# `$NEOTH_INSTALL_DIR` if set), copies `freedom.yaml.example` next to it,
# and prints next steps.
#
# Usage:
#   curl -fsSL https://example.invalid/neoth/install.sh | bash
#   NEOTH_VERSION=v0.2.0 ./install.sh                  # pin a specific version
#   NEOTH_INSTALL_DIR=/opt/neoth/bin ./install.sh      # alt install location
#   NEOTH_VERIFY_SIGNATURE=1 ./install.sh              # also cosign-verify
#
# Release format matches `.github/workflows/release.yml` (hand-rolled —
# OPEN_DECISIONS D-001 rejected cargo-dist):
#   - archive:  neothd-<version>-<target>.tar.gz
#   - checksum: neothd-<version>-<target>.tar.gz.sha256
#   - cosign:   neothd-<version>-<target>.tar.gz.cosign.bundle (optional)
#
# Heads-up: update RELEASE_URL_TEMPLATE below with the real owner/repo
# before publishing the installer.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────────
NEOTH_VERSION="${NEOTH_VERSION:-latest}"
NEOTH_INSTALL_DIR="${NEOTH_INSTALL_DIR:-$HOME/.local/bin}"
NEOTH_VERIFY_SIGNATURE="${NEOTH_VERIFY_SIGNATURE:-0}"
# Replace this with the real owner/repo before publishing the installer.
RELEASE_URL_TEMPLATE="https://github.com/REPLACE-WITH-OWNER/REPLACE-WITH-REPO/releases/download"
# Cosign certificate identity regex — matches the release.yml workflow path.
COSIGN_IDENTITY_REGEX="https://github.com/.*/neoth/\.github/workflows/release\.yml@.*"
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"

# ── Helpers ─────────────────────────────────────────────────────────────────
err() { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || err "missing required command: $1"
}

detect_target() {
    local os arch
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

verify_sha256() {
    local file="$1" expected="$2" got
    if command -v sha256sum >/dev/null 2>&1; then
        got="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        got="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        err "neither sha256sum nor shasum found — cannot verify checksum"
    fi
    if [ "$got" != "$expected" ]; then
        err "SHA256 mismatch: expected $expected, got $got — refusing to install"
    fi
    info "✓ SHA256 verified ($got)"
}

# ── Main ────────────────────────────────────────────────────────────────────
require_cmd curl
require_cmd uname
require_cmd mkdir
require_cmd install

if [[ "$RELEASE_URL_TEMPLATE" == *REPLACE-WITH-OWNER* ]]; then
    info "─────────────────────────────────────────────────────────────────────"
    info " RELEASE_URL_TEMPLATE in install.sh still has the placeholder."
    info " Edit it to point at your org/repo before publishing the installer."
    info " (Release workflow lives in .github/workflows/release.yml.)"
    info "─────────────────────────────────────────────────────────────────────"
    exit 1
fi

TARGET="$(detect_target)"
info "→ detected target: $TARGET"
info "→ version: $NEOTH_VERSION"
info "→ install dir: $NEOTH_INSTALL_DIR"

# Release workflow naming (see .github/workflows/release.yml):
#   neothd-<version>-<target>.tar.gz
#   neothd-<version>-<target>.tar.gz.sha256
#   neothd-<version>-<target>.tar.gz.cosign.bundle  (optional verify)
if [ "$NEOTH_VERSION" = "latest" ]; then
    BASE_URL="$RELEASE_URL_TEMPLATE/latest"
else
    BASE_URL="$RELEASE_URL_TEMPLATE/$NEOTH_VERSION"
fi
ARCHIVE="neothd-$NEOTH_VERSION-$TARGET.tar.gz"
CHECKSUM="$ARCHIVE.sha256"
COSIGN_BUNDLE="$ARCHIVE.cosign.bundle"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info "→ downloading $ARCHIVE"
curl -fsSL "$BASE_URL/$ARCHIVE" -o "$TMP/$ARCHIVE" \
    || err "failed to download $BASE_URL/$ARCHIVE"
curl -fsSL "$BASE_URL/$CHECKSUM" -o "$TMP/$CHECKSUM" \
    || err "failed to download $BASE_URL/$CHECKSUM"

EXPECTED_SHA="$(awk '{print $1}' "$TMP/$CHECKSUM")"
[ -n "$EXPECTED_SHA" ] || err "checksum file is empty"
verify_sha256 "$TMP/$ARCHIVE" "$EXPECTED_SHA"

# Optional cosign keyless verify — proves the binary was built by the
# release.yml workflow on GitHub Actions (transparency log on Rekor).
if [ "$NEOTH_VERIFY_SIGNATURE" = "1" ]; then
    if ! command -v cosign >/dev/null 2>&1; then
        err "NEOTH_VERIFY_SIGNATURE=1 set but cosign not installed (https://docs.sigstore.dev/cosign/installation)"
    fi
    curl -fsSL "$BASE_URL/$COSIGN_BUNDLE" -o "$TMP/$COSIGN_BUNDLE" \
        || err "failed to download $BASE_URL/$COSIGN_BUNDLE"
    info "→ verifying cosign signature"
    cosign verify-blob \
        --bundle "$TMP/$COSIGN_BUNDLE" \
        --certificate-identity-regexp "$COSIGN_IDENTITY_REGEX" \
        --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
        "$TMP/$ARCHIVE" \
        || err "cosign verification failed — refusing to install"
    info "✓ cosign signature verified"
fi

info "→ extracting"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP" || err "tar extraction failed"

# Release workflow packs into a subdirectory `neothd-<version>-<target>/`.
ARCHIVE_NAME="neothd-$NEOTH_VERSION-$TARGET"
BINARY_SRC="$TMP/$ARCHIVE_NAME/neothd"
[ -f "$BINARY_SRC" ] || BINARY_SRC="$TMP/neothd"
[ -f "$BINARY_SRC" ] || err "could not locate neothd binary in extracted archive"

mkdir -p "$NEOTH_INSTALL_DIR"
install -m 0755 "$BINARY_SRC" "$NEOTH_INSTALL_DIR/neothd" \
    || err "could not install to $NEOTH_INSTALL_DIR"

# Drop the example config alongside if the release bundled one + the
# target isn't already populated.
EXAMPLE_SRC="$TMP/$ARCHIVE_NAME/freedom.yaml.example"
[ -f "$EXAMPLE_SRC" ] || EXAMPLE_SRC="$TMP/freedom.yaml.example"
if [ -f "$EXAMPLE_SRC" ] && [ ! -f "$NEOTH_INSTALL_DIR/freedom.yaml.example" ]; then
    install -m 0644 "$EXAMPLE_SRC" \
        "$NEOTH_INSTALL_DIR/freedom.yaml.example"
fi

info ""
info "✓ neothd installed: $NEOTH_INSTALL_DIR/neothd"
info ""

# PATH hint when the install dir isn't already on PATH.
case ":$PATH:" in
    *":$NEOTH_INSTALL_DIR:"*) ;;
    *)
        info "Add $NEOTH_INSTALL_DIR to your PATH:"
        info "  echo 'export PATH=\"$NEOTH_INSTALL_DIR:\$PATH\"' >> ~/.bashrc"
        info ""
        ;;
esac

info "Next steps:"
info "  1. Run the onboarding wizard:  neothd init"
info "  2. Or copy the example config: cp $NEOTH_INSTALL_DIR/freedom.yaml.example ~/.neoth/freedom.yaml"
info "  3. Start the daemon:           neothd serve"
