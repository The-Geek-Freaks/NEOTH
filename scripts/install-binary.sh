#!/usr/bin/env bash
#
# NEOTH zero-install binary fetcher (Round-3 v0.4 R-08).
#
# Downloads the latest prebuilt `neothd` binary from GitHub Releases,
# verifies its SHA-256, and places it at $HOME/.local/bin/neothd. No
# Rust toolchain required — the operator on a fresh laptop runs this
# script + `neothd init` and is in the wizard. This is the "Alex's-mom
# path" the R-08 spec calls for.
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install-binary.sh | bash
#
# Environment toggles (all optional):
#   NEOTH_REPO       — owner/repo to fetch releases from
#                      (default: The-Geek-Freaks/NEOTH)
#   NEOTH_VERSION    — pin to a specific tag (default: latest)
#   NEOTH_BIN_DIR    — install dir (default: $HOME/.local/bin)
#   NEOTH_TARGET     — force a target triple (otherwise auto-detected)
#   NEOTH_FROM_SOURCE=1 — fall through to scripts/install.sh
#                      (kept for the source-build power-user path)
#   INSTALL_DEBUG=1  — verbose tracing
#
# Idempotent: re-running overwrites the existing binary (with backup).
# No sudo required.

set -euo pipefail

NEOTH_REPO="${NEOTH_REPO:-The-Geek-Freaks/NEOTH}"
NEOTH_BIN_DIR="${NEOTH_BIN_DIR:-$HOME/.local/bin}"
NEOTH_VERSION="${NEOTH_VERSION:-latest}"

[[ "${INSTALL_DEBUG:-0}" == "1" ]] && set -x

if [ -t 1 ]; then
    R='\033[0m' G='\033[0;32m' Y='\033[0;33m' RE='\033[0;31m' B='\033[1m'
else
    R='' G='' Y='' RE='' B=''
fi

log_info()  { echo -e "${G}[neoth]${R} $*"; }
log_warn()  { echo -e "${Y}[neoth WARNING]${R} $*" >&2; }
log_error() { echo -e "${RE}[neoth ERROR]${R} $*" >&2; }
log_step()  { echo -e "\n${B}==> $*${R}"; }

if [[ "${NEOTH_FROM_SOURCE:-0}" == "1" ]]; then
    log_info "NEOTH_FROM_SOURCE=1 — delegating to scripts/install.sh"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -x "$SCRIPT_DIR/install.sh" ]]; then
        exec "$SCRIPT_DIR/install.sh"
    else
        log_error "scripts/install.sh not found alongside this script."
        log_error "Run it manually after cloning the repo:"
        log_error "  git clone https://github.com/${NEOTH_REPO}.git"
        log_error "  cd NEOTH/scripts && bash install.sh"
        exit 1
    fi
fi

detect_target_triple() {
    if [[ -n "${NEOTH_TARGET:-}" ]]; then
        TARGET="$NEOTH_TARGET"
        log_info "Target (forced): $TARGET"
        return
    fi
    local os arch
    os="$(uname -s)" arch="$(uname -m)"
    case "$os" in
        Linux*)
            case "$arch" in
                x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
                aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
                *) log_error "Unsupported Linux arch: $arch"; exit 1 ;;
            esac
            ;;
        Darwin*)
            case "$arch" in
                x86_64) TARGET="x86_64-apple-darwin" ;;
                arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
                *) log_error "Unsupported macOS arch: $arch"; exit 1 ;;
            esac
            ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            log_error "Native Windows detected. Use the PowerShell installer:"
            log_error "  iwr -useb https://raw.githubusercontent.com/${NEOTH_REPO}/main/scripts/install-binary.ps1 | iex"
            log_error "Or use WSL2 + re-run this script."
            exit 1
            ;;
        *)
            log_error "Unknown OS: $os"
            exit 1
            ;;
    esac
    log_info "Target (auto-detected): $TARGET"
}

resolve_version() {
    if [[ "$NEOTH_VERSION" != "latest" ]]; then
        VERSION="$NEOTH_VERSION"
        log_info "Version (pinned): $VERSION"
        return
    fi
    log_info "Resolving latest tag from GitHub Releases..."
    local api_url="https://api.github.com/repos/${NEOTH_REPO}/releases/latest"
    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl is required + not on PATH."
        exit 1
    fi
    local tag
    tag="$(curl -sSf "$api_url" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    if [[ -z "$tag" ]]; then
        log_error "No release tag found at $api_url"
        log_error "If this is a fresh repo without releases, build from source:"
        log_error "  NEOTH_FROM_SOURCE=1 bash $0"
        exit 1
    fi
    VERSION="$tag"
    log_info "Latest tag: $VERSION"
}

download_and_verify() {
    local archive="neothd-${VERSION}-${TARGET}.tar.gz"
    local checksum="${archive}.sha256"
    local base="https://github.com/${NEOTH_REPO}/releases/download/${VERSION}"

    mkdir -p "$NEOTH_BIN_DIR"
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    log_step "Downloading $archive"
    if ! curl -sSf -L -o "$tmp/$archive" "$base/$archive"; then
        log_error "Download failed: $base/$archive"
        log_error "Possible causes: tag has no $TARGET artifact / network blocked / repo private."
        exit 1
    fi
    if ! curl -sSf -L -o "$tmp/$checksum" "$base/$checksum"; then
        log_warn "Checksum file missing — proceeding without verification."
        log_warn "(Older releases may not ship .sha256 sidecars.)"
    else
        log_step "Verifying SHA-256"
        local expected actual
        expected="$(awk '{print $1}' "$tmp/$checksum")"
        if command -v sha256sum >/dev/null 2>&1; then
            actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
            actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
        else
            log_error "Neither sha256sum nor shasum found — cannot verify."
            exit 1
        fi
        if [[ "$expected" != "$actual" ]]; then
            log_error "SHA-256 mismatch!"
            log_error "  expected: $expected"
            log_error "  actual:   $actual"
            log_error "Aborting — do NOT trust this artifact."
            exit 1
        fi
        log_info "Checksum OK"
    fi

    log_step "Extracting + installing to $NEOTH_BIN_DIR/neothd"
    tar -xzf "$tmp/$archive" -C "$tmp"
    local extracted_bin="$tmp/neothd-${VERSION}-${TARGET}/neothd"
    if [[ ! -f "$extracted_bin" ]]; then
        log_error "Expected binary at $extracted_bin but archive layout differs."
        log_error "Archive contents:"
        tar -tzf "$tmp/$archive" >&2
        exit 1
    fi

    if [[ -f "$NEOTH_BIN_DIR/neothd" ]]; then
        local backup="$NEOTH_BIN_DIR/neothd.bak.$(date +%s)"
        log_info "Existing neothd → $backup"
        mv "$NEOTH_BIN_DIR/neothd" "$backup"
    fi
    install -m 0755 "$extracted_bin" "$NEOTH_BIN_DIR/neothd"
    log_info "Installed: $($NEOTH_BIN_DIR/neothd --version 2>/dev/null || echo "$NEOTH_BIN_DIR/neothd")"
}

check_path() {
    case ":$PATH:" in
        *":$NEOTH_BIN_DIR:"*)
            log_info "$NEOTH_BIN_DIR is on PATH."
            ;;
        *)
            log_warn "$NEOTH_BIN_DIR is NOT on PATH."
            log_warn "Add to your shell profile (bash / zsh):"
            log_warn "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
            log_warn "Or run neothd via its full path: $NEOTH_BIN_DIR/neothd"
            ;;
    esac
}

main() {
    log_step "NEOTH zero-install binary fetcher"
    detect_target_triple
    resolve_version
    download_and_verify
    check_path
    log_step "Next step: \`neothd init\` to launch the wizard"
}

main "$@"
