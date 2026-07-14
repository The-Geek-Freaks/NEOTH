#!/usr/bin/env bash
# neoth install script
# Installs neoth to $HOME/.local/bin
# NO sudo required. Idempotent (safe to re-run).
# Usage: curl -sSf https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install.sh | bash
# INSTALL_DEBUG=1 bash install.sh for verbose output.

set -euo pipefail

NEOTH_REPO="${NEOTH_REPO:-https://github.com/The-Geek-Freaks/NEOTH.git}"
NEOTH_SRC_DIR="${NEOTH_SRC_DIR:-$HOME/.local/src/neoth}"
NEOTH_BIN_DIR="${NEOTH_BIN_DIR:-$HOME/.local/bin}"
NEOTH_MIN_RUST_VER="1.86"
NEOTH_BRANCH="${NEOTH_BRANCH:-main}"

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

detect_platform() {
    local os arch
    os="$(uname -s)" arch="$(uname -m)"
    case "$os" in
        Linux*)  OS="linux" ;;
        Darwin*) OS="macos" ;;
        MINGW*|MSYS*|CYGWIN*)
            log_error "Native Windows detected. Use WSL2:"
            log_error "  wsl --install  (then re-run inside WSL2)"
            exit 1 ;;
        *) log_error "Unsupported OS: $os"; exit 1 ;;
    esac
    case "$arch" in
        x86_64)        ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)             log_error "Unsupported architecture: $arch"; exit 1 ;;
    esac
    log_info "Platform: $OS / $ARCH"
}

_version_gte() {
    local IFS=. a=($1) b=($2)
    for ((i=0; i<${#b[@]}; i++)); do
        [[ "${a[$i]:-0}" -gt "${b[$i]:-0}" ]] && return 0
        [[ "${a[$i]:-0}" -lt "${b[$i]:-0}" ]] && return 1
    done
    return 0
}

check_or_install_rust() {
    log_step "Rust toolchain"
    if command -v rustup &>/dev/null && command -v cargo &>/dev/null; then
        local ver
        ver="$(rustc --version 2>/dev/null | awk '{print $2}')"
        log_info "rustup found. rustc $ver"
        if ! _version_gte "$ver" "$NEOTH_MIN_RUST_VER"; then
            log_warn "rustc $ver < MSRV $NEOTH_MIN_RUST_VER. Updating..."
            rustup update stable
        fi
        return 0
    fi
    log_info "rustup not found. Installing (no sudo)..."
    if command -v curl &>/dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --no-modify-path --default-toolchain stable
    elif command -v wget &>/dev/null; then
        wget -qO- https://sh.rustup.rs \
            | sh -s -- -y --no-modify-path --default-toolchain stable
    else
        log_error "Neither curl nor wget found. Install one and re-run."
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    log_info "Rust installed."
}

clone_or_update_repo() {
    log_step "Source at $NEOTH_SRC_DIR"
    mkdir -p "$(dirname "$NEOTH_SRC_DIR")"
    if [[ -d "$NEOTH_SRC_DIR/.git" ]]; then
        log_info "Repo exists. Fetching latest $NEOTH_BRANCH..."
        git -C "$NEOTH_SRC_DIR" fetch origin
        git -C "$NEOTH_SRC_DIR" checkout "$NEOTH_BRANCH"
        git -C "$NEOTH_SRC_DIR" pull --ff-only origin "$NEOTH_BRANCH"
    else
        log_info "Cloning $NEOTH_REPO ..."
        git clone --branch "$NEOTH_BRANCH" --depth 1 "$NEOTH_REPO" "$NEOTH_SRC_DIR"
    fi
}

build_neoth() {
    log_step "Building neoth and companion binaries"
    log_info "The first full-feature build can take several minutes."
    cd "$NEOTH_SRC_DIR/SRC"
    command -v cargo &>/dev/null || source "$HOME/.cargo/env"
    # Match the signed desktop-release feature contract. A source install must
    # not silently omit the advertised WASM host or optional channel adapters.
    cargo build --release --locked -p neoth --bins --features release-desktop
    cargo build --release --locked \
        -p neothd-gui -p neoth-migrate -p neoth-relay
    log_info "Build complete."
}

install_binaries() {
    log_step "Installing to $NEOTH_BIN_DIR"
    mkdir -p "$NEOTH_BIN_DIR"
    local rel="$NEOTH_SRC_DIR/SRC/target/release"
    local stage payload backup bin destination rollback_index rollback_bin
    local -a binaries replaced
    # `neoth` is the public command. `neothd` remains a small compatibility
    # launcher that delegates to the sibling public binary.
    for bin in neoth neothd neothd-gui neoth-migrate neoth-relay; do
        if [[ ! -f "$rel/$bin" ]]; then
            log_error "Required build output is missing: $rel/$bin"
            exit 1
        fi
    done

    case "$NEOTH_BIN_DIR" in
        *$'\n'*|*$'\r'*) log_error "Install directory must not contain a newline."; exit 1 ;;
    esac
    stage="$(mktemp -d "$NEOTH_BIN_DIR/.neoth-install.XXXXXX")"
    payload="$stage/payload"
    backup="$stage/backup"
    mkdir -p "$payload" "$backup"
    binaries=(neothd neothd-gui neoth-migrate neoth-relay neoth)
    for bin in "${binaries[@]}"; do
        if ! install -m 0755 "$rel/$bin" "$payload/$bin"; then
            rm -rf "$stage"
            log_error "Could not stage $bin."
            exit 1
        fi
    done

    rollback_replaced() {
        local rollback_failed=0
        for ((rollback_index=${#replaced[@]} - 1; rollback_index >= 0; rollback_index--)); do
            rollback_bin="${replaced[$rollback_index]}"
            rm -f "$NEOTH_BIN_DIR/$rollback_bin" || rollback_failed=1
            if [[ -e "$backup/$rollback_bin" || -L "$backup/$rollback_bin" ]]; then
                mv "$backup/$rollback_bin" "$NEOTH_BIN_DIR/$rollback_bin" || rollback_failed=1
            fi
        done
        return "$rollback_failed"
    }

    replaced=()
    for bin in "${binaries[@]}"; do
        destination="$NEOTH_BIN_DIR/$bin"
        if [[ ( -e "$destination" || -L "$destination" ) && ! -f "$destination" && ! -L "$destination" ]]; then
            if ! rollback_replaced; then
                log_error "Rollback failed; backups retained at $backup"
                exit 1
            fi
            rm -rf "$stage"
            log_error "Install target is not a regular file: $destination"
            exit 1
        fi
        if [[ -e "$destination" || -L "$destination" ]] && ! mv "$destination" "$backup/$bin"; then
            if ! rollback_replaced; then
                log_error "Rollback failed; backups retained at $backup"
                exit 1
            fi
            rm -rf "$stage"
            log_error "Could not back up $destination."
            exit 1
        fi
        replaced+=("$bin")
        if ! mv "$payload/$bin" "$destination"; then
            if ! rollback_replaced; then
                log_error "Rollback failed; backups retained at $backup"
                exit 1
            fi
            rm -rf "$stage"
            log_error "Could not install $bin; previous files were restored."
            exit 1
        fi
        log_info "Installed: $destination"
    done
    rm -rf "$stage"
}

check_path() {
    case ":$PATH:" in
        *":$NEOTH_BIN_DIR:"*) return ;;
    esac
    local profile marker
    case "${SHELL:-}" in
        */zsh) profile="$HOME/.zshrc" ;;
        */bash) profile="$HOME/.bashrc" ;;
        *) profile="$HOME/.profile" ;;
    esac
    marker="# NEOTH installer PATH: $NEOTH_BIN_DIR"
    touch "$profile" || { log_error "Could not update $profile"; exit 1; }
    if ! grep -Fqx "$marker" "$profile"; then
        {
            printf '\n%s\n' "$marker"
            printf 'export PATH=%q:"$PATH"\n' "$NEOTH_BIN_DIR"
        } >> "$profile" || { log_error "Could not update $profile"; exit 1; }
    fi
    log_info "Wired $NEOTH_BIN_DIR into $profile"
    printf 'For this current shell, run: export PATH=%q:"$PATH"\n' "$NEOTH_BIN_DIR"
}

verify_installation() {
    log_step "Verifying"
    log_info "$($NEOTH_BIN_DIR/neoth --version 2>/dev/null || echo "$NEOTH_BIN_DIR/neoth")"
}

main() {
    echo -e "\n${B}neoth installer${R} -- no sudo, installs to $NEOTH_BIN_DIR\n"
    detect_platform
    check_or_install_rust
    clone_or_update_repo
    build_neoth
    install_binaries
    check_path
    verify_installation
    echo ""
    echo -e "${B}Done!${R} Run the onboarding wizard:"
    echo ""
    echo "  $NEOTH_BIN_DIR/neoth init"
    echo ""
    echo "Then: $NEOTH_BIN_DIR/neoth chat \"hello\""
    echo "Docs: https://github.com/The-Geek-Freaks/NEOTH/blob/main/docs/install.md"
}

main "$@"
