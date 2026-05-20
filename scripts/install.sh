#!/usr/bin/env bash
# neoth install script
# Installs neoth to $HOME/.local/bin
# NO sudo required. Idempotent (safe to re-run).
# Usage: curl -sSf https://raw.githubusercontent.com/<owner>/neoth/main/scripts/install.sh | bash
# INSTALL_DEBUG=1 bash install.sh for verbose output.

set -euo pipefail

NEOTH_REPO="${NEOTH_REPO:-https://github.com/<owner>/neoth.git}"
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
        *) log_warn "Unknown OS: $os. Assuming linux."; OS="linux" ;;
    esac
    case "$arch" in
        x86_64)        ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)             log_warn "Unknown arch: $arch. Assuming x86_64."; ARCH="x86_64" ;;
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
    log_step "Building neoth (cargo build --release)"
    log_info "First build takes 30-120s."
    cd "$NEOTH_SRC_DIR"
    command -v cargo &>/dev/null || source "$HOME/.cargo/env"
    cargo build --release
    log_info "Build complete."
}

install_binaries() {
    log_step "Installing to $NEOTH_BIN_DIR"
    mkdir -p "$NEOTH_BIN_DIR"
    local rel="$NEOTH_SRC_DIR/target/release"
    local installed=()
    # Cargo builds `neothd` (daemon + CLI) and `neothd-gui` (Slint
    # wizard). There is no separate `neoth` binary today; the README's
    # "thin `neoth` alias" is provided by a symlink to `neothd` so the
    # documented `neoth chat …` UX works.
    for bin in neothd neothd-gui; do
        [[ -f "$rel/$bin" ]] || continue
        cp "$rel/$bin" "$NEOTH_BIN_DIR/$bin"
        chmod +x "$NEOTH_BIN_DIR/$bin"
        installed+=("$bin")
        log_info "Installed: $NEOTH_BIN_DIR/$bin"
    done
    # Create the `neoth` alias as a symlink to `neothd` so operators
    # can type `neoth <subcommand>` per the README. Symlink not copy
    # — keeps the alias in sync with future daemon upgrades.
    if [[ -f "$NEOTH_BIN_DIR/neothd" ]]; then
        ln -sf neothd "$NEOTH_BIN_DIR/neoth"
        log_info "Aliased: $NEOTH_BIN_DIR/neoth -> neothd"
    fi
    [[ ${#installed[@]} -gt 0 ]] || { log_error "No binaries built."; exit 1; }
}

check_path() {
    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$NEOTH_BIN_DIR"; then
        log_warn "$NEOTH_BIN_DIR not in PATH. Add to your shell profile:"
        log_warn '  export PATH="$HOME/.local/bin:$PATH"'
    fi
}

verify_installation() {
    log_step "Verifying"
    command -v neoth &>/dev/null \
        && log_info "neoth $(neoth --version 2>/dev/null || echo '?')" \
        || log_warn "neoth not found in PATH yet."
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
    echo "  neoth init"
    echo ""
    echo "Then: neoth chat \"hello\""
    echo "Docs: https://github.com/<owner>/neoth/blob/main/docs/install.md"
}

main "$@"
