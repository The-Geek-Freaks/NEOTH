#!/usr/bin/env bash
# Compatibility entrypoint for the canonical signed-release installer.
# Keeping the download/authentication/transaction logic in SRC/install.sh
# prevents the two public URLs from drifting.
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install-binary.sh | bash
#
# Supported compatibility variables:
#   NEOTH_VERSION, NEOTH_TARGET, NEOTH_BIN_DIR,
#   NEOTH_ALLOW_UNVERIFIED_RECOVERY, NEOTH_FROM_SOURCE
set -euo pipefail

OFFICIAL_REPO="The-Geek-Freaks/NEOTH"
NEOTH_REPO="${NEOTH_REPO:-$OFFICIAL_REPO}"
if [ "$NEOTH_REPO" != "$OFFICIAL_REPO" ]; then
    printf 'error: signed binary installer only trusts %s, got %s\n' \
        "$OFFICIAL_REPO" "$NEOTH_REPO" >&2
    exit 1
fi

if [ "${NEOTH_FROM_SOURCE:-0}" = "1" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/install.sh" ]; then
        exec bash "$SCRIPT_DIR/install.sh"
    fi
    printf 'error: source fallback requires a checkout; run:\n' >&2
    printf '  git clone https://github.com/%s.git\n' "$OFFICIAL_REPO" >&2
    printf '  cd NEOTH && bash scripts/install.sh\n' >&2
    exit 1
fi

export NEOTH_VERSION="${NEOTH_VERSION:-latest}"
export NEOTH_INSTALL_DIR="${NEOTH_INSTALL_DIR:-${NEOTH_BIN_DIR:-$HOME/.local/bin}}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
LOCAL_CANONICAL="${SCRIPT_DIR:+$SCRIPT_DIR/../SRC/install.sh}"
if [ -n "$LOCAL_CANONICAL" ] && [ -f "$LOCAL_CANONICAL" ]; then
    exec bash "$LOCAL_CANONICAL"
fi

command -v curl >/dev/null 2>&1 || {
    printf 'error: curl is required\n' >&2
    exit 1
}
TMP_SCRIPT="$(mktemp)"
trap 'rm -f "$TMP_SCRIPT"' EXIT
curl -fsSL \
    "https://raw.githubusercontent.com/$OFFICIAL_REPO/main/SRC/install.sh" \
    -o "$TMP_SCRIPT"
bash "$TMP_SCRIPT"
