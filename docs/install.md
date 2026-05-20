# neoth — Installation Guide

> **neoth knows.**

---

## Overview

neoth is a Rust-based personal AI agent. It runs as a single binary (`neothd` daemon +
`neoth` CLI). No cloud dependency by default -- your data stays on your machine.

Three installation paths:

| Path | When to use |
|------|-------------|
| **Pre-built binary** (GitHub Releases) | Fastest. No Rust toolchain needed. |
| **Build from source** (git + cargo) | Full control. MSRV 1.86. |
| **cargo install** (crates.io) | Future -- not yet published. |

---

## Path A: Pre-built Binary (Recommended for most users)

> Status: **Not yet available**. Pre-built binaries will be attached to GitHub Releases
> once the first public release is tagged. Subscribe to the repo to be notified.

When available:

```bash
# Linux x86_64
curl -sSfL https://github.com/<owner>/neoth/releases/latest/download/neoth-linux-x86_64.tar.gz \
  | tar -xz -C ~/.local/bin/

# Linux aarch64
curl -sSfL https://github.com/<owner>/neoth/releases/latest/download/neoth-linux-aarch64.tar.gz \
  | tar -xz -C ~/.local/bin/

# macOS x86_64
curl -sSfL https://github.com/<owner>/neoth/releases/latest/download/neoth-macos-x86_64.tar.gz \
  | tar -xz -C ~/.local/bin/

# macOS aarch64 (Apple Silicon)
curl -sSfL https://github.com/<owner>/neoth/releases/latest/download/neoth-macos-aarch64.tar.gz \
  | tar -xz -C ~/.local/bin/
```

Verify:
```bash
neoth --version
```

Then run the onboarding wizard:
```bash
neoth init
```

---

## Path B: Build from Source (Recommended today)

### Prerequisites

- **Rust 1.86+** (MSRV). Install via [rustup](https://rustup.rs):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source $HOME/.cargo/env
  ```

- **git**

- **C linker** (usually pre-installed):
  - Linux: `gcc` or `clang` (install via package manager)
  - macOS: `xcode-select --install`

### Install Script (Automated)

The install script handles Rust detection, cloning, building, and installing
to `$HOME/.local/bin` with no sudo:

```bash
curl -sSf https://raw.githubusercontent.com/<owner>/neoth/main/scripts/install.sh | bash
```

For verbose output:
```bash
INSTALL_DEBUG=1 bash <(curl -sSf https://raw.githubusercontent.com/<owner>/neoth/main/scripts/install.sh)
```

The script is idempotent -- safe to re-run (pulls latest and rebuilds if source already exists).

### Manual Build

```bash
# Clone
git clone https://github.com/<owner>/neoth.git ~/.local/src/neoth
cd ~/.local/src/neoth

# Build (first build ~30-120s depending on machine)
cargo build --release

# Install to PATH
mkdir -p ~/.local/bin
cp target/release/neoth ~/.local/bin/
cp target/release/neothd ~/.local/bin/
chmod +x ~/.local/bin/neoth ~/.local/bin/neothd
```

Add to PATH if needed (add to `~/.bashrc`, `~/.zshrc`, or `~/.profile`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

## Path C: cargo install (Future -- not yet published)

> **neoth is not yet published to crates.io.** This path will become available
> after the first stable release. Do not use it yet.

When published:
```bash
cargo install neoth
```

---

## Windows

### Recommended: WSL2 (Windows Subsystem for Linux)

neoth is developed and tested primarily on Linux. WSL2 is the recommended path for Windows:

1. Install WSL2 (requires Windows 10 version 2004+ or Windows 11):
   ```powershell
   wsl --install
   ```
   Restart when prompted. Complete Ubuntu setup.

2. Inside WSL2, run the Linux install:
   ```bash
   curl -sSf https://raw.githubusercontent.com/<owner>/neoth/main/scripts/install.sh | bash
   ```

3. Run wizard:
   ```bash
   neoth init
   ```

**PowerShell helper script** (handles WSL2 detection automatically):
```powershell
irm https://raw.githubusercontent.com/<owner>/neoth/main/scripts/install.ps1 | iex
```

### Native Windows (Partial)

Day-1 status: `cargo build --release` compiles on Windows. Binary prints banner.
Channel adapters (Telegram etc.) are Linux-tested only in Phase 1.
Native Windows channel support is planned for Phase 2+.

To build on native Windows:
```powershell
git clone https://github.com/<owner>/neoth.git
cd neoth\SRC\neothd
cargo build --release
```

---

## After Installation: Onboarding

Run the 7-step wizard to configure neoth:

```bash
neoth init
```

The wizard will:
1. Accept the license (MIT OR Apache-2.0)
2. Set your operator identity
3. Choose your primary language and role
4. Connect an LLM provider (Claude CLI, OpenAI, Gemini, or custom)
5. Optionally connect a Telegram bot
6. Write config to `~/.neoth/`

Non-interactive / scripted mode (for CI/Docker):

```bash
NEOTH_PROVIDER_KEY="sk-..." neoth init \
  --noninteractive \
  --accept-license \
  --operator-id myname \
  --language en \
  --role developer \
  --provider openai_api
```

---

## Verifying the Installation

```bash
neoth --version
neoth --help
neoth init --help
```

If `neoth init` was completed:
```bash
neoth chat "hello"
```

---

## Troubleshooting

### `cargo: command not found`

Rust/cargo not in PATH. Source the cargo environment:
```bash
source "$HOME/.cargo/env"
```
Or add permanently to shell profile:
```bash
echo 'source "$HOME/.cargo/env"' >> ~/.bashrc
```

### Build fails: `linker 'cc' not found`

Install a C linker:
```bash
# Debian/Ubuntu
sudo apt install build-essential

# Fedora/RHEL
sudo dnf install gcc

# macOS
xcode-select --install
```

### Build fails: `error: package requires Rust X, found Y`

Upgrade Rust:
```bash
rustup update stable
```

### `neoth: command not found` after install

Ensure `~/.local/bin` is in PATH:
```bash
export PATH="$HOME/.local/bin:$PATH"
# Add to ~/.bashrc or ~/.zshrc for persistence
```

### `~/.neoth/` permission errors

```bash
chmod 700 ~/.neoth/
chmod 600 ~/.neoth/credentials/providers.yaml
chmod 600 ~/.neoth/credentials/channels.yaml
```

### WSL2 not recognized on Windows

Ensure Windows is updated and WSL2 is enabled:
```powershell
wsl --status
wsl --update
```

---

## Uninstalling

```bash
# Remove binaries
rm -f ~/.local/bin/neoth ~/.local/bin/neothd

# Remove source (if built from source)
rm -rf ~/.local/src/neoth

# Remove config (WARNING: deletes all credentials and config)
rm -rf ~/.neoth/
```

---

## Getting Help

- GitHub Issues: https://github.com/<owner>/neoth/issues
- Design specs: `PLAN/` directory in the repository
- `neoth --help` and `neoth <command> --help`
