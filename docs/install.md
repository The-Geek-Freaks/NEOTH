# Installation Guide

NEOTH 1.0 installs as a Rust operator runtime with an optional GUI. Normal users should prefer release binaries or `cargo install`; operators can build from source.

## Install paths

| Path | Best for |
| :-- | :-- |
| **Release binary** | Normal users. No Rust toolchain. |
| **cargo install** | Rust users who want the simplest source-distribution path. |
| **Source build** | Contributors, packagers, operators, and private forks. |
| **Installer script** | Linux/macOS or Windows setup with PATH wiring. |

## Path A: install from source (cargo)

> ⚠️ Not yet on crates.io (`1.0.0-beta.3`) — `cargo install neoth` lands with the
> 1.0 release. Until then, install from a source checkout:

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH && cd NEOTH/SRC
cargo install --path neothd
neoth --version
neoth gui
```

If you only want the CLI/daemon path after install:

```bash
neoth init
```

## Path B: release binaries

Download the latest release from:

```text
https://github.com/The-Geek-Freaks/NEOTH/releases/latest
```

Verify the binary, put it on your PATH, then run:

```bash
neoth --version
neoth doctor
neoth gui
```

Typical Linux/macOS layout:

```bash
mkdir -p ~/.local/bin
tar -xzf neoth-*.tar.gz -C ~/.local/bin
export PATH="$HOME/.local/bin:$PATH"
neoth --version
```

## Path C: Linux/macOS installer

```bash
curl -fsSL https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install.sh | bash
```

Verbose mode:

```bash
INSTALL_DEBUG=1 bash <(curl -fsSL https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install.sh)
```

The installer detects Rust, installs to a user-writable location, and avoids sudo for the normal path.

## Path D: Windows installer

PowerShell:

```powershell
irm https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install.ps1 | iex
```

Then:

```powershell
neoth --version
neoth doctor
neoth gui
```

## Path E: build from source

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH ~/.local/src/neoth
cd ~/.local/src/neoth/SRC
cargo build --release
cargo install --path neothd
cargo install --path neothd-gui
```

Run:

```bash
neoth init
neoth doctor
```

## Windows source builds: use MSVC

NEOTH's Windows source build expects the MSVC Rust target, not GNU/MinGW.

```powershell
rustup default stable-x86_64-pc-windows-msvc
rustup target add x86_64-pc-windows-msvc
.\scripts\cargo-msvc.ps1 check --workspace
```

If `cargo` uses the GNU target, plugin registration can compile but fail at runtime. Use the wrapper script for checks and CI parity.

## Requirements

| Requirement | Minimum | Recommended |
| :-- | :-- | :-- |
| OS | Linux, macOS, Windows | Recent Linux/macOS/Windows 11 |
| Rust | 1.86+ for source builds | Latest stable |
| Disk | 2 GB | 10+ GB if using local models and document indexes |
| RAM | 4 GB | 8-32 GB depending on local models |
| GPU | Optional | NVIDIA/CUDA, ROCm, or Apple Silicon for local model speed |
| Network | Optional for local-only memory | Required for cloud providers, updates, channels, mesh |

## Optional dependencies

| Dependency | Used for |
| :-- | :-- |
| `ffmpeg` | Audio/video extraction and thumbnails. |
| Tailscale | Private device mesh. |
| Hysteria | Restricted-network relay path. |
| Obsidian | Human-readable vault mirror. |
| n8n | Workflow automation. |
| Paperless-ngx | OCR/document knowledge workflows. |

The wizard can detect and help install optional dependencies.

## First run

```bash
neoth gui
```

or:

```bash
neoth init
neoth chat "hello"
```

## Verify install

```bash
neoth doctor
neoth status
neoth privacy audit --last 24h
neoth wal verify
```

Expected result:

| Check | Good result |
| :-- | :-- |
| `neoth --version` | Prints installed version. |
| `neoth doctor` | Shows provider/channel/model/setup status. |
| `neoth status` | Shows daemon, WAL, memory, provider, channel state. |
| `neoth privacy audit` | Shows destinations and recent sensitive events. |
| `neoth wal verify` | Verifies the local event chain. |

## Uninstall

Remove binaries:

```bash
cargo uninstall neoth || true
cargo uninstall neothd || true
rm -f ~/.local/bin/neoth ~/.local/bin/neothd
```

Remove local state only if you intentionally want to delete memory:

```bash
rm -rf ~/.neoth
```

Export first if you want to keep your vault, profile, or logs:

```bash
neoth export --out ~/neoth-export
```
