# Installation Guide

NEOTH 1.0 installs as a Rust operator runtime with an optional GUI. Until the
first signed tag and ordered crates.io publication exist, the only working
public path is a source checkout. After publication, normal users should prefer
the verified release installer; Rust users may use
`cargo install neoth --locked --features release-desktop`.

## Install paths

| Path | Best for |
| :-- | :-- |
| **Release binary** | Normal users. No Rust toolchain. |
| **cargo install** | Rust users after publication; installs the core CLI/daemon package only. |
| **Source build** | Contributors, packagers, operators, and private forks. |
| **Installer script** | Linux/macOS or Windows setup with PATH wiring. |

## Path A: install from source (cargo)

> The source tree is versioned for **1.0.0**, but tagged release artifacts and
> the crates.io package are not published yet. Until publication, install from a
> source checkout:

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH && cd NEOTH/SRC
cargo install --locked --path neothd --features release-desktop
cargo install --locked --path neothd-gui
cargo install --locked --path neoth-migrate
cargo install --locked --path neoth-relay
neoth --version
neoth gui
```

If you only want the CLI/daemon path after install:

```bash
neoth init
```

## Path B: release binaries

> Available only after a signed `v1.0.0` release has been published. Before
> that, `/releases/latest` may point to an incompatible prerelease or nothing at
> all; use Path A.

Download the latest release from:

```text
https://github.com/The-Geek-Freaks/NEOTH/releases/latest
```

Verify the archive with the repository-pinned key before extracting it:

```bash
TARGET=x86_64-unknown-linux-gnu  # choose the archive for your platform
minisign -Vm "neoth-v1.0.0-$TARGET.tar.gz" \
  -x "neoth-v1.0.0-$TARGET.tar.gz.minisig" \
  -P RWQa0n4hqyE1huqkKoU+4aUs+YjbMiWabY4MwnwIafb79dWiSLV7qGBi
```

The same key is versioned in
[`NEOTH_RELEASE_MINISIGN_PUBKEY.txt`](../NEOTH_RELEASE_MINISIGN_PUBKEY.txt).
Then put the binaries on your PATH and run:

```bash
neoth --version
neoth doctor
neoth gui
```

Typical Linux/macOS layout:

```bash
mkdir -p ~/.local/bin
TARGET=x86_64-unknown-linux-gnu  # choose the archive for your platform
tar -xzf "neoth-v1.0.0-$TARGET.tar.gz"
install -m 0755 "neoth-v1.0.0-$TARGET/neoth" ~/.local/bin/neoth
install -m 0755 "neoth-v1.0.0-$TARGET/neothd" ~/.local/bin/neothd
install -m 0755 "neoth-v1.0.0-$TARGET/neothd-gui" ~/.local/bin/neothd-gui
install -m 0755 "neoth-v1.0.0-$TARGET/neoth-migrate" ~/.local/bin/neoth-migrate
install -m 0755 "neoth-v1.0.0-$TARGET/neoth-relay" ~/.local/bin/neoth-relay
export PATH="$HOME/.local/bin:$PATH"
neoth --version
```

Desktop archives for GNU Linux, macOS, and Windows include all five
executables. The static musl server archive is deliberately headless and omits
only `neothd-gui`; use the CLI wizard there with `neoth init`.

## Path C: Linux/macOS installer

> Available only after the first compatible signed release archive exists.

```bash
curl -fsSL https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.sh | bash
```

Verbose mode:

```bash
NEOTH_VERSION=v1.0.0 bash <(curl -fsSL https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.sh)
```

The installer downloads the matching release archive, verifies its checksum,
requires authenticity through installed `minisign` or `cosign`, requires
`neoth`, the `neothd` compatibility launcher, `neoth-migrate`,
`neoth-relay`, `freedom.yaml.example`, and `neothd-gui` on desktop targets,
installs the complete set transactionally, wires the install directory into the
detected user shell profile, and avoids sudo. The profile change applies to new
shells; for the current shell run:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

With neither verifier installed the installer refuses to proceed. The explicit
`NEOTH_ALLOW_UNVERIFIED_RECOVERY=1` override is only for an archive whose
authenticity you verified out of band; it never disables SHA-256 checking and
cannot bypass a failed signature. The minisign path also requires the globally
signed trusted comment to equal `file:<downloaded-archive>` exactly, preventing
a valid signature from being replayed under another release asset name.

## Path D: Windows installer

> Available only after the first compatible signed Windows archive exists.

PowerShell:

```powershell
irm https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.ps1 | iex
```

Then:

```powershell
neoth --version
neoth doctor
neoth gui
```

The PowerShell installer applies the install directory to both the real user
PATH and the current process PATH, without copying system PATH entries into the
user value. It enforces the same minisign/cosign and transactional replacement
contract as the Unix installer.

## Path E: build from source

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH ~/.local/src/neoth
cd ~/.local/src/neoth/SRC
cargo build --release --locked -p neoth --bins --features release-desktop
cargo install --locked --path neothd --features release-desktop
cargo install --locked --path neothd-gui
cargo install --locked --path neoth-migrate
cargo install --locked --path neoth-relay
```

The named `release-desktop` / `release-server` bundles intentionally omit the
source-only IMAP feature. Operators who need live inbox triage can build the
core binary explicitly with it:

```bash
cargo install --locked --path neothd --features release-desktop,imap_fetch
```

This adds non-destructive IMAP fetch and local triage; it does not add SMTP or
an email-send path.

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
| Release verifier | `minisign` or `cosign` for binary installers | `minisign` |

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
neoth verify
```

Expected result:

| Check | Good result |
| :-- | :-- |
| `neoth --version` | Prints installed version. |
| `neoth doctor` | Shows provider/channel/model/setup status. |
| `neoth status` | Shows daemon, WAL, memory, provider, channel state. |
| `neoth privacy audit` | Shows destinations and recent sensitive events. |
| `neoth verify` | Verifies HMAC compaction markers in the local WAL. |

## Uninstall

Remove binaries:

```bash
cargo uninstall neoth || true
cargo uninstall neothd-gui || true
cargo uninstall neoth-migrate || true
cargo uninstall neoth-relay || true
rm -f ~/.local/bin/neoth ~/.local/bin/neothd ~/.local/bin/neothd-gui \
  ~/.local/bin/neoth-migrate ~/.local/bin/neoth-relay
```

Remove local state only if you intentionally want to delete memory:

```bash
rm -rf ~/.neoth
```

Export first if you want to keep your vault, profile, or logs:

```bash
neoth export --out ~/neoth-export
```
