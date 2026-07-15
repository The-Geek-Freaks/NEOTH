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
| **Native package** | `.deb`/`.rpm` on Linux, signed `.pkg`/`.dmg` on macOS, signed Setup `.exe` on Windows. |
| **cargo install** | Rust users after publication; installs the core CLI/daemon package only. |
| **Source build** | Contributors, packagers, operators, and private forks. |
| **Installer script** | Linux/macOS or Windows setup with PATH wiring. |

## Path A: install from source (cargo)

> The source tree is versioned for **1.0.0**, but tagged release artifacts and
> the crates.io package are not published yet. Until publication, install from a
> source checkout:

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH && cd NEOTH
NEOTH_SRC_DIR="$PWD" bash scripts/install.sh
neoth --version
neoth
```

This all-components source path needs Node.js 22.16+ to compile the Keet
standalone. Signed desktop archives already contain it and need no Node.js.

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
neoth
```

Typical Linux/macOS layout (the target-aware branch keeps the headless musl
contract intact):

```bash
mkdir -p ~/.local/bin
TARGET=x86_64-unknown-linux-gnu  # choose the archive for your platform
tar -xzf "neoth-v1.0.0-$TARGET.tar.gz"
for name in neoth neothd neoth-migrate neoth-relay; do
  install -m 0755 "neoth-v1.0.0-$TARGET/$name" "$HOME/.local/bin/$name"
done
mkdir -p "$HOME/.local/bin/neoth-support"
for name in README.md LICENSE-MIT LICENSE-APACHE THIRD_PARTY_LICENSES freedom.yaml.example import-manifest.example.yaml; do
  install -m 0644 "neoth-v1.0.0-$TARGET/$name" "$HOME/.local/bin/neoth-support/$name"
done
cp -R "neoth-v1.0.0-$TARGET/self-knowledge" "$HOME/.local/bin/neoth-support/self-knowledge"
case "$TARGET" in
  *-unknown-linux-musl) ;;
  *)
    for name in neothd-gui neoth-keet-bridge; do
      install -m 0755 "neoth-v1.0.0-$TARGET/$name" "$HOME/.local/bin/$name"
    done
    ;;
esac
export PATH="$HOME/.local/bin:$PATH"
neoth --version
```

Desktop archives for GNU Linux, macOS, and Windows include all six executables,
including the self-contained Keet companion. Every archive, including the
headless musl build, also contains the exact release-bound `self-knowledge/`
snapshot generated from the tagged source by pinned Graphify. NEOTH verifies
its closed file set, source HEAD, release version, and payload digest at runtime;
normal users do not install Python or Graphify. The static musl server archive
deliberately omits `neothd-gui` plus the glibc-linked Keet companion; use the CLI
wizard there with `neoth init`.

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
and authenticates it through installed `minisign`, installed `cosign`, or a
temporary Cosign verifier whose platform digest is pinned to the immutable
official Sigstore source recorded in `packaging/cosign-bootstrap.json`. It requires
`neoth`, the `neothd` compatibility launcher, `neoth-migrate`,
`neoth-relay`, `freedom.yaml.example`, and `neothd-gui` plus
`neoth-keet-bridge` on desktop targets, validates the companion against the
exact release version before mutation, verifies the complete
`self-knowledge/` tree, and passes the exact extracted root to the verified
release binary's hidden native installer. That one engine owns a common OS
lock, destination-local staging, a durable hash-bound journal, automatic crash
recovery, and the final `neoth` commit point. Every release replaces all
package-owned binaries, examples, README/licenses, third-party notices, and the
immutable self-knowledge baseline together. Portable support files live below
the namespaced `neoth-support/` directory, so a shared `~/.local/bin` keeps any
unrelated README, license, example, or `self-knowledge/` sentinel untouched.
A markerless existing NEOTH binary or `neoth-support/` target fails closed with
an explicit migration error; `~/.neoth`, credentials, private
configuration, and user overlays are outside that transaction. Headless musl
installs also remove stale desktop-only GUI/Keet companions atomically. It then
wires the install directory into the detected user shell profile, and avoids
sudo. The profile change applies to new
shells; for the current shell run:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

No verifier has to be preinstalled. A wrong bootstrap-verifier digest blocks
execution and cannot be overridden. The explicit
`NEOTH_ALLOW_UNVERIFIED_RECOVERY=1` override is only for the case where the
temporary verifier cannot be downloaded and the archive was authenticated out
of band; it never disables archive SHA-256 checking and cannot bypass a failed
signature. The minisign path also requires the globally
signed trusted comment to equal `file:<downloaded-archive>` exactly, preventing
a valid signature from being replayed under another release asset name.

## Path D: Windows installer

> Available only after the first compatible signed Windows release exists.

Recommended: download and double-click `NEOTH-1.0.0-x64-Setup.exe` (or
`NEOTH-1.0.0-arm64-Setup.exe`) from the GitHub Releases page. The installer is
Authenticode-signed by the release pipeline, validates its payload before any
mutation, installs the CLI, GUI, migration, relay, Keet companion, and the
release-bound self-knowledge snapshot, wires
the user PATH, and supports clean rollback/uninstall.

Non-interactive PowerShell alternative:

```powershell
irm https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.ps1 | iex
```

Then:

```powershell
neoth --version
neoth doctor
neoth
```

The PowerShell installer needs no preinstalled signature utility. It applies the install directory to both the real user
PATH and the current process PATH, without copying system PATH entries into the
user value. It enforces the same minisign/cosign and native crash-recoverable
bundle transaction as the Unix installer; PowerShell has no second file-swap
algorithm or caller-defined member list.
It also starts the packaged Keet standalone in a hidden console for an exact
pre-install version check; a missing, broken, or mixed-version companion blocks
the transaction before the public `neoth.exe` commit point.

## Path E: native packages

After the signed release exists, Linux users can install the matching `.deb` or
`.rpm`; macOS users can open the signed/notarized `.pkg` or drag the `.app` from
the `.dmg`. These packages contain the same CLI, GUI, companions, examples, and
verified self-knowledge bytes as the portable archive. Package uninstall removes
only package-owned files. It never removes `~/.neoth`, the materialized NEOTH
Wiki, or `User Overlays`.

## Path F: build from source

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH ~/.local/src/neoth
cd ~/.local/src/neoth/SRC
cargo build --release --locked -p neoth --bins --features release-desktop
cargo install --locked --path neothd --features release-desktop
cargo install --locked --path neothd-gui
cargo install --locked --path neoth-migrate
cargo install --locked --path neoth-relay
cd ../bridges/keet
corepack prepare pnpm@10.32.1 --activate
corepack pnpm install --frozen-lockfile
corepack pnpm run check
corepack pnpm test
corepack pnpm run make
KEET_HOST="$(node -p "process.platform === 'darwin' ? 'darwin-' + (process.arch === 'x64' ? 'x64' : 'arm64') : 'linux-' + (process.arch === 'x64' ? 'x64' : 'arm64')")"
mkdir -p ~/.local/bin
install -m 0755 "out/$KEET_HOST/neoth-keet-bridge" ~/.local/bin/neoth-keet-bridge
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
| Rust | 1.91+ for source builds | Latest stable |
| Node.js | 22.16+ only for building the Keet companion from source | 22 LTS; release archives need no Node.js |
| Disk | 2 GB | 10+ GB if using local models and document indexes |
| RAM | 4 GB | 8-32 GB depending on local models |
| GPU | Optional | NVIDIA/CUDA, ROCm, or Apple Silicon for local model speed |
| Network | Optional for local-only memory | Required for cloud providers, updates, channels, mesh |
| Release verifier | None; binary installers bootstrap a digest-pinned temporary Cosign if needed | Optional installed `minisign` or `cosign` |

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
neoth
```

On a desktop this asks **Graphical setup / Command-line setup** exactly once and
persists the answer under the active `NEOTH_HOME`. SSH, CI, Windows Session 0,
and display-less Unix sessions stay in the CLI without opening a window. For a
scripted install, set exactly `NEOTH_INTERFACE=gui` or
`NEOTH_INTERFACE=cli`; malformed values stop with an actionable error.

Direct launch and switching remain available:

```bash
neoth gui
neoth init --cli
neoth interface set gui
neoth interface set cli
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
  ~/.local/bin/neoth-migrate ~/.local/bin/neoth-relay \
  ~/.local/bin/neoth-keet-bridge
```

Remove local state only if you intentionally want to delete memory:

```bash
rm -rf ~/.neoth
```

Export first if you want to keep your vault, profile, or logs:

```bash
neoth export --out ~/neoth-export
```
