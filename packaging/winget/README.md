# winget package manifests for NEOTH

These manifests prepare NEOTH for submission to
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs). The command
below is the post-submission contract; it is not live yet:

```powershell
winget install TheGeekFreaks.NEOTH
```

## Status

**Pre-submission manifests, intentionally blocked on real release hashes.**
`.github/workflows/release.yml` builds x64 and ARM64 Windows ZIPs and packages
`neoth.exe`, the `neothd.exe` compatibility launcher, `neothd-gui.exe`,
`neoth-migrate.exe`, and `neoth-relay.exe`.
The stable `v1.0.0` tag/assets do not exist yet, and both SHA-256 fields remain
all zeroes. Do not submit these manifests or claim `winget install` works until
the published sidecars have replaced those placeholders.

R-08 closure path:

1. **Push the explicitly approved release tag.** The existing matrix builds
   and signs `neoth-vX.Y.Z-{x86_64,aarch64}-pc-windows-msvc.zip` and publishes
   a `.sha256` sidecar for each archive.
2. **Refresh these manifests from the published assets:**
   - `PackageVersion` → `X.Y.Z` (no `v` prefix)
   - `InstallerUrl` → release-download URL
   - `InstallerSha256` → from the published `.sha256` sidecars
3. Run `winget validate --manifest packaging\winget\` and refuse submission if
   either zero hash remains.
4. **PR to microsoft/winget-pkgs**:
   `manifests/t/TheGeekFreaks/NEOTH/X.Y.Z/` with all three YAMLs:
   - `TheGeekFreaks.NEOTH.installer.yaml`
   - `TheGeekFreaks.NEOTH.yaml` (version manifest)
   - `TheGeekFreaks.NEOTH.locale.en-US.yaml` (locale + metadata)
5. Once merged, the `winget install` one-liner works.

## Operator install paths (today)

Until the stable release and winget submission land, install from source:

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH.git
cd NEOTH/SRC
cargo install --locked --path neothd --features release-desktop
cargo install --locked --path neothd-gui
cargo install --locked --path neoth-migrate
cargo install --locked --path neoth-relay
```

After the stable assets ship, the canonical binary installers are
`SRC/install.sh` and `SRC/install.ps1`.

## Local validation

After the URLs and real hashes are filled in:

```powershell
winget validate --manifest packaging\winget\
```

This requires the [winget client](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
already installed (it ships with Windows 11 + recent Windows 10 builds).
