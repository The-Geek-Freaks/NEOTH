# winget package manifests for NEOTH

These manifests prepare NEOTH for submission to
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) so
Windows operators can install via:

```powershell
winget install TheGeekFreaks.NEOTH
```

## Status

**Stub manifests pending the Windows release-matrix extension.** The
current `.github/workflows/release.yml` ships Linux + macOS binaries
only; Windows is a `stretch goal` per the workflow comment. Until the
Windows targets land in the matrix, `winget install` would fail with
404 on the InstallerUrl.

R-08 closure path:

1. **Extend release.yml** with two Windows targets:
   - `x86_64-pc-windows-msvc`
   - `aarch64-pc-windows-msvc`
   Use `.zip` archive format (Windows convention; matches winget's
   default `NestedInstallerType: portable` handling).
2. **Cut a release tag** (e.g. `v0.3.0`). The matrix builds + uploads
   `neothd-vX.Y.Z-{x86_64,aarch64}-pc-windows-msvc.zip` + `.sha256`.
3. **Refresh these manifests** with real values:
   - `PackageVersion` → vX.Y.Z
   - `InstallerUrl` → release-download URL
   - `InstallerSha256` → from the published `.sha256` sidecars
4. **PR to microsoft/winget-pkgs**:
   `manifests/t/TheGeekFreaks/NEOTH/0.3.0/` with all three YAMLs:
   - `TheGeekFreaks.NEOTH.installer.yaml`
   - `TheGeekFreaks.NEOTH.yaml` (version manifest)
   - `TheGeekFreaks.NEOTH.locale.en-US.yaml` (locale + metadata)
5. Once merged, the `winget install` one-liner works.

## Operator install paths (today)

Until the winget submission lands, operators have three paths:

```bash
# Linux + macOS (zero-install binary download)
curl -sSf https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install-binary.sh | bash
```

```powershell
# Windows (zero-install binary download — works once Windows release artifacts ship)
iwr -useb https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install-binary.ps1 | iex
```

```bash
# Source build (any OS with Rust toolchain)
git clone https://github.com/The-Geek-Freaks/NEOTH.git
cd NEOTH/scripts && bash install.sh
```

## Local validation

Once values are filled in:

```powershell
winget validate --manifest packaging\winget\
```

This requires the [winget client](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
already installed (it ships with Windows 11 + recent Windows 10 builds).
