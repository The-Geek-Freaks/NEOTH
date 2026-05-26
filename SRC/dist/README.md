# NEOTH — distribution artifacts

This directory holds the operator-facing install entrypoints + the
templates that get published to upstream package registries.

```
SRC/
├─ install.sh                          # curl | sh entry for Linux + macOS
├─ install.ps1                         # PowerShell entry for Windows
└─ dist/
   └─ winget/
      └─ manifests/
         └─ T/TheGeekFreaks/NEOTH/0.2.1/
            ├─ TheGeekFreaks.NEOTH.yaml          (version)
            ├─ TheGeekFreaks.NEOTH.installer.yaml (installer)
            └─ TheGeekFreaks.NEOTH.locale.en-US.yaml (locale)
```

## install.sh / install.ps1

- Pull a tagged release from
  `https://github.com/The-Geek-Freaks/NEOTH/releases/download/v{VERSION}/`.
- Verify SHA-256 against the matching `.sha256` file.
- Optionally verify the cosign keyless signature
  (`NEOTH_VERIFY_SIGNATURE=1`).
- Install to `~/.local/bin` (Linux/macOS) or
  `$env:LOCALAPPDATA\Programs\neoth` (Windows).

Today only Linux + macOS targets are in the release matrix
(`.github/workflows/release.yml`). The PowerShell installer carries
build-from-source guidance until Windows binaries join the matrix.

## winget manifests

The three files under `dist/winget/manifests/T/TheGeekFreaks/NEOTH/0.2.1/`
mirror the layout
[winget-pkgs](https://github.com/microsoft/winget-pkgs) expects. They
are stubs — the `InstallerSha256` is a placeholder until a Windows
binary publishes to the release page. The actual PR against
microsoft/winget-pkgs uses these files verbatim once the SHA is real.

Layout pinned by Microsoft's manifest validator:
- `T/` = first-letter bucket of the publisher (case-sensitive).
- `TheGeekFreaks/NEOTH/0.2.1/` = publisher / package / version.
- One file per manifest type (singleton manifests are deprecated in
  schema 1.6+).

## Source of truth

The URLs + package id are rendered from
`SRC/neothd/src/installers/zero_install.rs` constants (`RELEASES_BASE_URL`,
`WINGET_PACKAGE_ID`, `INSTALL_SH_URL`, `INSTALL_PS1_URL`). A diff in
either direction must update both — drift-guard tests live in
`zero_install.rs::tests`.
