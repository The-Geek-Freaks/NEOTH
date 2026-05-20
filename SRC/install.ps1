# ─────────────────────────────────────────────────────────────────────────────
# install.ps1 — NEOTH bootstrap installer for Windows
# ─────────────────────────────────────────────────────────────────────────────
# IMPORTANT: Phase 1 release.yml does NOT build Windows targets (see the
# matrix in `.github/workflows/release.yml` — Windows is flagged as a
# stretch goal, no x86_64-pc-windows-msvc artifact published). This
# script bails with build-from-source guidance until a Windows target is
# added to the release matrix.
#
# Once Windows is in the matrix, this installer will:
#   - Download the published neothd.exe from the GitHub Releases page
#   - Verify SHA256 against the matching .sha256 checksum file
#   - Optionally verify cosign keyless signature (NEOTH_VERIFY_SIGNATURE=1)
#   - Install to "$env:LOCALAPPDATA\Programs\neoth" (or $env:NEOTH_INSTALL_DIR)
#   - Copy freedom.yaml.example next to it
#
# Usage (PowerShell, once Windows builds are published):
#   irm https://example.invalid/neoth/install.ps1 | iex
#   $env:NEOTH_VERSION = 'v0.2.0'; .\install.ps1
#   $env:NEOTH_INSTALL_DIR = 'C:\opt\neoth'; .\install.ps1
#   $env:NEOTH_VERIFY_SIGNATURE = '1'; .\install.ps1   # cosign verify
#
# Build-from-source today (until Windows targets join the release matrix):
#   1. Install Rust (https://rustup.rs/) + Visual Studio Build Tools 2022
#      with the "Desktop development with C++" workload.
#   2. From a Developer Command Prompt that's run `vcvars64.bat`:
#        cd SRC\neothd
#        cargo build --release
#   3. Copy SRC\target\release\neothd.exe to your PATH.
# ─────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = 'Stop'

# Phase 1 guard: Windows artifacts not in the release matrix yet. When
# release.yml adds the windows-msvc target this block can be deleted +
# the rest of the script becomes live.
Write-Host "─────────────────────────────────────────────────────────────────────"
Write-Host " Phase 1 release.yml does not build Windows targets."
Write-Host " Build from source today:"
Write-Host "   1. Install Rust + VS Build Tools 2022 (Desktop C++ workload)."
Write-Host "   2. From a Developer Command Prompt with vcvars64.bat run:"
Write-Host "        cd SRC\neothd"
Write-Host "        cargo build --release"
Write-Host "   3. Copy SRC\target\release\neothd.exe onto your PATH."
Write-Host "─────────────────────────────────────────────────────────────────────"
Write-Host " The download/verify path below is ready for activation once"
Write-Host " the release.yml matrix gains a windows-msvc target."
Write-Host "─────────────────────────────────────────────────────────────────────"
exit 1

# ── Config ───────────────────────────────────────────────────────────────────
$Version = if ($env:NEOTH_VERSION) { $env:NEOTH_VERSION } else { 'latest' }
$InstallDir = if ($env:NEOTH_INSTALL_DIR) {
    $env:NEOTH_INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA 'Programs\neoth'
}
$VerifySignature = $env:NEOTH_VERIFY_SIGNATURE -eq '1'
# Replace this with the real owner/repo before publishing the installer.
$ReleaseUrlTemplate = 'https://github.com/REPLACE-WITH-OWNER/REPLACE-WITH-REPO/releases/download'
# Cosign certificate identity regex — matches the release.yml workflow path.
$CosignIdentityRegex = 'https://github.com/.*/neoth/\.github/workflows/release\.yml@.*'
$CosignOidcIssuer = 'https://token.actions.githubusercontent.com'

# ── Helpers ──────────────────────────────────────────────────────────────────
function Write-Info {
    param([string]$Message)
    Write-Host $Message
}

function Throw-Error {
    param([string]$Message)
    Write-Host "error: $Message" -ForegroundColor Red
    exit 1
}

function Get-Target {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
    switch ($arch) {
        'X64' { return 'x86_64-pc-windows-msvc' }
        'Arm64' { return 'aarch64-pc-windows-msvc' }
        default { Throw-Error "unsupported Windows architecture: $arch" }
    }
}

function Verify-Sha256 {
    param(
        [string]$Path,
        [string]$Expected
    )
    $got = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
    $exp = $Expected.ToLowerInvariant()
    if ($got -ne $exp) {
        Throw-Error "SHA256 mismatch: expected $exp, got $got — refusing to install"
    }
    Write-Info "  SHA256 verified ($got)"
}

# ── Main ─────────────────────────────────────────────────────────────────────
if ($ReleaseUrlTemplate -like '*REPLACE-WITH-OWNER*') {
    Write-Info "─────────────────────────────────────────────────────────────────────"
    Write-Info " The NEOTH release pipeline (V02-01) hasn't shipped yet."
    Write-Info " This installer is templated and ready to use once the first"
    Write-Info " GitHub Release exists. Edit `$ReleaseUrlTemplate` in install.ps1"
    Write-Info " to point at your org/repo before re-running."
    Write-Info "─────────────────────────────────────────────────────────────────────"
    exit 1
}

$Target = Get-Target
Write-Info "  detected target: $Target"
Write-Info "  version: $Version"
Write-Info "  install dir: $InstallDir"

if ($Version -eq 'latest') {
    $BaseUrl = "$ReleaseUrlTemplate/latest"
} else {
    $BaseUrl = "$ReleaseUrlTemplate/$Version"
}
$Archive = "neothd-$Version-$Target.tar.gz"
$Checksum = "$Archive.sha256"
$CosignBundle = "$Archive.cosign.bundle"

$Tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "neoth-install-$([guid]::NewGuid())")
try {
    Write-Info "  downloading $Archive"
    Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile (Join-Path $Tmp $Archive) `
        -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/$Checksum" -OutFile (Join-Path $Tmp $Checksum) `
        -UseBasicParsing

    $ExpectedSha = (Get-Content -Raw -Path (Join-Path $Tmp $Checksum)).Split()[0].Trim()
    if (-not $ExpectedSha) { Throw-Error "checksum file is empty" }
    Verify-Sha256 -Path (Join-Path $Tmp $Archive) -Expected $ExpectedSha

    if ($VerifySignature) {
        if (-not (Get-Command cosign -ErrorAction SilentlyContinue)) {
            Throw-Error "NEOTH_VERIFY_SIGNATURE=1 set but cosign not installed (https://docs.sigstore.dev/cosign/installation)"
        }
        Invoke-WebRequest -Uri "$BaseUrl/$CosignBundle" -OutFile (Join-Path $Tmp $CosignBundle) `
            -UseBasicParsing
        Write-Info "  verifying cosign signature"
        & cosign verify-blob `
            --bundle (Join-Path $Tmp $CosignBundle) `
            --certificate-identity-regexp $CosignIdentityRegex `
            --certificate-oidc-issuer $CosignOidcIssuer `
            (Join-Path $Tmp $Archive)
        if ($LASTEXITCODE -ne 0) {
            Throw-Error "cosign verification failed — refusing to install"
        }
        Write-Info "  cosign signature verified"
    }

    Write-Info "  extracting"
    # tar is available natively on Windows 10 1803+ (bsdtar). Powershell's
    # Expand-Archive doesn't handle .tar.gz directly.
    & tar -xzf (Join-Path $Tmp $Archive) -C $Tmp
    if ($LASTEXITCODE -ne 0) { Throw-Error "tar extraction failed" }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }
    # release.yml packs into a subdir `neothd-<version>-<target>/`.
    $ArchiveName = "neothd-$Version-$Target"
    $BinarySrc = Join-Path (Join-Path $Tmp $ArchiveName) 'neothd.exe'
    if (-not (Test-Path $BinarySrc)) {
        $BinarySrc = Join-Path $Tmp 'neothd.exe'
    }
    if (-not (Test-Path $BinarySrc)) {
        Throw-Error "could not locate neothd.exe in extracted archive"
    }
    Copy-Item -Force -Path $BinarySrc -Destination (Join-Path $InstallDir 'neothd.exe')

    $ExamplePath = Join-Path (Join-Path $Tmp $ArchiveName) 'freedom.yaml.example'
    if (-not (Test-Path $ExamplePath)) {
        $ExamplePath = Join-Path $Tmp 'freedom.yaml.example'
    }
    $TargetExample = Join-Path $InstallDir 'freedom.yaml.example'
    if ((Test-Path $ExamplePath) -and (-not (Test-Path $TargetExample))) {
        Copy-Item -Path $ExamplePath -Destination $TargetExample
    }

    Write-Info ""
    Write-Info "  neothd installed: $(Join-Path $InstallDir 'neothd.exe')"
    Write-Info ""

    # PATH hint when the install dir isn't already on PATH.
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not ($userPath -split ';' | Where-Object { $_ -eq $InstallDir })) {
        Write-Info "Add $InstallDir to your PATH:"
        Write-Info "  [Environment]::SetEnvironmentVariable('Path', `"`$env:Path;$InstallDir`", 'User')"
        Write-Info ""
    }

    Write-Info "Next steps:"
    Write-Info "  1. Run the onboarding wizard:  neothd init"
    Write-Info "  2. Or copy the example config: Copy-Item '$TargetExample' `"`$env:USERPROFILE\.neoth\freedom.yaml`""
    Write-Info "  3. Start the daemon:           neothd serve"
}
finally {
    if (Test-Path $Tmp) { Remove-Item -Recurse -Force $Tmp }
}
