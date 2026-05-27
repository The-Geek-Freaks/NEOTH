#requires -version 5.0
<#
.SYNOPSIS
    NEOTH zero-install binary fetcher for Windows (Round-3 v0.4 R-08).

.DESCRIPTION
    Downloads the latest prebuilt `neothd.exe` binary from GitHub
    Releases, verifies its SHA-256, and places it at
    $env:LOCALAPPDATA\Programs\neoth\neothd.exe. No Rust toolchain
    required — the operator on a fresh laptop runs this script then
    `neothd init` and is in the wizard.

    NOTE: Windows release artifacts must be added to
    `.github/workflows/release.yml` before this script can pull a
    real binary. Until then the script surfaces a clear "no Windows
    artifact yet" error so the operator knows to either:
      1. Use WSL2 + the install-binary.sh path, OR
      2. Wait for the Windows release-matrix extension.

.PARAMETER Version
    Specific tag to install (default: latest).

.PARAMETER InstallDir
    Override install directory.

.PARAMETER FromSource
    Skip the binary download and delegate to scripts/install.ps1
    (the source-build path for power users with Rust + MSVC).

.EXAMPLE
    iwr -useb https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install-binary.ps1 | iex

.EXAMPLE
    .\install-binary.ps1 -Version v0.3.1
#>

param(
    [string]$Repo       = "The-Geek-Freaks/NEOTH",
    [string]$Version    = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\neoth",
    [switch]$FromSource
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"  # speeds up Invoke-WebRequest

function Write-Step($msg)  { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Info($msg)  { Write-Host "[neoth] $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "[neoth WARNING] $msg" -ForegroundColor Yellow }
function Write-Err2($msg)  { Write-Host "[neoth ERROR] $msg" -ForegroundColor Red }

if ($FromSource) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $source = Join-Path $scriptDir "install.ps1"
    if (Test-Path $source) {
        Write-Info "Delegating to $source"
        & $source
        exit $LASTEXITCODE
    }
    Write-Err2 "scripts/install.ps1 not found. Clone the repo manually:"
    Write-Err2 "  git clone https://github.com/$Repo.git"
    Write-Err2 "  cd NEOTH/scripts; powershell -ExecutionPolicy Bypass -File install.ps1"
    exit 1
}

function Get-TargetTriple {
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "i686" }
    $isArm = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
    if ($isArm -eq "Arm64") { $arch = "aarch64" }
    return "$arch-pc-windows-msvc"
}

function Resolve-Version {
    param([string]$RequestedVersion)
    if ($RequestedVersion -ne "latest") {
        Write-Info "Version (pinned): $RequestedVersion"
        return $RequestedVersion
    }
    Write-Info "Resolving latest tag from GitHub Releases..."
    $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
        $tag = $response.tag_name
    } catch {
        Write-Err2 "GitHub API request failed: $($_.Exception.Message)"
        Write-Err2 "If this is a fresh repo without releases, build from source:"
        Write-Err2 "  .\install-binary.ps1 -FromSource"
        exit 1
    }
    if (-not $tag) {
        Write-Err2 "No release tag found."
        exit 1
    }
    Write-Info "Latest tag: $tag"
    return $tag
}

function Download-And-Verify {
    param(
        [string]$Version,
        [string]$Target
    )
    $archive  = "neothd-$Version-$Target.zip"
    $checksum = "$archive.sha256"
    $baseUrl  = "https://github.com/$Repo/releases/download/$Version"

    $tmp = Join-Path $env:TEMP "neoth-install-$(Get-Random)"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null

    Write-Step "Downloading $archive"
    try {
        Invoke-WebRequest -Uri "$baseUrl/$archive" -OutFile "$tmp\$archive" -UseBasicParsing
    } catch {
        Write-Err2 "Download failed: $baseUrl/$archive"
        Write-Err2 "Possible cause: Windows release artifacts are not yet"
        Write-Err2 "published. Track release.yml extension status in"
        Write-Err2 "PLAN/PROGRESS_v1_0.md R-08."
        Write-Err2 "Workaround: use WSL2 + scripts/install-binary.sh, or"
        Write-Err2 "build from source: .\install-binary.ps1 -FromSource"
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        exit 1
    }

    # Try to fetch checksum; missing checksum surfaces as a warning,
    # not an abort, because older releases may not ship sidecars.
    try {
        Invoke-WebRequest -Uri "$baseUrl/$checksum" -OutFile "$tmp\$checksum" -UseBasicParsing
        Write-Step "Verifying SHA-256"
        $expected = (Get-Content "$tmp\$checksum" -Raw).Trim().Split()[0]
        $actual = (Get-FileHash -Algorithm SHA256 "$tmp\$archive").Hash.ToLower()
        if ($expected.ToLower() -ne $actual) {
            Write-Err2 "SHA-256 mismatch!"
            Write-Err2 "  expected: $expected"
            Write-Err2 "  actual:   $actual"
            Write-Err2 "Aborting — do NOT trust this artifact."
            exit 1
        }
        Write-Info "Checksum OK"
    } catch {
        Write-Warn2 "Checksum sidecar missing — proceeding without verification."
    }

    Write-Step "Extracting + installing to $InstallDir\neothd.exe"
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    Expand-Archive -Path "$tmp\$archive" -DestinationPath $tmp -Force
    $extractedBin = Join-Path $tmp "neothd-$Version-$Target\neothd.exe"
    if (-not (Test-Path $extractedBin)) {
        Write-Err2 "Expected binary at $extractedBin but archive layout differs."
        exit 1
    }

    $targetBin = Join-Path $InstallDir "neothd.exe"
    if (Test-Path $targetBin) {
        $backup = "$targetBin.bak.$(Get-Date -UFormat %s)"
        Write-Info "Existing neothd.exe -> $backup"
        Move-Item -Path $targetBin -Destination $backup
    }
    Copy-Item -Path $extractedBin -Destination $targetBin
    Write-Info "Installed: $targetBin"

    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

function Check-Path {
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -split ";" | Where-Object { $_ -eq $InstallDir }) {
        Write-Info "$InstallDir is on User PATH."
        return
    }
    Write-Warn2 "$InstallDir is NOT on PATH."
    Write-Warn2 "Add it via:"
    Write-Warn2 "  [Environment]::SetEnvironmentVariable('PATH', `"`$env:PATH;$InstallDir`", 'User')"
    Write-Warn2 "Or run neothd via its full path: $InstallDir\neothd.exe"
}

Write-Step "NEOTH zero-install binary fetcher (Windows)"
$target  = Get-TargetTriple
Write-Info "Target: $target"
$version = Resolve-Version -RequestedVersion $Version
Download-And-Verify -Version $version -Target $target
Check-Path
Write-Step "Next step: neothd init (launches the wizard)"
