# neoth Windows source-build helper
# Installs neoth from source via WSL2. For the native prebuilt Windows release,
# use https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.ps1.
#
# Usage: irm https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install.ps1 | iex
# Or:    .\install.ps1

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

function Write-Step  { Write-Host "`n==> $args" -ForegroundColor Cyan }
function Write-Ok    { Write-Host "[neoth] $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "[neoth WARNING] $args" -ForegroundColor Yellow }
function Write-Fail  { Write-Host "[neoth ERROR] $args" -ForegroundColor Red }

Write-Host ""
Write-Host "neoth Windows installer" -ForegroundColor Bold
Write-Host "This script installs neoth via WSL2."
Write-Host ""

# ── Check WSL2 ────────────────────────────────────────────────────────────────
Write-Step "Checking WSL2"

try {
    $wslStatus = wsl --status 2>&1
    $wslExit = $LASTEXITCODE
} catch {
    $wslStatus = ""
    $wslExit = 1
}

if ($wslExit -ne 0) {
    Write-Fail "WSL2 is not installed."
    Write-Host ""
    Write-Host "Install WSL2 and then re-run this script:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Open PowerShell as Administrator"
    Write-Host "  2. Run: wsl --install"
    Write-Host "  3. Restart your computer when prompted"
    Write-Host "  4. Complete the Ubuntu setup (username + password)"
    Write-Host "  5. Re-run this installer"
    Write-Host ""
    Write-Host "WSL2 documentation: https://learn.microsoft.com/en-us/windows/wsl/install"
    Write-Host ""
    exit 1
}

Write-Ok "WSL2 is installed."
Write-Host $wslStatus

# ── Check default WSL distribution ───────────────────────────────────────────
Write-Step "Checking default WSL distribution"

try {
    $defaultDistro = (wsl --list --verbose 2>&1) | Where-Object { $_ -match "\*" } |
        ForEach-Object { ($_ -split "\s+") | Where-Object { $_ -ne "" -and $_ -ne "*" } | Select-Object -First 1 }
} catch {
    $defaultDistro = $null
}

if (-not $defaultDistro) {
    Write-Warn "No default WSL distribution found."
    Write-Host ""
    Write-Host "Install Ubuntu (recommended):" -ForegroundColor Yellow
    Write-Host "  wsl --install -d Ubuntu"
    Write-Host ""
    Write-Host "Or pick any distribution from: wsl --list --online"
    Write-Host ""
    $resp = Read-Host "Attempt to install Ubuntu now? [y/N]"
    if ($resp -match "^[yY]") {
        Write-Ok "Launching Ubuntu install..."
        wsl --install -d Ubuntu
        Write-Host ""
        Write-Host "After Ubuntu setup completes, re-run this installer." -ForegroundColor Yellow
        exit 0
    } else {
        Write-Warn "Skipping. Install a WSL distribution and re-run."
        exit 1
    }
}

Write-Ok "Default WSL distribution: $defaultDistro"

# ── Download and run install.sh inside WSL2 ───────────────────────────────────
Write-Step "Running neoth install.sh inside WSL2"
Write-Host "This will:"
Write-Host "  - Check/install Rust toolchain inside WSL2"
Write-Host "  - Clone neoth to ~/.local/src/neoth"
Write-Host "  - Build neoth, GUI, migration, relay, compatibility, and Keet binaries"
Write-Host "  - Require Node.js 22.16+ only for the source-built Keet standalone"
Write-Host "  - Install to ~/.local/bin"
Write-Host ""

# The install script URL
$installScriptUrl = "https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install.sh"
$localInstallScript = "/tmp/neoth_install.sh"

# Check if install.sh is available locally (for offline/dev use)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$localScriptPath = Join-Path $scriptDir "install.sh"

if (Test-Path $localScriptPath) {
    Write-Ok "Using local install.sh from $localScriptPath"
    # Convert Windows path to WSL path
    $wslScriptPath = wsl --exec wslpath -a $localScriptPath.Replace("\", "/")
    $installCmd = "bash '$wslScriptPath'"
} else {
    Write-Ok "Downloading install.sh from GitHub..."
    $installCmd = "curl -sSf '$installScriptUrl' | bash"
}

# Run inside WSL2
$wslResult = wsl bash -c $installCmd
$wslExit = $LASTEXITCODE

if ($wslExit -ne 0) {
    Write-Fail "WSL2 install failed with exit code $wslExit."
    Write-Host "Try running manually inside WSL2:"
    Write-Host "  wsl"
    Write-Host "  curl -sSf $installScriptUrl | bash"
    exit 1
}

Write-Ok "Install complete inside WSL2."

# ── Path reminder ─────────────────────────────────────────────────────────────
Write-Step "PATH configuration"
Write-Host ""
Write-Host "To run neoth from PowerShell via WSL2, use:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  wsl neoth init"
Write-Host "  wsl neoth chat `"hello`""
Write-Host "  wsl neoth"
Write-Host "  wsl neoth-keet-bridge setup"
Write-Host ""
Write-Host "Or open a WSL terminal: wsl"
Write-Host ""

# ── Notes on native Windows ───────────────────────────────────────────────────
Write-Host "Native Windows release:" -ForegroundColor Yellow
Write-Host "  This helper deliberately creates a WSL source build."
Write-Host "  For the prebuilt native binary, run:"
Write-Host "  irm https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.ps1 | iex"
Write-Host ""

# ── Next steps ────────────────────────────────────────────────────────────────
Write-Host "Next step: onboarding wizard" -ForegroundColor Green
Write-Host ""
Write-Host "  wsl neoth init"
Write-Host ""
Write-Host "Docs: https://github.com/The-Geek-Freaks/NEOTH/blob/main/docs/install.md"
Write-Host ""
