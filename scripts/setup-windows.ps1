# setup-windows.ps1 -- one-shot dev-environment bootstrap for Windows.
#
# Verifies Rust + Visual Studio C++ Build Tools + Windows SDK are present,
# then writes C:\Temp\build-neoth.cmd -- a cmd-script wrapper that loads
# vcvars64 + LIB/INCLUDE for the UCRT SDK and forwards to cargo. The
# wrapper lets bash / Git Bash / Make / build agents run cargo on Windows
# MSVC without per-shell vcvars64.bat initialisation.
#
# Usage (PowerShell, repo root):
#   .\scripts\setup-windows.ps1                        # default: write C:\Temp\build-neoth.cmd
#   .\scripts\setup-windows.ps1 -Path C:\Tools\neoth.cmd
#   .\scripts\setup-windows.ps1 -CheckOnly             # report status, do not write
#
# Idempotent. Re-running overwrites the wrapper with current SDK paths.

[CmdletBinding()]
param(
    [string]$Path = 'C:\Temp\build-neoth.cmd',
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
}
function Write-Ok {
    param([string]$Text)
    Write-Host "  [OK] $Text" -ForegroundColor Green
}
function Write-Bad {
    param([string]$Text)
    Write-Host "  [!!] $Text" -ForegroundColor Red
}

# Step 1: Rust toolchain

Write-Section "Rust toolchain"
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    Write-Bad "cargo not found on PATH. Install Rust via https://rustup.rs/ then re-run."
    exit 1
}
$rustcVer = (& rustc --version) 2>$null
Write-Ok "found: $rustcVer"
$msvcTarget = (& rustup target list --installed) | Where-Object { $_ -eq 'x86_64-pc-windows-msvc' }
if (-not $msvcTarget) {
    Write-Bad "x86_64-pc-windows-msvc target not installed. Run: rustup target add x86_64-pc-windows-msvc"
    exit 1
}
Write-Ok "target x86_64-pc-windows-msvc installed"

# Step 2: Visual Studio C++ Build Tools

Write-Section "Visual Studio C++ Build Tools"
$programFilesX86 = ${env:ProgramFiles(x86)}
if (-not $programFilesX86) {
    Write-Bad "ProgramFiles(x86) env var unset -- cannot locate Visual Studio installer."
    exit 1
}
$vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Bad "vswhere.exe not found at $vswhere"
    Write-Host "  Install via: winget install Microsoft.VisualStudio.2022.BuildTools --override `"--add Microsoft.VisualStudio.Workload.VCTools`""
    exit 1
}
$vsInstall = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $vsInstall) {
    Write-Bad "VC++ x64 Build Tools workload not installed in any VS edition."
    Write-Host "  Install workload Microsoft.VisualStudio.Component.VC.Tools.x86.x64 via the VS Installer."
    exit 1
}
Write-Ok "found VS install: $vsInstall"
$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    Write-Bad "vcvars64.bat missing at $vcvars"
    exit 1
}
Write-Ok "vcvars64.bat at $vcvars"

# Step 3: Windows SDK (UCRT)

Write-Section "Windows 10/11 SDK"
$sdkLibRoot = Join-Path $programFilesX86 "Windows Kits\10\Lib"
if (-not (Test-Path $sdkLibRoot)) {
    Write-Bad "Windows SDK Lib root not at $sdkLibRoot"
    Write-Host "  Install via the VS Installer: Windows 10 SDK or Windows 11 SDK component."
    exit 1
}
$sdk = Get-ChildItem $sdkLibRoot -Directory |
    Where-Object {
        (Test-Path (Join-Path $_.FullName "um\x64\kernel32.lib")) -and
        (Test-Path (Join-Path $_.FullName "ucrt\x64\ucrt.lib"))
    } |
    Sort-Object Name -Descending |
    Select-Object -First 1
if (-not $sdk) {
    Write-Bad "No SDK directory contains both um\x64\kernel32.lib and ucrt\x64\ucrt.lib."
    exit 1
}
Write-Ok "SDK version $($sdk.Name) ($($sdk.FullName))"
$ucrtLib = Join-Path $sdk.FullName "ucrt\x64"
$ucrtInclude = Join-Path $programFilesX86 "Windows Kits\10\Include\$($sdk.Name)\ucrt"
if (-not (Test-Path $ucrtInclude)) {
    Write-Bad "UCRT include dir missing at $ucrtInclude"
    exit 1
}
Write-Ok "UCRT lib: $ucrtLib"
Write-Ok "UCRT include: $ucrtInclude"

# Step 4: Cargo workspace location

Write-Section "Cargo workspace"
$repoRoot = Split-Path -Parent $PSScriptRoot
$workspace = Join-Path $repoRoot "SRC"
if (-not (Test-Path (Join-Path $workspace "Cargo.toml"))) {
    Write-Bad "Cargo workspace not found at $workspace"
    Write-Host "  Run setup-windows.ps1 from a checkout that has SRC\Cargo.toml at the repo root."
    exit 1
}
Write-Ok "workspace at $workspace"

if ($CheckOnly) {
    Write-Section "Check-only mode"
    Write-Ok "All prerequisites present. Skipping wrapper write."
    exit 0
}

# Step 5: Write the wrapper

Write-Section "Wrapper script"
$parentDir = Split-Path -Parent $Path
if ($parentDir -and -not (Test-Path $parentDir)) {
    New-Item -ItemType Directory -Force -Path $parentDir | Out-Null
    Write-Ok "created $parentDir"
}

$wrapperLines = @(
    '@echo off',
    ':: =============================================================================',
    ':: build-neoth.cmd -- cargo wrapper for the Windows MSVC dev environment.',
    '::',
    ':: Auto-generated by scripts\setup-windows.ps1. Loads vcvars64 + ucrt SDK',
    ':: paths into LIB/INCLUDE, cds into the workspace, forwards every argument',
    ':: to cargo. Lets bash / Git Bash / Make / build agents run cargo on Windows',
    ':: without per-shell vcvars setup.',
    '::',
    ':: Regenerate after updating Visual Studio or installing a new Windows SDK:',
    '::   pwsh .\scripts\setup-windows.ps1',
    ':: =============================================================================',
    'setlocal EnableDelayedExpansion',
    "call `"$vcvars`" >nul",
    "set `"LIB=!LIB!;$ucrtLib`"",
    "set `"INCLUDE=!INCLUDE!;$ucrtInclude`"",
    "cd /d `"$workspace`"",
    'cargo %*',
    'exit /b !ERRORLEVEL!'
)

$wrapperLines -join "`r`n" | Set-Content -Path $Path -Encoding ASCII -Force
Write-Ok "wrote $Path"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  - From any shell:  cmd //c `"$Path test --bin neothd`""
Write-Host "  - Or PowerShell:   .\scripts\cargo-msvc.ps1 test --workspace"
Write-Host "  - Run again with -CheckOnly to verify the toolchain is still healthy."
