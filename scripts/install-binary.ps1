#requires -version 5.1
<#
.SYNOPSIS
    Compatibility entrypoint for the canonical signed-release installer.

.DESCRIPTION
    Delegates to SRC/install.ps1 so strict SemVer validation, mandatory
    minisign/cosign authentication, PATH wiring, and transactional multi-binary
    replacement have one implementation.

.EXAMPLE
    iwr -useb https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/scripts/install-binary.ps1 | iex

.EXAMPLE
    .\install-binary.ps1 -Version v1.0.0
#>

param(
    [string]$Repo       = 'The-Geek-Freaks/NEOTH',
    [string]$Version    = 'latest',
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\neoth",
    [switch]$FromSource
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$officialRepo = 'The-Geek-Freaks/NEOTH'

if ($Repo -ne $officialRepo) {
    throw "signed binary installer only trusts $officialRepo, got $Repo"
}

if ($FromSource) {
    $invocationPath = $MyInvocation.MyCommand.Path
    $scriptDir = if ($invocationPath) { Split-Path -Parent $invocationPath } else { $null }
    if (-not $scriptDir) {
        throw "source fallback requires a checkout; clone the repository and run scripts/install.ps1"
    }
    $sourceInstaller = Join-Path $scriptDir 'install.ps1'
    if (Test-Path -LiteralPath $sourceInstaller) {
        & $sourceInstaller
        exit $LASTEXITCODE
    }
    throw "source fallback requires a checkout; clone the repository and run scripts/install.ps1"
}

$env:NEOTH_VERSION = $Version
$env:NEOTH_INSTALL_DIR = $InstallDir

$invocationPath = $MyInvocation.MyCommand.Path
$scriptDir = if ($invocationPath) { Split-Path -Parent $invocationPath } else { $null }
$localCanonical = if ($scriptDir) {
    Join-Path (Split-Path -Parent $scriptDir) 'SRC\install.ps1'
} else {
    $null
}
if ($localCanonical -and (Test-Path -LiteralPath $localCanonical)) {
    & $localCanonical
    exit $LASTEXITCODE
}

$canonicalUrl = "https://raw.githubusercontent.com/$officialRepo/main/SRC/install.ps1"
try {
    $canonicalSource = Invoke-RestMethod -Uri $canonicalUrl -UseBasicParsing
} catch {
    throw "could not download canonical installer: $($_.Exception.Message)"
}
& ([scriptblock]::Create([string]$canonicalSource))
