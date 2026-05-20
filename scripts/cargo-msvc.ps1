param(
    [switch] $D,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CargoArgs
)

$ErrorActionPreference = "Stop"

if (-not $CargoArgs -or $CargoArgs.Count -eq 0) {
    $CargoArgs = @("test", "--workspace")
}

if ($env:NEOTH_CARGO_MSVC_DEBUG) {
    Write-Host "cargo-msvc args: $($CargoArgs -join ' ')"
}

if ($D -and $CargoArgs[0] -eq "clippy" -and -not ($CargoArgs -contains "-D")) {
    if ($CargoArgs.Count -lt 2) {
        throw "-D was passed for clippy but no lint level/name followed it."
    }
    $CargoArgs = @($CargoArgs[0..($CargoArgs.Count - 2)]) + @("-D", $CargoArgs[$CargoArgs.Count - 1])
}

# PowerShell treats `--` as a script-argument delimiter and does not keep it in
# ValueFromRemainingArguments. For `cargo clippy ... -- -D warnings`, repair the
# common case by inserting the separator before lint-driver flags.
if ($CargoArgs[0] -eq "clippy" -and -not ($CargoArgs -contains "--")) {
    $lintFlagIndex = -1
    for ($i = 1; $i -lt $CargoArgs.Count; $i++) {
        if ($CargoArgs[$i] -in @("-A", "-W", "-D", "-F") -or
            $CargoArgs[$i].StartsWith("--allow") -or
            $CargoArgs[$i].StartsWith("--warn") -or
            $CargoArgs[$i].StartsWith("--deny") -or
            $CargoArgs[$i].StartsWith("--forbid")) {
            $lintFlagIndex = $i
            break
        }
    }
    if ($lintFlagIndex -ge 0) {
        $CargoArgs = @($CargoArgs[0..($lintFlagIndex - 1)]) + @("--") + @($CargoArgs[$lintFlagIndex..($CargoArgs.Count - 1)])
    }
}

$programFilesX86 = ${env:ProgramFiles(x86)}
if (-not $programFilesX86) {
    throw "ProgramFiles(x86) is not set; cannot locate Visual Studio BuildTools."
}

$vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found at $vswhere"
}

$vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) {
    throw "Visual Studio C++ BuildTools not found. Install workload Microsoft.VisualStudio.Component.VC.Tools.x86.x64."
}

$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    throw "vcvars64.bat not found at $vcvars"
}

$sdkLibRoot = Join-Path $programFilesX86 "Windows Kits\10\Lib"
if (-not (Test-Path $sdkLibRoot)) {
    throw "Windows 10 SDK Lib root not found at $sdkLibRoot"
}

$sdk = Get-ChildItem $sdkLibRoot -Directory |
    Where-Object {
        (Test-Path (Join-Path $_.FullName "um\x64\kernel32.lib")) -and
        (Test-Path (Join-Path $_.FullName "ucrt\x64\ucrt.lib"))
    } |
    Sort-Object Name -Descending |
    Select-Object -First 1

if (-not $sdk) {
    throw "No Windows SDK version contains both um\x64\kernel32.lib and ucrt\x64\ucrt.lib under $sdkLibRoot"
}

$sdkVersion = $sdk.Name
$ucrtLib = Join-Path $sdk.FullName "ucrt\x64"
$ucrtInclude = Join-Path $programFilesX86 "Windows Kits\10\Include\$sdkVersion\ucrt"
if (-not (Test-Path $ucrtInclude)) {
    throw "Windows SDK UCRT include path not found at $ucrtInclude"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$workspace = Join-Path $repoRoot "SRC"
if (-not (Test-Path (Join-Path $workspace "Cargo.toml"))) {
    throw "Cargo workspace not found at $workspace"
}

function Quote-CmdArg {
    param([string] $Arg)
    if ($Arg -match '^[A-Za-z0-9_./:=,+@-]+$') {
        return $Arg
    }
    return '"' + ($Arg -replace '"', '\"') + '"'
}

$cargoArgLine = ($CargoArgs | ForEach-Object { Quote-CmdArg $_ }) -join " "

# Use delayed expansion so LIB/INCLUDE are expanded after vcvars64.bat mutates them.
$cmd = "`"$vcvars`" >nul && " +
    "set `"LIB=!LIB!;$ucrtLib`" && " +
    "set `"INCLUDE=!INCLUDE!;$ucrtInclude`" && " +
    "cd /d `"$workspace`" && " +
    "cargo $cargoArgLine"

cmd /V:ON /d /s /c $cmd
exit $LASTEXITCODE
