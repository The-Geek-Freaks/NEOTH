[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NativeRoot,
    [Parameter(Mandatory)][string]$AndroidManifest,
    [Parameter(Mandatory)][string]$IosManifest,
    [Parameter(Mandatory)][string]$OutputManifest,
    [Parameter(Mandatory)][string]$ExpectedSourceHead
)
$ErrorActionPreference = 'Stop'
function Require-File([string]$Path) { if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing required file: $Path" } }
function Get-Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant() }
function Read-Origin([string]$Path, [string]$Platform) {
    Require-File $Path
    $origin = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($origin.schema -ne 'neoth.mobile-native-artifact-manifest.v1' -or $origin.platform -ne $Platform -or $null -eq $origin.source -or $null -eq $origin.files) { throw "Unexpected native producer manifest: $Path" }
    return $origin
}
function Test-Entry($Entry) {
    if ($Entry.relative_path -isnot [string] -or $Entry.sha256 -isnot [string] -or $Entry.relative_path -match '(^[\\/]|^[A-Za-z]:|(^|[\\/])\.\.([\\/]|$))' -or $Entry.sha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'Native manifest contains an unsafe or invalid file entry.' }
    $path = Join-Path $NativeRoot $Entry.relative_path
    Require-File $path
    if ((Get-Sha256 $path) -ne $Entry.sha256.ToUpperInvariant()) { throw "Native artifact hash mismatch: $($Entry.relative_path)" }
}

$android = Read-Origin $AndroidManifest 'android'; $ios = Read-Origin $IosManifest 'ios'
if ($ExpectedSourceHead -notmatch '^[0-9A-Fa-f]{40}$') { throw 'ExpectedSourceHead must be a 40-character Git commit SHA.' }
foreach ($field in 'head','bridge_cargo_sha256','bridge_lib_sha256','bridge_header_sha256','canonical_protocol_sha256','bridge_cargo_lock_sha256','src_cargo_lock_sha256') {
    if ([string]::IsNullOrWhiteSpace([string]$android.source.$field) -or $android.source.$field -ne $ios.source.$field) { throw "Producer manifests disagree on source.$field" }
}
if ($android.source.head -ne $ExpectedSourceHead) { throw "Native producer source head $($android.source.head) does not equal materialization checkout $ExpectedSourceHead" }
$files = @($android.files) + @($ios.files)
if ($files.Count -eq 0 -or @($files.relative_path | Sort-Object -Unique).Count -ne $files.Count) { throw 'Native producer manifests contain no files or duplicate paths.' }
foreach ($entry in $files) { Test-Entry $entry }
foreach ($required in @('android/arm64-v8a/libneoth_companion_bridge.so','android/armeabi-v7a/libneoth_companion_bridge.so','android/x86_64/libneoth_companion_bridge.so','ios/NEOTHCompanionBridge.xcframework/Info.plist')) {
    if ($files.relative_path -notcontains $required) { throw "Native producer manifest lacks required input: $required" }
}
$result = [ordered]@{ schema = 'neoth.mobile-native-artifact-manifest.v1'; source_head = $android.source.head; bridge_cargo_lock_sha256 = $android.source.bridge_cargo_lock_sha256; files = @($files | ForEach-Object { [ordered]@{ relative_path = $_.relative_path; sha256 = $_.sha256.ToUpperInvariant() } }) }
$json = $result | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText((Resolve-Path -LiteralPath (Split-Path -Parent $OutputManifest)).Path + [System.IO.Path]::DirectorySeparatorChar + (Split-Path -Leaf $OutputManifest), $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
