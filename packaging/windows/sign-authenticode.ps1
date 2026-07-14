[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$File
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$thumbprint = ($env:NEOTH_WINDOWS_CERT_THUMBPRINT -replace '\s', '').ToUpperInvariant()
if ($thumbprint -notmatch '^[0-9A-F]{40}$') {
    throw 'NEOTH_WINDOWS_CERT_THUMBPRINT is missing or malformed'
}
$filePath = (Resolve-Path -LiteralPath $File).Path

$signTool = Get-Command signtool.exe -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $signTool) {
    $kitRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $preferredToolArchitecture = if (
        [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq
        [System.Runtime.InteropServices.Architecture]::Arm64
    ) { 'arm64' } else { 'x64' }
    $candidate = Get-ChildItem -LiteralPath $kitRoot -Filter signtool.exe -File -Recurse |
        Where-Object { $_.Directory.Name -in @($preferredToolArchitecture, 'x64', 'arm64') } |
        Sort-Object `
            @{ Expression = { $_.Directory.Name -eq $preferredToolArchitecture }; Descending = $true }, `
            @{ Expression = { [version]$_.Directory.Parent.Name }; Descending = $true } |
        Select-Object -First 1
    if ($null -eq $candidate) {
        throw 'signtool.exe was not found in PATH or the Windows 10 SDK'
    }
    $signToolPath = $candidate.FullName
} else {
    $signToolPath = $signTool.Source
}

$timestampUrl = if ($env:NEOTH_WINDOWS_TIMESTAMP_URL) {
    $env:NEOTH_WINDOWS_TIMESTAMP_URL
} else {
    'https://timestamp.digicert.com'
}

& $signToolPath sign /sha1 $thumbprint /fd SHA256 /tr $timestampUrl /td SHA256 /d 'NEOTH' $filePath
if ($LASTEXITCODE -ne 0) {
    throw "signtool failed for $filePath with exit code $LASTEXITCODE"
}
& $signToolPath verify /pa /all $filePath
if ($LASTEXITCODE -ne 0) {
    throw "signtool verification failed for $filePath with exit code $LASTEXITCODE"
}

$signature = Get-AuthenticodeSignature -LiteralPath $filePath
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "invalid Authenticode signature on ${filePath}: $($signature.Status)"
}
if ($null -eq $signature.SignerCertificate -or
    $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $thumbprint) {
    throw "unexpected signing certificate on $filePath"
}
