[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Destination,

    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version = '6.7.3',

    [ValidatePattern('^is-\d+_\d+_\d+$')]
    [string]$Tag = 'is-6_7_3'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Packaging {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "Inno Setup bootstrap failed: $Message"
}

$destinationPath = [System.IO.Path]::GetFullPath($Destination)
$assetName = "innosetup-$Version.exe"
$releaseUri = "https://api.github.com/repos/jrsoftware/issrc/releases/tags/$Tag"
$headers = @{
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent' = 'NEOTH-release-packager'
}
if ($env:GITHUB_TOKEN) {
    $headers.Authorization = "Bearer $($env:GITHUB_TOKEN)"
}

$release = Invoke-RestMethod -Uri $releaseUri -Headers $headers
if (-not $release.immutable) {
    Stop-Packaging "upstream release $Tag is not marked immutable"
}
$assets = @($release.assets | Where-Object { $_.name -eq $assetName })
if ($assets.Count -ne 1) {
    Stop-Packaging "expected one immutable $assetName asset, found $($assets.Count)"
}
$asset = $assets[0]
if ($asset.digest -notmatch '^sha256:([0-9a-fA-F]{64})$') {
    Stop-Packaging "GitHub did not expose a SHA-256 digest for $assetName"
}
$expectedSha256 = $Matches[1].ToLowerInvariant()

New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
$downloadPath = Join-Path ([System.IO.Path]::GetTempPath()) $assetName
try {
    Invoke-WebRequest -Uri $asset.browser_download_url -Headers $headers -OutFile $downloadPath
    $actualSha256 = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
        Stop-Packaging "digest mismatch for $assetName"
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $downloadPath
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        Stop-Packaging "invalid upstream Authenticode signature: $($signature.Status)"
    }
    $signerSubject = if ($null -eq $signature.SignerCertificate) {
        ''
    } else {
        $signature.SignerCertificate.Subject
    }
    if ($signerSubject -notmatch '(^|,\s*)CN=Pyrsys B\.V\.(,|$)') {
        Stop-Packaging "unexpected upstream signer '$signerSubject'"
    }

    $arguments = @(
        '/VERYSILENT'
        '/CURRENTUSER'
        '/SUPPRESSMSGBOXES'
        '/NORESTART'
        ('/DIR="' + $destinationPath + '"')
    )
    $process = Start-Process -FilePath $downloadPath -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        Stop-Packaging "upstream installer exited $($process.ExitCode)"
    }

    $compiler = Join-Path $destinationPath 'ISCC.exe'
    if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
        Stop-Packaging "ISCC.exe was not installed"
    }
    $productVersion = (Get-Item -LiteralPath $compiler).VersionInfo.ProductVersion
    if (-not $productVersion.StartsWith($Version, [System.StringComparison]::Ordinal)) {
        Stop-Packaging "ISCC version is '$productVersion', expected $Version"
    }
} finally {
    Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
}

Write-Output (Join-Path $destinationPath 'ISCC.exe')
