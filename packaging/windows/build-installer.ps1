[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Archive,

    [Parameter(Mandatory = $true)]
    [string]$Checksum,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture,

    [Parameter(Mandatory = $true)]
    [string]$Iscc,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$SigningThumbprint = '',

    [switch]$RequireSigning,

    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

function Stop-Packaging {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NEOTH Windows packaging failed: $Message"
}

function Test-StrictSemVer {
    param([Parameter(Mandatory = $true)][string]$Value)

    $match = [regex]::Match(
        $Value,
        '\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+(?<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\z',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success) {
        return $false
    }
    foreach ($identifier in $match.Groups['pre'].Value -split '\.') {
        if ($identifier -cmatch '^[0-9]+$' -and
            $identifier.Length -gt 1 -and
            $identifier[0] -eq '0') {
            return $false
        }
    }
    return $true
}

function Write-ArtifactSidecars {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Format,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Architecture,
        [Parameter(Mandatory = $true)][bool]$AuthenticodeSigned
    )

    $name = Split-Path -Leaf $Path
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    # Release assembly runs on Linux. Write the checksum contract with an
    # explicit LF so GNU sha256sum never interprets a trailing CR as part of
    # the artifact name.
    [System.IO.File]::WriteAllText(
        "$Path.sha256",
        "$hash  $name`n",
        [System.Text.UTF8Encoding]::new($false))
    $metadataJson = [ordered]@{
        schema_version = 1
        product = 'NEOTH'
        name = $name
        version = $Version
        target = $Target
        architecture = $Architecture
        format = $Format
        sha256 = $hash
        trust = [ordered]@{
            authenticode_signed = $AuthenticodeSigned
        }
    } | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText(
        "$Path.json",
        $metadataJson + "`n",
        [System.Text.UTF8Encoding]::new($false))
}

function New-PortableArchive {
    param(
        [Parameter(Mandatory = $true)][string]$StagingRoot,
        [Parameter(Mandatory = $true)][string]$BundleName,
        [Parameter(Mandatory = $true)][string[]]$RequiredFiles,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $temporaryZip = Join-Path ([System.IO.Path]::GetTempPath()) ("neoth-portable-" + [guid]::NewGuid().ToString('N') + '.zip')
    try {
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $StagingRoot,
            $temporaryZip,
            [System.IO.Compression.CompressionLevel]::Optimal,
            $false
        )
        $zip = [System.IO.Compression.ZipFile]::OpenRead($temporaryZip)
        try {
            $actualEntries = @(
                $zip.Entries |
                    Where-Object { -not [string]::IsNullOrEmpty($_.Name) } |
                    ForEach-Object { $_.FullName.Replace('\', '/') } |
                    Sort-Object
            )
            $expectedEntries = @(
                $RequiredFiles |
                    ForEach-Object { "$BundleName/$($_)" } |
                    Sort-Object
            )
            if (Compare-Object -ReferenceObject $expectedEntries -DifferenceObject $actualEntries) {
                Stop-Packaging 'generated portable ZIP has an unexpected or incomplete file set'
            }
        } finally {
            $zip.Dispose()
        }
        Move-Item -LiteralPath $temporaryZip -Destination $Destination -Force
    } finally {
        Remove-Item -LiteralPath $temporaryZip -Force -ErrorAction SilentlyContinue
    }
}

function Assert-ZipBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$BundleName,
        [Parameter(Mandatory = $true)][string[]]$RequiredFiles
    )

    $zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $actualFiles = [Collections.Generic.List[string]]::new()
        foreach ($entry in $zip.Entries) {
            # Windows PowerShell's Compress-Archive writes backslash-separated
            # member names. Normalize those names before applying the same
            # exact-set and traversal checks used for slash-separated ZIPs.
            # The normalized-name set also rejects slash/backslash aliases.
            $rawEntryName = $entry.FullName
            $entryName = $rawEntryName.Replace('\', '/')
            if ($entryName.StartsWith('/', [StringComparison]::Ordinal) -or
                $entryName.IndexOf('../', [StringComparison]::Ordinal) -ge 0 -or
                $entryName.IndexOf('//', [StringComparison]::Ordinal) -ge 0 -or
                $entryName -match '^[A-Za-z]:') {
                Stop-Packaging "unsafe ZIP entry: $rawEntryName"
            }
            if (-not $seen.Add($entryName)) {
                Stop-Packaging "duplicate ZIP entry after path normalization: $rawEntryName"
            }
            if ($entryName.EndsWith('/', [StringComparison]::Ordinal)) {
                if ($entryName -cne "$BundleName/") {
                    Stop-Packaging "unexpected ZIP directory entry: $rawEntryName"
                }
                continue
            }
            $actualFiles.Add($entryName)
        }
        $expectedFiles = @(
            $RequiredFiles |
                ForEach-Object { "$BundleName/$($_)" } |
                Sort-Object
        )
        if (Compare-Object -ReferenceObject $expectedFiles -DifferenceObject @($actualFiles | Sort-Object)) {
            Stop-Packaging 'source ZIP has an unexpected or incomplete entry set'
        }
    } finally {
        $zip.Dispose()
    }
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            Stop-Packaging "$(Split-Path -Leaf $Path) is not a PE executable"
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 6)) {
            Stop-Packaging "$(Split-Path -Leaf $Path) has an invalid PE header offset"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            Stop-Packaging "$(Split-Path -Leaf $Path) has no PE signature"
        }
        return $reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }
}

function Assert-SignedByThumbprint {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        Stop-Packaging "invalid Authenticode signature on $(Split-Path -Leaf $Path): $($signature.Status)"
    }
    if ($null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $Thumbprint) {
        Stop-Packaging "unexpected signing certificate on $(Split-Path -Leaf $Path)"
    }
}

$archivePath = (Resolve-Path -LiteralPath $Archive).Path
$checksumPath = (Resolve-Path -LiteralPath $Checksum).Path
$isccPath = (Resolve-Path -LiteralPath $Iscc).Path
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
$scriptRoot = Split-Path -Parent $PSCommandPath
$issPath = Join-Path $scriptRoot 'neoth.iss'
$signScript = Join-Path $scriptRoot 'sign-authenticode.ps1'

if (-not (Test-StrictSemVer -Value $Version)) {
    Stop-Packaging "version '$Version' is not strict SemVer"
}

$coreVersion = ($Version -split '[-+]', 2)[0]
$windowsVersionLimit = '65535'
foreach ($component in $coreVersion -split '\.') {
    if ($component.Length -gt $windowsVersionLimit.Length -or
        ($component.Length -eq $windowsVersionLimit.Length -and
         [string]::CompareOrdinal($component, $windowsVersionLimit) -gt 0)) {
        Stop-Packaging "SemVer core component '$component' exceeds the Windows version-resource limit 65535"
    }
}
$numericVersion = "$coreVersion.0"
$target = if ($Architecture -eq 'x64') {
    'x86_64-pc-windows-msvc'
} else {
    'aarch64-pc-windows-msvc'
}
$archiveName = "neoth-v$Version-$target.zip"
if ((Split-Path -Leaf $archivePath) -cne $archiveName) {
    Stop-Packaging "archive name must be exactly $archiveName"
}

$checksumLines = @(Get-Content -LiteralPath $checksumPath)
if ($checksumLines.Count -ne 1 -or
    $checksumLines[0] -cnotmatch '^([0-9A-Fa-f]{64})  ([^\\/]+)$') {
    Stop-Packaging 'checksum sidecar must contain exactly one bound SHA-256 line'
}
$expectedHash = $Matches[1].ToLowerInvariant()
if ($Matches[2] -cne $archiveName) {
    Stop-Packaging "checksum sidecar is bound to '$($Matches[2])', expected '$archiveName'"
}
$actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    Stop-Packaging "SHA-256 mismatch for $archiveName"
}

$normalizedThumbprint = ($SigningThumbprint -replace '\s', '').ToUpperInvariant()
if ($normalizedThumbprint -ne '' -and $normalizedThumbprint -notmatch '^[0-9A-F]{40}$') {
    Stop-Packaging 'Windows signing certificate thumbprint must be exactly 40 hexadecimal characters'
}
if ($RequireSigning -and $normalizedThumbprint -notmatch '^[0-9A-F]{40}$') {
    Stop-Packaging 'a stable installer requires a valid Windows signing certificate thumbprint'
}
$signedBuild = $normalizedThumbprint -match '^[0-9A-F]{40}$'

$requiredFiles = @(
    'neoth.exe'
    'neothd.exe'
    'neothd-gui.exe'
    'neoth-migrate.exe'
    'neoth-relay.exe'
    'neoth-keet-bridge.exe'
    'freedom.yaml.example'
    'import-manifest.example.yaml'
    'README.md'
    'LICENSE-MIT'
    'LICENSE-APACHE'
    'THIRD_PARTY_LICENSES'
)
$expectedMachine = if ($Architecture -eq 'x64') { 0x8664 } else { 0xAA64 }
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("neoth-windows-package-" + [guid]::NewGuid().ToString('N'))

try {
    Assert-ZipBundle `
        -Archive $archivePath `
        -BundleName "neoth-v$Version-$target" `
        -RequiredFiles $requiredFiles
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $temporaryRoot
    $bundlePath = Join-Path $temporaryRoot "neoth-v$Version-$target"
    if (-not (Test-Path -LiteralPath $bundlePath -PathType Container)) {
        Stop-Packaging "archive is missing its exact version/target root directory"
    }
    $topLevel = @(Get-ChildItem -LiteralPath $temporaryRoot -Force)
    if ($topLevel.Count -ne 1 -or $topLevel[0].FullName -cne $bundlePath) {
        Stop-Packaging 'archive contains unexpected top-level entries'
    }

    foreach ($name in $requiredFiles) {
        $path = Join-Path $bundlePath $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -eq 0) {
            Stop-Packaging "release bundle is missing non-empty $name"
        }
    }
    $unexpectedDirectories = @(Get-ChildItem -LiteralPath $bundlePath -Directory -Force)
    if ($unexpectedDirectories.Count -ne 0) {
        Stop-Packaging 'release bundle contains unexpected nested directories'
    }
    $actualFiles = @(Get-ChildItem -LiteralPath $bundlePath -File -Force | ForEach-Object Name | Sort-Object)
    $expectedFiles = @($requiredFiles | Sort-Object)
    if (Compare-Object -ReferenceObject $expectedFiles -DifferenceObject $actualFiles) {
        Stop-Packaging 'release bundle contains an unexpected or incomplete file set'
    }

    foreach ($name in $requiredFiles | Where-Object { $_.EndsWith('.exe', [System.StringComparison]::Ordinal) }) {
        $machine = Get-PeMachine -Path (Join-Path $bundlePath $name)
        if ($machine -ne $expectedMachine) {
            Stop-Packaging "$name has PE machine 0x$($machine.ToString('X4')), expected 0x$($expectedMachine.ToString('X4'))"
        }
    }

    if ($ValidateOnly) {
        Write-Output "Validated $archiveName ($Architecture, SHA-256 $actualHash)"
        return
    }

    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    if ($signedBuild) {
        $env:NEOTH_WINDOWS_CERT_THUMBPRINT = $normalizedThumbprint
        foreach ($name in $requiredFiles | Where-Object { $_.EndsWith('.exe', [System.StringComparison]::Ordinal) }) {
            & $signScript -File (Join-Path $bundlePath $name)
            Assert-SignedByThumbprint -Path (Join-Path $bundlePath $name) -Thumbprint $normalizedThumbprint
        }
    }

    $portablePath = Join-Path $outputPath $archiveName
    New-PortableArchive `
        -StagingRoot $temporaryRoot `
        -BundleName (Split-Path -Leaf $bundlePath) `
        -RequiredFiles $requiredFiles `
        -Destination $portablePath
    Write-ArtifactSidecars `
        -Path $portablePath `
        -Format 'zip' `
        -Version $Version `
        -Target $target `
        -Architecture $Architecture `
        -AuthenticodeSigned $signedBuild

    $compilerArguments = @(
        '/Qp'
        "/DAppVersion=$Version"
        "/DNumericVersion=$numericVersion"
        ('/DSourceDir="' + $bundlePath + '"')
        ('/DOutputDir="' + $outputPath + '"')
        ('/DTargetArch="' + $Architecture + '"')
    )
    if ($signedBuild) {
        $powerShellPath = (Get-Process -Id $PID).Path
        $signCommand = '$q' + $powerShellPath + '$q -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $q' + $signScript + '$q $f'
        $compilerArguments += '/DSignedBuild'
        $compilerArguments += "/Sneoth=$signCommand"
    }
    $compilerArguments += $issPath

    & $isccPath @compilerArguments
    if ($LASTEXITCODE -ne 0) {
        Stop-Packaging "ISCC exited $LASTEXITCODE"
    }

    $installerName = "NEOTH-$Version-$Architecture-Setup.exe"
    $installerPath = Join-Path $outputPath $installerName
    if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf) -or
        (Get-Item -LiteralPath $installerPath).Length -eq 0) {
        Stop-Packaging "ISCC did not produce $installerName"
    }
    $productVersion = (Get-Item -LiteralPath $installerPath).VersionInfo.ProductVersion
    if ($productVersion -ne $Version) {
        Stop-Packaging "installer product version is '$productVersion', expected '$Version'"
    }
    if ($signedBuild) {
        Assert-SignedByThumbprint -Path $installerPath -Thumbprint $normalizedThumbprint
    }

    Write-ArtifactSidecars `
        -Path $installerPath `
        -Format 'exe' `
        -Version $Version `
        -Target $target `
        -Architecture $Architecture `
        -AuthenticodeSigned $signedBuild
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:NEOTH_WINDOWS_CERT_THUMBPRINT -ErrorAction SilentlyContinue
}
