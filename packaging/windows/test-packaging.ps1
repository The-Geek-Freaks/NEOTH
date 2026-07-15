[CmdletBinding()]
param(
    [string]$Iscc = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Test {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NEOTH Windows packaging test failed: $Message"
}

function Set-Utf8NoBomContent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Value + [Environment]::NewLine, $utf8NoBom)
}

function New-MinimalPe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][uint16]$Machine
    )

    $bytes = [byte[]]::new(512)
    [BitConverter]::GetBytes([uint16]0x5A4D).CopyTo($bytes, 0)
    [BitConverter]::GetBytes([uint32]0x80).CopyTo($bytes, 0x3C)
    [BitConverter]::GetBytes([uint32]0x00004550).CopyTo($bytes, 0x80)
    [BitConverter]::GetBytes($Machine).CopyTo($bytes, 0x84)
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Assert-FailsWith {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    try {
        & $Action
    } catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            Stop-Test "failure '$($_.Exception.Message)' did not match '$Pattern'"
        }
        return
    }
    Stop-Test "action unexpectedly succeeded; expected '$Pattern'"
}

function Assert-Metadata {
    param(
        [Parameter(Mandatory = $true)][string]$Artifact,
        [Parameter(Mandatory = $true)][string]$ExpectedFormat,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedTarget
    )

    $metadata = Get-Content -LiteralPath "$Artifact.json" -Raw | ConvertFrom-Json
    $required = @(
        'schema_version', 'product', 'name', 'version', 'target',
        'architecture', 'format', 'sha256', 'trust'
    ) | Sort-Object
    $actual = @($metadata.PSObject.Properties.Name | Sort-Object)
    if (Compare-Object -ReferenceObject $required -DifferenceObject $actual) {
        Stop-Test "metadata keys are not canonical for $(Split-Path -Leaf $Artifact)"
    }
    $name = Split-Path -Leaf $Artifact
    $hash = (Get-FileHash -LiteralPath $Artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($metadata.schema_version -ne 1 -or
        $metadata.product -cne 'NEOTH' -or
        $metadata.name -cne $name -or
        $metadata.version -cne $ExpectedVersion -or
        $metadata.target -cne $ExpectedTarget -or
        $metadata.architecture -cne 'x64' -or
        $metadata.format -cne $ExpectedFormat -or
        $metadata.sha256 -cne $hash -or
        $metadata.trust.authenticode_signed -ne $false) {
        Stop-Test "metadata values are not bound to $name"
    }
    $sidecar = Get-Content -LiteralPath "$Artifact.sha256" -Raw
    if ($sidecar -cnotmatch "^$hash  $([regex]::Escape($name))\r?\n?$") {
        Stop-Test "checksum sidecar is not bound to $name"
    }
}

function Assert-PortableEntries {
    param(
        [Parameter(Mandatory = $true)][string]$Artifact,
        [Parameter(Mandatory = $true)][string]$BundleName,
        [Parameter(Mandatory = $true)][string[]]$RequiredFiles
    )

    $zip = [IO.Compression.ZipFile]::OpenRead($Artifact)
    try {
        $entries = @(
            $zip.Entries |
                Where-Object { $_.Name } |
                ForEach-Object { $_.FullName.Replace('\', '/') }
        )
        foreach ($name in $RequiredFiles) {
            if ($entries -cnotcontains "$BundleName/$name") {
                Stop-Test "portable ZIP is missing $name"
            }
        }
        if ($entries.Count -ne $RequiredFiles.Count) {
            Stop-Test 'portable ZIP has an unexpected file count'
        }
    } finally {
        $zip.Dispose()
    }
}

$scriptRoot = Split-Path -Parent $PSCommandPath
$buildScript = Join-Path $scriptRoot 'build-installer.ps1'
$issPath = Join-Path $scriptRoot 'neoth.iss'
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("neoth-windows-tests-" + [guid]::NewGuid().ToString('N'))
$version = '1.2.3-rc.999999999999999999999+build.0001'
$target = 'x86_64-pc-windows-msvc'
$archiveName = "neoth-v$version-$target.zip"
$archive = Join-Path $temporaryRoot $archiveName
$checksum = "$archive.sha256"
$output = Join-Path $temporaryRoot 'output'
$isccForValidation = (Get-Process -Id $PID).Path
$requiredExecutables = @(
    'neoth.exe', 'neothd.exe', 'neothd-gui.exe',
    'neoth-migrate.exe', 'neoth-relay.exe', 'neoth-keet-bridge.exe'
)
$supportFiles = @(
    'freedom.yaml.example', 'import-manifest.example.yaml', 'README.md',
    'LICENSE-MIT', 'LICENSE-APACHE', 'THIRD_PARTY_LICENSES'
)

try {
    $allParseErrors = @()
    foreach ($script in Get-ChildItem -LiteralPath $scriptRoot -Filter '*.ps1' -File) {
        $tokens = $null
        $parseErrors = $null
        [Management.Automation.Language.Parser]::ParseFile(
            $script.FullName, [ref]$tokens, [ref]$parseErrors
        ) | Out-Null
        $allParseErrors += @($parseErrors)
    }
    if ($allParseErrors.Count -ne 0) {
        Stop-Test "PowerShell parse errors: $($allParseErrors -join '; ')"
    }

    $iss = Get-Content -LiteralPath $issPath -Raw
    foreach ($contract in @(
        '#define InstallerStateKey',
        "IsValidSemVer('1.0.0+build.01')",
        "CompareSemVer('999999999999999999999999.0.0', '2.0.0')",
        '/ALLOWDOWNGRADE never bypasses corrupt installation metadata',
        "RegKeyExists(HKCU, '{#UninstallKey}')",
        "RegKeyExists(HKLM, '{#UninstallKey}')",
        'VersionInfoProductVersion={#NumericVersion}',
        'VersionInfoProductTextVersion={#AppVersion}',
        'VersionInfoTextVersion={#AppVersion}'
    )) {
        if ($iss.IndexOf($contract, [StringComparison]::Ordinal) -lt 0) {
            Stop-Test "Inno contract is missing: $contract"
        }
    }
    if ($iss.IndexOf("'{#UninstallKey}', 'PathEntryOwned'", [StringComparison]::Ordinal) -ge 0) {
        Stop-Test 'PATH ownership is still tied to the replaceable uninstall key'
    }
    $buildSource = Get-Content -LiteralPath $buildScript -Raw
    $signIndex = $buildSource.IndexOf('& $signScript -File', [StringComparison]::Ordinal)
    $portableIndex = $buildSource.IndexOf('$portablePath =', [StringComparison]::Ordinal)
    $compilerIndex = $buildSource.IndexOf('& $isccPath @compilerArguments', [StringComparison]::Ordinal)
    if ($signIndex -lt 0 -or $portableIndex -le $signIndex -or $compilerIndex -le $portableIndex) {
        Stop-Test 'signed leaves, portable ZIP, and installer are built in the wrong order'
    }
    foreach ($schemaField in @(
        'schema_version = 1', "product = 'NEOTH'", 'name = $name',
        'version = $Version', 'target = $Target',
        'architecture = $Architecture', 'format = $Format',
        'sha256 = $hash', 'trust = [ordered]@{'
    )) {
        if ($buildSource.IndexOf($schemaField, [StringComparison]::Ordinal) -lt 0) {
            Stop-Test "artifact metadata schema is missing: $schemaField"
        }
    }

    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    $stagingRoot = Join-Path $temporaryRoot 'staging'
    $bundle = Join-Path $stagingRoot "neoth-v$version-$target"
    New-Item -ItemType Directory -Path $bundle -Force | Out-Null
    foreach ($name in $requiredExecutables) {
        New-MinimalPe -Path (Join-Path $bundle $name) -Machine 0x8664
    }
    foreach ($name in $supportFiles) {
        Set-Utf8NoBomContent -Path (Join-Path $bundle $name) -Value $name
    }
    Compress-Archive -LiteralPath $bundle -DestinationPath $archive -CompressionLevel Optimal
    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Utf8NoBomContent -Path $checksum -Value "$archiveHash  $archiveName"

    $validation = & $buildScript `
        -Archive $archive `
        -Checksum $checksum `
        -Version $version `
        -Architecture x64 `
        -Iscc $isccForValidation `
        -OutputDirectory $output `
        -ValidateOnly
    if (($validation | Out-String) -notmatch '^Validated ') {
        Stop-Test 'valid unbounded strict SemVer fixture was not validated'
    }

    New-MinimalPe -Path (Join-Path $bundle 'neoth-relay.exe') -Machine 0xAA64
    Remove-Item -LiteralPath $archive -Force
    Compress-Archive -LiteralPath $bundle -DestinationPath $archive -CompressionLevel Optimal
    $wrongMachineHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Utf8NoBomContent -Path $checksum -Value "$wrongMachineHash  $archiveName"
    Assert-FailsWith -Pattern 'PE machine' -Action {
        & $buildScript `
            -Archive $archive `
            -Checksum $checksum `
            -Version $version `
            -Architecture x64 `
            -Iscc $isccForValidation `
            -OutputDirectory $output `
            -ValidateOnly | Out-Null
    }
    New-MinimalPe -Path (Join-Path $bundle 'neoth-relay.exe') -Machine 0x8664
    Remove-Item -LiteralPath $archive -Force
    Compress-Archive -LiteralPath $bundle -DestinationPath $archive -CompressionLevel Optimal
    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Utf8NoBomContent -Path $checksum -Value "$archiveHash  $archiveName"

    foreach ($invalidVersion in @(
        '1.0.0-rc.01', '01.0.0', '1.0', '1.0.0+',
        '1.0.0+one..two', "1.0.0`n"
    )) {
        Assert-FailsWith -Pattern 'not strict SemVer' -Action {
            & $buildScript `
                -Archive $archive `
                -Checksum $checksum `
                -Version $invalidVersion `
                -Architecture x64 `
                -Iscc $isccForValidation `
                -OutputDirectory $output `
                -ValidateOnly | Out-Null
        }
    }
    Assert-FailsWith -Pattern 'Windows version-resource limit' -Action {
        & $buildScript `
            -Archive $archive `
            -Checksum $checksum `
            -Version '65536.0.0' `
            -Architecture x64 `
            -Iscc $isccForValidation `
            -OutputDirectory $output `
            -ValidateOnly | Out-Null
    }

    Set-Utf8NoBomContent -Path $checksum -Value "$archiveHash  wrong.zip"
    Assert-FailsWith -Pattern 'checksum sidecar is bound' -Action {
        & $buildScript `
            -Archive $archive `
            -Checksum $checksum `
            -Version $version `
            -Architecture x64 `
            -Iscc $isccForValidation `
            -OutputDirectory $output `
            -ValidateOnly | Out-Null
    }
    Set-Utf8NoBomContent -Path $checksum -Value "$('0' * 64)  $archiveName"
    Assert-FailsWith -Pattern 'SHA-256 mismatch' -Action {
        & $buildScript `
            -Archive $archive `
            -Checksum $checksum `
            -Version $version `
            -Architecture x64 `
            -Iscc $isccForValidation `
            -OutputDirectory $output `
            -ValidateOnly | Out-Null
    }
    Set-Utf8NoBomContent -Path $checksum -Value "$archiveHash  $archiveName"

    # A deliberately failing compiler still exercises the complete portable
    # path, which runs before ISCC and does not require Inno to be installed.
    $fakeIscc = Join-Path $temporaryRoot 'fake-iscc.cmd'
    Set-Content -LiteralPath $fakeIscc -Value @('@echo off', 'exit /b 23') -Encoding ascii
    $portableOnlyOutput = Join-Path $temporaryRoot 'portable-output'
    Assert-FailsWith -Pattern 'ISCC exited 23' -Action {
        & $buildScript `
            -Archive $archive `
            -Checksum $checksum `
            -Version $version `
            -Architecture x64 `
            -Iscc $fakeIscc `
            -OutputDirectory $portableOnlyOutput | Out-Null
    }
    $portableFixture = Join-Path $portableOnlyOutput $archiveName
    Assert-Metadata -Artifact $portableFixture -ExpectedFormat 'zip' -ExpectedVersion $version -ExpectedTarget $target
    Assert-PortableEntries `
        -Artifact $portableFixture `
        -BundleName "neoth-v$version-$target" `
        -RequiredFiles @($requiredExecutables + $supportFiles)

    if ($Iscc -eq '') {
        $candidates = @(
            (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
        )
        $found = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if ($null -ne $found) { $Iscc = $found }
    }
    if ($Iscc -ne '') {
        & $buildScript `
            -Archive $archive `
            -Checksum $checksum `
            -Version $version `
            -Architecture x64 `
            -Iscc $Iscc `
            -OutputDirectory $output

        $portable = Join-Path $output $archiveName
        $installer = Join-Path $output "NEOTH-$version-x64-Setup.exe"
        Assert-Metadata -Artifact $portable -ExpectedFormat 'zip' -ExpectedVersion $version -ExpectedTarget $target
        Assert-Metadata -Artifact $installer -ExpectedFormat 'exe' -ExpectedVersion $version -ExpectedTarget $target
        Assert-PortableEntries `
            -Artifact $portable `
            -BundleName "neoth-v$version-$target" `
            -RequiredFiles @($requiredExecutables + $supportFiles)
        Write-Output 'Inno compile/package fixture: PASS'
    } else {
        Write-Warning 'Inno Setup compiler unavailable; compile/package fixture skipped'
    }

    Write-Output 'Windows packaging static/validation fixtures: PASS'
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
