# ─────────────────────────────────────────────────────────────────────────────
# install.ps1 — NEOTH bootstrap installer for Windows
# ─────────────────────────────────────────────────────────────────────────────
# The release matrix publishes x86_64 and ARM64 Windows ZIP archives. This
# installer downloads the matching archive and fails closed on any missing
# checksum, binary, or example configuration.
#
# It will:
#   - Download the published neoth.exe from the GitHub Releases page
#   - Verify SHA256 plus mandatory minisign/cosign release authenticity
#   - Install to "$env:LOCALAPPDATA\Programs\neoth" (or $env:NEOTH_INSTALL_DIR)
#   - Copy freedom.yaml.example, compatibility, GUI, migration, and relay binaries
#
# Usage (PowerShell):
#   irm https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.ps1 | iex
#   $env:NEOTH_VERSION = 'v1.0.0'; .\install.ps1
#   $env:NEOTH_INSTALL_DIR = 'C:\opt\neoth'; .\install.ps1
#   $env:NEOTH_ALLOW_UNVERIFIED_RECOVERY = '1'; .\install.ps1 # emergency only
#
# Build from source:
#   1. Install Rust (https://rustup.rs/) + Visual Studio Build Tools 2022
#      with the "Desktop development with C++" workload.
#   2. From a Developer Command Prompt that's run `vcvars64.bat`:
#        cd SRC
#        cargo build --release --locked -p neoth --bins --features release-desktop
#        cargo build --release --locked -p neothd-gui -p neoth-migrate -p neoth-relay
#   3. Copy the five binaries from SRC\target\release to your PATH.
# ─────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = 'Stop'

# ── Config ───────────────────────────────────────────────────────────────────
$Version = if ($env:NEOTH_VERSION) { $env:NEOTH_VERSION } else { 'latest' }
$InstallDir = if ($env:NEOTH_INSTALL_DIR) {
    $env:NEOTH_INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA 'Programs\neoth'
}
$AllowUnverifiedRecovery = $env:NEOTH_ALLOW_UNVERIFIED_RECOVERY -eq '1'
$ReleasesUrl = 'https://github.com/The-Geek-Freaks/NEOTH/releases'
$ReleasesApiUrl = 'https://api.github.com/repos/The-Geek-Freaks/NEOTH/releases'
$PinnedMinisignPubkey = 'RWQa0n4hqyE1huqkKoU+4aUs+YjbMiWabY4MwnwIafb79dWiSLV7qGBi'
$CosignOidcIssuer = 'https://token.actions.githubusercontent.com'

# ── Helpers ──────────────────────────────────────────────────────────────────
function Write-Info {
    param([string]$Message)
    Write-Host $Message
}

function Throw-Error {
    param([string]$Message)
    Write-Host "error: $Message" -ForegroundColor Red
    exit 1
}

function Get-Target {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
    switch ($arch) {
        'X64' { return 'x86_64-pc-windows-msvc' }
        'Arm64' { return 'aarch64-pc-windows-msvc' }
        default { Throw-Error "unsupported Windows architecture: $arch" }
    }
}

function Verify-Sha256Sidecar {
    param(
        [string]$Path,
        [string]$ChecksumPath,
        [string]$ExpectedAssetName
    )
    $checksumText = [System.IO.File]::ReadAllText($ChecksumPath)
    $checksumPattern = '^(?<sha>[0-9A-Fa-f]{64})  (?<asset>[^\r\n]+)\r?\n?\z'
    $checksumMatch = [regex]::Match($checksumText, $checksumPattern)
    if (-not $checksumMatch.Success) {
        Throw-Error 'checksum sidecar must be exactly one line: <64 hex><two spaces><asset name>'
    }
    $assetName = $checksumMatch.Groups['asset'].Value
    if ($assetName -cne $ExpectedAssetName) {
        Throw-Error "checksum sidecar names '$assetName', expected '$ExpectedAssetName'"
    }
    $Expected = $checksumMatch.Groups['sha'].Value
    $got = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
    $exp = $Expected.ToLowerInvariant()
    if ($got -ne $exp) {
        Throw-Error "SHA256 mismatch: expected $exp, got $got — refusing to install"
    }
    Write-Info "  SHA256 verified ($got)"
}

# ── Main ─────────────────────────────────────────────────────────────────────
$Target = Get-Target
$ResolvedVersion = if ($Version -eq 'latest') {
    Write-Info "  resolving latest published release"
    try {
        (Invoke-RestMethod -Uri "$ReleasesApiUrl/latest" -UseBasicParsing).tag_name
    } catch {
        Throw-Error "could not resolve the latest GitHub release tag: $($_.Exception.Message)"
    }
} else {
    $Version
}

function Assert-ReleaseTag {
    param([string]$Tag)
    $pattern = '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(?<pre>[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
    if ($Tag -notmatch $pattern) {
        Throw-Error "invalid release tag (strict SemVer required): $Tag"
    }
    if ($Matches['pre']) {
        foreach ($part in $Matches['pre'].Split('.')) {
            if ($part -match '^[0-9]+$' -and $part.Length -gt 1 -and $part.StartsWith('0')) {
                Throw-Error "invalid numeric prerelease identifier with leading zero: $Tag"
            }
        }
    }
}

function Verify-ReleaseAuthenticity {
    param(
        [string]$ArchivePath,
        [string]$SignaturePath,
        [string]$BundlePath,
        [string]$BaseUrl,
        [string]$ArchiveName,
        [string]$ReleaseTag
    )
    $signatureName = "$ArchiveName.minisig"
    try {
        Invoke-WebRequest -Uri "$BaseUrl/$signatureName" -OutFile $SignaturePath -UseBasicParsing
    } catch {
        Throw-Error "mandatory release signature is missing: $($_.Exception.Message)"
    }

    $minisign = Get-Command minisign -ErrorAction SilentlyContinue
    if ($minisign) {
        Write-Info "  verifying minisign release signature"
        & $minisign.Source -Vm $ArchivePath -x $SignaturePath -P $PinnedMinisignPubkey
        if ($LASTEXITCODE -ne 0) {
            Throw-Error "minisign verification failed — refusing to install"
        }
        $trustedComments = @(Get-Content -LiteralPath $SignaturePath | Where-Object {
            $_ -like 'trusted comment:*'
        })
        $expectedComment = "trusted comment: file:$ArchiveName"
        if ($trustedComments.Count -ne 1 -or $trustedComments[0] -cne $expectedComment) {
            Throw-Error "minisign trusted comment is not bound to file:$ArchiveName"
        }
        Write-Info "  minisign signature verified"
        return
    }

    $cosign = Get-Command cosign -ErrorAction SilentlyContinue
    if ($cosign) {
        $bundleName = "$ArchiveName.cosign.bundle"
        try {
            Invoke-WebRequest -Uri "$BaseUrl/$bundleName" -OutFile $BundlePath -UseBasicParsing
        } catch {
            Throw-Error "cosign bundle is missing: $($_.Exception.Message)"
        }
        $certificateIdentity = "https://github.com/The-Geek-Freaks/NEOTH/.github/workflows/release.yml@refs/tags/$ReleaseTag"
        Write-Info "  verifying exact cosign workflow identity"
        & $cosign.Source verify-blob `
            --bundle $BundlePath `
            --certificate-identity $certificateIdentity `
            --certificate-oidc-issuer $CosignOidcIssuer `
            $ArchivePath
        if ($LASTEXITCODE -ne 0) {
            Throw-Error "cosign verification failed — refusing to install"
        }
        Write-Info "  cosign signature verified"
        return
    }

    if ($AllowUnverifiedRecovery) {
        Write-Warning "NEOTH_ALLOW_UNVERIFIED_RECOVERY=1: authenticity was NOT verified. Use only with an archive authenticated out of band."
        return
    }
    Throw-Error "no authenticity verifier found; install minisign or cosign (emergency only: NEOTH_ALLOW_UNVERIFIED_RECOVERY=1)"
}

function Install-FileSetTransaction {
    param(
        [string]$DestinationDirectory,
        [object[]]$Items
    )
    $stage = Join-Path $DestinationDirectory ".neoth-install-$([guid]::NewGuid())"
    $payload = Join-Path $stage 'payload'
    $backup = Join-Path $stage 'backup'
    New-Item -ItemType Directory -Force -Path $payload, $backup | Out-Null
    $completed = [System.Collections.Generic.List[string]]::new()
    $preserveStage = $false

    try {
        foreach ($item in $Items) {
            $destination = Join-Path $DestinationDirectory $item.Name
            if ((Test-Path -LiteralPath $destination) -and
                -not (Test-Path -LiteralPath $destination -PathType Leaf)) {
                throw "install target is not a regular file: $destination"
            }
            Copy-Item -LiteralPath $item.Source -Destination (Join-Path $payload $item.Name) -Force
        }

        foreach ($item in $Items) {
            $destination = Join-Path $DestinationDirectory $item.Name
            $backupPath = Join-Path $backup $item.Name
            if (Test-Path -LiteralPath $destination) {
                Move-Item -LiteralPath $destination -Destination $backupPath -Force
            }
            # Track the replacement before moving the payload. If that move
            # fails, rollback still restores the backup for this item.
            [void]$completed.Add($item.Name)
            Move-Item -LiteralPath (Join-Path $payload $item.Name) -Destination $destination -Force
        }
    } catch {
        $installError = $_.Exception.Message
        $rollbackFailures = [System.Collections.Generic.List[string]]::new()
        for ($index = $completed.Count - 1; $index -ge 0; $index--) {
            $name = $completed[$index]
            $destination = Join-Path $DestinationDirectory $name
            $backupPath = Join-Path $backup $name
            try {
                if (Test-Path -LiteralPath $destination) {
                    Remove-Item -LiteralPath $destination -Force -ErrorAction Stop
                }
                if (Test-Path -LiteralPath $backupPath) {
                    Move-Item -LiteralPath $backupPath -Destination $destination -Force -ErrorAction Stop
                }
            } catch {
                [void]$rollbackFailures.Add("${name}: $($_.Exception.Message)")
            }
        }
        if ($rollbackFailures.Count -gt 0) {
            $preserveStage = $true
            throw "transactional install failed and rollback was incomplete; backups retained at ${backup}: $($rollbackFailures -join '; '); install error: $installError"
        }
        throw "transactional install failed; previous files were restored: $installError"
    } finally {
        if (-not $preserveStage) {
            Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Add-InstallDirectoryToPath {
    param([string]$Directory)
    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $normalized = $Directory.TrimEnd('\')
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $userEntries = @($userPath -split ';' | Where-Object { $_ })
    $inUserPath = $userEntries | Where-Object {
        [string]::Equals($_.TrimEnd('\'), $normalized, $comparison)
    }
    if (-not $inUserPath) {
        $newUserPath = if ($userEntries.Count -eq 0) {
            $Directory
        } else {
            ($userEntries + $Directory) -join ';'
        }
        [System.Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
        Write-Info "  added $Directory to the user PATH"
    }

    $processEntries = @($env:Path -split ';' | Where-Object { $_ })
    $inProcessPath = $processEntries | Where-Object {
        [string]::Equals($_.TrimEnd('\'), $normalized, $comparison)
    }
    if (-not $inProcessPath) {
        $env:Path = if ($env:Path) { "$env:Path;$Directory" } else { $Directory }
    }
}
if (-not $ResolvedVersion) { Throw-Error "latest GitHub release did not contain a tag" }
Assert-ReleaseTag -Tag $ResolvedVersion
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
Write-Info "  detected target: $Target"
Write-Info "  version: $ResolvedVersion"
Write-Info "  install dir: $InstallDir"

$BaseUrl = "$ReleasesUrl/download/$ResolvedVersion"
$Archive = "neoth-$ResolvedVersion-$Target.zip"
$Checksum = "$Archive.sha256"
$Signature = "$Archive.minisig"
$CosignBundle = "$Archive.cosign.bundle"

$Tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "neoth-install-$([guid]::NewGuid())")
try {
    Write-Info "  downloading $Archive"
    Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile (Join-Path $Tmp $Archive) `
        -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/$Checksum" -OutFile (Join-Path $Tmp $Checksum) `
        -UseBasicParsing

    Verify-Sha256Sidecar `
        -Path (Join-Path $Tmp $Archive) `
        -ChecksumPath (Join-Path $Tmp $Checksum) `
        -ExpectedAssetName $Archive
    Verify-ReleaseAuthenticity `
        -ArchivePath (Join-Path $Tmp $Archive) `
        -SignaturePath (Join-Path $Tmp $Signature) `
        -BundlePath (Join-Path $Tmp $CosignBundle) `
        -BaseUrl $BaseUrl `
        -ArchiveName $Archive `
        -ReleaseTag $ResolvedVersion

    Write-Info "  extracting"
    Expand-Archive -Path (Join-Path $Tmp $Archive) -DestinationPath $Tmp -Force

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }
    # release.yml packs into a subdir `neoth-<version>-<target>/`.
    $ArchiveName = "neoth-$ResolvedVersion-$Target"
    $BinarySrc = Join-Path (Join-Path $Tmp $ArchiveName) 'neoth.exe'
    if (-not (Test-Path $BinarySrc)) {
        $BinarySrc = Join-Path $Tmp 'neoth.exe'
    }
    if (-not (Test-Path $BinarySrc)) {
        Throw-Error "could not locate neoth.exe in extracted archive"
    }
    $CompatSrc = Join-Path (Join-Path $Tmp $ArchiveName) 'neothd.exe'
    if (-not (Test-Path $CompatSrc)) {
        $CompatSrc = Join-Path $Tmp 'neothd.exe'
    }
    if (-not (Test-Path $CompatSrc)) {
        Throw-Error "could not locate neothd.exe compatibility launcher in extracted archive"
    }
    $GuiSrc = Join-Path (Join-Path $Tmp $ArchiveName) 'neothd-gui.exe'
    if (-not (Test-Path $GuiSrc)) {
        $GuiSrc = Join-Path $Tmp 'neothd-gui.exe'
    }
    if (-not (Test-Path $GuiSrc)) {
        Throw-Error "desktop release archive is missing neothd-gui.exe"
    }
    $MigrateSrc = Join-Path (Join-Path $Tmp $ArchiveName) 'neoth-migrate.exe'
    if (-not (Test-Path $MigrateSrc)) {
        $MigrateSrc = Join-Path $Tmp 'neoth-migrate.exe'
    }
    if (-not (Test-Path $MigrateSrc)) {
        Throw-Error "release archive is missing neoth-migrate.exe"
    }
    $RelaySrc = Join-Path (Join-Path $Tmp $ArchiveName) 'neoth-relay.exe'
    if (-not (Test-Path $RelaySrc)) {
        $RelaySrc = Join-Path $Tmp 'neoth-relay.exe'
    }
    if (-not (Test-Path $RelaySrc)) {
        Throw-Error "release archive is missing neoth-relay.exe"
    }
    $ExamplePath = Join-Path (Join-Path $Tmp $ArchiveName) 'freedom.yaml.example'
    if (-not (Test-Path $ExamplePath)) {
        $ExamplePath = Join-Path $Tmp 'freedom.yaml.example'
    }
    if (-not (Test-Path $ExamplePath)) {
        Throw-Error "release archive is missing freedom.yaml.example"
    }
    $TargetExample = Join-Path $InstallDir 'freedom.yaml.example'
    $ImportExamplePath = Join-Path (Join-Path $Tmp $ArchiveName) 'import-manifest.example.yaml'
    if (-not (Test-Path $ImportExamplePath)) {
        $ImportExamplePath = Join-Path $Tmp 'import-manifest.example.yaml'
    }
    if (-not (Test-Path $ImportExamplePath)) {
        Throw-Error "release archive is missing import-manifest.example.yaml"
    }
    $TargetImportExample = Join-Path $InstallDir 'import-manifest.example.yaml'
    # Companions are replaced before the public core entrypoint. All files are
    # staged first; any failed move restores completed replacements in reverse.
    $installItems = @(
        [pscustomobject]@{ Name = 'neothd.exe'; Source = $CompatSrc },
        [pscustomobject]@{ Name = 'neothd-gui.exe'; Source = $GuiSrc },
        [pscustomobject]@{ Name = 'neoth-migrate.exe'; Source = $MigrateSrc },
        [pscustomobject]@{ Name = 'neoth-relay.exe'; Source = $RelaySrc }
    )
    if (-not (Test-Path -LiteralPath $TargetExample)) {
        $installItems += [pscustomobject]@{ Name = 'freedom.yaml.example'; Source = $ExamplePath }
    }
    if (-not (Test-Path -LiteralPath $TargetImportExample)) {
        $installItems += [pscustomobject]@{ Name = 'import-manifest.example.yaml'; Source = $ImportExamplePath }
    }
    $installItems += [pscustomobject]@{ Name = 'neoth.exe'; Source = $BinarySrc }
    try {
        Install-FileSetTransaction -DestinationDirectory $InstallDir -Items $installItems
    } catch {
        Throw-Error $_.Exception.Message
    }
    Add-InstallDirectoryToPath -Directory $InstallDir

    Write-Info ""
    Write-Info "  neoth installed: $(Join-Path $InstallDir 'neoth.exe')"
    Write-Info ""

    Write-Info "Next steps:"
    Write-Info "  1. Launch the GUI wizard:       neoth gui"
    Write-Info "  2. Or copy the example config: Copy-Item '$TargetExample' `"`$env:USERPROFILE\.neoth\freedom.yaml`""
    Write-Info "  3. Start the daemon:           neoth serve"
}
finally {
    if (Test-Path $Tmp) { Remove-Item -Recurse -Force $Tmp }
}
