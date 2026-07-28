# ─────────────────────────────────────────────────────────────────────────────
# install.ps1 — NEOTH bootstrap installer for Windows
# ─────────────────────────────────────────────────────────────────────────────
# The release matrix publishes x86_64 and ARM64 Windows ZIP archives. This
# installer downloads the matching archive and fails closed on any missing
# checksum, binary, or example configuration.
#
# It will:
#   - Download the published neoth.exe from the GitHub Releases page
#   - Verify SHA256 plus mandatory minisign or digest-pinned cosign authenticity
#   - Install to "$env:LOCALAPPDATA\Programs\neoth" (or $env:NEOTH_INSTALL_DIR)
#   - Atomically install every package-owned binary, example, legal/support
#     file, and the verified self-knowledge snapshot
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
#        cargo build --release --locked -p neothd-gui --features release-desktop
#        cargo build --release --locked -p neoth-migrate -p neoth-relay
#   3. Build `bridges\keet` with its pinned pnpm toolchain, then copy all six
#      executables to your PATH. `scripts\install.sh` automates this in WSL.
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
# Digest copied from sigstore/cosign-installer action.yml at the immutable
# source commit recorded in packaging/cosign-bootstrap.json. Windows on ARM64
# uses the OS-provided x64 compatibility layer for this temporary verifier.
$CosignBootstrapVersion = 'v3.0.6'
$CosignBootstrapWindowsAmd64Sha256 = '9b85a88ebff2d9dd30ff4984a6f61f2cedc232dd87d81fa7f2ff3c0ed96c241c'
$MaxArchiveBytes = 1073741824L
$MaxMetadataBytes = 16777216L
$MaxVerifierBytes = 268435456L
$MaxArchiveEntries = 100000
$MaxArchiveDepth = 64
$MaxArchiveMemberBytes = 1073741824L
$MaxArchiveTotalBytes = 8589934592L
$MaxArchiveDirectoryBytes = 67108864L
$MaxDownloadSeconds = 600

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

function Invoke-Download {
    param(
        [string]$Uri,
        [string]$OutFile,
        [long]$MaxBytes = $MaxMetadataBytes
    )
    if ($MaxBytes -le 0) { throw 'download byte ceiling must be positive' }
    $requestedUri = [Uri]$Uri
    if (-not $requestedUri.IsAbsoluteUri -or $requestedUri.Scheme -cne 'https') {
        throw "download URI must be absolute HTTPS: $Uri"
    }
    Add-Type -AssemblyName System.Net.Http
    $lastError = $null
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    foreach ($attempt in 1..3) {
        $handler = $null
        $client = $null
        $response = $null
        $input = $null
        $output = $null
        $cancellation = $null
        try {
            $remainingSeconds = $MaxDownloadSeconds - $stopwatch.Elapsed.TotalSeconds
            if ($remainingSeconds -le 0) {
                throw "download exceeded its $MaxDownloadSeconds-second wall-clock ceiling"
            }
            $cancellation = [Threading.CancellationTokenSource]::new(
                [TimeSpan]::FromSeconds($remainingSeconds)
            )
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            $handler = [System.Net.Http.HttpClientHandler]::new()
            $client = [System.Net.Http.HttpClient]::new($handler)
            $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
            $client.DefaultRequestHeaders.UserAgent.ParseAdd('NEOTH-bootstrap/1.0')
            $response = $client.GetAsync(
                $requestedUri,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,
                $cancellation.Token
            ).GetAwaiter().GetResult()
            $response.EnsureSuccessStatusCode()
            if ($response.RequestMessage.RequestUri.Scheme -cne 'https') {
                throw 'download redirected outside HTTPS'
            }
            $declared = $response.Content.Headers.ContentLength
            if ($null -ne $declared -and $declared -gt $MaxBytes) {
                throw "download exceeds the $MaxBytes-byte ceiling"
            }
            $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $output = [System.IO.FileStream]::new(
                $OutFile,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None
            )
            $buffer = New-Object byte[] 131072
            [long]$written = 0
            while (($read = $input.ReadAsync(
                $buffer,
                0,
                $buffer.Length,
                $cancellation.Token
            ).GetAwaiter().GetResult()) -gt 0) {
                $written += $read
                if ($written -gt $MaxBytes) {
                    throw "download exceeds the $MaxBytes-byte ceiling"
                }
                $output.Write($buffer, 0, $read)
            }
            $output.Flush($true)
            return
        } catch {
            $lastError = $_
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            if ($attempt -lt 3) {
                Start-Sleep -Seconds $attempt
            }
        } finally {
            if ($output) { $output.Dispose() }
            if ($input) { $input.Dispose() }
            if ($response) { $response.Dispose() }
            if ($client) { $client.Dispose() }
            if ($handler) { $handler.Dispose() }
            if ($cancellation) { $cancellation.Dispose() }
        }
    }
    Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
    throw $lastError
}

function New-PrivateTemporaryDirectory {
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "neoth-install-$([guid]::NewGuid().ToString('N'))"
    [System.IO.Directory]::CreateDirectory($path) | Out-Null
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $security = [System.Security.AccessControl.DirectorySecurity]::new()
        $security.SetOwner($identity.User)
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($sid in @(
            $identity.User,
            [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        )) {
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $security.AddAccessRule($rule) | Out-Null
        }
        Set-Acl -LiteralPath $path -AclObject $security
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'temporary directory is a reparse point'
        }
        return $item.FullName
    } catch {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Read-CanonicalZipCentralNames {
    param(
        [System.IO.FileStream]$File,
        [int]$MaxEntries
    )
    if ($File.Length -lt 22) { throw 'release ZIP has no complete end record' }
    $tailLength = [int][Math]::Min(65557L, $File.Length)
    $tail = New-Object byte[] $tailLength
    $File.Position = $File.Length - $tailLength
    $tailRead = 0
    while ($tailRead -lt $tailLength) {
        $read = $File.Read($tail, $tailRead, $tailLength - $tailRead)
        if ($read -le 0) { throw 'release ZIP end record is truncated' }
        $tailRead += $read
    }
    $eocdIndex = -1
    for ($index = $tailLength - 22; $index -ge 0; $index--) {
        if ($tail[$index] -eq 0x50 -and $tail[$index + 1] -eq 0x4b -and
            $tail[$index + 2] -eq 0x05 -and $tail[$index + 3] -eq 0x06) {
            $commentLength = [BitConverter]::ToUInt16($tail, $index + 20)
            if ($index + 22 + $commentLength -eq $tailLength) {
                $eocdIndex = $index
                break
            }
        }
    }
    if ($eocdIndex -lt 0) { throw 'release ZIP has no canonical end record' }

    $diskNumber = [BitConverter]::ToUInt16($tail, $eocdIndex + 4)
    $centralDisk = [BitConverter]::ToUInt16($tail, $eocdIndex + 6)
    $diskEntries = [BitConverter]::ToUInt16($tail, $eocdIndex + 8)
    $entryCount = [BitConverter]::ToUInt16($tail, $eocdIndex + 10)
    [long]$centralSize = [BitConverter]::ToUInt32($tail, $eocdIndex + 12)
    [long]$centralOffset = [BitConverter]::ToUInt32($tail, $eocdIndex + 16)
    if ($diskNumber -ne 0 -or $centralDisk -ne 0 -or $diskEntries -ne $entryCount) {
        throw 'multi-disk release ZIPs are not supported'
    }
    if ($entryCount -eq 0xFFFF -or $centralSize -eq 0xFFFFFFFFL -or
        $centralOffset -eq 0xFFFFFFFFL) {
        throw 'ZIP64 release archives are not supported by the bounded bootstrap parser'
    }
    if ($entryCount -eq 0 -or $entryCount -gt $MaxEntries) {
        throw "release ZIP entry count must be 1..$MaxEntries"
    }
    if ($centralSize -gt $MaxArchiveDirectoryBytes) {
        throw "release ZIP central directory exceeds the $MaxArchiveDirectoryBytes-byte ceiling"
    }
    [long]$eocdOffset = $File.Length - $tailLength + $eocdIndex
    if ($centralOffset -lt 0 -or $centralSize -lt 0 -or
        $centralOffset -gt $eocdOffset -or
        $centralSize -ne ($eocdOffset - $centralOffset)) {
        throw 'release ZIP central directory is non-canonical or out of bounds'
    }

    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $reader = [IO.BinaryReader]::new($File, $utf8, $true)
    $names = New-Object System.Collections.Generic.List[string]
    try {
        $File.Position = $centralOffset
        for ($entryIndex = 0; $entryIndex -lt $entryCount; $entryIndex++) {
            if ($File.Position + 46 -gt $eocdOffset -or $reader.ReadUInt32() -ne 0x02014b50) {
                throw 'release ZIP central directory entry is truncated or malformed'
            }
            [void]$reader.ReadUInt16() # version made by
            [void]$reader.ReadUInt16() # version needed
            $flags = $reader.ReadUInt16()
            [void]$reader.ReadUInt16() # compression method
            [void]$reader.ReadUInt16() # time
            [void]$reader.ReadUInt16() # date
            [void]$reader.ReadUInt32() # crc32
            $compressedSize = $reader.ReadUInt32()
            $expandedSize = $reader.ReadUInt32()
            $nameLength = $reader.ReadUInt16()
            $extraLength = $reader.ReadUInt16()
            $commentLength = $reader.ReadUInt16()
            $entryDisk = $reader.ReadUInt16()
            [void]$reader.ReadUInt16() # internal attributes
            [void]$reader.ReadUInt32() # external attributes
            $localOffset = $reader.ReadUInt32()
            if (($flags -band 0x41) -ne 0) { throw 'encrypted release ZIP members are not supported' }
            if ($entryDisk -ne 0) { throw 'multi-disk release ZIP member is not supported' }
            if ($compressedSize -eq 0xFFFFFFFFL -or $expandedSize -eq 0xFFFFFFFFL -or
                $localOffset -eq 0xFFFFFFFFL) {
                throw 'ZIP64 release members are not supported by the bounded bootstrap parser'
            }
            [long]$variableLength = $nameLength + $extraLength + $commentLength
            if ($nameLength -eq 0 -or $nameLength -gt 4096 -or
                $File.Position + $variableLength -gt $eocdOffset) {
                throw 'release ZIP central directory name is empty or out of bounds'
            }
            $nameBytes = $reader.ReadBytes($nameLength)
            if ($nameBytes.Length -ne $nameLength) { throw 'release ZIP member name is truncated' }
            foreach ($value in $nameBytes) {
                if ($value -eq 0 -or $value -eq 0x5c) {
                    throw 'release ZIP contains a NUL or raw backslash path separator'
                }
            }
            try { $name = $utf8.GetString($nameBytes) } catch {
                throw "release ZIP member name is not canonical UTF-8: $($_.Exception.Message)"
            }
            $names.Add($name)
            $File.Position += $extraLength + $commentLength
        }
        if ($File.Position -ne $eocdOffset) {
            throw 'release ZIP central directory has unaccounted bytes'
        }
    } finally {
        $reader.Dispose()
    }
    return $names.ToArray()
}

function Expand-SafeZipArchive {
    param(
        [string]$ArchivePath,
        [string]$ExpectedRoot,
        [string]$DestinationRoot,
        [int]$MaxEntries = $MaxArchiveEntries,
        [int]$MaxDepth = $MaxArchiveDepth,
        [long]$MaxMemberBytes = $MaxArchiveMemberBytes,
        [long]$MaxTotalBytes = $MaxArchiveTotalBytes
    )
    Add-Type -AssemblyName System.IO.Compression
    $archiveInfo = Get-Item -LiteralPath $ArchivePath -Force
    if (($archiveInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
        throw 'release ZIP must be a regular non-reparse file'
    }
    if ($archiveInfo.Length -gt $MaxArchiveBytes) {
        throw "compressed release archive exceeds the $MaxArchiveBytes-byte ceiling"
    }
    if (Test-Path -LiteralPath $DestinationRoot) {
        throw "archive destination already exists: $DestinationRoot"
    }
    [System.IO.Directory]::CreateDirectory($DestinationRoot) | Out-Null

    $file = $null
    $zip = $null
    try {
        $file = [System.IO.File]::Open(
            $ArchivePath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        $centralNames = @(Read-CanonicalZipCentralNames -File $file -MaxEntries $MaxEntries)
        $file.Position = 0
        $zip = [System.IO.Compression.ZipArchive]::new(
            $file,
            [System.IO.Compression.ZipArchiveMode]::Read,
            $false
        )
        if ($zip.Entries.Count -eq 0 -or $zip.Entries.Count -gt $MaxEntries) {
            throw "release ZIP entry count must be 1..$MaxEntries"
        }
        if ($zip.Entries.Count -ne $centralNames.Count) {
            throw 'release ZIP parser views disagree on the central-directory entry count'
        }

        $actualKinds = @{}
        $implicitDirectories = @{}
        $plans = New-Object System.Collections.Generic.List[object]
        [long]$totalBytes = 0
        $rootEntries = 0
        $fileEntries = 0
        for ($entryIndex = 0; $entryIndex -lt $zip.Entries.Count; $entryIndex++) {
            $entry = $zip.Entries[$entryIndex]
            $raw = $entry.FullName
            if ($raw -cne $centralNames[$entryIndex]) {
                throw "release ZIP member name was normalized by the platform parser: '$raw'"
            }
            if ([string]::IsNullOrEmpty($raw) -or $raw.Length -gt 4096 -or
                $raw.StartsWith('/') -or $raw.StartsWith('\') -or
                $raw.Contains('\') -or $raw.Contains([char]0) -or
                $raw -match '^[A-Za-z]:' -or $raw.Contains('//')) {
                throw "unsafe release ZIP path: '$raw'"
            }
            $isDirectory = $raw.EndsWith('/')
            $normalized = if ($isDirectory) { $raw.Substring(0, $raw.Length - 1) } else { $raw }
            if ([string]::IsNullOrEmpty($normalized)) { throw 'release ZIP contains an empty path' }
            $segments = $normalized.Split('/')
            if ($segments.Count -gt ($MaxDepth + 1) -or $segments[0] -cne $ExpectedRoot) {
                throw "release ZIP member is outside exact root $ExpectedRoot`: '$raw'"
            }
            foreach ($segment in $segments) {
                if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.' -or $segment -eq '..' -or
                    $segment -match '[<>:"|?*\x00-\x1f]' -or
                    $segment.EndsWith('.') -or $segment.EndsWith(' ')) {
                    throw "unsafe release ZIP path segment in '$raw'"
                }
                $device = $segment.Split('.')[0].ToUpperInvariant()
                if ($device -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
                    throw "reserved Windows device path in release ZIP: '$raw'"
                }
            }

            [uint32]$attributes = ([int64]$entry.ExternalAttributes -band 0xFFFFFFFFL)
            if (($attributes -band 0x400) -ne 0) {
                throw "release ZIP contains a reparse-point member: '$raw'"
            }
            $unixType = (($attributes -shr 16) -band 0xF000)
            $expectedUnixType = if ($isDirectory) { 0x4000 } else { 0x8000 }
            if ($unixType -ne 0 -and $unixType -ne $expectedUnixType) {
                throw "release ZIP contains a symlink, hardlink, or special member: '$raw'"
            }
            if ($isDirectory -and $entry.Length -ne 0) {
                throw "release ZIP directory carries file data: '$raw'"
            }
            if (-not $isDirectory) {
                $fileEntries++
                if ($entry.Length -lt 0 -or $entry.Length -gt $MaxMemberBytes) {
                    throw "release ZIP member exceeds the $MaxMemberBytes-byte ceiling: '$raw'"
                }
                if ($totalBytes -gt ($MaxTotalBytes - $entry.Length)) {
                    throw "release ZIP exceeds the $MaxTotalBytes-byte expanded ceiling"
                }
                $totalBytes += $entry.Length
            }

            $key = $normalized.Normalize([Text.NormalizationForm]::FormC).ToUpperInvariant()
            if ($actualKinds.ContainsKey($key)) {
                throw "release ZIP contains duplicate or case-fold-colliding member: '$raw'"
            }
            if (-not $isDirectory -and $implicitDirectories.ContainsKey($key)) {
                throw "release ZIP contains a file/directory conflict: '$raw'"
            }
            $parent = $normalized
            while ($parent.Contains('/')) {
                $parent = $parent.Substring(0, $parent.LastIndexOf('/'))
                $parentKey = $parent.Normalize([Text.NormalizationForm]::FormC).ToUpperInvariant()
                if ($actualKinds.ContainsKey($parentKey) -and $actualKinds[$parentKey] -eq 'file') {
                    throw "release ZIP places a member below a file: '$raw'"
                }
                $implicitDirectories[$parentKey] = $true
            }
            $actualKinds[$key] = if ($isDirectory) { 'directory' } else { 'file' }
            if ($normalized -ceq $ExpectedRoot) {
                if (-not $isDirectory) { throw "release ZIP root is not a directory: '$raw'" }
                $rootEntries++
            }

            $relativeWindows = $normalized.Replace('/', [IO.Path]::DirectorySeparatorChar)
            $destination = [IO.Path]::GetFullPath((Join-Path $DestinationRoot $relativeWindows))
            $trimSeparators = [char[]]@(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar
            )
            $destinationPrefix = [IO.Path]::GetFullPath($DestinationRoot).TrimEnd(
                $trimSeparators
            ) + [IO.Path]::DirectorySeparatorChar
            if (-not $destination.StartsWith($destinationPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "release ZIP destination escaped its private extraction root: '$raw'"
            }
            $plans.Add([pscustomobject]@{
                Entry = $entry
                Destination = $destination
                IsDirectory = $isDirectory
            })
        }
        if ($rootEntries -ne 1) { throw "release ZIP must contain exactly one explicit root $ExpectedRoot/" }
        if ($fileEntries -eq 0) { throw 'release ZIP contains no installable files' }

        foreach ($plan in $plans) {
            if ($plan.IsDirectory) {
                [IO.Directory]::CreateDirectory($plan.Destination) | Out-Null
                continue
            }
            [IO.Directory]::CreateDirectory((Split-Path -Parent $plan.Destination)) | Out-Null
            $input = $null
            $output = $null
            try {
                $input = $plan.Entry.Open()
                $output = [IO.FileStream]::new(
                    $plan.Destination,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::None
                )
                $buffer = New-Object byte[] 131072
                [long]$written = 0
                while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $written += $read
                    if ($written -gt $plan.Entry.Length -or $written -gt $MaxMemberBytes) {
                        throw "release ZIP member expanded beyond its declared size: '$($plan.Entry.FullName)'"
                    }
                    $output.Write($buffer, 0, $read)
                }
                if ($written -ne $plan.Entry.Length) {
                    throw "release ZIP member size disagrees with its central directory: '$($plan.Entry.FullName)'"
                }
                $output.Flush($true)
            } finally {
                if ($output) { $output.Dispose() }
                if ($input) { $input.Dispose() }
            }
        }
    } finally {
        if ($zip) { $zip.Dispose() }
        if ($file) { $file.Dispose() }
    }
}

function Get-StandaloneVersion {
    param(
        [string]$Path,
        [string]$TemporaryDirectory
    )
    # Bare redirects stdout to NUL when started without an attached console.
    # Start-Process supplies a hidden console and captures the exact output so
    # GUI/bootstrap launches still enforce the release-version binding.
    $suffix = [guid]::NewGuid().ToString('N')
    $stdoutPath = Join-Path $TemporaryDirectory "keet-version-$suffix.stdout"
    $stderrPath = Join-Path $TemporaryDirectory "keet-version-$suffix.stderr"
    try {
        $process = Start-Process `
            -FilePath $Path `
            -ArgumentList '--version' `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -WindowStyle Hidden `
            -Wait `
            -PassThru
        if ($process.ExitCode -ne 0) {
            $stderr = if (Test-Path -LiteralPath $stderrPath) {
                [System.IO.File]::ReadAllText($stderrPath).Trim()
            } else { '' }
            throw "neoth-keet-bridge --version exited $($process.ExitCode): $stderr"
        }
        $value = [System.IO.File]::ReadAllText($stdoutPath).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw 'neoth-keet-bridge --version returned no version'
        }
        return $value
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
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

function Resolve-CosignVerifier {
    param([string]$TemporaryDirectory)

    $installed = Get-Command cosign -ErrorAction SilentlyContinue
    if ($installed) {
        return $installed.Source
    }

    $arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
    if ($arch -ne 'X64' -and $arch -ne 'Arm64') {
        Throw-Error "no digest-pinned cosign bootstrap for Windows architecture $arch"
    }
    if ($arch -eq 'Arm64') {
        Write-Info '  using the Windows ARM64 x64-compatibility layer for the verifier'
    }

    $fileName = 'cosign-windows-amd64.exe'
    $path = Join-Path $TemporaryDirectory $fileName
    $uri = "https://github.com/sigstore/cosign/releases/download/$CosignBootstrapVersion/$fileName"
    Write-Info "  downloading digest-pinned cosign $CosignBootstrapVersion verifier"
    try {
        Invoke-Download -Uri $uri -OutFile $path -MaxBytes $MaxVerifierBytes
    } catch {
        if ($AllowUnverifiedRecovery) {
            Write-Warning "NEOTH_ALLOW_UNVERIFIED_RECOVERY=1: the digest-pinned cosign verifier could not be downloaded. Authenticity was NOT verified. Use only with an archive authenticated out of band."
            return $null
        }
        Throw-Error "failed to download digest-pinned cosign verifier: $($_.Exception.Message)"
    }

    $got = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -cne $CosignBootstrapWindowsAmd64Sha256) {
        Throw-Error "bootstrap cosign SHA256 mismatch: expected $CosignBootstrapWindowsAmd64Sha256, got $got — refusing to execute it"
    }
    Write-Info "  digest-pinned cosign verifier ready ($got)"
    return $path
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
        Invoke-Download -Uri "$BaseUrl/$signatureName" -OutFile $SignaturePath -MaxBytes $MaxMetadataBytes
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

    $cosignPath = Resolve-CosignVerifier -TemporaryDirectory (Split-Path -Parent $ArchivePath)
    if ($cosignPath) {
        $bundleName = "$ArchiveName.cosign.bundle"
        try {
            Invoke-Download -Uri "$BaseUrl/$bundleName" -OutFile $BundlePath -MaxBytes $MaxMetadataBytes
        } catch {
            Throw-Error "cosign bundle is missing: $($_.Exception.Message)"
        }
        $certificateIdentity = "https://github.com/The-Geek-Freaks/NEOTH/.github/workflows/release.yml@refs/tags/$ReleaseTag"
        Write-Info "  verifying exact cosign workflow identity"
        & $cosignPath verify-blob `
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
    Throw-Error "digest-pinned cosign verifier was not available (emergency only: NEOTH_ALLOW_UNVERIFIED_RECOVERY=1)"
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

function Read-PortableInstallMarker {
    param(
        [string]$MarkerPath,
        [string]$ExpectedInstallRoot,
        [string]$ExpectedVersion = ''
    )
    $item = Get-Item -LiteralPath $MarkerPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Test-Path -LiteralPath $MarkerPath -PathType Leaf) -or
        $item.Length -le 0 -or $item.Length -gt 16384) {
        throw "portable ownership marker is not a bounded regular file: $MarkerPath"
    }
    $raw = [IO.File]::ReadAllText($MarkerPath)
    $propertyTokens = [regex]::Matches($raw, '"(?<name>(?:\\.|[^"\\])*)"\s*:')
    if ($propertyTokens.Count -ne 6) {
        throw 'portable ownership marker must contain exactly six JSON properties'
    }
    $allowed = @('schema_version', 'owner', 'install_root', 'release_version', 'profile', 'support_dir')
    $seen = @{}
    foreach ($token in $propertyTokens) {
        $name = $token.Groups['name'].Value
        if ($allowed -cnotcontains $name -or $seen.ContainsKey($name)) {
            throw "portable ownership marker has an unknown or duplicate property: $name"
        }
        $seen[$name] = $true
    }
    try { $marker = $raw | ConvertFrom-Json } catch { throw "invalid portable ownership marker JSON: $($_.Exception.Message)" }
    if ($marker.schema_version -ne 2 -or $marker.owner -cne 'neoth_portable_release' -or
        $marker.profile -cnotin @('desktop', 'headless_musl') -or
        $marker.support_dir -cne 'neoth-support' -or
        $marker.release_version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$') {
        throw 'portable ownership marker has an invalid schema, owner, profile, or version'
    }
    if ($ExpectedVersion -and $marker.release_version -cne $ExpectedVersion) {
        throw "portable ownership marker version $($marker.release_version) does not match $ExpectedVersion"
    }
    if ($marker.install_root -isnot [string] -or [string]::IsNullOrWhiteSpace($marker.install_root)) {
        throw 'portable ownership marker install_root is missing'
    }
    $markerFull = [IO.Path]::GetFullPath($marker.install_root).TrimEnd('\')
    if (-not [string]::Equals($marker.install_root.TrimEnd('\'), $markerFull, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($markerFull, $ExpectedInstallRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "portable ownership marker does not own canonical install root $ExpectedInstallRoot"
    }
    return $marker
}

function Assert-PortableInstallOwnership {
    param(
        [string]$InstallRoot,
        [string]$DefaultPortableRoot
    )
    if ([string]::Equals(
        $InstallRoot.TrimEnd('\'),
        $DefaultPortableRoot.TrimEnd('\'),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        $uninstallId = 'TheGeekFreaks.NEOTH.BF6060F4-B75D-4E9A-BEB6-7EC8CB94A3C1_is1'
        $registryOwners = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$uninstallId",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$uninstallId",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$uninstallId"
        )
        if ($registryOwners | Where-Object { Test-Path -LiteralPath $_ }) {
            throw 'the default portable path collides with an Inno Setup-owned NEOTH installation; uninstall it first'
        }
    }
    if (-not (Test-Path -LiteralPath $InstallRoot)) { return }
    $rootItem = Get-Item -LiteralPath $InstallRoot -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Test-Path -LiteralPath $InstallRoot -PathType Container)) {
        throw "portable install root must be a real directory: $InstallRoot"
    }
    $markerPath = Join-Path $InstallRoot '.neoth-portable-install.json'
    $markerItem = Get-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
    if ($null -eq $markerItem) {
        foreach ($name in @(
            'neoth.exe', 'neothd.exe', 'neoth-migrate.exe', 'neoth-relay.exe',
            'neothd-gui.exe', 'neoth-keet-bridge.exe', 'neoth-support'
        )) {
            $owned = Get-Item -LiteralPath (Join-Path $InstallRoot $name) -Force -ErrorAction SilentlyContinue
            if ($null -ne $owned) {
                throw "markerless first install found existing NEOTH target $($owned.FullName); move/uninstall that legacy target or choose another install directory (unrelated files may remain)"
            }
        }
        return
    }
    Read-PortableInstallMarker -MarkerPath $markerPath -ExpectedInstallRoot $InstallRoot | Out-Null
}

function Read-TransactionReceipt {
    param(
        [string[]]$Lines,
        [string]$ExpectedVersion,
        [string]$ExpectedProfile
    )
    if ($Lines.Count -ne 1 -or $Lines[0].Length -gt 4096) {
        throw 'native bundle transaction returned a non-canonical receipt'
    }
    try { $receipt = $Lines[0] | ConvertFrom-Json } catch { throw "native transaction receipt is invalid JSON: $($_.Exception.Message)" }
    $names = @($receipt.PSObject.Properties.Name)
    $expectedNames = @('status', 'profile', 'version', 'transaction_id', 'members')
    if ($names.Count -ne $expectedNames.Count -or @($names | Where-Object { $expectedNames -cnotcontains $_ }).Count -ne 0 -or
        $receipt.status -cne 'committed' -or $receipt.profile -cne $ExpectedProfile -or
        $receipt.version -cne $ExpectedVersion -or
        $receipt.transaction_id -cnotmatch '^[0-9a-f]{32}$' -or
        -not ($receipt.members -is [int] -or $receipt.members -is [long]) -or
        $receipt.members -le 0) {
        throw 'native bundle transaction returned a mismatched receipt'
    }
    return $receipt
}

# ── Main ─────────────────────────────────────────────────────────────────────
$Target = Get-Target
$Tmp = New-PrivateTemporaryDirectory
try {
$ResolvedVersion = if ($Version -eq 'latest') {
    Write-Info "  resolving latest published release"
    $latestPath = Join-Path $Tmp 'latest-release.json'
    try {
        Invoke-Download -Uri "$ReleasesApiUrl/latest" -OutFile $latestPath -MaxBytes $MaxMetadataBytes
        ([IO.File]::ReadAllText($latestPath) | ConvertFrom-Json).tag_name
    } catch {
        Throw-Error "could not resolve the latest GitHub release tag: $($_.Exception.Message)"
    }
} else {
    $Version
}
if (-not $ResolvedVersion) { Throw-Error "latest GitHub release did not contain a tag" }
Assert-ReleaseTag -Tag $ResolvedVersion
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$DefaultPortableRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs\neoth'))
try {
    Assert-PortableInstallOwnership -InstallRoot $InstallDir -DefaultPortableRoot $DefaultPortableRoot
} catch {
    Throw-Error $_.Exception.Message
}
Write-Info "  detected target: $Target"
Write-Info "  version: $ResolvedVersion"
Write-Info "  install dir: $InstallDir"

$BaseUrl = "$ReleasesUrl/download/$ResolvedVersion"
$Archive = "neoth-$ResolvedVersion-$Target.zip"
$Checksum = "$Archive.sha256"
$Signature = "$Archive.minisig"
$CosignBundle = "$Archive.cosign.bundle"
$ArchiveName = "neoth-$ResolvedVersion-$Target"

    Write-Info "  downloading $Archive"
    Invoke-Download -Uri "$BaseUrl/$Archive" -OutFile (Join-Path $Tmp $Archive) -MaxBytes $MaxArchiveBytes
    Invoke-Download -Uri "$BaseUrl/$Checksum" -OutFile (Join-Path $Tmp $Checksum) -MaxBytes $MaxMetadataBytes

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

    Write-Info "  validating and extracting"
    $ExtractionRoot = Join-Path $Tmp 'extracted'
    try {
        Expand-SafeZipArchive `
            -ArchivePath (Join-Path $Tmp $Archive) `
            -ExpectedRoot $ArchiveName `
            -DestinationRoot $ExtractionRoot
    } catch {
        Throw-Error "unsafe release ZIP: $($_.Exception.Message)"
    }

    # release.yml packs into a subdir `neoth-<version>-<target>/`.
    $BundleRoot = Join-Path $ExtractionRoot $ArchiveName
    if (-not (Test-Path -LiteralPath $BundleRoot -PathType Container)) {
        Throw-Error "release archive is missing its exact root $ArchiveName"
    }
    $BundleRootItem = Get-Item -LiteralPath $BundleRoot -Force
    if (($BundleRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-Error "release archive root must not be a reparse point: $BundleRoot"
    }
    $BinarySrc = Join-Path $BundleRoot 'neoth.exe'
    if (-not (Test-Path -LiteralPath $BinarySrc -PathType Leaf)) {
        Throw-Error "release archive is missing its neoth.exe transaction helper"
    }
    if (((Get-Item -LiteralPath $BinarySrc -Force).Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-Error "release transaction helper must not be a reparse point: $BinarySrc"
    }
    $KeetSrc = Join-Path $BundleRoot 'neoth-keet-bridge.exe'
    if (-not (Test-Path -LiteralPath $KeetSrc -PathType Leaf)) {
        Throw-Error "desktop release archive is missing neoth-keet-bridge.exe"
    }
    try {
        $KeetVersion = Get-StandaloneVersion -Path $KeetSrc -TemporaryDirectory $Tmp
    } catch {
        Throw-Error $_.Exception.Message
    }
    $ExpectedKeetVersion = $ResolvedVersion.Substring(1)
    if ($KeetVersion -cne $ExpectedKeetVersion) {
        Throw-Error "neoth-keet-bridge version $KeetVersion does not match release $ExpectedKeetVersion"
    }
    $TargetExample = Join-Path $InstallDir 'neoth-support\freedom.yaml.example'
    $SelfKnowledgePath = Join-Path $BundleRoot 'self-knowledge'
    $SelfKnowledgeManifestPath = Join-Path $SelfKnowledgePath 'manifest.json'
    if (-not (Test-Path -LiteralPath $SelfKnowledgeManifestPath -PathType Leaf) -or
        (Get-Item -LiteralPath $SelfKnowledgeManifestPath).Length -eq 0) {
        Throw-Error "release archive is missing self-knowledge/manifest.json"
    }
    foreach ($SnapshotItem in @(Get-Item -LiteralPath $SelfKnowledgePath -Force) +
        @(Get-ChildItem -LiteralPath $SelfKnowledgePath -Recurse -Force)) {
        if (($SnapshotItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-Error "release self-knowledge contains a reparse point: $($SnapshotItem.FullName)"
        }
    }
    try {
        $SelfKnowledgeManifest = Get-Content -LiteralPath $SelfKnowledgeManifestPath -Raw | ConvertFrom-Json
    } catch {
        Throw-Error "release self-knowledge manifest is invalid JSON: $($_.Exception.Message)"
    }
    $ExpectedReleaseVersion = $ResolvedVersion.Substring(1)
    if ($SelfKnowledgeManifest.schema_version -ne 1 -or
        $SelfKnowledgeManifest.product -cne 'NEOTH' -or
        $SelfKnowledgeManifest.release_version -cne $ExpectedReleaseVersion -or
        $SelfKnowledgeManifest.source_head -cnotmatch '^[0-9a-f]{40,64}$' -or
        $SelfKnowledgeManifest.payload_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        @($SelfKnowledgeManifest.files).Count -eq 0) {
        Throw-Error "release self-knowledge identity does not match $ResolvedVersion"
    }
    & $BinarySrc --output json self-knowledge verify --snapshot $SelfKnowledgePath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Throw-Error "release binary rejected its self-knowledge snapshot"
    }
    # The verified extracted helper owns the common lock, destination-local
    # staging, durable journal, crash recovery, closed payload selection, and
    # final neoth.exe commit point. The script does not create or mutate the
    # install root before that lock, and the helper copies its running image.
    $ReceiptLines = @(& $BinarySrc --output json internal bundle-transaction apply `
        --bundle-root $BundleRoot `
        --install-root $InstallDir `
        --expected-version $ExpectedReleaseVersion)
    $TransactionExitCode = $LASTEXITCODE
    if ($TransactionExitCode -ne 0) {
        Throw-Error "native crash-safe bundle transaction failed"
    }
    try {
        Read-TransactionReceipt `
            -Lines $ReceiptLines `
            -ExpectedVersion $ExpectedReleaseVersion `
            -ExpectedProfile 'desktop' | Out-Null
        Read-PortableInstallMarker `
            -MarkerPath (Join-Path $InstallDir '.neoth-portable-install.json') `
            -ExpectedInstallRoot $InstallDir `
            -ExpectedVersion $ExpectedReleaseVersion | Out-Null
    } catch {
        Throw-Error $_.Exception.Message
    }
    Add-InstallDirectoryToPath -Directory $InstallDir

    Write-Info ""
    Write-Info "  neoth installed: $(Join-Path $InstallDir 'neoth.exe')"
    Write-Info "  Keet companion installed: $(Join-Path $InstallDir 'neoth-keet-bridge.exe')"
    Write-Info ""

    Write-Info "Next steps:"
    Write-Info "  1. Launch the GUI wizard:       neoth gui"
    Write-Info "  2. Or copy the example config: Copy-Item '$TargetExample' `"`$env:USERPROFILE\.neoth\freedom.yaml`""
    Write-Info "  3. Start the daemon:           neoth serve"
    Write-Info "  4. To enable the Keet channel: neoth-keet-bridge setup"
}
finally {
    if (Test-Path $Tmp) { Remove-Item -Recurse -Force $Tmp }
}
