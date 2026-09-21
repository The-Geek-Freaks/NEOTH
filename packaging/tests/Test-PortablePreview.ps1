[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Archive,

    [Parameter(Mandatory = $true)]
    [string]$ArchiveSha256,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedSourceSha,

    [string]$WorkRoot = '',

    [switch]$GuiRuntimeProbe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Acceptance {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "Portable preview acceptance failed: $Message"
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][System.IO.Stream]$Stream)

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($hasher.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Read-ZipUtf8 {
    param(
        [Parameter(Mandatory = $true)][System.IO.Compression.ZipArchive]$Zip,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $entry = $Zip.GetEntry($Name)
    if ($null -eq $entry) {
        Stop-Acceptance "archive is missing $Name"
    }
    $stream = $entry.Open()
    $reader = [System.IO.StreamReader]::new($stream, [System.Text.UTF8Encoding]::new($false), $true)
    try {
        return $reader.ReadToEnd()
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Assert-ArchiveSafetyAndInventory {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha
    )

    $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $prefix = "neoth-unreleased-preview-windows-x64-$ExpectedSha/"
        $files = @{}
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($name) -or
                $name.StartsWith('/') -or
                $name.Contains('../') -or
                $name.Contains('/./') -or
                -not $name.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                Stop-Acceptance "unsafe or unexpected archive member: $name"
            }
            if ($name.EndsWith('/')) {
                continue
            }
            if ($files.ContainsKey($name)) {
                Stop-Acceptance "duplicate archive member: $name"
            }
            $files[$name] = $entry
        }

        $provenance = Read-ZipUtf8 -Zip $zip -Name "$prefix`PREVIEW-PROVENANCE.json" |
            ConvertFrom-Json -ErrorAction Stop
        if ($provenance.schema_version -ne 1 -or
            $provenance.artifact_kind -ne 'unreleased_windows_x64_preview' -or
            $provenance.source_sha -cne $ExpectedSha -or
            $provenance.build_profile -ne 'release' -or
            $provenance.optimization_profile -ne 'preview-fast-v1' -or
            $provenance.cargo_profile_release_opt_level -ne '1' -or
            $provenance.cargo_profile_release_debug -ne '0' -or
            $provenance.cargo_profile_release_lto -ne 'false' -or
            $provenance.cargo_profile_release_codegen_units -ne '16' -or
            $provenance.toolchain -ne '1.93.0' -or
            $provenance.crt_mode -ne 'static-msvc-v1' -or
            $provenance.signing -ne 'none' -or
            $provenance.github_release -ne 'not_created' -or
            $provenance.installer -ne 'not_created' -or
            $provenance.installed_acceptance -ne 'not_run') {
            Stop-Acceptance 'preview provenance is not the expected unsigned portable artifact'
        }

        $inventory = Read-ZipUtf8 -Zip $zip -Name "$prefix`SHA256SUMS.json" |
            ConvertFrom-Json -ErrorAction Stop
        if ($inventory.schema_version -ne 1 -or $inventory.source_sha -cne $ExpectedSha) {
            Stop-Acceptance 'inventory source SHA does not match the requested commit'
        }
        if (@($inventory.excludes).Count -ne 1 -or $inventory.excludes[0] -cne 'SHA256SUMS.json') {
            Stop-Acceptance 'inventory exclusions are not the expected self-exclusion'
        }

        $expectedFiles = @{}
        foreach ($file in @($inventory.files)) {
            if ([string]::IsNullOrWhiteSpace([string]$file.path) -or
                [string]::IsNullOrWhiteSpace([string]$file.sha256) -or
                $file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $file.path.Contains('/') -or
                $file.path.Contains('\') -or
                $file.path -eq 'SHA256SUMS.json' -or
                $expectedFiles.ContainsKey($file.path)) {
                Stop-Acceptance 'inventory has an unsafe, duplicate, or malformed entry'
            }
            $member = "$prefix$($file.path)"
            if (-not $files.ContainsKey($member)) {
                Stop-Acceptance "inventory member is absent from archive: $($file.path)"
            }
            if ([int64]$file.bytes -ne $files[$member].Length) {
                Stop-Acceptance "inventory byte count differs for $($file.path)"
            }
            $stream = $files[$member].Open()
            try {
                $actual = Get-Sha256Hex -Stream $stream
            } finally {
                $stream.Dispose()
            }
            if ($actual -cne $file.sha256) {
                Stop-Acceptance "inventory SHA-256 differs for $($file.path)"
            }
            $expectedFiles[$member] = $true
        }
        $expectedFiles["$prefix`SHA256SUMS.json"] = $true
        if ($expectedFiles.Count -ne $files.Count -or
            @($files.Keys | Where-Object { -not $expectedFiles.ContainsKey($_) }).Count -ne 0) {
            Stop-Acceptance 'archive has a member absent from the committed inventory'
        }

        foreach ($required in @(
            'neoth.exe', 'neothd.exe', 'neothd-gui.exe', 'neoth-migrate.exe',
            'neoth-relay.exe', 'neoth-keet-bridge.exe', 'PREVIEW-PROVENANCE.json',
            'UNRELEASED-PREVIEW.md', 'SHA256SUMS.json'
        )) {
            if (-not $files.ContainsKey("$prefix$required")) {
                Stop-Acceptance "required portable preview member missing: $required"
            }
        }
        return [pscustomobject]@{ Prefix = $prefix; Provenance = $provenance; Inventory = $inventory }
    } finally {
        $zip.Dispose()
    }
}

function Invoke-PortableProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$NeothHome,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$ExpectFailure
    )

    $process = $null
    try {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $Executable
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.Environment['NEOTH_HOME'] = $NeothHome
        foreach ($argument in $Arguments) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            Stop-Acceptance "$Label did not start"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) {
            $process.Kill($true)
            $process.WaitForExit()
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            Stop-Acceptance "$Label timed out after 120 seconds: $stdout $stderr"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($ExpectFailure) {
            if ($process.ExitCode -eq 0) {
                Stop-Acceptance "$Label unexpectedly succeeded"
            }
        } elseif ($process.ExitCode -ne 0) {
            Stop-Acceptance "$Label exited $($process.ExitCode): $stderr"
        }
        return [pscustomobject]@{
            Label = $Label
            ExitCode = $process.ExitCode
            StdoutSha256 = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($stdout)))).Replace('-', '').ToLowerInvariant()
            StderrSha256 = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($stderr)))).Replace('-', '').ToLowerInvariant()
            Stdout = $stdout
        }
    } finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Invoke-PortableJson {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$NeothHome,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$ExpectFailure
    )

    $result = Invoke-PortableProcess @PSBoundParameters
    try {
        $result | Add-Member -NotePropertyName Json -NotePropertyValue ($result.Stdout | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Stop-Acceptance "$Label did not emit one JSON document: $($result.Stdout)"
    }
    return $result
}

function Assert-Generation {
    param([Parameter(Mandatory = $true)]$Generation, [Parameter(Mandatory = $true)][string]$Label)

    if ($null -eq $Generation -or $Generation.index_generation -le 0 -or
        $Generation.graph_generation -le 0 -or
        $Generation.index_generation -ne $Generation.graph_generation) {
        Stop-Acceptance "$Label did not contain equal positive index/graph generations"
    }
}

function Add-Result {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Process
    )
    $Results.Add([ordered]@{
        check = $Name
        exit_code = $Process.ExitCode
        stdout_sha256 = $Process.StdoutSha256
        stderr_sha256 = $Process.StderrSha256
    })
}

if ($ExpectedSourceSha -cnotmatch '^[0-9a-f]{40}$') {
    Stop-Acceptance 'ExpectedSourceSha must be the lowercase 40-character source commit SHA'
}
$archivePath = (Resolve-Path -LiteralPath $Archive).Path
$sidecarPath = (Resolve-Path -LiteralPath $ArchiveSha256).Path
$sidecar = @(Get-Content -LiteralPath $sidecarPath)
if ($sidecar.Count -ne 1 -or $sidecar[0] -cnotmatch '^([0-9a-f]{64})  ([^\\/]+)$') {
    Stop-Acceptance 'archive SHA-256 sidecar must contain one lowercase bound hash line'
}
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($archiveHash -cne $Matches[1] -or $Matches[2] -cne (Split-Path -Leaf $archivePath)) {
    Stop-Acceptance 'archive SHA-256 sidecar does not bind the supplied ZIP bytes and name'
}
$inspection = Assert-ArchiveSafetyAndInventory -ArchivePath $archivePath -ExpectedSha $ExpectedSourceSha

$scriptRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
if ([string]::IsNullOrWhiteSpace($WorkRoot)) {
    $WorkRoot = Join-Path $scriptRoot "runs/portable acceptance $($ExpectedSourceSha.Substring(0, 12))"
}
$workRootPath = [System.IO.Path]::GetFullPath($WorkRoot)
$allowedPrefix = $scriptRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
$runnerTempPrefix = ''
if ($env:GITHUB_ACTIONS -eq 'true' -and -not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    $runnerTempPrefix = [System.IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
}
$withinAcceptanceFolder = $workRootPath.StartsWith($allowedPrefix, [System.StringComparison]::OrdinalIgnoreCase)
$withinGitHubRunnerTemp = $runnerTempPrefix.Length -gt 0 -and $workRootPath.StartsWith($runnerTempPrefix, [System.StringComparison]::OrdinalIgnoreCase)
if ((-not $withinAcceptanceFolder -and -not $withinGitHubRunnerTemp) -or
    -not $workRootPath.Contains(' ')) {
    Stop-Acceptance 'WorkRoot must be a new, space-containing child of this acceptance folder or GitHub RUNNER_TEMP'
}
if (Test-Path -LiteralPath $workRootPath) {
    Stop-Acceptance "refusing to overwrite or delete preexisting work root: $workRootPath"
}
New-Item -ItemType Directory -Path $workRootPath | Out-Null
[System.IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $workRootPath)
$payloadRoot = Join-Path $workRootPath $inspection.Prefix.TrimEnd('/')
$neoth = Join-Path $payloadRoot 'neoth.exe'
$binaryHash = (Get-FileHash -LiteralPath $neoth -Algorithm SHA256).Hash.ToLowerInvariant()
$neothHome = Join-Path $workRootPath 'private NEOTH_HOME'
$repoA = Join-Path $workRootPath 'repo A with spaces'
$repoB = Join-Path $workRootPath 'repo B with spaces'
$database = Join-Path $neothHome 'code_map.db'
New-Item -ItemType Directory -Path $neothHome, $repoA, $repoB | Out-Null
Set-Content -LiteralPath (Join-Path $repoA 'fixture.rs') -Value 'fn stable() {}' -Encoding utf8
Set-Content -LiteralPath (Join-Path $repoB 'other.rs') -Value 'fn isolated() {}' -Encoding utf8

$results = [System.Collections.Generic.List[object]]::new()
Add-Result -Results $results -Name 'cli_version' -Process (Invoke-PortableProcess -Executable $neoth -Arguments @('--version') -NeothHome $neothHome -Label 'portable CLI version')
Add-Result -Results $results -Name 'cli_help' -Process (Invoke-PortableProcess -Executable $neoth -Arguments @('--help') -NeothHome $neothHome -Label 'portable CLI help')

$absent = Invoke-PortableJson -Executable $neoth -Arguments @('--output', 'json', 'code-map', 'status', $repoA) -NeothHome $neothHome -Label 'portable code-map absent status'
if ($absent.Json.lifecycle.state.kind -ne 'absent' -or (Test-Path -LiteralPath $database)) { Stop-Acceptance 'absent status was not read-only absent truth' }
Add-Result -Results $results -Name 'code_map_absent' -Process $absent

$first = Invoke-PortableJson -Executable $neoth -Arguments @('--output', 'json', 'code-map', 'refresh', $repoA) -NeothHome $neothHome -Label 'portable code-map first refresh'
if ($first.Json.outcome -ne 'indexed_first_time') { Stop-Acceptance 'first refresh was not indexed_first_time' }
Assert-Generation -Generation $first.Json.published_generation -Label 'first refresh'
$firstGeneration = [int64]$first.Json.published_generation.index_generation
Add-Result -Results $results -Name 'code_map_first_refresh' -Process $first

$fresh = Invoke-PortableJson -Executable $neoth -Arguments @('--output', 'json', 'code-map', 'status', $repoA) -NeothHome $neothHome -Label 'portable code-map fresh status'
if ($fresh.Json.lifecycle.state.kind -ne 'fresh' -or $fresh.Json.lifecycle.state.snapshot.index_generation -ne $firstGeneration) { Stop-Acceptance 'fresh status did not retain the published generation' }
Assert-Generation -Generation $fresh.Json.lifecycle.state.snapshot -Label 'fresh status'
Add-Result -Results $results -Name 'code_map_fresh' -Process $fresh

Add-Content -LiteralPath (Join-Path $repoA 'fixture.rs') -Value "`nfn changed() {}" -Encoding utf8
$stale = Invoke-PortableJson -Executable $neoth -Arguments @('--output', 'json', 'code-map', 'status', $repoA) -NeothHome $neothHome -Label 'portable code-map stale status'
if ($stale.Json.lifecycle.state.kind -ne 'stale') { Stop-Acceptance 'source edit did not become stale' }
Add-Result -Results $results -Name 'code_map_stale' -Process $stale

$refreshed = Invoke-PortableJson -Executable $neoth -Arguments @('--output', 'json', 'code-map', 'refresh', $repoA) -NeothHome $neothHome -Label 'portable code-map stale refresh'
if ($refreshed.Json.outcome -ne 'refreshed_stale') { Stop-Acceptance 'stale refresh did not report refreshed_stale' }
Assert-Generation -Generation $refreshed.Json.published_generation -Label 'stale refresh'
Add-Result -Results $results -Name 'code_map_stale_refresh' -Process $refreshed

Set-Content -LiteralPath $database -Value 'not a sqlite database' -Encoding ascii
$corrupt = Invoke-PortableJson -Executable $neoth -Arguments @('--output', 'json', 'code-map', 'status', $repoA) -NeothHome $neothHome -Label 'portable code-map corrupt status'
if ($corrupt.Json.lifecycle.state.kind -ne 'corrupt' -or [string]::IsNullOrWhiteSpace([string]$corrupt.Json.lifecycle.state.diagnostic)) { Stop-Acceptance 'corrupt database was not visibly corrupt' }
$corruptHash = (Get-FileHash -LiteralPath $database -Algorithm SHA256).Hash
Add-Result -Results $results -Name 'code_map_corrupt' -Process $corrupt

$normal = Invoke-PortableJson -Executable $neoth -Arguments @('--output', 'json', 'code-map', 'refresh', $repoA) -NeothHome $neothHome -Label 'portable normal corrupt refresh' -ExpectFailure
$normalFailureDiagnostic = $normal.Json.PSObject.Properties['failure_diagnostic']
if ($normal.Json.outcome -ne 'corrupt_repair_required' -or $null -ne $normalFailureDiagnostic -or (Get-FileHash -LiteralPath $database -Algorithm SHA256).Hash -cne $corruptHash) { Stop-Acceptance 'normal corrupt refresh did not preserve corrupt-repair provenance or its no-failure receipt contract' }
Add-Result -Results $results -Name 'code_map_corrupt_no_implicit_repair' -Process $normal

$repaired = Invoke-PortableJson -Executable $neoth -Arguments @('--output', 'json', 'code-map', 'refresh', $repoA, '--repair-corrupt') -NeothHome $neothHome -Label 'portable explicit corrupt repair'
Assert-Generation -Generation $repaired.Json.published_generation -Label 'explicit corrupt repair'
Add-Result -Results $results -Name 'code_map_explicit_repair' -Process $repaired

$other = Invoke-PortableJson -Executable $neoth -Arguments @('--output', 'json', 'code-map', 'status', $repoB) -NeothHome $neothHome -Label 'portable second-root status'
if ($other.Json.lifecycle.state.kind -ne 'unmapped') { Stop-Acceptance 'second root was not unmapped' }
Add-Result -Results $results -Name 'code_map_second_root_unmapped' -Process $other

if ($GuiRuntimeProbe) {
    $guiHome = Join-Path $workRootPath 'private GUI probe home'
    $gui = Join-Path $payloadRoot 'neothd-gui.exe'
    $probe = Invoke-PortableProcess -Executable $gui -Arguments @('--runtime-probe') -NeothHome $guiHome -Label 'portable GUI runtime probe'
    if (Test-Path -LiteralPath $guiHome) { Stop-Acceptance 'GUI runtime probe mutated its process-scoped NEOTH_HOME' }
    Add-Result -Results $results -Name 'gui_runtime_probe' -Process $probe
}

$result = [ordered]@{
    schema_version = 1
    artifact_kind = 'PORTABLE_NOT_INSTALLED'
    source_sha = $ExpectedSourceSha
    archive_sha256 = $archiveHash
    binary_sha256 = $binaryHash
    build_profile = $inspection.Provenance.build_profile
    optimization_profile = $inspection.Provenance.optimization_profile
    cargo_profile_release_opt_level = $inspection.Provenance.cargo_profile_release_opt_level
    cargo_profile_release_debug = $inspection.Provenance.cargo_profile_release_debug
    cargo_profile_release_lto = $inspection.Provenance.cargo_profile_release_lto
    cargo_profile_release_codegen_units = $inspection.Provenance.cargo_profile_release_codegen_units
    toolchain = $inspection.Provenance.toolchain
    crt_mode = $inspection.Provenance.crt_mode
    artifact_toolchain = if ($null -ne $inspection.Provenance.PSObject.Properties['toolchain']) { $inspection.Provenance.toolchain } else { $null }
    work_root = $workRootPath
    check_count = $results.Count
    results = @($results)
}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $workRootPath 'portable-acceptance-result.json') -Encoding utf8
$result | ConvertTo-Json -Depth 6
