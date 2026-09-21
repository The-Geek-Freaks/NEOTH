[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Executable,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedSourceSha,

    [string]$WorkRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Acceptance {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "Portable diff-impact acceptance failed: $Message"
}

function Get-TextSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    return ([System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Text))
    )).Replace('-', '').ToLowerInvariant()
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [string]$NeothHome = '',
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$ExpectFailure
    )

    $process = $null
    try {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $FileName
        $startInfo.WorkingDirectory = $WorkingDirectory
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        if (-not [string]::IsNullOrWhiteSpace($NeothHome)) {
            $startInfo.Environment['NEOTH_HOME'] = $NeothHome
        }
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
            Stdout = $stdout
            Stderr = $stderr
            StdoutSha256 = Get-TextSha256 -Text $stdout
            StderrSha256 = Get-TextSha256 -Text $stderr
        }
    } finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Invoke-NeothJson {
    param(
        [Parameter(Mandatory = $true)][string]$Neoth,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$NeothHome,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $result = Invoke-BoundedProcess -FileName $Neoth -Arguments $Arguments -WorkingDirectory $WorkingDirectory -NeothHome $NeothHome -Label $Label
    try {
        $result | Add-Member -NotePropertyName Json -NotePropertyValue ($result.Stdout | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Stop-Acceptance "$Label did not emit one JSON document: $($result.Stdout)"
    }
    return $result
}

function Assert-Generation {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Label)

    if ($null -eq $Value -or $Value.index_generation -le 0 -or
        $Value.graph_generation -le 0 -or $Value.index_generation -ne $Value.graph_generation) {
        Stop-Acceptance "$Label did not contain equal positive index/graph generations"
    }
}

function Normalize-Root {
    param([Parameter(Mandatory = $true)][string]$Root)

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\', '/'))
        # Rust std::fs::canonicalize may render a normal Windows directory with
        # the verbatim namespace prefix. It denotes the same exact root as the
        # ordinary Win32 spelling passed to the fixture, so remove only that
        # presentation prefix before retaining the case-exact root comparison.
        if ($fullPath.StartsWith('\\?\UNC\', [System.StringComparison]::OrdinalIgnoreCase)) {
            return '\\' + $fullPath.Substring(8)
        }
        if ($fullPath.StartsWith('\\?\', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $fullPath.Substring(4)
        }
        return $fullPath
    } catch {
        Stop-Acceptance "result root is not a valid absolute path: $Root"
    }
}

function Assert-Root {
    param(
        [Parameter(Mandatory = $true)][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ((Normalize-Root -Root $Actual) -cne (Normalize-Root -Root $Expected)) {
        Stop-Acceptance "$Label root was not bound to the requested fixture root"
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
$neoth = (Resolve-Path -LiteralPath $Executable).Path
if ((Get-Item -LiteralPath $neoth).PSIsContainer -or (Split-Path -Leaf $neoth) -cne 'neoth.exe') {
    Stop-Acceptance 'Executable must be the extracted portable neoth.exe'
}
$payloadRoot = Split-Path -Parent $neoth
$provenancePath = Join-Path $payloadRoot 'PREVIEW-PROVENANCE.json'
$inventoryPath = Join-Path $payloadRoot 'SHA256SUMS.json'
if (-not (Test-Path -LiteralPath $provenancePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) {
    Stop-Acceptance 'extracted neoth.exe must have sibling PREVIEW-PROVENANCE.json and SHA256SUMS.json'
}
$provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json -ErrorAction Stop
if ($provenance.schema_version -ne 1 -or
    $provenance.artifact_kind -ne 'unreleased_windows_x64_preview' -or
    $provenance.source_sha -cne $ExpectedSourceSha -or
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
    Stop-Acceptance 'sibling preview provenance is not the expected unsigned portable artifact'
}
$inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json -ErrorAction Stop
if ($inventory.schema_version -ne 1 -or $inventory.source_sha -cne $ExpectedSourceSha) {
    Stop-Acceptance 'sibling inventory source SHA does not match the requested commit'
}
$neothInventory = @($inventory.files | Where-Object { $_.path -ceq 'neoth.exe' })
if ($neothInventory.Count -ne 1 -or $neothInventory[0].sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [int64]$neothInventory[0].bytes -ne (Get-Item -LiteralPath $neoth).Length) {
    Stop-Acceptance 'sibling inventory does not contain one valid neoth.exe record'
}
$binaryHash = (Get-FileHash -LiteralPath $neoth -Algorithm SHA256).Hash.ToLowerInvariant()
if ($binaryHash -cne $neothInventory[0].sha256) {
    Stop-Acceptance 'sibling inventory SHA-256 does not bind the supplied neoth.exe bytes'
}

$scriptRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
if ([string]::IsNullOrWhiteSpace($WorkRoot)) {
    $WorkRoot = Join-Path $scriptRoot "runs/portable diff impact $($ExpectedSourceSha.Substring(0, 12))"
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
$repo = Join-Path $workRootPath 'CRG fixture repo with spaces'
$src = Join-Path $repo 'src'
$tests = Join-Path $repo 'tests'
$neothHome = Join-Path $workRootPath 'private NEOTH_HOME'
New-Item -ItemType Directory -Path $src, $tests, $neothHome | Out-Null

$libraryPath = Join-Path $src 'lib.rs'
$testPath = Join-Path $tests 'diff_impact_test.rs'
@'
pub fn changed_symbol() -> &'static str {
    "before"
}

pub fn caller_symbol() -> &'static str {
    changed_symbol()
}
'@ | Set-Content -LiteralPath $libraryPath -Encoding utf8
@'
#[test]
fn test_caller_symbol() {
    assert_eq!(caller_symbol(), "after");
}
'@ | Set-Content -LiteralPath $testPath -Encoding utf8

$results = [System.Collections.Generic.List[object]]::new()
$gitWorking = $repo
$gitInit = Invoke-BoundedProcess -FileName 'git' -Arguments @('init') -WorkingDirectory $gitWorking -Label 'fixture git init'
Add-Result -Results $results -Name 'fixture_git_init' -Process $gitInit
foreach ($gitConfig in @(
    @('config', 'user.email', 'portable-preview@example.invalid'),
    @('config', 'user.name', 'Portable Preview'),
    @('config', 'commit.gpgsign', 'false')
)) {
    $configured = Invoke-BoundedProcess -FileName 'git' -Arguments $gitConfig -WorkingDirectory $gitWorking -Label 'fixture git config'
    Add-Result -Results $results -Name "fixture_git_$($gitConfig[1])" -Process $configured
}
$gitAdd = Invoke-BoundedProcess -FileName 'git' -Arguments @('add', '--all') -WorkingDirectory $gitWorking -Label 'fixture git add'
Add-Result -Results $results -Name 'fixture_git_add' -Process $gitAdd
$gitCommit = Invoke-BoundedProcess -FileName 'git' -Arguments @('commit', '--no-gpg-sign', '-m', 'baseline') -WorkingDirectory $gitWorking -Label 'fixture git baseline commit'
Add-Result -Results $results -Name 'fixture_git_commit' -Process $gitCommit

$source = Get-Content -LiteralPath $libraryPath -Raw
if (-not $source.Contains('"before"')) { Stop-Acceptance 'fixture baseline is missing the exact changed declaration body' }
$source.Replace('"before"', '"after"') | Set-Content -LiteralPath $libraryPath -Encoding utf8

$refresh = Invoke-NeothJson -Neoth $neoth -Arguments @('--output', 'json', 'code-map', 'refresh', $repo) -WorkingDirectory $workRootPath -NeothHome $neothHome -Label 'fresh fixture code-map refresh'
if ($refresh.Json.outcome -ne 'indexed_first_time') { Stop-Acceptance 'fixture refresh was not indexed_first_time' }
Assert-Generation -Value $refresh.Json.published_generation -Label 'fixture refresh'
Assert-Root -Actual $refresh.Json.published_generation.root -Expected $repo -Label 'fixture refresh'
Add-Result -Results $results -Name 'code_map_refresh' -Process $refresh

$impact = Invoke-NeothJson -Neoth $neoth -Arguments @('--output', 'json', 'code-map', 'diff-impact', '--root', $repo, '--direction', 'callers', '--max-depth', '1', '--max-nodes', '16') -WorkingDirectory $workRootPath -NeothHome $neothHome -Label 'fresh exact diff impact'
Assert-Generation -Value $impact.Json -Label 'diff impact'
Assert-Root -Actual $impact.Json.root -Expected $repo -Label 'diff impact'
if ($impact.Json.stale -or $impact.Json.direction -ne 'callers') { Stop-Acceptance 'diff impact was stale or used an unexpected direction' }
if ([int64]$impact.Json.index_generation -ne [int64]$refresh.Json.published_generation.index_generation) {
    Stop-Acceptance 'diff impact generation did not bind to the refreshed root generation'
}
$exactSeeds = @($impact.Json.requested_seeds | Where-Object {
    $_.file -ceq 'src/lib.rs' -and
    $null -ne $_.PSObject.Properties['symbol'] -and
    $_.symbol -ceq 'changed_symbol'
})
if ($exactSeeds.Count -ne 1) { Stop-Acceptance 'one-hunk diff did not produce the exact changed_symbol seed' }
$impactDiagnostic = [ordered]@{
    kind = 'portable_diff_impact_identity_diagnostic'
    requested_seed_count = @($impact.Json.requested_seeds).Count
    impacted_node_count = @($impact.Json.impacted_nodes).Count
    traversed_edge_count = @($impact.Json.traversed_edges).Count
    unresolved_edge_count = @($impact.Json.unresolved_edges).Count
    truncated = [bool]$impact.Json.truncated
    budget_truncated = [bool]$impact.Json.budget_truncated
    evidence_truncated = [bool]$impact.Json.evidence_truncated
    impacted_identities = @($impact.Json.impacted_nodes | Select-Object -First 16 | ForEach-Object {
        [ordered]@{ file = $_.file; symbol = $_.symbol; line = $_.line; kind = $_.kind }
    })
    caller_edge_present = @($impact.Json.traversed_edges | Where-Object {
        $_.caller.file -ceq 'src/lib.rs' -and $_.caller.symbol -ceq 'caller_symbol' -and
        $_.callee.file -ceq 'src/lib.rs' -and $_.callee.symbol -ceq 'changed_symbol'
    }).Count -gt 0
    caller_edge_unresolved = @($impact.Json.unresolved_edges | Where-Object {
        $_.from_file -ceq 'src/lib.rs' -and $_.from_symbol -ceq 'caller_symbol' -and $_.to_name -ceq 'changed_symbol'
    }).Count -gt 0
}
$impactDiagnostic | ConvertTo-Json -Depth 5 -Compress | Write-Output
$callerNodes = @($impact.Json.impacted_nodes | Where-Object { $_.file -ceq 'src/lib.rs' -and $_.symbol -ceq 'caller_symbol' })
if ($callerNodes.Count -lt 1) { Stop-Acceptance 'callers impact did not retain caller_symbol as a concrete affected declaration' }
Add-Result -Results $results -Name 'diff_impact_exact_symbol_and_caller' -Process $impact

$gaps = Invoke-NeothJson -Neoth $neoth -Arguments @('--output', 'json', 'code-map', 'diff-test-gaps', '--root', $repo, '--direction', 'callers', '--max-depth', '1', '--max-nodes', '16') -WorkingDirectory $workRootPath -NeothHome $neothHome -Label 'fresh diff test gaps'
Assert-Generation -Value $gaps.Json -Label 'diff test gaps'
Assert-Root -Actual $gaps.Json.root -Expected $repo -Label 'diff test gaps'
if ($gaps.Json.outcome -ne 'complete' -or $gaps.Json.input.stale -or $gaps.Json.impact_partial -or
    -not $gaps.Json.no_observed_test_is_not_absence -or
    [int64]$gaps.Json.index_generation -ne [int64]$impact.Json.index_generation -or
    [int64]$gaps.Json.input.source_index_generation -ne [int64]$gaps.Json.index_generation -or
    [int64]$gaps.Json.input.source_graph_generation -ne [int64]$gaps.Json.graph_generation) {
    Stop-Acceptance 'diff test-gap receipt was not a fresh, complete generation-bound observation'
}
$callerGap = @($gaps.Json.per_node | Where-Object {
    $_.impact_node.file -ceq 'src/lib.rs' -and $_.impact_node.symbol -ceq 'caller_symbol' -and $_.identity -eq 'exact'
})
if ($callerGap.Count -ne 1 -or $null -eq $callerGap[0].coverage) {
    Stop-Acceptance 'diff test-gap receipt did not retain exact caller coverage evidence'
}
$observed = @($callerGap[0].coverage.observed_tests | Where-Object {
    $_.test.file -ceq 'tests/diff_impact_test.rs' -and $_.test.symbol -ceq 'test_caller_symbol' -and
    $_.target.file -ceq 'src/lib.rs' -and $_.target.symbol -ceq 'caller_symbol' -and
    $_.confidence_tier -eq 'resolved' -and $_.provenance -eq 'framework_and_conventional_path'
})
if ($observed.Count -ne 1 -or $callerGap[0].coverage.uncertainty.no_observed_test) {
    Stop-Acceptance 'fixture TestedBy evidence was not one supported resolved observation'
}
Add-Result -Results $results -Name 'diff_test_gaps_tested_by_observation' -Process $gaps

Add-Content -LiteralPath $libraryPath -Value "`n// stale mutation after refresh" -Encoding utf8
$stale = Invoke-BoundedProcess -FileName $neoth -Arguments @('--output', 'json', 'code-map', 'diff-impact', '--root', $repo, '--direction', 'callers', '--max-depth', '1', '--max-nodes', '16') -WorkingDirectory $workRootPath -NeothHome $neothHome -Label 'stale diff impact rejection' -ExpectFailure
if ((($stale.Stdout + "`n" + $stale.Stderr) -notmatch '(?i)is stale')) {
    Stop-Acceptance 'stale source input did not visibly fail with the stale-index diagnostic'
}
Add-Result -Results $results -Name 'diff_impact_stale_input_rejected' -Process $stale

$result = [ordered]@{
    schema_version = 1
    artifact_kind = 'PORTABLE_NOT_INSTALLED'
    source_sha = $ExpectedSourceSha
    binary_sha256 = $binaryHash
    build_profile = $provenance.build_profile
    optimization_profile = $provenance.optimization_profile
    cargo_profile_release_opt_level = $provenance.cargo_profile_release_opt_level
    cargo_profile_release_debug = $provenance.cargo_profile_release_debug
    cargo_profile_release_lto = $provenance.cargo_profile_release_lto
    cargo_profile_release_codegen_units = $provenance.cargo_profile_release_codegen_units
    toolchain = $provenance.toolchain
    crt_mode = $provenance.crt_mode
    artifact_toolchain = if ($null -ne $provenance.PSObject.Properties['toolchain']) { $provenance.toolchain } else { $null }
    work_root = $workRootPath
    check_count = $results.Count
    results = @($results)
}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $workRootPath 'portable-diff-impact-result.json') -Encoding utf8
$result | ConvertTo-Json -Depth 8
