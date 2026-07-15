[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Installer,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$PreviousInstaller = '',

    [switch]$RequireSignature
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'pe-inspection.ps1')

$uninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\TheGeekFreaks.NEOTH.BF6060F4-B75D-4E9A-BEB6-7EC8CB94A3C1_is1'
$installerStateKey = 'Software\The Geek Freaks\NEOTH\Installer'
$requiredExecutables = @(
    'neoth.exe'
    'neothd.exe'
    'neothd-gui.exe'
    'neoth-migrate.exe'
    'neoth-relay.exe'
    'neoth-keet-bridge.exe'
)
$requiredSupportFiles = @(
    'freedom.yaml.example'
    'import-manifest.example.yaml'
    'README.md'
    'LICENSE-MIT'
    'LICENSE-APACHE'
    'THIRD_PARTY_LICENSES'
)

function Stop-Smoke {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NEOTH Windows installer smoke failed: $Message"
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

function Assert-ValidSignature {
    param([Parameter(Mandatory = $true)][string]$Path)

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        Stop-Smoke "$(Split-Path -Leaf $Path) signature is $($signature.Status)"
    }
}

function Get-PathValue {
    param([Parameter(Mandatory = $true)][ValidateSet('User', 'Machine')][string]$Scope)

    $value = [Environment]::GetEnvironmentVariable('Path', $Scope)
    if ($null -eq $value) { return '' }
    return $value
}

function Test-PathEntry {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('User', 'Machine')][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Expected
    )

    $normalizedExpected = $Expected.Trim('"').TrimEnd('\')
    return @(
        (Get-PathValue -Scope $Scope) -split ';' |
            Where-Object { $_.Trim().Trim('"').TrimEnd('\') -ieq $normalizedExpected }
    ).Count
}

function Add-TestPathEntry {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('User', 'Machine')][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Entry
    )

    if ((Test-PathEntry -Scope $Scope -Expected $Entry) -ne 0) {
        Stop-Smoke "test PATH entry already exists in $Scope scope: $Entry"
    }
    $value = Get-PathValue -Scope $Scope
    if ($value -ne '' -and -not $value.EndsWith(';', [System.StringComparison]::Ordinal)) {
        $value += ';'
    }
    [Environment]::SetEnvironmentVariable('Path', $value + $Entry, $Scope)
}

function Remove-TestPathEntry {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('User', 'Machine')][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Entry
    )

    $normalizedEntry = $Entry.Trim('"').TrimEnd('\')
    $updated = @(
        (Get-PathValue -Scope $Scope) -split ';' |
            Where-Object { $_.Trim().Trim('"').TrimEnd('\') -ine $normalizedEntry }
    ) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $updated, $Scope)
}

function Get-RegistryBase {
    param([Parameter(Mandatory = $true)][ValidateSet('User', 'Machine')][string]$Scope)

    if ($Scope -eq 'User') { return 'Registry::HKEY_CURRENT_USER' }
    return 'Registry::HKEY_LOCAL_MACHINE'
}

function Set-TestInstallRegistration {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('User', 'Machine')][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Uninstaller
    )

    $key = Join-Path (Get-RegistryBase -Scope $Scope) $uninstallKey
    if (Test-Path -LiteralPath $key) {
        Stop-Smoke "test cannot replace an existing $Scope uninstall registration"
    }
    New-Item -Path $key -Force | Out-Null
    try {
        foreach ($property in @{
            InstallLocation = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
            DisplayVersion = $Version
            UninstallString = '"' + [IO.Path]::GetFullPath($Uninstaller) + '"'
            DisplayName = "NEOTH $Version"
            Publisher = 'The Geek Freaks'
        }.GetEnumerator()) {
            New-ItemProperty `
                -LiteralPath $key `
                -Name $property.Key `
                -Value $property.Value `
                -PropertyType String `
                -Force | Out-Null
        }
    } catch {
        Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Remove-TestInstallRegistration {
    param([Parameter(Mandatory = $true)][ValidateSet('User', 'Machine')][string]$Scope)

    $key = Join-Path (Get-RegistryBase -Scope $Scope) $uninstallKey
    Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
}

function New-FakeNeothProbe {
    param([Parameter(Mandatory = $true)][string]$Path)

    $compiler = @(
        Get-ChildItem `
            -LiteralPath (Join-Path $env:WINDIR 'Microsoft.NET') `
            -Filter csc.exe `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\v4\.0\.30319\\csc\.exe$' } |
            Sort-Object FullName -Descending
    ) | Select-Object -First 1
    if ($null -eq $compiler) {
        Stop-Smoke 'could not find the Windows .NET Framework C# compiler for the fake recovery probe'
    }
    $sourcePath = [IO.Path]::ChangeExtension($Path, '.cs')
    [IO.File]::WriteAllText($sourcePath, @'
using System;
using System.IO;
using System.Security.Principal;

public static class Program
{
    public static int Main()
    {
        string sentinel = Environment.GetEnvironmentVariable("NEOTH_FAKE_EXEC_SENTINEL");
        if (String.IsNullOrEmpty(sentinel)) return 71;
        bool elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);
        File.WriteAllText(sentinel, elevated ? "elevated" : "original-user");
        return 72;
    }
}
'@, [Text.UTF8Encoding]::new($false))
    try {
        & $compiler.FullName /nologo /target:exe "/out:$Path" $sourcePath
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            Stop-Smoke 'failed to build the fake recovery neoth.exe probe'
        }
    } finally {
        Remove-Item -LiteralPath $sourcePath -Force -ErrorAction SilentlyContinue
    }
}

function Get-OwnedPathEntry {
    param([Parameter(Mandatory = $true)][ValidateSet('User', 'Machine')][string]$Scope)

    $key = Join-Path (Get-RegistryBase -Scope $Scope) $installerStateKey
    if (-not (Test-Path -LiteralPath $key)) { return $null }
    $item = Get-ItemProperty -LiteralPath $key
    $owned = $item.PSObject.Properties['PathEntryOwned']
    $path = $item.PSObject.Properties['OwnedPathEntry']
    if ($null -eq $owned -or $owned.Value -ne 1 -or $null -eq $path) { return $null }
    return [string]$path.Value
}

function Invoke-Install {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('User', 'Machine')][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Directory,
        [string]$InstallerFile = $installerPath,
        [string[]]$AdditionalArguments = @(),
        [switch]$ExpectFailure
    )

    $scopeArgument = if ($Scope -eq 'User') { '/CURRENTUSER' } else { '/ALLUSERS' }
    $arguments = @(
        '/VERYSILENT'
        $scopeArgument
        '/SUPPRESSMSGBOXES'
        '/NORESTART'
        ('/DIR="' + $Directory + '"')
    )
    $arguments += $AdditionalArguments
    $process = Start-Process -FilePath $InstallerFile -ArgumentList $arguments -Wait -PassThru
    if ($ExpectFailure) {
        if ($process.ExitCode -eq 0) {
            Stop-Smoke "$Scope-scope negative install unexpectedly succeeded"
        }
        return
    }
    if ($process.ExitCode -ne 0) {
        Stop-Smoke "$Scope-scope install exited $($process.ExitCode)"
    }
}

function Invoke-Uninstall {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $uninstallers = @(Get-ChildItem -LiteralPath $Directory -Filter 'unins*.exe' -File -ErrorAction SilentlyContinue)
    if ($uninstallers.Count -ne 1) {
        Stop-Smoke "installed payload must have exactly one uninstaller in $Directory, found $($uninstallers.Count)"
    }
    if ($RequireSignature) {
        Assert-ValidSignature -Path $uninstallers[0].FullName
    }
    $process = Start-Process -FilePath $uninstallers[0].FullName -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'
    ) -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        Stop-Smoke "uninstaller in $Directory exited $($process.ExitCode)"
    }
    foreach ($name in @($requiredExecutables + $requiredSupportFiles)) {
        if (Test-Path -LiteralPath (Join-Path $Directory $name)) {
            Stop-Smoke "uninstaller in $Directory left $name behind"
        }
    }
    if (Test-Path -LiteralPath (Join-Path $Directory 'self-knowledge')) {
        Stop-Smoke "uninstaller in $Directory left self-knowledge behind"
    }
}

function Assert-Payload {
    param([Parameter(Mandatory = $true)][string]$Directory)

    foreach ($name in $requiredExecutables) {
        $path = Join-Path $Directory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Stop-Smoke "installed payload is missing $name"
        }
        Assert-PeStaticMsvcRuntime -Path $path | Out-Null
        if ($RequireSignature) {
            Assert-ValidSignature -Path $path
        }
    }
    foreach ($name in $requiredSupportFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $Directory $name) -PathType Leaf)) {
            Stop-Smoke "installed payload is missing $name"
        }
    }
    $selfKnowledgeManifest = Join-Path $Directory 'self-knowledge\manifest.json'
    if (-not (Test-Path -LiteralPath $selfKnowledgeManifest -PathType Leaf) -or
        (Get-Item -LiteralPath $selfKnowledgeManifest).Length -eq 0) {
        Stop-Smoke 'installed payload is missing self-knowledge/manifest.json'
    }
    $selfKnowledge = Get-Content -LiteralPath $selfKnowledgeManifest -Raw | ConvertFrom-Json
    if ($selfKnowledge.schema_version -ne 1 -or
        $selfKnowledge.product -cne 'NEOTH' -or
        $selfKnowledge.release_version -cne $Version -or
        $selfKnowledge.source_head -cnotmatch '^[0-9a-f]{40,64}$' -or
        $selfKnowledge.payload_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        Stop-Smoke 'installed self-knowledge manifest identity is invalid'
    }

    $publicVersion = (& (Join-Path $Directory 'neoth.exe') --version 2>&1 | Out-String).Trim()
    if ($publicVersion -notmatch "(^|\s)$([regex]::Escape($Version))($|\s)") {
        Stop-Smoke "neoth --version returned '$publicVersion'"
    }
    & (Join-Path $Directory 'neoth.exe') --output json self-knowledge verify `
        --snapshot (Join-Path $Directory 'self-knowledge') | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Stop-Smoke 'installed neoth.exe rejected its release self-knowledge snapshot'
    }
    & (Join-Path $Directory 'neoth.exe') --output json self-knowledge query NEOTH --limit 1 |
        Out-Null
    if ($LASTEXITCODE -ne 0) {
        Stop-Smoke 'installed neoth.exe cannot query its release self-knowledge snapshot'
    }
    $compatVersion = (& (Join-Path $Directory 'neothd.exe') --version 2>&1 | Out-String).Trim()
    if ($compatVersion -notmatch "(^|\s)$([regex]::Escape($Version))($|\s)") {
        Stop-Smoke "neothd --version returned '$compatVersion'"
    }
    $keetVersion = (& (Join-Path $Directory 'neoth-keet-bridge.exe') --version 2>&1 | Out-String).Trim()
    if ($keetVersion -ne $Version) {
        Stop-Smoke "neoth-keet-bridge --version returned '$keetVersion'"
    }
    $probeHome = Join-Path $Directory '.runtime-probe-state'
    $previousNeothHome = $env:NEOTH_HOME
    try {
        $env:NEOTH_HOME = $probeHome
        $guiProcess = Start-Process `
            -FilePath (Join-Path $Directory 'neothd-gui.exe') `
            -ArgumentList '--runtime-probe' `
            -Wait `
            -PassThru
        if ($guiProcess.ExitCode -ne 0) {
            Stop-Smoke "neothd-gui --runtime-probe exited $($guiProcess.ExitCode)"
        }
        if (Test-Path -LiteralPath $probeHome) {
            Stop-Smoke 'neothd-gui --runtime-probe mutated NEOTH_HOME'
        }
    } finally {
        $env:NEOTH_HOME = $previousNeothHome
    }
}

function Get-InstalledReleaseFingerprint {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $items = @(
        foreach ($name in $requiredExecutables) {
            Get-Item -LiteralPath (Join-Path $Directory $name)
        }
        Get-ChildItem -LiteralPath (Join-Path $Directory 'self-knowledge') -File -Recurse
    ) | Sort-Object FullName
    return @(
        foreach ($item in $items) {
            $relative = $item.FullName.Substring($Directory.Length).TrimStart('\')
            '{0}={1}' -f $relative, (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        }
    ) -join "`n"
}

function Get-DirectoryTreeFingerprint {
    param([Parameter(Mandatory = $true)][string]$Directory)

    return @(
        Get-ChildItem -LiteralPath $Directory -Force -Recurse | Sort-Object FullName | ForEach-Object {
            $relative = $_.FullName.Substring($Directory.Length).TrimStart('\')
            if ($_.PSIsContainer) {
                "directory:$relative"
            } else {
                'file:{0}={1}' -f $relative, (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }
    ) -join "`n"
}

function Assert-FakeRecoveryCandidateRejected {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('User', 'Machine')][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Directory
    )

    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $candidate = Join-Path $Directory 'neoth.exe'
    $uninstaller = Join-Path $Directory 'unins000.exe'
    New-FakeNeothProbe -Path $candidate
    Copy-Item -LiteralPath $installerPath -Destination $uninstaller
    foreach ($snapshotName in @('self-knowledge', '.neoth-self-knowledge-backup')) {
        $snapshot = Join-Path $Directory $snapshotName
        New-Item -ItemType Directory -Path $snapshot -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $snapshot 'manifest.json') -Value '{}' -Encoding ascii
    }
    Set-Content `
        -LiteralPath (Join-Path $Directory '.neoth-self-knowledge-committed') `
        -Value $Version `
        -NoNewline `
        -Encoding ascii

    $sentinel = Join-Path $root ("fake-recovery-executed-$($Scope.ToLowerInvariant()).txt")
    $candidateHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
    $before = Get-DirectoryTreeFingerprint -Directory $Directory
    $previousSentinel = $env:NEOTH_FAKE_EXEC_SENTINEL
    $registrationCreated = $false
    try {
        Set-TestInstallRegistration `
            -Scope $Scope `
            -Directory $Directory `
            -Uninstaller $uninstaller
        $registrationCreated = $true
        $env:NEOTH_FAKE_EXEC_SENTINEL = $sentinel
        Invoke-Install -Scope $Scope -Directory $Directory -ExpectFailure
        if (Test-Path -LiteralPath $sentinel) {
            Stop-Smoke 'fake recovery neoth.exe executed before trust was established'
        }
        if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash -cne $candidateHash -or
            (Get-DirectoryTreeFingerprint -Directory $Directory) -cne $before) {
            Stop-Smoke 'rejected fake recovery candidate was modified'
        }
        if (Test-Path -LiteralPath (Join-Path $Directory 'neothd.exe')) {
            Stop-Smoke 'fake recovery target received a packaged payload'
        }
    } finally {
        $env:NEOTH_FAKE_EXEC_SENTINEL = $previousSentinel
        if ($registrationCreated) {
            Remove-TestInstallRegistration -Scope $Scope
        }
        Remove-Item -LiteralPath $sentinel -Force -ErrorAction SilentlyContinue
    }
}

if (-not (Test-StrictSemVer -Value $Version)) {
    Stop-Smoke "version '$Version' is not strict SemVer"
}

$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$previousInstallerPath = if ($PreviousInstaller -eq '') {
    $installerPath
} else {
    (Resolve-Path -LiteralPath $PreviousInstaller).Path
}
$tempBase = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$runId = [guid]::NewGuid().ToString('N')
$root = Join-Path $tempBase ("NEOTH clean machine ü " + $runId)
$machineRoot = Join-Path $env:ProgramFiles ("NEOTH installer smoke " + $runId)
$ownedDirectory = Join-Path $root 'owned\NEOTH'
$preExistingDirectory = Join-Path $root 'pre-existing\NEOTH'
$foreignDirectory = Join-Path $root 'foreign\NEOTH'
$fakeRecoveryDirectory = Join-Path $root 'fake-recovery\NEOTH'
$fakeRecoveryMachineDirectory = Join-Path $machineRoot 'fake-recovery\NEOTH'
$registryOwnedDirectory = Join-Path $root 'registry-owned\NEOTH'
$registryMismatchAttemptDirectory = Join-Path $root 'registry-mismatch\NEOTH'
$reparseTarget = Join-Path $root 'reparse-target\NEOTH'
$reparseDirectory = Join-Path $root 'reparse-link\NEOTH'
$machineWritableAttemptDirectory = Join-Path $root 'machine-writable\NEOTH'
$machineAclWeakParent = Join-Path $machineRoot 'acl-weak-parent'
$machineAclWeakDirectory = Join-Path $machineAclWeakParent 'NEOTH'
$preExistingMachineDirectory = Join-Path $machineRoot 'pre-existing-machine\NEOTH'
$collisionUserDirectory = Join-Path $root 'scope-user\NEOTH'
$collisionMachineDirectory = Join-Path $machineRoot 'scope-machine\NEOTH'
$collisionAttemptDirectory = Join-Path $root 'scope-attempt\NEOTH'
$malformedAttemptDirectory = Join-Path $root 'malformed-attempt\NEOTH'
$testDirectories = @(
    $ownedDirectory
    $preExistingDirectory
    $foreignDirectory
    $fakeRecoveryDirectory
    $fakeRecoveryMachineDirectory
    $registryOwnedDirectory
    $registryMismatchAttemptDirectory
    $reparseDirectory
    $reparseTarget
    $machineWritableAttemptDirectory
    $machineAclWeakDirectory
    $preExistingMachineDirectory
    $collisionUserDirectory
    $collisionMachineDirectory
    $collisionAttemptDirectory
    $malformedAttemptDirectory
)
$stateDirectory = Join-Path $env:USERPROFILE '.neoth'
$stateMarker = Join-Path $stateDirectory ("installer-preserve-" + [guid]::NewGuid().ToString('N'))
$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$cleanRunnerConfirmed = $false

try {
    $userUninstall = Join-Path 'Registry::HKEY_CURRENT_USER' $uninstallKey
    $machineUninstall = Join-Path 'Registry::HKEY_LOCAL_MACHINE' $uninstallKey
    if ((Test-Path -LiteralPath $userUninstall) -or (Test-Path -LiteralPath $machineUninstall)) {
        Stop-Smoke 'runner is not clean: a NEOTH uninstall registration already exists'
    }
    if ($null -ne (Get-OwnedPathEntry -Scope User) -or
        ($isAdministrator -and $null -ne (Get-OwnedPathEntry -Scope Machine))) {
        Stop-Smoke 'runner is not clean: a NEOTH PATH ownership marker already exists'
    }
    $cleanRunnerConfirmed = $true

    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
    Set-Content -LiteralPath $stateMarker -Value 'must survive uninstall' -Encoding ascii
    if ($RequireSignature) {
        Assert-ValidSignature -Path $installerPath
        Assert-ValidSignature -Path $previousInstallerPath
    }

    # A /DIR value is never ownership. A non-empty target without an exact
    # uninstall registration must be rejected before the first payload write.
    $foreignSentinel = Join-Path $foreignDirectory 'self-knowledge\sentinel.txt'
    New-Item -ItemType Directory -Path (Split-Path -Parent $foreignSentinel) -Force | Out-Null
    Set-Content -LiteralPath $foreignSentinel -Value 'foreign-directory-must-survive' -Encoding ascii
    $foreignSentinelHash = (Get-FileHash -LiteralPath $foreignSentinel -Algorithm SHA256).Hash
    Invoke-Install -Scope User -Directory $foreignDirectory -ExpectFailure
    if (-not (Test-Path -LiteralPath $foreignSentinel -PathType Leaf) -or
        (Get-FileHash -LiteralPath $foreignSentinel -Algorithm SHA256).Hash -cne $foreignSentinelHash) {
        Stop-Smoke 'foreign self-knowledge sentinel changed during rejected install'
    }
    if (Test-Path -LiteralPath (Join-Path $foreignDirectory 'neoth.exe')) {
        Stop-Smoke 'foreign target received a packaged payload'
    }

    # A syntactically complete registration owns exactly one canonical path.
    # It must not authorize a sibling /DIR supplied on the command line.
    New-Item -ItemType Directory -Path $registryOwnedDirectory -Force | Out-Null
    $registryOwnedSentinel = Join-Path $registryOwnedDirectory 'owned-sentinel.txt'
    $registryOwnedUninstaller = Join-Path $registryOwnedDirectory 'unins000.exe'
    Set-Content -LiteralPath $registryOwnedSentinel -Value 'registered-owner' -Encoding ascii
    Copy-Item -LiteralPath $installerPath -Destination $registryOwnedUninstaller
    try {
        Set-TestInstallRegistration `
            -Scope User `
            -Directory $registryOwnedDirectory `
            -Uninstaller $registryOwnedUninstaller
        Invoke-Install -Scope User -Directory $registryMismatchAttemptDirectory -ExpectFailure
        if (Test-Path -LiteralPath $registryMismatchAttemptDirectory) {
            Stop-Smoke 'registry path mismatch wrote a payload'
        }
        if ((Get-Content -LiteralPath $registryOwnedSentinel -Raw).Trim() -cne 'registered-owner') {
            Stop-Smoke 'registry path mismatch modified the registered owner'
        }
    } finally {
        Remove-TestInstallRegistration -Scope User
    }

    # Even an exact registry registration cannot bless a junction target.
    $reparseSentinel = Join-Path $reparseTarget 'self-knowledge\sentinel.txt'
    New-Item -ItemType Directory -Path (Split-Path -Parent $reparseSentinel) -Force | Out-Null
    Set-Content -LiteralPath $reparseSentinel -Value 'reparse-target-must-survive' -Encoding ascii
    $reparseUninstaller = Join-Path $reparseTarget 'unins000.exe'
    Copy-Item -LiteralPath $installerPath -Destination $reparseUninstaller
    New-Item -ItemType Directory -Path (Split-Path -Parent $reparseDirectory) -Force | Out-Null
    New-Item -ItemType Junction -Path $reparseDirectory -Target $reparseTarget | Out-Null
    try {
        Set-TestInstallRegistration `
            -Scope User `
            -Directory $reparseDirectory `
            -Uninstaller (Join-Path $reparseDirectory 'unins000.exe')
        Invoke-Install -Scope User -Directory $reparseDirectory -ExpectFailure
        if (Test-Path -LiteralPath (Join-Path $reparseTarget 'neoth.exe')) {
            Stop-Smoke 'reparse target collision wrote a payload'
        }
        if ((Get-Content -LiteralPath $reparseSentinel -Raw).Trim() -cne 'reparse-target-must-survive') {
            Stop-Smoke 'reparse target collision changed its sentinel'
        }
    } finally {
        Remove-TestInstallRegistration -Scope User
        Remove-Item -LiteralPath $reparseDirectory -Force -ErrorAction SilentlyContinue
    }

    # The recovery path reaches an attacker-controlled candidate only after an
    # exact registration. Its unsigned probe must still never execute.
    Assert-FakeRecoveryCandidateRejected -Scope User -Directory $fakeRecoveryDirectory

    # Real N -> N+1 when -PreviousInstaller is supplied; otherwise this uses the
    # same package twice while exercising the identical replacement boundary.
    Invoke-Install `
        -Scope User `
        -Directory $ownedDirectory `
        -InstallerFile $previousInstallerPath
    $installedRecoverySignature = Get-AuthenticodeSignature `
        -LiteralPath (Join-Path $ownedDirectory 'neoth.exe')
    $setupRecoverySignature = Get-AuthenticodeSignature -LiteralPath $installerPath
    $trustedRecoveryCanRun =
        -not $isAdministrator -and
        $installedRecoverySignature.Status -eq [System.Management.Automation.SignatureStatus]::Valid -and
        $setupRecoverySignature.Status -eq [System.Management.Automation.SignatureStatus]::Valid -and
        $null -ne $installedRecoverySignature.SignerCertificate -and
        $null -ne $setupRecoverySignature.SignerCertificate -and
        $installedRecoverySignature.SignerCertificate.Subject -ceq
            $setupRecoverySignature.SignerCertificate.Subject

    # The manifest AfterInstall callback still runs inside Inno's rollback
    # window. A forced runtime rejection must restore both N binaries and the
    # complete N snapshot, with no transaction debris.
    $beforeVerifyFault = Get-InstalledReleaseFingerprint -Directory $ownedDirectory
    Invoke-Install `
        -Scope User `
        -Directory $ownedDirectory `
        -AdditionalArguments @('/TESTSELFKNOWLEDGEVERIFYFAIL') `
        -ExpectFailure
    $afterVerifyFault = Get-InstalledReleaseFingerprint -Directory $ownedDirectory
    if ($afterVerifyFault -cne $beforeVerifyFault) {
        Stop-Smoke 'verification failure did not restore the complete N release payload'
    }

    # Simulate interrupted N cleanup plus a forged-but-well-formed old marker.
    # Recovery is allowed only when the existing runtime and current setup have
    # matching valid signers and the original token is not elevated. Otherwise
    # the target must stay byte-for-byte unchanged until the operator repairs it.
    $snapshotDirectory = Join-Path $ownedDirectory 'self-knowledge'
    $backupDirectory = Join-Path $ownedDirectory '.neoth-self-knowledge-backup'
    Copy-Item -LiteralPath $snapshotDirectory -Destination $backupDirectory -Recurse
    Set-Content `
        -LiteralPath (Join-Path $ownedDirectory '.neoth-self-knowledge-committed') `
        -Value '0.9.0' `
        -NoNewline `
        -Encoding ascii
    $obsoleteDirectory = Join-Path $ownedDirectory 'self-knowledge\obsolete-from-prior-release'
    $obsoleteMember = Join-Path $obsoleteDirectory 'must-disappear.md'
    New-Item -ItemType Directory -Path $obsoleteDirectory -Force | Out-Null
    Set-Content -LiteralPath $obsoleteMember -Value 'obsolete N snapshot member' -Encoding ascii
    if (-not (Test-Path -LiteralPath $obsoleteMember -PathType Leaf)) {
        Stop-Smoke 'could not plant the obsolete N self-knowledge member'
    }
    if ($trustedRecoveryCanRun) {
        Invoke-Install -Scope User -Directory $ownedDirectory
    } else {
        $beforeRejectedRecovery = Get-DirectoryTreeFingerprint -Directory $ownedDirectory
        Invoke-Install -Scope User -Directory $ownedDirectory -ExpectFailure
        if ((Get-DirectoryTreeFingerprint -Directory $ownedDirectory) -cne $beforeRejectedRecovery) {
            Stop-Smoke 'untrusted interrupted recovery changed the registered installation'
        }
        Remove-Item -LiteralPath $snapshotDirectory -Recurse -Force
        Move-Item -LiteralPath $backupDirectory -Destination $snapshotDirectory
        Remove-Item `
            -LiteralPath (Join-Path $ownedDirectory '.neoth-self-knowledge-committed') `
            -Force
        Invoke-Install -Scope User -Directory $ownedDirectory
    }
    if (Test-Path -LiteralPath $obsoleteMember) {
        Stop-Smoke 'N -> N+1 self-knowledge replacement retained an obsolete N member'
    }

    # A crash with no backup is accepted only after the same old-runtime trust
    # boundary. Unsigned/elevated test contexts prove the fail-closed branch.
    Set-Content `
        -LiteralPath (Join-Path $ownedDirectory '.neoth-self-knowledge-committed.tmp') `
        -Value '0.9.0' `
        -NoNewline `
        -Encoding ascii
    if ($trustedRecoveryCanRun) {
        Invoke-Install -Scope User -Directory $ownedDirectory
    } else {
        $beforeRejectedMarker = Get-DirectoryTreeFingerprint -Directory $ownedDirectory
        Invoke-Install -Scope User -Directory $ownedDirectory -ExpectFailure
        if ((Get-DirectoryTreeFingerprint -Directory $ownedDirectory) -cne $beforeRejectedMarker) {
            Stop-Smoke 'untrusted transaction marker changed the registered installation'
        }
        Remove-Item `
            -LiteralPath (Join-Path $ownedDirectory '.neoth-self-knowledge-committed.tmp') `
            -Force
        Invoke-Install -Scope User -Directory $ownedDirectory
    }
    foreach ($transactionMember in @(
        '.neoth-self-knowledge-stage'
        '.neoth-self-knowledge-backup'
        '.neoth-self-knowledge-committed'
        '.neoth-self-knowledge-committed.tmp'
    )) {
        if (Test-Path -LiteralPath (Join-Path $ownedDirectory $transactionMember)) {
            Stop-Smoke "successful self-knowledge replacement left $transactionMember behind"
        }
    }
    Assert-Payload -Directory $ownedDirectory
    # Installer-owned PATH: the marker must survive an in-place upgrade and
    # authorize removal of exactly the entry NEOTH added.
    if ((Test-PathEntry -Scope User -Expected $ownedDirectory) -ne 1) {
        Stop-Smoke 'upgrade did not preserve exactly one installer-owned user PATH entry'
    }
    $ownedMarker = Get-OwnedPathEntry -Scope User
    if ($null -eq $ownedMarker -or $ownedMarker.TrimEnd('\') -ine $ownedDirectory.TrimEnd('\')) {
        Stop-Smoke 'upgrade did not preserve the user PATH ownership marker'
    }
    Invoke-Uninstall -Directory $ownedDirectory
    if ((Test-PathEntry -Scope User -Expected $ownedDirectory) -ne 0) {
        Stop-Smoke 'uninstaller left its owned directory on user PATH'
    }
    if ($null -ne (Get-OwnedPathEntry -Scope User)) {
        Stop-Smoke 'uninstaller left the user PATH ownership marker behind'
    }

    # Pre-existing PATH: installation must not claim it and uninstall must not
    # remove it, even after the product was successfully installed there.
    Add-TestPathEntry -Scope User -Entry $preExistingDirectory
    Invoke-Install -Scope User -Directory $preExistingDirectory
    if ($null -ne (Get-OwnedPathEntry -Scope User)) {
        Stop-Smoke 'installer claimed a pre-existing user PATH entry'
    }
    Invoke-Uninstall -Directory $preExistingDirectory
    if ((Test-PathEntry -Scope User -Expected $preExistingDirectory) -ne 1) {
        Stop-Smoke 'uninstaller removed or duplicated a pre-existing user PATH entry'
    }
    Remove-TestPathEntry -Scope User -Entry $preExistingDirectory

    # Corrupt uninstall metadata is never a downgrade. Even an explicit
    # recovery downgrade flag must fail before touching the filesystem.
    New-Item -Path $userUninstall -Force | Out-Null
    New-ItemProperty -LiteralPath $userUninstall -Name DisplayVersion -Value 'not-semver' -PropertyType String -Force | Out-Null
    try {
        Invoke-Install `
            -Scope User `
            -Directory $malformedAttemptDirectory `
            -AdditionalArguments @('/ALLOWDOWNGRADE') `
            -ExpectFailure
        if (Test-Path -LiteralPath (Join-Path $malformedAttemptDirectory 'neoth.exe')) {
            Stop-Smoke 'malformed installed metadata bypass wrote a payload'
        }
    } finally {
        Remove-Item -LiteralPath $userUninstall -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Both transition directions must fail before writing the second scope.
    if ($isAdministrator) {
        New-Item -ItemType Directory -Path $machineAclWeakParent -Force | Out-Null
        $weakAcl = Get-Acl -LiteralPath $machineAclWeakParent
        $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $weakRule = [Security.AccessControl.FileSystemAccessRule]::new(
            $usersSid,
            [Security.AccessControl.FileSystemRights]::Modify,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$weakAcl.AddAccessRule($weakRule)
        Set-Acl -LiteralPath $machineAclWeakParent -AclObject $weakAcl
        Invoke-Install `
            -Scope Machine `
            -Directory $machineAclWeakDirectory `
            -ExpectFailure
        if (Test-Path -LiteralPath (Join-Path $machineAclWeakDirectory 'neoth.exe')) {
            Stop-Smoke 'user-writable Program Files target wrote a payload'
        }

        Invoke-Install `
            -Scope Machine `
            -Directory $machineWritableAttemptDirectory `
            -ExpectFailure
        if (Test-Path -LiteralPath (Join-Path $machineWritableAttemptDirectory 'neoth.exe')) {
            Stop-Smoke 'user-writable machine target wrote a payload'
        }

        # This drives recovery from an elevated /ALLUSERS setup. The planted
        # executable records its token if invoked; the sentinel must not exist.
        Assert-FakeRecoveryCandidateRejected `
            -Scope Machine `
            -Directory $fakeRecoveryMachineDirectory

        Invoke-Install -Scope User -Directory $collisionUserDirectory
        Invoke-Install -Scope Machine -Directory $collisionMachineDirectory -ExpectFailure
        if (-not (Test-Path -LiteralPath (Join-Path $collisionUserDirectory 'neoth.exe')) -or
            (Test-Path -LiteralPath (Join-Path $collisionMachineDirectory 'neoth.exe'))) {
            Stop-Smoke 'user-to-machine collision changed the wrong installation'
        }
        Invoke-Uninstall -Directory $collisionUserDirectory

        Invoke-Install -Scope Machine -Directory $collisionMachineDirectory
        Invoke-Install -Scope User -Directory $collisionAttemptDirectory -ExpectFailure
        if (-not (Test-Path -LiteralPath (Join-Path $collisionMachineDirectory 'neoth.exe')) -or
            (Test-Path -LiteralPath (Join-Path $collisionAttemptDirectory 'neoth.exe'))) {
            Stop-Smoke 'machine-to-user collision changed the wrong installation'
        }
        Invoke-Uninstall -Directory $collisionMachineDirectory
        if ((Test-PathEntry -Scope Machine -Expected $collisionMachineDirectory) -ne 0) {
            Stop-Smoke 'machine-scope uninstall left its owned PATH entry behind'
        }

        Add-TestPathEntry -Scope Machine -Entry $preExistingMachineDirectory
        Invoke-Install -Scope Machine -Directory $preExistingMachineDirectory
        if ($null -ne (Get-OwnedPathEntry -Scope Machine)) {
            Stop-Smoke 'installer claimed a pre-existing machine PATH entry'
        }
        Invoke-Uninstall -Directory $preExistingMachineDirectory
        if ((Test-PathEntry -Scope Machine -Expected $preExistingMachineDirectory) -ne 1) {
            Stop-Smoke 'uninstaller removed or duplicated a pre-existing machine PATH entry'
        }
        Remove-TestPathEntry -Scope Machine -Entry $preExistingMachineDirectory
    } else {
        Write-Warning 'scope-collision smoke skipped because the runner is not elevated'
    }

    if (-not (Test-Path -LiteralPath $stateMarker -PathType Leaf)) {
        Stop-Smoke 'uninstaller deleted operator state under ~/.neoth'
    }
} finally {
    if ($cleanRunnerConfirmed) {
        if (Test-Path -LiteralPath $userUninstall) {
            $uninstallState = Get-ItemProperty -LiteralPath $userUninstall -ErrorAction SilentlyContinue
            if ($null -ne $uninstallState) {
                $displayVersion = $uninstallState.PSObject.Properties['DisplayVersion']
                if ($null -ne $displayVersion -and $displayVersion.Value -ceq 'not-semver') {
                    Remove-Item -LiteralPath $userUninstall -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        foreach ($directory in $testDirectories) {
            $uninstaller = Get-ChildItem -LiteralPath $directory -Filter 'unins*.exe' -File -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($null -ne $uninstaller -and
                (Test-Path -LiteralPath (Join-Path $directory 'neothd.exe') -PathType Leaf)) {
                Start-Process -FilePath $uninstaller.FullName -ArgumentList @(
                    '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'
                ) -Wait -ErrorAction SilentlyContinue | Out-Null
            }
            Remove-TestPathEntry -Scope User -Entry $directory
            if ($isAdministrator) {
                Remove-TestPathEntry -Scope Machine -Entry $directory
            }
        }
    }
    Remove-Item -LiteralPath $stateMarker -Force -ErrorAction SilentlyContinue
    $tempRootPrefix = [IO.Path]::GetFullPath($tempBase).TrimEnd('\') + '\NEOTH clean machine ü '
    $canonicalRoot = [IO.Path]::GetFullPath($root)
    if ($canonicalRoot.StartsWith($tempRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $canonicalRoot -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Warning "refusing to clean unexpected user smoke root: $canonicalRoot"
    }
    $programFilesRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
    $canonicalMachineRoot = [IO.Path]::GetFullPath($machineRoot)
    if ($canonicalMachineRoot.StartsWith(
        $programFilesRoot + 'NEOTH installer smoke ',
        [StringComparison]::OrdinalIgnoreCase
    )) {
        Remove-Item -LiteralPath $canonicalMachineRoot -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Warning "refusing to clean unexpected machine smoke root: $canonicalMachineRoot"
    }
}
