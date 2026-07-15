[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Installer,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [switch]$RequireSignature
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
    $process = Start-Process -FilePath $installerPath -ArgumentList $arguments -Wait -PassThru
    if ($ExpectFailure) {
        if ($process.ExitCode -eq 0) {
            Stop-Smoke "$Scope-scope collision install unexpectedly succeeded"
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
}

function Assert-Payload {
    param([Parameter(Mandatory = $true)][string]$Directory)

    foreach ($name in $requiredExecutables) {
        $path = Join-Path $Directory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Stop-Smoke "installed payload is missing $name"
        }
        if ($RequireSignature) {
            Assert-ValidSignature -Path $path
        }
    }
    foreach ($name in $requiredSupportFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $Directory $name) -PathType Leaf)) {
            Stop-Smoke "installed payload is missing $name"
        }
    }

    $publicVersion = (& (Join-Path $Directory 'neoth.exe') --version 2>&1 | Out-String).Trim()
    if ($publicVersion -notmatch "(^|\s)$([regex]::Escape($Version))($|\s)") {
        Stop-Smoke "neoth --version returned '$publicVersion'"
    }
    $compatVersion = (& (Join-Path $Directory 'neothd.exe') --version 2>&1 | Out-String).Trim()
    if ($compatVersion -notmatch "(^|\s)$([regex]::Escape($Version))($|\s)") {
        Stop-Smoke "neothd --version returned '$compatVersion'"
    }
    $keetVersion = (& (Join-Path $Directory 'neoth-keet-bridge.exe') --version 2>&1 | Out-String).Trim()
    if ($keetVersion -ne $Version) {
        Stop-Smoke "neoth-keet-bridge --version returned '$keetVersion'"
    }
}

if (-not (Test-StrictSemVer -Value $Version)) {
    Stop-Smoke "version '$Version' is not strict SemVer"
}

$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$tempBase = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$root = Join-Path $tempBase ("NEOTH clean machine ü " + [guid]::NewGuid().ToString('N'))
$ownedDirectory = Join-Path $root 'owned\NEOTH'
$preExistingDirectory = Join-Path $root 'pre-existing\NEOTH'
$preExistingMachineDirectory = Join-Path $root 'pre-existing-machine\NEOTH'
$collisionUserDirectory = Join-Path $root 'scope-user\NEOTH'
$collisionMachineDirectory = Join-Path $root 'scope-machine\NEOTH'
$collisionAttemptDirectory = Join-Path $root 'scope-attempt\NEOTH'
$malformedAttemptDirectory = Join-Path $root 'malformed-attempt\NEOTH'
$testDirectories = @(
    $ownedDirectory
    $preExistingDirectory
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
    }

    # Installer-owned PATH: the marker must survive an in-place upgrade and
    # authorize removal of exactly the entry NEOTH added.
    Invoke-Install -Scope User -Directory $ownedDirectory
    Invoke-Install -Scope User -Directory $ownedDirectory
    Assert-Payload -Directory $ownedDirectory
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
            if ($null -ne $uninstaller) {
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
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
