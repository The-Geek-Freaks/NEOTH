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
        [Parameter(Mandatory = $true)][uint16]$Machine,
        [AllowEmptyString()][string]$NormalImport = 'KERNEL32.dll',
        [AllowEmptyString()][string]$DelayImport = 'USER32.dll'
    )

    # Deterministic PE32+ fixture with one .rdata section. The import and
    # delay-import directories are complete enough to exercise the production
    # RVA parser; no compiler or linker is needed by this contract test.
    $bytes = [byte[]]::new(1536)
    [BitConverter]::GetBytes([uint16]0x5A4D).CopyTo($bytes, 0)
    [BitConverter]::GetBytes([uint32]0x80).CopyTo($bytes, 0x3C)
    [BitConverter]::GetBytes([uint32]0x00004550).CopyTo($bytes, 0x80)
    [BitConverter]::GetBytes($Machine).CopyTo($bytes, 0x84)
    [BitConverter]::GetBytes([uint16]1).CopyTo($bytes, 0x86)
    [BitConverter]::GetBytes([uint16]0xF0).CopyTo($bytes, 0x94)

    $optional = 0x98
    [BitConverter]::GetBytes([uint16]0x20B).CopyTo($bytes, $optional)
    [BitConverter]::GetBytes([uint64]0x0000000140000000).CopyTo($bytes, $optional + 24)
    [BitConverter]::GetBytes([uint32]0x1000).CopyTo($bytes, $optional + 32)
    [BitConverter]::GetBytes([uint32]0x200).CopyTo($bytes, $optional + 36)
    [BitConverter]::GetBytes([uint32]0x2000).CopyTo($bytes, $optional + 56)
    [BitConverter]::GetBytes([uint32]0x200).CopyTo($bytes, $optional + 60)
    [BitConverter]::GetBytes([uint32]16).CopyTo($bytes, $optional + 108)

    $section = $optional + 0xF0
    [Text.Encoding]::ASCII.GetBytes('.rdata').CopyTo($bytes, $section)
    [BitConverter]::GetBytes([uint32]0x400).CopyTo($bytes, $section + 8)
    [BitConverter]::GetBytes([uint32]0x1000).CopyTo($bytes, $section + 12)
    [BitConverter]::GetBytes([uint32]0x400).CopyTo($bytes, $section + 16)
    [BitConverter]::GetBytes([uint32]0x200).CopyTo($bytes, $section + 20)

    if ($NormalImport -ne '') {
        [BitConverter]::GetBytes([uint32]0x1000).CopyTo($bytes, $optional + 120)
        [BitConverter]::GetBytes([uint32]40).CopyTo($bytes, $optional + 124)
        [BitConverter]::GetBytes([uint32]0x1100).CopyTo($bytes, 0x20C)
        [Text.Encoding]::ASCII.GetBytes($NormalImport).CopyTo($bytes, 0x300)
    }
    if ($DelayImport -ne '') {
        [BitConverter]::GetBytes([uint32]0x1040).CopyTo($bytes, $optional + 216)
        [BitConverter]::GetBytes([uint32]64).CopyTo($bytes, $optional + 220)
        [BitConverter]::GetBytes([uint32]1).CopyTo($bytes, 0x240)
        [BitConverter]::GetBytes([uint32]0x1140).CopyTo($bytes, 0x244)
        [Text.Encoding]::ASCII.GetBytes($DelayImport).CopyTo($bytes, 0x340)
    }
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

function New-SelfKnowledgeFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Version
    )

    New-Item -ItemType Directory -Path (Join-Path $Path 'wiki') -Force | Out-Null
    Set-Utf8NoBomContent -Path (Join-Path $Path 'graph.json') -Value '{"nodes":[{"id":"neoth"}],"links":[{"source":"neoth","target":"neoth"}]}'
    Set-Utf8NoBomContent -Path (Join-Path $Path 'wiki\index.md') -Value '# NEOTH'
    $entries = @(
        [ordered]@{ path = 'graph.json'; role = 'graph' }
        [ordered]@{ path = 'wiki/index.md'; role = 'wiki' }
    )
    $payload = [Text.StringBuilder]::new()
    foreach ($entry in $entries) {
        $filePath = Join-Path $Path $entry.path.Replace('/', '\')
        $file = Get-Item -LiteralPath $filePath
        $entry.bytes = $file.Length
        $entry.sha256 = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
        [void]$payload.Append("$($entry.path)`0$($entry.sha256)`0$($entry.bytes)`0$($entry.role)`n")
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $payloadHash = [BitConverter]::ToString(
            $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload.ToString()))
        ).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    $manifest = [ordered]@{
        schema_version = 1
        product = 'NEOTH'
        release_version = $Version
        source_head = ('0' * 40)
        payload_sha256 = $payloadHash
        files = $entries
    } | ConvertTo-Json -Depth 5
    Set-Utf8NoBomContent -Path (Join-Path $Path 'manifest.json') -Value $manifest
}

$scriptRoot = Split-Path -Parent $PSCommandPath
$buildScript = Join-Path $scriptRoot 'build-installer.ps1'
$peScript = Join-Path $scriptRoot 'pe-inspection.ps1'
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
    . $peScript
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
        'VersionInfoTextVersion={#AppVersion}',
        'Name: "{group}\NEOTH"; Filename: "{app}\neothd-gui.exe"; Parameters: "--product-launcher"',
        'Name: "{group}\NEOTH CLI"; Filename: "{cmd}"; Parameters: "/D /K ""set NEOTH_INTERFACE=&& ',
        'Name: "{group}\NEOTH GUI"; Filename: "{app}\neothd-gui.exe"',
        'Name: "{autodesktop}\NEOTH"; Filename: "{app}\neothd-gui.exe"; Parameters: "--product-launcher"',
        'Filename: "{app}\neothd-gui.exe"; Parameters: "--product-launcher"; Description: "Launch NEOTH"',
        'Source: "{#SourceDir}\self-knowledge\*"; DestDir: "{app}\.neoth-self-knowledge-stage"; Excludes: "manifest.json"; Flags: ignoreversion recursesubdirs createallsubdirs uninsneveruninstall',
        'Source: "{#SourceDir}\self-knowledge\manifest.json"; DestDir: "{app}\.neoth-self-knowledge-stage"; Flags: ignoreversion uninsneveruninstall; AfterInstall: PrepareSelfKnowledgeTransaction',
        'Type: filesandordirs; Name: "{app}\self-knowledge"',
        'procedure RecoverSelfKnowledgeTransaction;',
        'procedure PrepareSelfKnowledgeTransaction;',
        'procedure RollbackSelfKnowledgeTransaction;',
        'procedure CommitSelfKnowledgeTransaction;',
        'VerifyNewSelfKnowledgeSnapshot(LivePath)',
        'VerifyInstalledSelfKnowledgeSnapshot(LivePath)',
        'RenameFile(LivePath, BackupPath)',
        'RenameFile(StagePath, LivePath)',
        'procedure DeinitializeSetup;',
        '/TESTSELFKNOWLEDGEVERIFYFAIL',
        'not IsValidSemVer(MarkerVersion)',
        'BackupVerified := VerifyInstalledSelfKnowledgeSnapshot(BackupPath)',
        'procedure AssertInstallTargetOwnership;',
        'DirectoryIsEmpty(AppPath)',
        'RequireNoReparsePathComponents(AppPath, ''NEOTH install target'')',
        '''InstallLocation'', InstallLocation',
        '''UninstallString'', UninstallCommand',
        '''Publisher'', Publisher',
        'Length(UninstallerName) = 12',
        '(CompareText(Trim(UninstallCommand), AddQuotes(UninstallerPath)) <> 0)',
        'user-writable custom targets are not trusted',
        'function MachinePathAclIsTrusted(Path: String): Boolean;',
        '$danger=[uint64]0x500D0156;',
        'RequireTrustedMachineAcl(AppPath, ''All-users NEOTH install target'')',
        'RequireRegularPayloadDestinations(AppPath);',
        'ExistingCandidateHasMatchingAuthenticode(CandidatePath)',
        'Get-AuthenticodeSignature -LiteralPath ',
        '$a.SignerCertificate.Subject -cne $b.SignerCertificate.Subject',
        'ExecAsOriginalUser(',
        'RequireRegularTree(Path, Description)',
        'RequireRegularTree(LivePath, ''NEOTH self-knowledge snapshot'')',
        'RequireRegularTree(BackupPath, ''NEOTH self-knowledge transaction backup'')'
    )) {
        if ($iss.IndexOf($contract, [StringComparison]::Ordinal) -lt 0) {
            Stop-Test "Inno contract is missing: $contract"
        }
    }
    foreach ($consoleRoutedGuiContract in @(
        'Name: "{group}\NEOTH"; Filename: "{app}\neoth.exe"',
        'Name: "{group}\NEOTH GUI"; Filename: "{app}\neoth.exe"',
        'Name: "{autodesktop}\NEOTH"; Filename: "{app}\neoth.exe"',
        'Filename: "{app}\neoth.exe"; Description: "Launch NEOTH"'
    )) {
        if ($iss.IndexOf($consoleRoutedGuiContract, [StringComparison]::Ordinal) -ge 0) {
            Stop-Test "GUI shell entry still routes through the console launcher: $consoleRoutedGuiContract"
        }
    }
    if ($iss -match 'Name: "\{group\}\\NEOTH GUI";[^\r\n]*Parameters: "--product-launcher"') {
        Stop-Test 'The explicit NEOTH GUI shortcut must force GUI, not product-launcher routing'
    }
    if ($iss.IndexOf("'{#UninstallKey}', 'PathEntryOwned'", [StringComparison]::Ordinal) -ge 0) {
        Stop-Test 'PATH ownership is still tied to the replaceable uninstall key'
    }
    if ($iss.IndexOf('DestDir: "{app}\self-knowledge"', [StringComparison]::Ordinal) -ge 0) {
        Stop-Test 'self-knowledge is still recursively overlaid onto the live snapshot'
    }
    if ($iss.IndexOf("MarkerVersion <> '{#AppVersion}'", [StringComparison]::Ordinal) -ge 0) {
        Stop-Test 'N+1 recovery incorrectly requires an N transaction marker to equal N+1'
    }
    $snapshotBackupIndex = $iss.IndexOf('RenameFile(LivePath, BackupPath)', [StringComparison]::Ordinal)
    $snapshotActivateIndex = $iss.IndexOf('RenameFile(StagePath, LivePath)', [StringComparison]::Ordinal)
    $snapshotVerifyIndex = $iss.IndexOf('VerifyNewSelfKnowledgeSnapshot(LivePath)', [StringComparison]::Ordinal)
    $snapshotCommitIndex = $iss.IndexOf('CommitSelfKnowledgeTransaction;', [StringComparison]::Ordinal)
    if ($snapshotBackupIndex -lt 0 -or
        $snapshotActivateIndex -le $snapshotBackupIndex -or
        $snapshotVerifyIndex -le $snapshotActivateIndex -or
        $snapshotCommitIndex -le $snapshotVerifyIndex) {
        Stop-Test 'self-knowledge backup, activation, verification, and commit order drifted'
    }
    $prepareStart = $iss.IndexOf('function PrepareToInstall(', [StringComparison]::Ordinal)
    if ($prepareStart -lt 0) {
        Stop-Test 'PrepareToInstall is missing'
    }
    $ownershipIndex = $iss.IndexOf('AssertInstallTargetOwnership;', $prepareStart, [StringComparison]::Ordinal)
    $recoveryIndex = $iss.IndexOf('RecoverSelfKnowledgeTransaction;', $prepareStart, [StringComparison]::Ordinal)
    if ($ownershipIndex -lt $prepareStart -or
        $recoveryIndex -le $ownershipIndex) {
        Stop-Test 'install target ownership is not established before recovery or writes'
    }
    $recoveryStart = $iss.IndexOf('procedure RecoverSelfKnowledgeTransaction;', [StringComparison]::Ordinal)
    if ($recoveryStart -lt 0) {
        Stop-Test 'RecoverSelfKnowledgeTransaction is missing'
    }
    $recoveryEnd = $iss.IndexOf('function InitializeSetup()', $recoveryStart, [StringComparison]::Ordinal)
    if ($recoveryEnd -le $recoveryStart) {
        Stop-Test 'RecoverSelfKnowledgeTransaction boundary is malformed'
    }
    $recoverySource = $iss.Substring($recoveryStart, $recoveryEnd - $recoveryStart)
    if ($recoverySource.IndexOf('VerifyNewSelfKnowledgeSnapshot(', [StringComparison]::Ordinal) -ge 0 -or
        $recoverySource.IndexOf('VerifyInstalledSelfKnowledgeSnapshot(', [StringComparison]::Ordinal) -lt 0) {
        Stop-Test 'pre-install recovery can use the newly staged/elevated verifier path'
    }
    $authStart = $iss.IndexOf('function ExistingCandidateHasMatchingAuthenticode(', [StringComparison]::Ordinal)
    $installedVerifyStart = $iss.IndexOf('function VerifyInstalledSelfKnowledgeSnapshot(', [StringComparison]::Ordinal)
    if ($authStart -lt 0 -or $installedVerifyStart -le $authStart) {
        Stop-Test 'old-state Authenticode verifier boundary is malformed'
    }
    $authSource = $iss.Substring($authStart, $installedVerifyStart - $authStart)
    if ($authSource.IndexOf('Get-AuthenticodeSignature', [StringComparison]::Ordinal) -lt 0 -or
        $authSource.IndexOf('WindowsBuiltInRole]::Administrator', [StringComparison]::Ordinal) -lt 0 -or
        $authSource.IndexOf('ExecAsOriginalUser(', [StringComparison]::Ordinal) -lt 0 -or
        $authSource.IndexOf('Exec(', [StringComparison]::Ordinal) -ge 0) {
        Stop-Test 'old-state trust probe is not pure-data/original-user fail-closed'
    }
    $installedVerifyEnd = $iss.IndexOf('procedure RollbackSelfKnowledgeTransaction;', $installedVerifyStart, [StringComparison]::Ordinal)
    if ($installedVerifyEnd -le $installedVerifyStart) {
        Stop-Test 'installed snapshot verifier boundary is malformed'
    }
    $installedVerifySource = $iss.Substring(
        $installedVerifyStart,
        $installedVerifyEnd - $installedVerifyStart
    )
    $installedAuthIndex = $installedVerifySource.IndexOf(
        'ExistingCandidateHasMatchingAuthenticode(CandidatePath)',
        [StringComparison]::Ordinal
    )
    $installedExecIndex = $installedVerifySource.IndexOf(
        'ExecAsOriginalUser(',
        [StringComparison]::Ordinal
    )
    if ($installedAuthIndex -lt 0 -or
        $installedExecIndex -le $installedAuthIndex -or
        $installedVerifySource.IndexOf('Exec(', [StringComparison]::Ordinal) -ge 0) {
        Stop-Test 'installed recovery executable can run before its pure-data trust gate'
    }
    $treeGateIndex = $recoverySource.IndexOf(
        'RequireRegularTree(LivePath, ''NEOTH self-knowledge snapshot'')',
        [StringComparison]::Ordinal
    )
    $runtimeVerifyIndex = $recoverySource.IndexOf(
        'VerifyInstalledSelfKnowledgeSnapshot(LivePath)',
        [StringComparison]::Ordinal
    )
    if ($treeGateIndex -lt 0 -or $runtimeVerifyIndex -le $treeGateIndex) {
        Stop-Test 'recovery runtime verification is not preceded by a recursive reparse gate'
    }
    $aclStart = $iss.IndexOf('function MachinePathAclIsTrusted(', [StringComparison]::Ordinal)
    $aclEnd = $iss.IndexOf('procedure RequireTrustedMachineAcl(', $aclStart, [StringComparison]::Ordinal)
    if ($aclStart -lt 0 -or $aclEnd -le $aclStart) {
        Stop-Test 'machine ACL verifier boundary is malformed'
    }
    $aclSource = $iss.Substring($aclStart, $aclEnd - $aclStart)
    foreach ($aclContract in @(
        'Microsoft.PowerShell.Security\Get-Acl',
        '$id.Groups',
        '[void]$s.Add($id.User.Value)',
        '$a.GetOwner([Security.Principal.SecurityIdentifier]).Value',
        'ExecAsOriginalUser('
    )) {
        if ($aclSource.IndexOf($aclContract, [StringComparison]::Ordinal) -lt 0) {
            Stop-Test "machine ACL verifier is missing: $aclContract"
        }
    }
    if ($aclSource.IndexOf('Exec(', [StringComparison]::Ordinal) -ge 0) {
        Stop-Test 'machine ACL trust gate can execute an elevated candidate'
    }
    $smokeSource = Get-Content -LiteralPath (Join-Path $scriptRoot 'smoke-installer.ps1') -Raw
    foreach ($upgradeContract in @(
        'obsolete-from-prior-release',
        'N -> N+1 self-knowledge replacement retained an obsolete N member',
        '/TESTSELFKNOWLEDGEVERIFYFAIL',
        'verification failure did not restore the complete N release payload',
        ".neoth-self-knowledge-committed')",
        ".neoth-self-knowledge-committed.tmp')",
        '.neoth-self-knowledge-backup',
        'Assert-Payload -Directory $ownedDirectory',
        'foreign self-knowledge sentinel changed during rejected install',
        'fake recovery neoth.exe executed before trust was established',
        'registry path mismatch wrote a payload',
        'reparse target collision wrote a payload',
        'user-writable machine target wrote a payload',
        'user-writable Program Files target wrote a payload'
    )) {
        if ($smokeSource.IndexOf($upgradeContract, [StringComparison]::Ordinal) -lt 0) {
            Stop-Test "Windows N -> N+1 replacement smoke is missing: $upgradeContract"
        }
    }
    $buildSource = Get-Content -LiteralPath $buildScript -Raw
    $releaseWorkflow = Get-Content `
        -LiteralPath (Join-Path (Split-Path -Parent $scriptRoot) '..\.github\workflows\release.yml') `
        -Raw
    if (($releaseWorkflow | Select-String -Pattern 'crt_mode: static-msvc-v1' -AllMatches).Matches.Count -ne 2 -or
        ([regex]::Matches($releaseWorkflow, [regex]::Escape("rustflags: '-C target-feature=+crt-static'"))).Count -ne 2 -or
        $releaseWorkflow.IndexOf('RUSTFLAGS: ${{ matrix.rustflags }}', [StringComparison]::Ordinal) -lt 0 -or
        $releaseWorkflow.IndexOf('${{ matrix.crt_mode }}-cargo-', [StringComparison]::Ordinal) -lt 0) {
        Stop-Test 'Windows static-CRT build and cache contract drifted'
    }
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

    $peFixture = Join-Path $temporaryRoot 'pe-import-fixture.exe'
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    New-MinimalPe -Path $peFixture -Machine 0x8664
    $image = Assert-PeStaticMsvcRuntime -Path $peFixture
    if ($image.Machine -ne 0x8664 -or
        $image.Imports -cnotcontains 'KERNEL32.dll' -or
        $image.DelayImports -cnotcontains 'USER32.dll') {
        Stop-Test 'valid PE fixture did not expose its normal and delay imports'
    }
    New-MinimalPe `
        -Path $peFixture `
        -Machine 0x8664 `
        -NormalImport 'VCRUNTIME140_1.dll'
    Assert-FailsWith -Pattern 'dynamically imports forbidden MSVC runtime VCRUNTIME140_1.dll' -Action {
        Assert-PeStaticMsvcRuntime -Path $peFixture | Out-Null
    }
    New-MinimalPe `
        -Path $peFixture `
        -Machine 0x8664 `
        -DelayImport 'MSVCP140_ATOMIC_WAIT.dll'
    Assert-FailsWith -Pattern 'dynamically imports forbidden MSVC runtime MSVCP140_ATOMIC_WAIT.dll' -Action {
        Assert-PeStaticMsvcRuntime -Path $peFixture | Out-Null
    }
    New-MinimalPe `
        -Path $peFixture `
        -Machine 0x8664 `
        -NormalImport 'api-ms-win-crt-runtime-l1-1-0.dll'
    Assert-FailsWith -Pattern 'dynamically imports forbidden MSVC runtime api-ms-win-crt-runtime-l1-1-0.dll' -Action {
        Assert-PeStaticMsvcRuntime -Path $peFixture | Out-Null
    }
    New-MinimalPe -Path $peFixture -Machine 0x8664
    $corruptBytes = [IO.File]::ReadAllBytes($peFixture)
    $outsideRva = [uint32]::Parse('90000000', [Globalization.NumberStyles]::HexNumber)
    [BitConverter]::GetBytes($outsideRva).CopyTo($corruptBytes, 0x20C)
    [IO.File]::WriteAllBytes($peFixture, $corruptBytes)
    Assert-FailsWith -Pattern 'normal import descriptor RVA .* is not backed by the file' -Action {
        Get-PeImageInfo -Path $peFixture | Out-Null
    }
    New-MinimalPe -Path $peFixture -Machine 0x8664
    $corruptBytes = [IO.File]::ReadAllBytes($peFixture)
    [BitConverter]::GetBytes($outsideRva).CopyTo($corruptBytes, 0x170)
    [IO.File]::WriteAllBytes($peFixture, $corruptBytes)
    Assert-FailsWith -Pattern 'delay import directory RVA .* is not backed by the file' -Action {
        Get-PeImageInfo -Path $peFixture | Out-Null
    }

    $stagingRoot = Join-Path $temporaryRoot 'staging'
    $bundle = Join-Path $stagingRoot "neoth-v$version-$target"
    New-Item -ItemType Directory -Path $bundle -Force | Out-Null
    foreach ($name in $requiredExecutables) {
        New-MinimalPe -Path (Join-Path $bundle $name) -Machine 0x8664
    }
    foreach ($name in $supportFiles) {
        Set-Utf8NoBomContent -Path (Join-Path $bundle $name) -Value $name
    }
    New-SelfKnowledgeFixture -Path (Join-Path $bundle 'self-knowledge') -Version $version
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

    Set-Utf8NoBomContent `
        -Path (Join-Path $bundle 'self-knowledge\graph.json') `
        -Value '{"nodes":[],"links":[]}'
    Remove-Item -LiteralPath $archive -Force
    Compress-Archive -LiteralPath $bundle -DestinationPath $archive -CompressionLevel Optimal
    $tamperedSnapshotHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Utf8NoBomContent -Path $checksum -Value "$tamperedSnapshotHash  $archiveName"
    Assert-FailsWith -Pattern 'self-knowledge (SHA-256|file metadata) mismatch' -Action {
        & $buildScript `
            -Archive $archive `
            -Checksum $checksum `
            -Version $version `
            -Architecture x64 `
            -Iscc $isccForValidation `
            -OutputDirectory $output `
            -ValidateOnly | Out-Null
    }
    New-SelfKnowledgeFixture -Path (Join-Path $bundle 'self-knowledge') -Version $version

    New-MinimalPe `
        -Path (Join-Path $bundle 'neoth-relay.exe') `
        -Machine 0x8664 `
        -NormalImport 'CONCRT140.dll'
    Remove-Item -LiteralPath $archive -Force
    Compress-Archive -LiteralPath $bundle -DestinationPath $archive -CompressionLevel Optimal
    $dynamicCrtHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Utf8NoBomContent -Path $checksum -Value "$dynamicCrtHash  $archiveName"
    Assert-FailsWith -Pattern 'neoth-relay.exe dynamically imports forbidden MSVC runtime CONCRT140.dll' -Action {
        & $buildScript `
            -Archive $archive `
            -Checksum $checksum `
            -Version $version `
            -Architecture x64 `
            -Iscc $isccForValidation `
            -OutputDirectory $output `
            -ValidateOnly | Out-Null
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
        -RequiredFiles @(
            $requiredExecutables +
            $supportFiles +
            @('self-knowledge/graph.json', 'self-knowledge/manifest.json', 'self-knowledge/wiki/index.md')
        )

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
